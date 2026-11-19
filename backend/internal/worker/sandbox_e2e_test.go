//go:build sandbox_e2e

package worker

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"
)

// TestSandboxE2E runs in the worker-fuzz image, as the worker, on networks
// with an "egress" and an "api" service, next to a sandbox runner container
// (network_mode: none). workers/fuzz/test/sandbox-e2e.sh sets this up; run
// it instead of this test directly.
//
// It runs the real go-fuzz and atheris manifests on a repository made of
// the fuzz sample (planted bugs: the normal results) and a malicious probe
// (workers/fuzz/test/sandbox-probe) that tries to escape: every attempt
// must fail, and the planted bugs must still be reported.
func TestSandboxE2E(t *testing.T) {
	testDir := os.Getenv("E2E_TEST_DIR") // workers/fuzz/test, read-only
	if testDir == "" {
		t.Skip("run workers/fuzz/test/sandbox-e2e.sh")
	}
	marker := os.Getenv("PATHOS_WORKER_BOOTSTRAP_TOKEN")
	if marker == "" {
		t.Fatal("the worker's token (a marker value) must be set")
	}

	// Control: from the worker container the services are reachable, so
	// the probe would see them if the sandbox let it.
	var targets []string
	for _, a := range []string{"egress:3128", "api:8081"} {
		host, port, _ := net.SplitHostPort(a)
		ips, err := net.LookupHost(host)
		if err != nil || len(ips) == 0 {
			t.Fatalf("control: %s does not resolve from the worker: %v", host, err)
		}
		c, err := net.DialTimeout("tcp", a, 5*time.Second)
		if err != nil {
			t.Fatalf("control: %s not reachable from the worker: %v", a, err)
		}
		_ = c.Close()
		targets = append(targets, net.JoinHostPort(ips[0], port))
	}
	src := filepath.Join(t.TempDir(), "repo")
	for _, d := range []string{"sample", "sandbox-probe"} {
		if err := os.CopyFS(filepath.Join(src, d), os.DirFS(filepath.Join(testDir, d))); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(src, "sandbox-targets.txt"), []byte(strings.Join(targets, "\n")+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	ctl := exec.Command("/opt/pathos/fuzz/bin/python", filepath.Join(src, "sandbox-probe/pyprobe/fuzz_probe.py"))
	ctl.Dir = src
	ctl.Env = append(os.Environ(), "PROBE_NO_FORK=1")
	raw, _ := ctl.CombinedOutput()
	control := probeResults(t, string(raw))
	t.Logf("control (unsandboxed, in the worker container): %s", strings.TrimSpace(string(raw)))
	for _, k := range []string{"tcp:egress:3128", "tcp:api:8081", "tcp:" + targets[0], "dns:api", "env", "proc1-environ"} {
		if v := control[k]; !strings.HasPrefix(v, "OPEN") && v != "readable" {
			t.Errorf("control: %s=%s; the probe would not detect an escape", k, v)
		}
	}

	// The real manifests, through the sandbox runner.
	s, err := OpenSandbox(os.Getenv(SandboxDirEnv))
	if err != nil {
		t.Fatal(err)
	}
	defs := LoadToolManifests("/opt/pathos/tools.d", slog.New(slog.NewTextHandler(io.Discard, nil)))
	work := t.TempDir()
	for _, c := range []struct {
		tool, rule, file string
		probes           []string
	}{
		{"go-fuzz", "go-fuzz/slice-bounds-out-of-range", "sample/parser/parser.go", nil},
		{"atheris", "atheris/uncaught-exception", "sample/pyharness/configparse.py", []string{"fork", "ifaces", "procs", "proc-environ"}},
	} {
		t.Run(c.tool, func(t *testing.T) {
			i := slices.IndexFunc(defs, func(d PluginDef) bool { return d.Key() == c.tool })
			if i < 0 {
				t.Fatalf("manifest %s not in the image", c.tool)
			}
			d := defs[i]
			if !d.Sandbox {
				t.Fatal("the manifest does not use the sandbox")
			}
			d.Env = map[string]string{"FUZZ_SECONDS": "15", "FUZZ_TOTAL_SECONDS": "600", "FUZZ_MAX_TARGETS": "20", "FUZZ_JOBS": "2"}
			out := filepath.Join(work, c.tool+".json")
			start := time.Now()
			skipped, err := (pluginTool{def: d, sandbox: s}).Run(context.Background(), RunInput{Src: src, Out: out})
			if err != nil || skipped != "" {
				t.Fatalf("run: %q %v", skipped, err)
			}
			t.Logf("%s ran in the sandbox in %s", c.tool, time.Since(start).Round(time.Second))
			raw, err := os.ReadFile(out)
			if err != nil {
				t.Fatal(err)
			}
			if strings.Contains(string(raw), marker) {
				t.Error("the worker's token appears in the report")
			}
			var rep struct {
				Targets []struct {
					Name, Status, Detail string
				} `json:"targets"`
				Findings []struct {
					RuleID string `json:"rule_id"`
					File   string `json:"file"`
					Output string `json:"output"`
				} `json:"findings"`
			}
			if err := json.Unmarshal(raw, &rep); err != nil {
				t.Fatal(err)
			}
			// Normal results: the planted bug is found.
			if !slices.ContainsFunc(rep.Findings, func(f struct {
				RuleID string `json:"rule_id"`
				File   string `json:"file"`
				Output string `json:"output"`
			}) bool {
				return f.RuleID == c.rule && f.File == c.file
			}) {
				t.Errorf("planted bug %s in %s not reported: %s", c.rule, c.file, raw)
			}
			// The probe's attempts all failed.
			text := ""
			for _, tg := range rep.Targets {
				text += tg.Detail + "\n"
				t.Logf("target %s: %s", tg.Name, tg.Status)
			}
			for _, f := range rep.Findings {
				text += f.Output + "\n"
			}
			got := probeResults(t, text)
			t.Logf("sandboxed probe: %v", got)
			want := []string{"tcp:egress:3128", "tcp:api:8081", "tcp:1.1.1.1:443", "dns:api", "dns:egress", "dns:example.com", "env",
				"proc1-environ", "write:/tmp", "write:/sandbox", "write:/sandbox/jobs", "write:/sandbox/queue", "write:/opt/pathos",
				"write:/etc", "write:/dev/shm", "write:/var/tmp"}
			for _, a := range targets {
				want = append(want, "tcp:"+a)
			}
			if c.tool == "go-fuzz" {
				want = append(want, "proc1-mem")
			}
			for k, v := range got {
				if strings.HasPrefix(v, "OPEN") {
					t.Errorf("ESCAPE %s=%s", k, v)
				}
			}
			for _, k := range append(want, c.probes...) {
				v, ok := got[k]
				switch {
				case !ok:
					t.Errorf("probe %s did not report", k)
				case k == "env" || k == "proc-environ":
					if !strings.HasPrefix(v, "clean") {
						t.Errorf("ESCAPE %s=%s", k, v)
					}
				case k == "ifaces":
					if v != "lo" {
						t.Errorf("network interfaces in the sandbox: %s", v)
					}
				case k == "procs":
					if strings.Contains(v, "worker.test") {
						t.Errorf("the worker's process is visible: %s", v)
					}
				case k == "fork":
					m := regexp.MustCompile(`^limited:(\d+):EAGAIN$`).FindStringSubmatch(v)
					if n, _ := strconv.Atoi(m2(m)); m == nil || n >= 256 {
						t.Errorf("fork bomb not limited by the runner's pids limit: %s", v)
					}
				case !strings.HasPrefix(v, "blocked"):
					t.Errorf("ESCAPE %s=%s", k, v)
				}
			}
		})
	}
	if entries, _ := os.ReadDir(filepath.Join(s.Dir(), "jobs")); len(entries) != 0 {
		t.Errorf("job directories left behind: %v", entries)
	}
}

func m2(m []string) string {
	if len(m) < 2 {
		return ""
	}
	return m[1]
}

var probeLineRe = regexp.MustCompile(`SANDBOX-PROBE ([^\n]+)`)

// probeResults merges the key=value pairs of every SANDBOX-PROBE line.
func probeResults(t *testing.T, text string) map[string]string {
	t.Helper()
	out := map[string]string{}
	for _, m := range probeLineRe.FindAllStringSubmatch(text, -1) {
		for _, kv := range strings.Fields(m[1]) {
			if k, v, ok := strings.Cut(kv, "="); ok {
				out[k] = v
			}
		}
	}
	if len(out) == 0 {
		t.Fatalf("no SANDBOX-PROBE line in:\n%s", text)
	}
	return out
}
