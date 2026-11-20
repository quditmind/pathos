//go:build rea_e2e

package worker

import (
	"context"
	"encoding/json"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
)

// TestREAE2E runs in the worker-rea image, as the worker, on a network
// with an "egress" and an "api" service, next to a sandbox runner container
// (network_mode: none). workers/rea/test/rea-e2e.sh sets this up; run it
// instead of this test directly.
//
// It analyses three artifacts through the real sandbox runner with the
// real pathos-rea: a tiny C program, a Go service with a planted
// net/http/pprof import (both built by the script: our own builds) and a
// firmware blob made from test data; then runs `pathos-rea selftest`
// through the runner and checks the isolation (no network, read-only root
// filesystem, no capabilities, its own UID, no worker environment).
func TestREAE2E(t *testing.T) {
	dir := os.Getenv("E2E_TEST_DIR") // the built fixtures, read-only
	if dir == "" {
		t.Skip("run workers/rea/test/rea-e2e.sh")
	}
	// Control: the services are reachable from the worker container.
	for _, a := range []string{"egress:3128", "api:8081"} {
		c, err := net.DialTimeout("tcp", a, 5*time.Second)
		if err != nil {
			t.Fatalf("control: %s not reachable from the worker: %v", a, err)
		}
		_ = c.Close()
	}
	s, err := OpenSandbox(os.Getenv(SandboxDirEnv))
	if err != nil {
		t.Fatal(err)
	}
	tool := reaTool{sandbox: s}
	if v, err := tool.Version(context.Background()); err != nil || v == "" {
		t.Fatalf("version %q: %v", v, err)
	}
	line, err := exec.Command(REABinary, "version").Output()
	if err != nil || !strings.Contains(string(line), "radare2 6.2.6") || !strings.Contains(string(line), "binwalk 3.1.0") {
		t.Fatalf("version line %q: %v", line, err)
	}
	t.Logf("%s", strings.TrimSpace(string(line)))
	cfg, _ := json.Marshal(REAConfig{Tools: REATools, MemoryMB: 2048, TimeoutSeconds: 900, MaxCode: 20})

	analyse := func(name string) map[string]any {
		t.Helper()
		out := filepath.Join(t.TempDir(), "out.json")
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Minute)
		defer cancel()
		start := time.Now()
		skipped, err := tool.Run(ctx, RunInput{Out: out, Config: cfg, Target: &JobTarget{Kind: "artifact", FileName: name},
			TargetFile: filepath.Join(dir, name)})
		if err != nil || skipped != "" {
			t.Fatalf("%s: skipped %q, err %v", name, skipped, err)
		}
		raw, err := os.ReadFile(out)
		if err != nil {
			t.Fatal(err)
		}
		var doc map[string]any
		if err := json.Unmarshal(raw, &doc); err != nil {
			t.Fatal(err)
		}
		if doc["schema"] != "pathos.rea/v1" {
			t.Fatalf("%s: schema %v", name, doc["schema"])
		}
		art := doc["artifact"].(map[string]any)
		t.Logf("%s: %s %v/%v in %s; tools %v; stats %v", name, art["format"], art["arch"], art["language"], time.Since(start).Round(time.Second),
			doc["tools"], doc["stats"])
		// No secret leaves the sandbox.
		if strings.Contains(string(raw), "AKIAIOSFODNN7EXAMPLE") {
			t.Errorf("%s: the planted AWS example key is not redacted", name)
		}
		return doc
	}
	list := func(doc map[string]any, key string) []map[string]any {
		var out []map[string]any
		for _, x := range doc[key].([]any) {
			out = append(out, x.(map[string]any))
		}
		return out
	}
	values := func(items []map[string]any, field string) []string {
		var out []string
		for _, x := range items {
			out = append(out, x[field].(string))
		}
		return out
	}

	// C: libc imports, the redacted key, sections, calls to imports.
	c := analyse("hello")
	if art := c["artifact"].(map[string]any); art["format"] != "elf" || art["language"] != "c" {
		t.Errorf("hello: artifact %v", art)
	}
	if !slices.Contains(values(list(c, "imports"), "name"), "puts") || len(list(c, "sections")) == 0 || len(list(c, "calls")) == 0 {
		t.Errorf("hello: imports %v, %d sections, %d calls", values(list(c, "imports"), "name"), len(list(c, "sections")), len(list(c, "calls")))
	}
	redacted := false
	for _, s := range list(c, "strings") {
		redacted = redacted || (s["redacted"] == true && strings.Contains(s["value"].(string), "[REDACTED:aws_access_key]"))
	}
	if !redacted {
		t.Error("hello: the AWS example key is not reported as a redacted string")
	}
	if c["tools"].(map[string]any)["radare2"].(map[string]any)["status"] != "succeeded" {
		t.Errorf("hello: radare2 %v", c["tools"].(map[string]any)["radare2"])
	}

	// Go: exact Go symbols, the pprof package, its route, the call graph.
	g := analyse("payments")
	fns := values(list(g, "functions"), "name")
	for _, want := range []string{"main.main", "main.CreateOrder", "net/http/pprof.Index"} {
		if !slices.Contains(fns, want) {
			t.Errorf("payments: function %s missing", want)
		}
	}
	if !slices.Contains(values(list(g, "imports"), "id"), "imp:go:net/http/pprof") {
		t.Error("payments: no import imp:go:net/http/pprof")
	}
	strs := values(list(g, "strings"), "value")
	for _, want := range []string{"/debug/pprof/", "/api/orders"} {
		if !slices.Contains(strs, want) {
			t.Errorf("payments: string %s missing", want)
		}
	}
	if len(list(g, "calls")) < 100 || len(list(g, "sections")) == 0 || len(list(g, "string_refs")) == 0 || len(list(g, "code")) == 0 {
		t.Errorf("payments: %d calls, %d sections, %d string refs, %d code", len(list(g, "calls")), len(list(g, "sections")),
			len(list(g, "string_refs")), len(list(g, "code")))
	}
	if gi, _ := g["go"].(map[string]any); gi == nil || gi["main_module"].(map[string]any)["path"] != "example.com/payments" {
		t.Errorf("payments: go %v", g["go"])
	}

	// Firmware: binwalk signatures and extracted files.
	f := analyse("firmware.bin")
	fw, _ := f["firmware"].(map[string]any)
	if fw == nil {
		t.Fatal("firmware: no firmware section")
	}
	var types []string
	for _, e := range fw["entries"].([]any) {
		types = append(types, e.(map[string]any)["type"].(string))
	}
	if !slices.Contains(types, "gzip") || !slices.Contains(types, "elf") {
		t.Errorf("firmware: entries %v", types)
	}
	var files []string
	for _, x := range fw["files"].([]any) {
		files = append(files, x.(map[string]any)["path"].(string))
	}
	if !slices.ContainsFunc(files, func(p string) bool { return strings.HasSuffix(p, "bin/app") }) {
		t.Errorf("firmware: extracted files %v", files)
	}
	if f["artifact"].(map[string]any)["format"] != "firmware" {
		t.Errorf("firmware: format %v", f["artifact"].(map[string]any)["format"])
	}

	// Isolation of what pathos-rea (and a parser exploit in a tool) can do.
	out := filepath.Join(t.TempDir(), "selftest.json")
	src := t.TempDir()
	res, err := s.RunUntrusted(context.Background(), UntrustedJob{Source: src, Command: REABinary, Args: []string{"selftest", "{output}"},
		Timeout: time.Minute, Output: out, Dir: "tmp"})
	if err != nil || res.ExitCode != 0 {
		t.Fatalf("selftest: %v %+v %s", err, res, res.Log)
	}
	var st struct {
		UID        int               `json:"uid"`
		CapEff     string            `json:"cap_eff"`
		Interfaces []string          `json:"interfaces"`
		DNSOK      bool              `json:"dns_ok"`
		Connect    map[string]string `json:"connect"`
		RootWrite  string            `json:"root_write"`
		EnvKeys    []string          `json:"env_keys"`
		Procs      int               `json:"proc_pids_visible"`
	}
	raw, _ := os.ReadFile(out)
	if err := json.Unmarshal(raw, &st); err != nil {
		t.Fatal(err)
	}
	t.Logf("selftest in the sandbox: %s", raw)
	if st.UID != 10002 {
		t.Errorf("uid %d, want 10002", st.UID)
	}
	if strings.Trim(st.CapEff, "0") != "" {
		t.Errorf("effective capabilities %s", st.CapEff)
	}
	for _, i := range st.Interfaces {
		if i != "lo" {
			t.Errorf("network interface %s in the sandbox", i)
		}
	}
	if st.DNSOK {
		t.Error("DNS resolves in the sandbox")
	}
	for a, e := range st.Connect {
		if e == "" {
			t.Errorf("connected to %s from the sandbox", a)
		}
	}
	if st.RootWrite == "" || !strings.Contains(st.RootWrite, "read-only") && !strings.Contains(st.RootWrite, "permission denied") {
		t.Errorf("root filesystem write: %q", st.RootWrite)
	}
	for _, k := range st.EnvKeys {
		if strings.HasPrefix(k, "PATHOS_") || strings.HasSuffix(k, "_PROXY") || strings.HasSuffix(k, "_proxy") {
			t.Errorf("environment variable %s in the sandbox", k)
		}
	}
	if st.Procs > 5 {
		t.Errorf("%d processes visible in the sandbox (the worker's must not be)", st.Procs)
	}
}
