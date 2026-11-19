package worker

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

// These tests run the agent's and the runner's side of the sandbox protocol
// in one process (the runner's kill(-1) replaced by killing the command's
// session). The isolation itself (no network, other UID, other PID
// namespace, cgroup limits) is Docker's and is tested in the built image by
// workers/fuzz/test/sandbox-e2e.sh.

func startTestRunner(t *testing.T) *Sandbox {
	t.Helper()
	dir := t.TempDir()
	s, err := OpenSandbox(dir)
	if err != nil {
		t.Fatal(err)
	}
	s.pollEvery = 20 * time.Millisecond
	// As in the container: orphans of a run are re-parented to the runner.
	if _, _, e := syscall.RawSyscall(syscall.SYS_PRCTL, prSetChildSubreaper, 1, 0); e != 0 {
		t.Fatal(e)
	}
	r := &sandboxRunner{dir: dir, log: slog.New(slog.NewTextHandler(io.Discard, nil)), done: map[string]bool{}, uid: os.Getuid()}
	r.signalAll = func() {
		if r.cur > 0 {
			_ = syscall.Kill(-r.cur, syscall.SIGKILL)
		}
	}
	r.killAll = func() bool {
		for range 1000 {
			r.signalAll()
			for {
				var ws syscall.WaitStatus
				if pid, err := syscall.Wait4(-1, &ws, syscall.WNOHANG, nil); pid <= 0 || err != nil {
					break
				}
			}
			if r.cur == 0 || errors.Is(syscall.Kill(-r.cur, 0), syscall.ESRCH) {
				return true
			}
			time.Sleep(5 * time.Millisecond)
		}
		return false
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { r.serve(ctx); close(done) }()
	t.Cleanup(func() { cancel(); <-done; _ = s.lock.Close() })
	return s
}

func TestRunUntrustedOutputLogAndEnvironment(t *testing.T) {
	t.Setenv("PATHOS_TEST_SECRET", "agent-secret-value")
	t.Setenv("HTTPS_PROXY", "http://egress.invalid:3128")
	s := startTestRunner(t)
	src := t.TempDir()
	if err := os.WriteFile(filepath.Join(src, "input.txt"), []byte("hello"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(src, ".git"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("/etc/passwd", filepath.Join(src, "link")); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(t.TempDir(), "report")
	res, err := s.RunUntrusted(context.Background(), UntrustedJob{Source: src, Command: "/bin/sh", Env: []string{"MODE=x"}, Timeout: time.Minute,
		Output: out, Args: []string{"-c", `env; pwd; ls -a; readlink link; cat input.txt > "$1"; echo " $MODE" >> "$1"; exit 3`, "sh", "{output}"}})
	if err != nil {
		t.Fatal(err)
	}
	log := string(res.Log)
	if res.ExitCode != 3 || !res.OutputWritten || res.TimedOut {
		t.Fatalf("result: %+v", res)
	}
	if got, _ := os.ReadFile(out); string(got) != "hello x\n" {
		t.Errorf("output: %q", got)
	}
	for _, bad := range []string{"agent-secret-value", "PATHOS_", "PROXY", ".git"} {
		if strings.Contains(log, bad) {
			t.Errorf("the run saw %s:\n%s", bad, log)
		}
	}
	for _, want := range []string{"MODE=x", "HOME=" + s.dir + "/jobs/", "TMPDIR=" + s.dir + "/jobs/", "/src\n", "/etc/passwd"} {
		if !strings.Contains(log, want) {
			t.Errorf("log lacks %q:\n%s", want, log)
		}
	}
	// Nothing is left behind.
	for _, d := range []string{"jobs", "queue"} {
		if entries, _ := os.ReadDir(filepath.Join(s.dir, d)); len(entries) != 0 {
			t.Errorf("%s not empty: %v", d, entries)
		}
	}
}

func TestRunUntrustedTimeoutAndCancel(t *testing.T) {
	s := startTestRunner(t)
	res, err := s.RunUntrusted(context.Background(), UntrustedJob{Command: "/bin/sh", Args: []string{"-c", "sleep 60 & sleep 60"},
		Timeout: time.Second})
	if err != nil || !res.TimedOut || res.Signal != "killed" {
		t.Fatalf("timeout: %+v %v", res, err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	start := time.Now()
	if _, err := s.RunUntrusted(ctx, UntrustedJob{Command: "/bin/sleep", Args: []string{"60"}, Timeout: time.Minute}); !errors.Is(err,
		context.DeadlineExceeded) || time.Since(start) > 10*time.Second {
		t.Fatalf("cancel: %v after %s", err, time.Since(start))
	}
	// The sandbox is usable again.
	if res, err := s.RunUntrusted(context.Background(), UntrustedJob{Command: "/bin/true", Timeout: time.Minute}); err != nil || res.ExitCode != 0 {
		t.Fatalf("after cancel: %+v %v", res, err)
	}
}

// The command shares the runner's UID, so it can write anything in its job
// directory: a forged result, a link or a FIFO instead of the output. None
// of it is believed.
func TestRunUntrustedForgeries(t *testing.T) {
	s := startTestRunner(t)
	forge := `printf '{"id":"%s","exit_code":0,"mac":"00"}' "$(basename "$(dirname "$PWD")")" > ../result.json; sleep 1; exit 7`
	res, err := s.RunUntrusted(context.Background(), UntrustedJob{Command: "/bin/sh", Args: []string{"-c", forge}, Timeout: time.Minute})
	if err != nil || res.ExitCode != 7 {
		t.Fatalf("forged result accepted: %+v %v", res, err)
	}
	out := filepath.Join(t.TempDir(), "report")
	for name, script := range map[string]string{
		"symlink": `ln -s /etc/passwd "$1"`,
		"fifo":    `mkfifo "$1"`,
		"escape":  `rm -rf ../out && ln -s / ../out`,
	} {
		_, err := s.RunUntrusted(context.Background(), UntrustedJob{Command: "/bin/sh", Args: []string{"-c", script, "sh", "{output}"},
			Timeout: time.Minute, Output: out})
		if err == nil {
			t.Errorf("%s: output accepted", name)
		}
	}
	// A run that locks its own files away is still cleaned up.
	if _, err := s.RunUntrusted(context.Background(), UntrustedJob{Command: "/bin/sh", Timeout: time.Minute,
		Args: []string{"-c", `mkdir -p d/e && touch d/e/f && chmod 000 d/e d`}}); err != nil {
		t.Fatal(err)
	}
	if entries, _ := os.ReadDir(filepath.Join(s.dir, "jobs")); len(entries) != 0 {
		t.Errorf("job directories left: %v", entries)
	}
}

func TestRunUntrustedWithoutRunner(t *testing.T) {
	var none *Sandbox
	if _, err := none.RunUntrusted(context.Background(), UntrustedJob{Command: "/bin/true", Timeout: time.Second}); !errors.Is(err, ErrNoSandbox) {
		t.Fatalf("nil sandbox: %v", err)
	}
	dir := t.TempDir()
	s, err := OpenSandbox(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer s.lock.Close()
	if _, err := OpenSandbox(dir); err == nil {
		t.Error("a second agent opened the same sandbox directory")
	}
	s.claimWait, s.pollEvery = 300*time.Millisecond, 20*time.Millisecond
	if _, err := s.RunUntrusted(context.Background(), UntrustedJob{Command: "/bin/true", Timeout: time.Second}); err == nil ||
		!strings.Contains(err.Error(), "did not pick the run up") {
		t.Fatalf("no runner: %v", err)
	}
	for _, j := range []UntrustedJob{
		{Command: "true", Timeout: time.Second},
		{Command: "/bin/true"},
		{Command: "/bin/true", Timeout: time.Second, Env: []string{"LD_PRELOAD=/x.so"}},
		{Command: "/bin/true", Timeout: time.Second, Env: []string{"PATHOS_WORKER_TOKEN=x"}},
		{Command: "/bin/true", Timeout: time.Second, Dir: "/"},
	} {
		if _, err := s.RunUntrusted(context.Background(), j); err == nil {
			t.Errorf("accepted %+v", j)
		}
	}
}

func TestSandboxManifests(t *testing.T) {
	base := "name: x\ncategory: fuzz\ncommand: /bin/true\nargs: [\"{source}\", \"{output}\"]\nsandbox: true\n"
	if _, err := decodeManifestSpec([]byte(base), false); err != nil {
		t.Fatalf("valid sandbox manifest: %v", err)
	}
	for _, bad := range []string{
		base + "network: registry\n",
		base + "output: stdout\n",
		strings.Replace(base, `"{output}"]`, `"{output}", "{cache}"]`, 1),
		strings.Replace(base, `["{source}", "{output}"]`, `["{target_url}", "{output}"]`, 1) + "targets: [url]\n",
	} {
		if _, err := decodeManifestSpec([]byte(bad), false); err == nil {
			t.Errorf("accepted:\n%s", bad)
		}
	}
	// Without a runner a sandbox tool is skipped, never run in the worker.
	d, err := decodeManifestSpec([]byte(base), false)
	if err != nil {
		t.Fatal(err)
	}
	skipped, err := (pluginTool{def: d}).Run(context.Background(), RunInput{Src: t.TempDir(), Out: filepath.Join(t.TempDir(), "o")})
	if err != nil || !strings.Contains(skipped, "sandbox runner") {
		t.Fatalf("skipped %q, %v", skipped, err)
	}
	for _, f := range []string{"go-fuzz.yaml", "atheris.yaml"} {
		if d := loadFamilySpec(t, "fuzz", f); !d.Sandbox {
			t.Errorf("%s runs repository code without the sandbox", f)
		}
	}
}

func TestSandboxedPluginRun(t *testing.T) {
	s := startTestRunner(t)
	d, err := decodeManifestSpec([]byte("name: x\ncategory: fuzz\ncommand: /bin/sh\nparser: jsonmap\njsonmap: {records: findings, rule_id: id, title: id}\n"+
		"args: [\"-c\", \"ls {source} > {tmp}/l; echo '{\\\"findings\\\":[]}' > {output}; echo progress >&2\"]\nsandbox: true\nenv: {A: b}\n"), false)
	if err != nil {
		t.Fatal(err)
	}
	src := t.TempDir()
	_ = os.WriteFile(filepath.Join(src, "main.go"), []byte("package main\n"), 0o600)
	out := filepath.Join(t.TempDir(), "report.json")
	skipped, err := (pluginTool{def: d, sandbox: s}).Run(context.Background(), RunInput{Src: src, Out: out})
	if err != nil || skipped != "" {
		t.Fatalf("%q %v", skipped, err)
	}
	if got, _ := os.ReadFile(out); strings.TrimSpace(string(got)) != `{"findings":[]}` {
		t.Errorf("report: %q", got)
	}
}
