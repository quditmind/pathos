package worker

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
	"time"
)

// The sandbox runner (`pathos-worker sandbox-runner`) runs in the sibling
// container described in sandbox.go. It holds no secret except the
// one-time key of the request it is handling, which it reads before any
// repository code of that request starts. It is not dumpable (so code of
// the same UID can neither read its memory nor its environment through
// /proc, nor ptrace it), it is the child subreaper (every orphaned process
// of a run is re-parented to it and reaped), and after each run it kills
// every process of its UID until none is left.

const (
	prSetDumpable       = 4
	prSetChildSubreaper = 36
	sandboxAckWait      = 60 * time.Second
	sandboxFileLimit    = 1 << 30 // RLIMIT_FSIZE of the commands
)

// RunSandboxRunner serves the requests in dir until ctx is done.
func RunSandboxRunner(ctx context.Context, dir string, log *slog.Logger) error {
	if _, _, e := syscall.RawSyscall(syscall.SYS_PRCTL, prSetDumpable, 0, 0); e != 0 {
		return fmt.Errorf("prctl(PR_SET_DUMPABLE): %w", e)
	}
	if _, _, e := syscall.RawSyscall(syscall.SYS_PRCTL, prSetChildSubreaper, 1, 0); e != 0 {
		return fmt.Errorf("prctl(PR_SET_CHILD_SUBREAPER): %w", e)
	}
	// Inherited by every command: no core dumps, bounded file size.
	_ = syscall.Setrlimit(syscall.RLIMIT_CORE, &syscall.Rlimit{})
	_ = syscall.Setrlimit(syscall.RLIMIT_FSIZE, &syscall.Rlimit{Cur: sandboxFileLimit, Max: sandboxFileLimit})
	if os.Getuid() == 0 {
		return errors.New("the sandbox runner must not run as root")
	}
	// kill(-1) must reach only the runs' processes: the runner is the
	// init process of its own container (compose: no `init: true`).
	if os.Getpid() != 1 {
		return errors.New("the sandbox runner must be its container's init process (PID 1)")
	}
	r := &sandboxRunner{dir: dir, log: log, done: map[string]bool{}, uid: os.Getuid(), signalAll: func() { _ = syscall.Kill(-1, syscall.SIGKILL) },
		killAll: killAllOwn}
	log.Info("sandbox runner started", "dir", dir, "pid", os.Getpid())
	r.serve(ctx)
	return nil
}

// serve handles requests one at a time until ctx is done.
func (r *sandboxRunner) serve(ctx context.Context) {
	r.recover()
	tick := time.NewTicker(200 * time.Millisecond)
	defer tick.Stop()
	for {
		if id := r.next(); id != "" {
			r.handle(ctx, id)
			continue
		}
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
		}
	}
}

type sandboxRunner struct {
	dir  string
	log  *slog.Logger
	uid  int
	done map[string]bool
	// signalAll sends SIGKILL to every process of the runs; killAll also
	// reaps them until none is left (false if some survive). In the
	// container: kill(-1). Tests replace them (kill(-1) outside a
	// container of its own would hit the test's own processes).
	signalAll func()
	killAll   func() bool
	// cur is the PID of the running command (its session id).
	cur int
}

func (r *sandboxRunner) queue(name string) string { return filepath.Join(r.dir, "queue", name) }
func (r *sandboxRunner) job(id string) string     { return filepath.Join(r.dir, "jobs", id) }

// recover answers requests a previous runner process had claimed: the
// container restarted, so their processes are gone.
func (r *sandboxRunner) recover() {
	for _, id := range r.pending() {
		if _, err := os.Lstat(filepath.Join(r.job(id), "claimed")); err == nil {
			req, err := r.read(id)
			r.done[id] = true
			if err == nil {
				r.finish(req, sandboxResult{ID: id, Error: "the sandbox runner restarted during this run"})
			}
		}
	}
}

func (r *sandboxRunner) pending() []string {
	entries, _ := os.ReadDir(filepath.Join(r.dir, "queue"))
	type item struct {
		id string
		t  time.Time
	}
	var items []item
	for _, e := range entries {
		id, ok := strings.CutSuffix(e.Name(), ".json")
		if !ok || !sandboxIDRe.MatchString(id) || !e.Type().IsRegular() {
			continue
		}
		info, err := e.Info()
		if err != nil {
			continue
		}
		items = append(items, item{id, info.ModTime()})
	}
	slices.SortFunc(items, func(a, b item) int { return a.t.Compare(b.t) })
	ids := make([]string, len(items))
	for i, it := range items {
		ids[i] = it.id
	}
	return ids
}

func (r *sandboxRunner) next() string {
	pending := r.pending()
	for id := range r.done {
		if !slices.Contains(pending, id) {
			delete(r.done, id) // the agent removed the request
		}
	}
	for _, id := range pending {
		if !r.done[id] {
			return id
		}
	}
	return ""
}

func (r *sandboxRunner) read(id string) (sandboxRequest, error) {
	var req sandboxRequest
	raw, err := readRegularFile(filepath.Join(r.dir, "queue"), id+".json", sandboxMaxResult)
	if err != nil {
		return req, err
	}
	if err := json.Unmarshal(raw, &req); err != nil {
		return req, err
	}
	if req.ID != id {
		return req, errors.New("request id mismatch")
	}
	return req, nil
}

func (r *sandboxRunner) handle(ctx context.Context, id string) {
	r.done[id] = true
	req, err := r.read(id)
	if err != nil {
		r.log.Warn("sandbox request unreadable", "id", id, "err", err)
		return
	}
	jobDir := r.job(id)
	if st, err := os.Lstat(jobDir); err != nil || !st.IsDir() {
		r.log.Warn("sandbox request without a job directory", "id", id)
		return
	}
	if err := writeFileAtomic(filepath.Join(jobDir, "claimed"), []byte("claimed\n"), 0o660); err != nil {
		r.log.Warn("sandbox request: cannot claim", "id", id, "err", err)
		return
	}
	// The agent deletes the request (and with it the key) once it sees the
	// claim; nothing runs before that.
	deadline := time.Now().Add(sandboxAckWait)
	for {
		if _, err := os.Lstat(r.queue(id + ".json")); errors.Is(err, fs.ErrNotExist) {
			break
		}
		if time.Now().After(deadline) || ctx.Err() != nil {
			r.finish(req, sandboxResult{ID: id, Error: "the worker did not acknowledge the run"})
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	res := sandboxResult{ID: id}
	if req.Command != "" {
		res = r.execute(ctx, req, jobDir)
	}
	// Whatever happened, nothing of this run survives the result. If
	// processes cannot be killed, the runner exits: Docker restarts the
	// container, which ends them, and the restarted runner answers the run.
	if !r.killAll() {
		r.log.Error("sandbox run: processes survive kill; exiting", "id", id)
		os.Exit(70)
	}
	r.fixPermissions(jobDir)
	r.finish(req, res)
	r.log.Info("sandbox run finished", "id", id, "exit_code", res.ExitCode, "signal", res.Signal, "timed_out", res.TimedOut,
		"canceled", res.Canceled, "seconds", res.Seconds, "error", res.Error)
}

func (r *sandboxRunner) execute(ctx context.Context, req sandboxRequest, jobDir string) sandboxResult {
	res := sandboxResult{ID: req.ID}
	if !filepath.IsAbs(req.Command) || checkUntrustedEnv(req.Env) != nil {
		res.Error = "invalid request"
		return res
	}
	wd := filepath.Join(jobDir, "src")
	switch req.Dir {
	case "tmp", "home":
		wd = filepath.Join(jobDir, req.Dir)
	}
	env := []string{"PATH=" + os.Getenv("PATH"), "LANG=C.UTF-8", "HOME=" + filepath.Join(jobDir, "home"),
		"TMPDIR=" + filepath.Join(jobDir, "tmp")}
	env = append(env, req.Env...)
	devnull, err := os.Open(os.DevNull)
	if err != nil {
		res.Error = err.Error()
		return res
	}
	defer devnull.Close()
	pr, pw, err := os.Pipe()
	if err != nil {
		res.Error = err.Error()
		return res
	}
	start := time.Now()
	p, err := os.StartProcess(req.Command, append([]string{req.Command}, req.Args...), &os.ProcAttr{
		Dir: wd, Env: env, Files: []*os.File{devnull, pw, pw},
		Sys: &syscall.SysProcAttr{Setsid: true, Pdeathsig: syscall.SIGKILL},
	})
	_ = pw.Close()
	if err != nil {
		_ = pr.Close()
		res.Error = "cannot start the command: " + err.Error()
		return res
	}
	pid := p.Pid
	r.cur = pid
	_ = p.Release()
	logDone := make(chan []byte, 1)
	go func() {
		buf := &limitedBuffer{max: sandboxMaxLog}
		_, _ = io.Copy(buf, pr)
		_ = pr.Close()
		logDone <- buf.Bytes()
	}()
	// Reap every child (orphans are re-parented to the runner) until the
	// command itself has exited.
	status := make(chan syscall.WaitStatus, 1)
	go func() {
		for {
			var ws syscall.WaitStatus
			wpid, err := syscall.Wait4(-1, &ws, 0, nil)
			if errors.Is(err, syscall.EINTR) {
				continue
			}
			if err != nil {
				return
			}
			if wpid == pid {
				status <- ws
				return
			}
		}
	}()
	timeout := time.Duration(req.TimeoutSeconds) * time.Second
	if timeout <= 0 || timeout > sandboxMaxTimeout {
		timeout = sandboxMaxTimeout
	}
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	poll := time.NewTicker(500 * time.Millisecond)
	defer poll.Stop()
	var ws syscall.WaitStatus
wait:
	for {
		select {
		case ws = <-status:
			break wait
		// Signal only: the reaper goroutine collects the command's status.
		case <-timer.C:
			res.TimedOut = true
			r.signalAll()
		case <-poll.C:
			if _, err := os.Lstat(r.queue(req.ID + ".cancel")); err == nil {
				res.Canceled = true
				r.signalAll()
			}
		case <-ctx.Done():
			res.Canceled = true
			r.signalAll()
		}
	}
	res.Seconds = time.Since(start).Seconds()
	// The output pipe closes once every process holding it is gone.
	if !r.killAll() {
		r.log.Error("sandbox run: processes survive kill; exiting", "id", req.ID)
		os.Exit(70)
	}
	select {
	case res.Log = <-logDone:
	case <-time.After(10 * time.Second):
		res.Log = []byte("(output unavailable)")
	}
	switch {
	case ws.Exited():
		res.ExitCode = ws.ExitStatus()
	case ws.Signaled():
		res.ExitCode = -1
		res.Signal = ws.Signal().String()
	}
	return res
}

// killAllOwn kills every process of this UID except the runner itself
// (kill(-1)) and reaps them, until none is left; false if some survive
// 30 seconds of this.
func killAllOwn() bool {
	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		err := syscall.Kill(-1, syscall.SIGKILL)
		for {
			var ws syscall.WaitStatus
			if pid, werr := syscall.Wait4(-1, &ws, syscall.WNOHANG, nil); pid <= 0 || werr != nil {
				break
			}
		}
		if errors.Is(err, syscall.ESRCH) {
			return true
		}
		time.Sleep(5 * time.Millisecond)
	}
	return false
}

// fixPermissions makes what the run created readable and removable by the
// agent's group (the run may have restricted its own files). WalkDir calls
// fn for a directory before reading it, so the chmod comes first. Symbolic
// links are not followed.
func (r *sandboxRunner) fixPermissions(jobDir string) {
	// Every process of the run is gone when this runs; os.Root still keeps
	// each change inside the job directory whatever the run left there.
	root, err := os.OpenRoot(jobDir)
	if err != nil {
		return
	}
	defer root.Close()
	_ = fs.WalkDir(root.FS(), ".", func(rel string, d fs.DirEntry, err error) error {
		if err != nil || d == nil || d.Type()&fs.ModeSymlink != 0 {
			return nil
		}
		info, ierr := d.Info()
		if ierr != nil {
			return nil
		}
		st, ok := info.Sys().(*syscall.Stat_t)
		if !ok || int(st.Uid) != r.uid {
			return nil
		}
		switch {
		case d.IsDir():
			_ = root.Chmod(rel, info.Mode().Perm()|0o770) // #nosec G302 -- the agent (same group) must read and remove the run's files
		case info.Mode().IsRegular():
			_ = root.Chmod(rel, info.Mode().Perm()|0o660) // #nosec G302 -- the agent (same group) must read and remove the run's files
		}
		return nil
	})
}

func (r *sandboxRunner) finish(req sandboxRequest, res sandboxResult) {
	key, err := hex.DecodeString(req.Key)
	if err != nil || len(key) < 16 {
		return
	}
	res.ID = req.ID
	res.Seconds = float64(int64(res.Seconds*1000)) / 1000
	res.MAC = res.mac(key)
	raw, _ := json.Marshal(res)
	path := filepath.Join(r.job(req.ID), "result.json")
	_ = os.RemoveAll(path)
	if err := writeFileAtomic(path, raw, 0o640); err != nil {
		r.log.Warn("sandbox result not written", "id", req.ID, "err", err)
	}
}
