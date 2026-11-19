package worker

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

// Repository code (fuzz harnesses, a repository's own test suite) never
// runs in the worker container. The worker agent hands it to a sandbox
// runner: a sibling container started from the same image with
// `network_mode: none` (no network interface but loopback), its own PID
// and IPC namespaces, a read-only root filesystem, no capabilities, another
// UID (10002), no worker token and no proxy settings, and its own cgroup
// limits (memory, CPU, pids). The two containers share only one volume, the
// sandbox directory (PATHOS_SANDBOX_DIR, a size-limited tmpfs volume).
// Docker's own isolation enforces all of this; nothing depends on the
// repository code cooperating. The agent never needs the Docker socket.
//
// The sandbox directory (owned by the agent's UID 10001, group 10001; the
// runner runs as 10002:10001):
//
//	queue/<id>.json    request, written by the agent (0640, read-only
//	                   for the runner: queue/ is 0750)
//	queue/<id>.cancel  cancellation, written by the agent
//	jobs/<id>/         the job directory (0770): the only place the
//	                   runner and the code it runs can write
//	  src/ out/ tmp/ home/
//	  claimed          the runner picked the request up
//	  result.json      the runner's result, authenticated with the
//	                   request's one-time key
//	agent.lock         held by the agent (one agent per sandbox directory)
//
// One run: the agent copies the source into jobs/<id>/src and writes the
// request (with a random one-time key). The runner reads it and writes
// "claimed"; the agent then deletes the request, and the runner starts the
// command only once the request is gone, so the code it runs can never read
// the key. When the command exits (or times out, or the agent cancels), the
// runner kills every process of its UID (kill(-1)) until none is left,
// makes the job's files readable by the agent's group and writes
// result.json with an HMAC under the key. The agent accepts only a result
// whose HMAC verifies, so repository code can neither forge a result nor
// make the agent move on while it is still running; the runner handles one
// request at a time, so no repository code is alive when the next job's
// source is copied in.

// SandboxDirEnv names the sandbox directory in both containers.
const SandboxDirEnv = "PATHOS_SANDBOX_DIR"

// ErrNoSandbox means this worker has no sandbox runner: repository code
// must not run, and the caller reports the step as skipped.
var ErrNoSandbox = errors.New("no sandbox runner is configured for this worker (" + SandboxDirEnv + "); repository code is not run without one")

const (
	sandboxClaimWait  = 60 * time.Second // runner must pick a request up within this
	sandboxCancelWait = 30 * time.Second // and answer a cancellation within this
	sandboxMaxLog     = 64 << 10
	sandboxMaxResult  = 1 << 20
	sandboxMaxTimeout = 6 * time.Hour
	// DefaultUntrustedOutput bounds the output file copied back.
	DefaultUntrustedOutput = 256 << 20
	defaultUntrustedSource = 2 << 30
)

var sandboxIDRe = regexp.MustCompile(`^[0-9a-f]{32}$`)

// UntrustedJob is one run of repository code in the sandbox runner.
//
// Command and Args are executed directly (no shell) by the runner, as UID
// 10002, in the runner image (the worker image of the same family, so the
// same toolchains are installed). In Args and Env, these placeholders are
// replaced by paths inside the job directory (the same path in both
// containers):
//
//	{source}  the copy of Source (writable by the command)
//	{output}  a file the command may write; copied back to Output
//	{tmp}     an empty writable directory (also TMPDIR)
//	{home}    an empty writable directory (also HOME)
//
// The environment is only PATH, LANG, HOME, TMPDIR and Env: never the
// worker's token, proxy settings or any PATHOS_ variable.
type UntrustedJob struct {
	// Source is a local directory copied into {source}: directories,
	// regular files (mode 0660, 0770 if executable) and symbolic links
	// (as links, never followed); .git is not copied. Empty: {source}
	// is an empty directory.
	Source string
	// MaxSourceBytes bounds the copy (default 2 GiB).
	MaxSourceBytes int64
	Command        string
	Args           []string
	// Env entries are KEY=value; PATH, HOME, TMPDIR, LD_*, *_PROXY and
	// PATHOS_* are not allowed.
	Env []string
	// Dir is the working directory: "source" (default), "tmp" or "home".
	Dir string
	// Timeout bounds the run (required, at most 6h). When it expires, or
	// ctx is done, every process of the run is killed.
	Timeout time.Duration
	// Output, if set, is the local path {output} is copied to after the
	// run (a regular file inside the job directory, at most
	// MaxOutputBytes, default 256 MiB). A missing file is not an error:
	// UntrustedResult.OutputWritten is false.
	Output         string
	MaxOutputBytes int64
}

// UntrustedResult is what the runner reports; it is authenticated (the
// repository code cannot forge it).
type UntrustedResult struct {
	ExitCode int    // -1 when killed by a signal
	Signal   string // the signal that ended the command, if any
	TimedOut bool
	Canceled bool
	// Log is stdout and stderr combined, at most 64 KiB (the beginning).
	Log      []byte
	Duration time.Duration
	// OutputWritten: {output} existed and was copied to Output.
	OutputWritten bool
}

// sandboxRequest is queue/<id>.json.
type sandboxRequest struct {
	ID             string   `json:"id"`
	Key            string   `json:"key"` // hex, one-time HMAC key
	Command        string   `json:"command,omitempty"`
	Args           []string `json:"args,omitempty"`
	Env            []string `json:"env,omitempty"`
	Dir            string   `json:"dir,omitempty"`
	TimeoutSeconds int      `json:"timeout_seconds"`
}

// sandboxResult is jobs/<id>/result.json.
type sandboxResult struct {
	ID       string  `json:"id"`
	ExitCode int     `json:"exit_code"`
	Signal   string  `json:"signal,omitempty"`
	TimedOut bool    `json:"timed_out,omitempty"`
	Canceled bool    `json:"canceled,omitempty"`
	Error    string  `json:"error,omitempty"` // the runner could not run the command
	Log      []byte  `json:"log,omitempty"`
	Seconds  float64 `json:"seconds"`
	MAC      string  `json:"mac"`
}

func (r sandboxResult) mac(key []byte) string {
	m := hmac.New(sha256.New, key)
	sum := sha256.Sum256(r.Log)
	fmt.Fprintf(m, "pathos-sandbox-result\x00%s\x00%d\x00%s\x00%t\x00%t\x00%s\x00%s\x00%x", r.ID, r.ExitCode, r.Signal, r.TimedOut,
		r.Canceled, r.Error, strconv.FormatFloat(r.Seconds, 'f', 3, 64), sum)
	return hex.EncodeToString(m.Sum(nil))
}

// Sandbox is the agent's side of the sandbox directory.
type Sandbox struct {
	dir  string
	lock *os.File
	mu   sync.Mutex
	// dirty: the last run has no authenticated result, so its processes
	// may still be alive; the next run first waits for an empty run.
	dirty bool
	// claimWait and pollEvery are shortened in tests.
	claimWait time.Duration
	pollEvery time.Duration
}

// OpenSandbox prepares dir (the shared volume, owned by the agent's user)
// and takes the agent lock: a sandbox directory serves one agent.
func OpenSandbox(dir string) (*Sandbox, error) {
	st, err := os.Lstat(dir)
	if err != nil || !st.IsDir() {
		return nil, fmt.Errorf("sandbox directory %s: not a directory", dir)
	}
	for _, d := range []string{"queue", "jobs"} {
		p := filepath.Join(dir, d)
		if err := os.Mkdir(p, 0o750); err != nil && !errors.Is(err, fs.ErrExist) {
			return nil, err
		}
		if err := os.Chmod(p, 0o750); err != nil { // #nosec G302 -- directory, readable by the sandbox runner's group
			return nil, fmt.Errorf("sandbox directory: %w", err)
		}
	}
	// #nosec G304 -- fixed name in the agent-owned sandbox directory
	lock, err := os.OpenFile(filepath.Join(dir, "agent.lock"), os.O_CREATE|os.O_RDWR|syscall.O_NOFOLLOW, 0o600)
	if err != nil {
		return nil, err
	}
	if err := syscall.Flock(int(lock.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		_ = lock.Close()
		return nil, errors.New("the sandbox directory is in use by another worker (one worker per sandbox runner)")
	}
	s := &Sandbox{dir: dir, lock: lock, dirty: true, claimWait: sandboxClaimWait, pollEvery: 100 * time.Millisecond}
	// Leftovers of a previous agent process.
	for _, d := range []string{"queue", "jobs"} {
		entries, _ := os.ReadDir(filepath.Join(dir, d))
		for _, e := range entries {
			_ = os.RemoveAll(filepath.Join(dir, d, e.Name()))
		}
	}
	return s, nil
}

// Dir is the sandbox directory.
func (s *Sandbox) Dir() string { return s.dir }

// RunUntrusted runs repository code in the sandbox runner and waits for it.
//
// Contract (see docs/ARCHITECTURE.md, "Running repository code"):
//   - a nil *Sandbox returns ErrNoSandbox: the caller must not fall back to
//     running the code anywhere else;
//   - runs are serialized per worker; each starts in a job directory no
//     other run can see, and returns only after the runner has killed every
//     process the run started;
//   - the command has no network (no interface but loopback, no DNS), no
//     access to the worker's environment, token or processes, and can write
//     only inside its job directory; CPU, memory and process count are the
//     runner container's cgroup limits; the run's wall time is Timeout;
//   - a non-zero exit is not an error (see UntrustedResult); an error means
//     the run did not happen or did not finish (no runner, timeout waiting
//     for the runner, ctx done);
//   - everything the run produced (Log, the Output file) is untrusted data.
func (s *Sandbox) RunUntrusted(ctx context.Context, job UntrustedJob) (UntrustedResult, error) {
	if s == nil {
		return UntrustedResult{}, ErrNoSandbox
	}
	if job.Command == "" || !filepath.IsAbs(job.Command) {
		return UntrustedResult{}, errors.New("sandbox: the command must be an absolute path")
	}
	if job.Timeout <= 0 || job.Timeout > sandboxMaxTimeout {
		return UntrustedResult{}, errors.New("sandbox: the timeout must be set and at most 6h")
	}
	if err := checkUntrustedEnv(job.Env); err != nil {
		return UntrustedResult{}, err
	}
	switch job.Dir {
	case "", "source", "tmp", "home":
	default:
		return UntrustedResult{}, errors.New("sandbox: dir must be source, tmp or home")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.dirty {
		// Wait until the runner has finished (and cleaned up) whatever it
		// ran before: an empty run is answered only after that.
		if _, err := s.run(ctx, UntrustedJob{Timeout: time.Minute}); err != nil {
			return UntrustedResult{}, fmt.Errorf("sandbox runner: %w", err)
		}
	}
	return s.run(ctx, job)
}

// run executes one request; an empty Command is a no-op run (the runner
// still cleans up before answering).
func (s *Sandbox) run(ctx context.Context, job UntrustedJob) (UntrustedResult, error) {
	s.dirty = true
	id, key := randomHex(16), make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return UntrustedResult{}, err
	}
	jobDir := filepath.Join(s.dir, "jobs", id)
	reqPath := filepath.Join(s.dir, "queue", id+".json")
	cancelPath := filepath.Join(s.dir, "queue", id+".cancel")
	defer func() {
		_ = os.Remove(reqPath)
		_ = os.Remove(cancelPath)
		_ = os.RemoveAll(jobDir)
	}()
	for _, d := range []string{"", "src", "out", "tmp", "home"} {
		p := filepath.Join(jobDir, d)
		if err := os.Mkdir(p, 0o770); err != nil { // #nosec G301 -- shared with the sandbox runner's UID through the group
			return UntrustedResult{}, err
		}
		if err := os.Chmod(p, 0o770); err != nil { // #nosec G302 -- shared with the sandbox runner's UID through the group
			return UntrustedResult{}, err
		}
	}
	if job.Source != "" {
		limit := job.MaxSourceBytes
		if limit <= 0 {
			limit = defaultUntrustedSource
		}
		if err := copySandboxSource(job.Source, filepath.Join(jobDir, "src"), limit); err != nil {
			return UntrustedResult{}, err
		}
	}
	paths := strings.NewReplacer("{source}", filepath.Join(jobDir, "src"), "{output}", filepath.Join(jobDir, "out", "output"),
		"{tmp}", filepath.Join(jobDir, "tmp"), "{home}", filepath.Join(jobDir, "home"))
	req := sandboxRequest{ID: id, Key: hex.EncodeToString(key), Command: job.Command, Dir: job.Dir,
		TimeoutSeconds: int((job.Timeout + time.Second - 1) / time.Second)}
	for _, a := range job.Args {
		req.Args = append(req.Args, paths.Replace(a))
	}
	for _, e := range job.Env {
		req.Env = append(req.Env, paths.Replace(e))
	}
	raw, _ := json.Marshal(req)
	if err := writeFileAtomic(reqPath, raw, 0o640); err != nil {
		return UntrustedResult{}, err
	}
	// The runner claims the request, then starts the command only after
	// the request (and its key) is gone.
	if err := s.wait(ctx, s.claimWait, func() bool {
		_, err := os.Lstat(filepath.Join(jobDir, "claimed"))
		return err == nil
	}); err != nil {
		if ctx.Err() == nil {
			err = fmt.Errorf("the sandbox runner did not pick the run up within %s (is the sandbox runner container running?)", s.claimWait)
		}
		return UntrustedResult{}, err
	}
	if err := os.Remove(reqPath); err != nil {
		return UntrustedResult{}, err
	}
	var res sandboxResult
	got := func() bool {
		raw, err := readRegularFile(jobDir, "result.json", sandboxMaxResult)
		if err != nil {
			return false
		}
		var r sandboxResult
		if json.Unmarshal(raw, &r) != nil || r.ID != id || !hmac.Equal([]byte(r.MAC), []byte(r.mac(key))) {
			return false // not (yet) the runner's result
		}
		res = r
		return true
	}
	start := time.Now()
	err := s.wait(ctx, job.Timeout+sandboxCancelWait, got)
	if err != nil {
		// Cancel, and wait for the runner to confirm that the run is over.
		_ = writeFileAtomic(cancelPath, []byte("cancel\n"), 0o640)
		if werr := s.wait(context.Background(), sandboxCancelWait, got); werr != nil {
			return UntrustedResult{}, fmt.Errorf("sandbox run %s did not finish: %w", id, err)
		}
		if ctx.Err() != nil {
			s.dirty = false
			return UntrustedResult{}, ctx.Err()
		}
	}
	s.dirty = false
	if res.Error != "" {
		return UntrustedResult{}, errors.New("sandbox runner: " + res.Error)
	}
	out := UntrustedResult{ExitCode: res.ExitCode, Signal: res.Signal, TimedOut: res.TimedOut, Canceled: res.Canceled, Log: res.Log,
		Duration: time.Duration(res.Seconds * float64(time.Second))}
	if out.Duration == 0 {
		out.Duration = time.Since(start)
	}
	if job.Output != "" {
		limit := job.MaxOutputBytes
		if limit <= 0 {
			limit = DefaultUntrustedOutput
		}
		ok, err := copyRegularFile(jobDir, filepath.Join("out", "output"), job.Output, limit)
		if err != nil {
			return out, fmt.Errorf("sandbox output: %w", err)
		}
		out.OutputWritten = ok
	}
	return out, nil
}

// wait polls cond until it holds, ctx is done or d has passed.
func (s *Sandbox) wait(ctx context.Context, d time.Duration, cond func() bool) error {
	deadline := time.NewTimer(d)
	defer deadline.Stop()
	tick := time.NewTicker(s.pollEvery)
	defer tick.Stop()
	for {
		if cond() {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-deadline.C:
			return context.DeadlineExceeded
		case <-tick.C:
		}
	}
}

func checkUntrustedEnv(env []string) error {
	for _, e := range env {
		k, _, ok := strings.Cut(e, "=")
		u := strings.ToUpper(k)
		if !ok || !envKeyRe.MatchString(k) || u == "PATH" || u == "HOME" || u == "TMPDIR" || strings.HasPrefix(u, "LD_") ||
			strings.HasSuffix(u, "_PROXY") || strings.HasPrefix(u, "PATHOS_") {
			return fmt.Errorf("sandbox: env %q is not allowed", k)
		}
	}
	return nil
}

func randomHex(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

func writeFileAtomic(path string, data []byte, mode os.FileMode) error {
	tmp := path + ".tmp-" + randomHex(4)
	// #nosec G304 -- path is built from the sandbox directory and a random id
	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_EXCL|os.O_WRONLY|syscall.O_NOFOLLOW, mode)
	if err != nil {
		return err
	}
	_, err = f.Write(data)
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err == nil {
		err = os.Chmod(tmp, mode)
	}
	if err == nil {
		err = os.Rename(tmp, path)
	}
	if err != nil {
		_ = os.Remove(tmp)
	}
	return err
}

// openRegular opens name below root without leaving it (os.Root: no
// "..", no symbolic link out of root, none at the last component) and
// only if it is a regular file (O_NONBLOCK: a FIFO cannot block the
// agent).
func openRegular(root, name string) (*os.File, os.FileInfo, error) {
	r, err := os.OpenRoot(root)
	if err != nil {
		return nil, nil, err
	}
	defer r.Close()
	f, err := r.OpenFile(name, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, nil, err
	}
	st, err := f.Stat()
	if err != nil || !st.Mode().IsRegular() {
		_ = f.Close()
		return nil, nil, errors.New("not a regular file")
	}
	return f, st, nil
}

func readRegularFile(root, name string, limit int64) ([]byte, error) {
	f, st, err := openRegular(root, name)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	if st.Size() > limit {
		return nil, errors.New("file too large")
	}
	return io.ReadAll(io.LimitReader(f, limit))
}

// copyRegularFile copies root/name to dst; false if name does not exist.
func copyRegularFile(root, name, dst string, limit int64) (bool, error) {
	f, st, err := openRegular(root, name)
	if errors.Is(err, fs.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	defer f.Close()
	if st.Size() > limit {
		return false, fmt.Errorf("the output is larger than %d MiB", limit>>20)
	}
	// #nosec G304 -- dst is a path in the worker's own job directory
	w, err := os.OpenFile(dst, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
	if err != nil {
		return false, err
	}
	n, err := io.Copy(w, io.LimitReader(f, limit+1))
	if cerr := w.Close(); err == nil {
		err = cerr
	}
	if err == nil && n > limit {
		err = fmt.Errorf("the output is larger than %d MiB", limit>>20)
	}
	return err == nil, err
}

// copySandboxSource copies src to dst for the runner (group-writable, so
// the command can modify its copy). Symbolic links are copied as links and
// never followed; other special files and .git are skipped.
func copySandboxSource(src, dst string, limit int64) error {
	// Both trees are opened as os.Root, so no path below them can resolve
	// outside them, even if a component is replaced by a symbolic link
	// while the copy runs.
	srcRoot, err := os.OpenRoot(src)
	if err != nil {
		return err
	}
	defer srcRoot.Close()
	dstRoot, err := os.OpenRoot(dst)
	if err != nil {
		return err
	}
	defer dstRoot.Close()
	var total int64
	return fs.WalkDir(srcRoot.FS(), ".", func(rel string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if rel == "." {
			return nil
		}
		switch {
		case d.IsDir():
			if d.Name() == ".git" {
				return fs.SkipDir
			}
			// Group-writable: the runner (another UID in the agent's
			// group) works in the copy.
			if err := dstRoot.Mkdir(rel, 0o770); err != nil { // #nosec G301 -- shared with the sandbox runner's UID through the group
				return err
			}
			return dstRoot.Chmod(rel, 0o770) // #nosec G302 -- shared with the sandbox runner's UID through the group
		case d.Type()&fs.ModeSymlink != 0:
			if d.Name() == ".git" {
				return nil
			}
			link, err := srcRoot.Readlink(rel)
			if err != nil {
				return err
			}
			// Copied as a link, never followed; the runner resolves it
			// inside its own read-only view.
			return dstRoot.Symlink(link, rel)
		case d.Type().IsRegular():
			info, err := d.Info()
			if err != nil {
				return err
			}
			total += info.Size()
			if total > limit {
				return fmt.Errorf("the source is larger than %d MiB", limit>>20)
			}
			mode := os.FileMode(0o660)
			if info.Mode().Perm()&0o100 != 0 {
				mode = 0o770
			}
			return copyFileMode(srcRoot, dstRoot, rel, mode)
		}
		return nil
	})
}

func copyFileMode(srcRoot, dstRoot *os.Root, rel string, mode os.FileMode) error {
	in, err := srcRoot.OpenFile(rel, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := dstRoot.OpenFile(rel, os.O_CREATE|os.O_EXCL|os.O_WRONLY|syscall.O_NOFOLLOW, mode)
	if err != nil {
		return err
	}
	_, err = io.Copy(out, in)
	if cerr := out.Close(); err == nil {
		err = cerr
	}
	if err == nil {
		err = dstRoot.Chmod(rel, mode) // #nosec G302 -- shared with the sandbox runner's UID through the group
	}
	return err
}

// lastLogLine is the last non-empty line of a run's log, for errors.
func lastLogLine(log []byte) string {
	return lastLine(string(bytes.TrimSpace(log)))
}
