package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// Every analysis tool runs as a separate process in its own process group
// (a timeout kills the whole group), with a minimal environment, a memory
// limit (RLIMIT_AS for native tools, -Xmx for JVM tools) and bounded output.
// The sandbox runner adds the container's limits and no network.

// errTimeout marks a tool killed by its time budget.
var errTimeout = errors.New("timed out")

// limitedBuffer keeps at most max bytes.
type limitedBuffer struct {
	buf       bytes.Buffer
	max       int
	truncated bool
}

func (l *limitedBuffer) Write(p []byte) (int, error) {
	if room := l.max - l.buf.Len(); room > 0 {
		if len(p) > room {
			l.buf.Write(p[:room])
			l.truncated = true
		} else {
			l.buf.Write(p)
		}
	} else if len(p) > 0 {
		l.truncated = true
	}
	return len(p), nil
}

// toolEnv is the environment of every tool: no proxy settings, no
// inherited secrets.
func toolEnv(extra ...string) []string {
	env := []string{"PATH=/opt/pathos/rea/bin:/usr/local/bin:/usr/bin:/bin", "LANG=C.UTF-8", "LC_ALL=C.UTF-8"}
	for _, k := range []string{"HOME", "TMPDIR"} {
		if v := os.Getenv(k); v != "" {
			env = append(env, k+"="+v)
		}
	}
	return append(env, extra...)
}

// runOpts configures one tool run.
type runOpts struct {
	timeout   time.Duration
	memoryMB  int // RLIMIT_AS (0: none, for JVM tools that use -Xmx)
	maxStdout int
	stdout    io.Writer // instead of the buffer
	dir       string
	env       []string
}

// runTool runs name with args under the limits; it returns stdout (bounded)
// and the end of stderr.
func runTool(ctx context.Context, o runOpts, name string, args ...string) ([]byte, string, error) {
	if o.maxStdout == 0 {
		o.maxStdout = 64 << 20
	}
	ctx, cancel := context.WithTimeout(ctx, o.timeout)
	defer cancel()
	cmdName, cmdArgs := name, args
	if o.memoryMB > 0 {
		// Re-exec through pathos-rea, which sets RLIMIT_AS and then execs
		// the tool (Go cannot set a child's rlimits directly).
		self, err := os.Executable()
		if err != nil {
			return nil, "", err
		}
		cmdName = self
		cmdArgs = append([]string{"limit", strconv.Itoa(o.memoryMB), "--", name}, args...)
	}
	// #nosec G204 G702 -- the tools and their arguments are fixed by pathos-rea; the artifact is only a file argument
	cmd := exec.Command(cmdName, cmdArgs...)
	cmd.Env = toolEnv(o.env...)
	cmd.Dir = o.dir
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	out := &limitedBuffer{max: o.maxStdout}
	if o.stdout != nil {
		cmd.Stdout = o.stdout
	} else {
		cmd.Stdout = out
	}
	errb := &limitedBuffer{max: 64 << 10}
	cmd.Stderr = errb
	if err := cmd.Start(); err != nil {
		return nil, "", err
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	var err error
	select {
	case err = <-done:
	case <-ctx.Done():
		_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
		<-done
		return out.buf.Bytes(), tail(errb.buf.String()), errTimeout
	}
	// Leftover children of the tool's group.
	_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
	if err != nil {
		return out.buf.Bytes(), tail(errb.buf.String()), fmt.Errorf("%s: %w: %s", name, err, tail(errb.buf.String()))
	}
	return out.buf.Bytes(), tail(errb.buf.String()), nil
}

// tail is the last line(s) of a tool's error output, at most 500 bytes.
func tail(s string) string {
	s = strings.TrimSpace(s)
	if len(s) > 500 {
		s = s[len(s)-500:]
	}
	r, _ := redact(s)
	return r
}

// limitMain is `pathos-rea limit <memory_mb> -- <tool> <args...>`.
func limitMain(args []string) int {
	if len(args) < 3 || args[1] != "--" {
		fmt.Fprintln(os.Stderr, "usage: pathos-rea limit <memory_mb> -- <tool> [args...]")
		return 2
	}
	mb, err := strconv.Atoi(args[0])
	if err != nil || mb < 64 {
		fmt.Fprintln(os.Stderr, "invalid memory limit")
		return 2
	}
	lim := uint64(mb) << 20
	if err := syscall.Setrlimit(syscall.RLIMIT_AS, &syscall.Rlimit{Cur: lim, Max: lim}); err != nil {
		fmt.Fprintln(os.Stderr, "setrlimit:", err)
		return 2
	}
	// No core dumps of a crashing parser.
	_ = syscall.Setrlimit(syscall.RLIMIT_CORE, &syscall.Rlimit{})
	path, err := exec.LookPath(args[2])
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 127
	}
	// #nosec G204 G702 -- the tool and arguments come from runTool (pathos-rea's own fixed command lines)
	if err := syscall.Exec(path, args[2:], os.Environ()); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 126
	}
	return 0
}
