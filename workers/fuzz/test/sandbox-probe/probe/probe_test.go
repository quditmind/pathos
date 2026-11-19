// Package probe is a deliberately malicious fuzz target, used only by
// workers/fuzz/test/sandbox-e2e.sh. It tries to escape the PATHOS sandbox
// runner (TCP to the egress proxy, the API, their addresses from
// sandbox-targets.txt and 1.1.1.1; DNS; the environment of PID 1 and its
// memory; writes outside the job directory) and fails with one
// SANDBOX-PROBE line giving the outcome of each attempt (blocked:<reason>
// or OPEN), which ends up in the fuzz report's target details.
package probe

import (
	"bytes"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

func reason(err error) string {
	var errno syscall.Errno
	if errors.As(err, &errno) {
		return fmt.Sprintf("errno%d", int(errno))
	}
	var dns *net.DNSError
	if errors.As(err, &dns) {
		return "dns"
	}
	if errors.Is(err, os.ErrDeadlineExceeded) {
		return "timeout"
	}
	s := strings.ReplaceAll(err.Error(), " ", "_")
	return s[max(0, len(s)-30):]
}

// targets reads the addresses the test wrote next to the repository root.
func targets() []string {
	dir, _ := os.Getwd()
	for range 6 {
		if b, err := os.ReadFile(filepath.Join(dir, "sandbox-targets.txt")); err == nil {
			return strings.Fields(string(b))
		}
		dir = filepath.Dir(dir)
	}
	return nil
}

func probe() string {
	var out []string
	add := func(k, v string) { out = append(out, k+"="+v) }
	dial := append([]string{"egress:3128", "api:8081", "1.1.1.1:443"}, targets()...)
	for _, a := range dial {
		c, err := net.DialTimeout("tcp", a, 3*time.Second)
		if err == nil {
			_ = c.Close()
			add("tcp:"+a, "OPEN")
		} else {
			add("tcp:"+a, "blocked:"+reason(err))
		}
	}
	for _, h := range []string{"api", "egress", "example.com"} {
		if addrs, err := net.LookupHost(h); err == nil {
			add("dns:"+h, "OPEN:"+strings.Join(addrs, ","))
		} else {
			add("dns:"+h, "blocked:"+reason(err))
		}
	}
	leak := ""
	for _, kv := range os.Environ() {
		k, _, _ := strings.Cut(kv, "=")
		if strings.Contains(k, "TOKEN") || strings.HasSuffix(strings.ToUpper(k), "_PROXY") || strings.HasPrefix(k, "PATHOS_API") {
			leak += k + ","
		}
	}
	if leak == "" {
		add("env", "clean")
	} else {
		add("env", "OPEN:"+leak)
	}
	if b, err := os.ReadFile("/proc/1/environ"); err != nil {
		add("proc1-environ", "blocked:"+reason(err))
	} else if bytes.Contains(b, []byte("TOKEN")) || bytes.Contains(b, []byte("PATHOS_API")) || bytes.Contains(b, []byte("_PROXY=")) {
		add("proc1-environ", "OPEN:secrets")
	} else {
		add("proc1-environ", "readable-no-secrets")
	}
	if f, err := os.Open("/proc/1/mem"); err != nil {
		add("proc1-mem", "blocked:"+reason(err))
	} else {
		_ = f.Close()
		add("proc1-mem", "OPEN")
	}
	for _, p := range []string{"/tmp", "/var/tmp", "/dev/shm", "/sandbox", "/sandbox/jobs", "/sandbox/queue", "/opt/pathos", "/etc", "/work"} {
		f := filepath.Join(p, "pathos-probe")
		if err := os.WriteFile(f, []byte("x"), 0o600); err != nil {
			add("write:"+p, "blocked:"+reason(err))
		} else {
			_ = os.Remove(f)
			add("write:"+p, "OPEN")
		}
	}
	return strings.Join(out, " ")
}

func FuzzSandboxProbe(f *testing.F) {
	f.Add([]byte("x"))
	f.Fuzz(func(t *testing.T, _ []byte) {
		t.Fatalf("SANDBOX-PROBE %s", probe())
	})
}
