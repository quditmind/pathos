package worker

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/binary"
	"encoding/pem"
	"errors"
	"net"
	"net/http/cgi"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"
)

// Generic Git over SSH: the worker clones with the real ssh client, the
// pinned known_hosts entry and StrictHostKeyChecking=yes, from an
// in-process SSH server running the real git-upload-pack.

func sshTestServer(t *testing.T, root string, allowed ssh.PublicKey) (addr string, hostKey ssh.PublicKey) {
	t.Helper()
	_, hp, _ := ed25519.GenerateKey(rand.Reader)
	hs, _ := ssh.NewSignerFromKey(hp)
	cfg := &ssh.ServerConfig{PublicKeyCallback: func(_ ssh.ConnMetadata, k ssh.PublicKey) (*ssh.Permissions, error) {
		if string(k.Marshal()) == string(allowed.Marshal()) {
			return nil, nil
		}
		return nil, errors.New("denied")
	}}
	cfg.AddHostKey(hs)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			nc, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer nc.Close()
				_, chans, reqs, err := ssh.NewServerConn(nc, cfg)
				if err != nil {
					return
				}
				go ssh.DiscardRequests(reqs)
				for nch := range chans {
					ch, creqs, err := nch.Accept()
					if err != nil {
						continue
					}
					go func() {
						defer ch.Close()
						for req := range creqs {
							if req.Type != "exec" {
								_ = req.Reply(req.Type == "env", nil)
								continue
							}
							n := binary.BigEndian.Uint32(req.Payload[:4])
							command := string(req.Payload[4 : 4+n])
							_ = req.Reply(true, nil)
							p := strings.Trim(strings.TrimPrefix(command, "git-upload-pack "), "'")
							cmd := exec.Command("git-upload-pack", filepath.Join(root, filepath.Clean("/"+p)))
							cmd.Stdin, cmd.Stdout, cmd.Stderr = ch, ch, ch.Stderr()
							status := uint32(0)
							if cmd.Run() != nil {
								status = 1
							}
							_, _ = ch.SendRequest("exit-status", false, ssh.Marshal(struct{ S uint32 }{status}))
							return
						}
					}()
				}
			}()
		}
	}()
	return ln.Addr().String(), hs.PublicKey()
}

func TestCloneOverSSHPinnedHostKey(t *testing.T) {
	for _, bin := range []string{"ssh", "git-upload-pack"} {
		if _, err := exec.LookPath(bin); err != nil {
			t.Skip(bin + " not installed")
		}
	}
	if exec.Command("id", "-un").Run() != nil {
		// OpenSSH refuses to run for a uid without a passwd entry (the
		// toolchain container); the worker image has its user.
		t.Skip("no passwd entry for this uid (run with /etc/passwd mounted)")
	}
	base := t.TempDir()
	work := filepath.Join(base, "work")
	_ = os.MkdirAll(work, 0o700)
	gitRun(t, work, "init", "-q", "-b", "main")
	_ = os.WriteFile(filepath.Join(work, "a.txt"), []byte("1"), 0o600)
	gitRun(t, work, "add", ".")
	gitRun(t, work, "commit", "-q", "-m", "first")
	head := gitRun(t, work, "rev-parse", "HEAD")
	_ = os.MkdirAll(filepath.Join(base, "srv", "team"), 0o700)
	gitRun(t, base, "clone", "-q", "--bare", work, filepath.Join(base, "srv", "team", "app.git"))

	_, cp, _ := ed25519.GenerateKey(rand.Reader)
	cs, _ := ssh.NewSignerFromKey(cp)
	blk, _ := ssh.MarshalPrivateKey(cp, "")
	keyPEM := string(pem.EncodeToMemory(blk))
	addr, hostKey := sshTestServer(t, filepath.Join(base, "srv"), cs.PublicKey())
	host, port, _ := net.SplitHostPort(addr)
	known := "[" + host + "]:" + port + " " + strings.TrimSpace(string(ssh.MarshalAuthorizedKey(hostKey)))

	job := Job{CloneURL: "ssh://git@" + addr + "/team/app.git", Ref: "main",
		Credential: &JobCredential{Username: "git", SSHPrivateKey: keyPEM, SSHKnownHosts: known}}
	ws := t.TempDir()
	commit, err := clone(context.Background(), job, filepath.Join(ws, "src"), filepath.Join(ws, "git"), 1<<30)
	if err != nil || commit != head {
		t.Fatalf("clone over SSH: %s %v", commit, err)
	}
	if b, _ := os.ReadFile(filepath.Join(ws, "src", "a.txt")); string(b) != "1" {
		t.Fatal("checkout content")
	}
	// Credential files are gone after the clone.
	if m, _ := filepath.Glob(filepath.Join(os.TempDir(), "pathos-git-cred-*")); len(m) != 0 {
		t.Fatalf("credential files left behind: %v", m)
	}

	// Another pinned key: ssh refuses, no accept-new.
	_, op, _ := ed25519.GenerateKey(rand.Reader)
	os2, _ := ssh.NewSignerFromKey(op)
	job.Credential.SSHKnownHosts = "[" + host + "]:" + port + " " + strings.TrimSpace(string(ssh.MarshalAuthorizedKey(os2.PublicKey())))
	ws2 := t.TempDir()
	if _, err := clone(context.Background(), job, filepath.Join(ws2, "src"), filepath.Join(ws2, "git"), 1<<30); err == nil {
		t.Fatal("clone with a mismatching pinned host key must fail")
	}
	// No known_hosts: refused before running git.
	job.Credential.SSHKnownHosts = ""
	if _, err := clone(context.Background(), job, filepath.Join(ws2, "s2"), filepath.Join(ws2, "g2"), 1<<30); err == nil {
		t.Fatal("SSH clone without a pinned host key must be refused")
	}
	// ssh:// without an SSH key is refused (no agent, no defaults).
	if _, err := clone(context.Background(), Job{CloneURL: "ssh://git@" + addr + "/team/app.git", Ref: "main"}, filepath.Join(ws2, "s3"), filepath.Join(ws2, "g3"), 1<<30); err == nil {
		t.Fatal("ssh:// without a key must be refused")
	}
}

// A private CA: the worker trusts the connection's bundle for the clone.
func TestCloneWithPrivateCA(t *testing.T) {
	backend := ""
	for _, p := range []string{"/usr/lib/git-core/git-http-backend", "/usr/libexec/git-core/git-http-backend"} {
		if _, err := os.Stat(p); err == nil {
			backend = p
		}
	}
	if backend == "" {
		t.Skip("git-http-backend not installed")
	}
	base := t.TempDir()
	work := filepath.Join(base, "work")
	_ = os.MkdirAll(work, 0o700)
	gitRun(t, work, "init", "-q", "-b", "main")
	_ = os.WriteFile(filepath.Join(work, "a.txt"), []byte("1"), 0o600)
	gitRun(t, work, "add", ".")
	gitRun(t, work, "commit", "-q", "-m", "first")
	gitRun(t, base, "clone", "-q", "--bare", work, filepath.Join(base, "repo.git"))
	srv := httptest.NewTLSServer(&cgi.Handler{Path: backend, Env: []string{"GIT_PROJECT_ROOT=" + base, "GIT_HTTP_EXPORT_ALL=1",
		"GIT_CONFIG_GLOBAL=/dev/null", "GIT_CONFIG_NOSYSTEM=1"}})
	defer srv.Close()
	ca := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw}))

	ws := t.TempDir()
	if _, err := clone(context.Background(), Job{CloneURL: srv.URL + "/repo.git", Ref: "main"}, filepath.Join(ws, "a"), filepath.Join(ws, "ga"), 1<<30); err == nil {
		t.Fatal("clone from a private-CA server without the bundle must fail")
	}
	job := Job{CloneURL: srv.URL + "/repo.git", Ref: "main", Credential: &JobCredential{CABundle: ca}}
	if _, err := clone(context.Background(), job, filepath.Join(ws, "b"), filepath.Join(ws, "gb"), 1<<30); err != nil {
		t.Fatalf("clone with the private CA: %v", err)
	}
}
