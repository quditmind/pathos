package scm

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/binary"
	"encoding/pem"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/cgi"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

// Generic Git is tested against real git: a bare repository served by
// `git http-backend` (smart HTTP, behind a private-CA TLS server) and by
// `git-upload-pack` behind an in-process SSH server. No container needed.

func needGit(t *testing.T) string {
	t.Helper()
	git, err := exec.LookPath("git")
	if err != nil {
		t.Skip("git not installed")
	}
	return git
}

func run(t *testing.T, dir string, args ...string) string {
	t.Helper()
	cmd := exec.Command("git", args...)
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), "GIT_CONFIG_NOSYSTEM=1", "GIT_CONFIG_GLOBAL=/dev/null",
		"GIT_AUTHOR_NAME=t", "GIT_AUTHOR_EMAIL=t@example.com", "GIT_COMMITTER_NAME=t", "GIT_COMMITTER_EMAIL=t@example.com")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("git %v: %v\n%s", args, err, out)
	}
	return strings.TrimSpace(string(out))
}

// bareRepo creates root/team/app.git with branches trunk (HEAD) and dev.
func bareRepo(t *testing.T) (root, head string) {
	t.Helper()
	root = t.TempDir()
	work := filepath.Join(root, "work")
	run(t, root, "init", "-q", "-b", "trunk", work)
	if err := os.WriteFile(filepath.Join(work, "README"), []byte("hi\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	run(t, work, "add", "README")
	run(t, work, "commit", "-q", "-m", "first")
	run(t, work, "branch", "dev")
	head = run(t, work, "rev-parse", "HEAD")
	if err := os.MkdirAll(filepath.Join(root, "team"), 0o700); err != nil {
		t.Fatal(err)
	}
	run(t, root, "clone", "-q", "--bare", work, filepath.Join(root, "team", "app.git"))
	return root, head
}

func TestGenericGitHTTPS(t *testing.T) {
	git := needGit(t)
	root, head := bareRepo(t)
	srv, caPEM := privateCAServer(t, func(w http.ResponseWriter, r *http.Request) {
		if u, p, ok := r.BasicAuth(); !ok || u != "reader" || p != "s3cret" {
			w.Header().Set("WWW-Authenticate", `Basic realm="git"`)
			w.WriteHeader(401)
			return
		}
		h := &cgi.Handler{Path: git, Args: []string{"http-backend"},
			Env: []string{"GIT_PROJECT_ROOT=" + root, "GIT_HTTP_EXPORT_ALL=1", "GIT_CONFIG_NOSYSTEM=1", "GIT_CONFIG_GLOBAL=/dev/null"}}
		h.ServeHTTP(w, r)
	})
	hc, err := NetPolicy{}.ClientWithCA(caPEM)
	if err != nil {
		t.Fatal(err)
	}
	repoURL, err := CanonicalGitURL(srv.URL+"/team/app.git/", false)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	c, err := New(Config{Provider: GenericGit, BaseURL: repoURL, AuthType: AuthAPIToken,
		Secret: []byte(`{"username":"reader","token":"s3cret"}`), HTTP: loopback(hc)})
	if err != nil {
		t.Fatal(err)
	}
	msg, err := c.Check(ctx)
	if err != nil || !strings.Contains(msg, "2 branches") || !strings.Contains(msg, "trunk") {
		t.Fatalf("check: %q %v", msg, err)
	}
	rr, err := c.GetRepository(ctx, RepoRef{})
	if err != nil || rr.DefaultBranch != "trunk" || rr.CloneURL != repoURL || rr.Name != "app" {
		t.Fatalf("repository %+v %v", rr, err)
	}
	if _, err := c.GetRepository(ctx, RepoRef{ExternalID: "https://elsewhere/x.git"}); !errors.Is(err, ErrNotFound) {
		t.Fatal("another repository must not be served")
	}
	cm, err := c.LatestCommit(ctx, rr.Ref(), "")
	if err != nil || cm.SHA != head {
		t.Fatalf("latest commit %+v %v (want %s)", cm, err, head)
	}
	cred, _ := c.CloneCredential(ctx)
	if cred.Username != "reader" || cred.Token != "s3cret" {
		t.Fatalf("clone credential %+v", cred)
	}

	// Wrong token: PTH-CONN-1141.
	bad, _ := New(Config{Provider: GenericGit, BaseURL: repoURL, AuthType: AuthAPIToken, Secret: []byte(`{"token":"x"}`), HTTP: loopback(hc)})
	if _, err := bad.Check(ctx); DiagCode(err) != "PTH-CONN-1141" {
		t.Fatalf("bad token: %s %v", DiagCode(err), err)
	}
	// Without the private CA: PTH-CONN-1004.
	plain, _ := New(Config{Provider: GenericGit, BaseURL: repoURL, AuthType: AuthAPIToken,
		Secret: []byte(`{"username":"reader","token":"s3cret"}`), HTTP: loopback(NetPolicy{}.Client())})
	if _, err := plain.Check(ctx); DiagCode(err) != "PTH-CONN-1004" {
		t.Fatalf("untrusted CA: %s %v", DiagCode(err), err)
	}
	// Missing repository: PTH-CONN-1011.
	missing, _ := New(Config{Provider: GenericGit, BaseURL: srv.URL + "/team/none.git", AuthType: AuthAPIToken,
		Secret: []byte(`{"username":"reader","token":"s3cret"}`), HTTP: loopback(hc)})
	if _, err := missing.Check(ctx); DiagCode(err) != "PTH-CONN-1011" {
		t.Fatalf("missing repository: %s %v", DiagCode(err), err)
	}
}

// sshGitServer serves git-upload-pack for repositories under root, accepting
// only clientKey. It returns host:port and the server's public host key.
func sshGitServer(t *testing.T, root string, clientKey ssh.PublicKey) (string, ssh.PublicKey) {
	t.Helper()
	_, hostPriv, _ := ed25519.GenerateKey(rand.Reader)
	hostSigner, err := ssh.NewSignerFromKey(hostPriv)
	if err != nil {
		t.Fatal(err)
	}
	cfg := &ssh.ServerConfig{PublicKeyCallback: func(_ ssh.ConnMetadata, k ssh.PublicKey) (*ssh.Permissions, error) {
		if string(k.Marshal()) == string(clientKey.Marshal()) {
			return nil, nil
		}
		return nil, errors.New("denied")
	}}
	cfg.AddHostKey(hostSigner)
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
			go serveSSH(nc, cfg, root)
		}
	}()
	return ln.Addr().String(), hostSigner.PublicKey()
}

func serveSSH(nc net.Conn, cfg *ssh.ServerConfig, root string) {
	defer nc.Close()
	_, chans, reqs, err := ssh.NewServerConn(nc, cfg)
	if err != nil {
		return
	}
	go ssh.DiscardRequests(reqs)
	for nch := range chans {
		if nch.ChannelType() != "session" {
			_ = nch.Reject(ssh.UnknownChannelType, "")
			continue
		}
		ch, creqs, err := nch.Accept()
		if err != nil {
			continue
		}
		go func() {
			defer ch.Close()
			for req := range creqs {
				if req.Type != "exec" {
					_ = req.Reply(false, nil)
					continue
				}
				n := binary.BigEndian.Uint32(req.Payload[:4])
				command := string(req.Payload[4 : 4+n])
				_ = req.Reply(true, nil)
				path := strings.Trim(strings.TrimPrefix(strings.TrimPrefix(command, "git-upload-pack "), "git upload-pack "), "'")
				cmd := exec.Command("git-upload-pack", filepath.Join(root, filepath.Clean("/"+path)))
				cmd.Stdin, cmd.Stdout, cmd.Stderr = ch, ch, ch.Stderr()
				status := uint32(0)
				if err := cmd.Run(); err != nil {
					status = 1
				}
				_, _ = ch.SendRequest("exit-status", false, ssh.Marshal(struct{ S uint32 }{status}))
				return
			}
		}()
	}
}

func clientKey(t *testing.T) (string, ssh.PublicKey) {
	t.Helper()
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	blk, err := ssh.MarshalPrivateKey(priv, "")
	if err != nil {
		t.Fatal(err)
	}
	s, _ := ssh.NewSignerFromKey(priv)
	return string(pem.EncodeToMemory(blk)), s.PublicKey()
}

func TestGenericGitSSHPinnedHostKey(t *testing.T) {
	needGit(t)
	if _, err := exec.LookPath("git-upload-pack"); err != nil {
		t.Skip("git-upload-pack not on PATH")
	}
	root, head := bareRepo(t)
	keyPEM, pub := clientKey(t)
	addr, hostKey := sshGitServer(t, root, pub)
	host, port, _ := net.SplitHostPort(addr)
	knownHosts := "[" + host + "]:" + port + " " + strings.TrimSpace(string(ssh.MarshalAuthorizedKey(hostKey)))
	entries, err := ParseKnownHosts(knownHosts)
	if err != nil || entries[0].Fingerprint != ssh.FingerprintSHA256(hostKey) {
		t.Fatalf("known_hosts: %+v %v", entries, err)
	}
	repoURL := "ssh://git@" + addr + "/team/app.git"
	secret := []byte(`{"private_key":` + jsonString(keyPEM) + `}`)
	// Tests reach 127.0.0.1; production policy always blocks loopback.
	np := NetPolicy{AllowPrivate: true}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	c, err := New(Config{Provider: GenericGit, BaseURL: repoURL, AuthType: AuthSSHKey, Secret: secret, KnownHosts: knownHosts, Net: np, HTTP: http.DefaultClient})
	if err != nil {
		t.Fatal(err)
	}
	g := c.(*genericGit)
	g.cfg.Net = NetPolicy{}
	if _, err := c.Check(ctx); DiagCode(err) != "PTH-CONN-1003" {
		t.Fatalf("loopback must be blocked by the network policy: %s %v", DiagCode(err), err)
	}
	g.dial = func(ctx context.Context, addr string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "tcp", addr)
	}
	msg, err := c.Check(ctx)
	if err != nil || !strings.Contains(msg, "HEAD → trunk") {
		t.Fatalf("check: %q %v", msg, err)
	}
	cm, err := c.LatestCommit(ctx, RepoRef{}, "dev")
	if err != nil || cm.SHA != head {
		t.Fatalf("dev head %+v %v", cm, err)
	}
	cred, _ := c.CloneCredential(ctx)
	if cred.SSHPrivateKey == "" || cred.SSHKnownHosts != knownHosts || cred.Username != "git" {
		t.Fatalf("SSH clone credential %+v", cred.Username)
	}

	// Another host key pinned: PTH-CONN-1140, and nothing is read.
	_, otherPub := clientKey(t)
	wrong := "[" + host + "]:" + port + " " + strings.TrimSpace(string(ssh.MarshalAuthorizedKey(otherPub)))
	w, _ := New(Config{Provider: GenericGit, BaseURL: repoURL, AuthType: AuthSSHKey, Secret: secret, KnownHosts: wrong, Net: np})
	w.(*genericGit).dial = g.dial
	if _, err := w.Check(ctx); DiagCode(err) != "PTH-CONN-1140" {
		t.Fatalf("pinned key mismatch: %s %v", DiagCode(err), err)
	}
	// No entry for this host: also PTH-CONN-1140 (never accept-new).
	none := "other.example.com " + strings.TrimSpace(string(ssh.MarshalAuthorizedKey(hostKey)))
	n, _ := New(Config{Provider: GenericGit, BaseURL: repoURL, AuthType: AuthSSHKey, Secret: secret, KnownHosts: none, Net: np})
	n.(*genericGit).dial = g.dial
	if _, err := n.Check(ctx); DiagCode(err) != "PTH-CONN-1140" {
		t.Fatalf("unknown host: %s %v", DiagCode(err), err)
	}
	// Key not authorized: PTH-CONN-1141.
	otherKey, _ := clientKey(t)
	k, _ := New(Config{Provider: GenericGit, BaseURL: repoURL, AuthType: AuthSSHKey,
		Secret: []byte(`{"private_key":` + jsonString(otherKey) + `}`), KnownHosts: knownHosts, Net: np})
	k.(*genericGit).dial = g.dial
	if _, err := k.Check(ctx); DiagCode(err) != "PTH-CONN-1141" {
		t.Fatalf("unauthorized key: %s %v", DiagCode(err), err)
	}
}

func jsonString(s string) string {
	b := strings.Builder{}
	b.WriteByte('"')
	for _, r := range s {
		switch r {
		case '\n':
			b.WriteString(`\n`)
		case '"':
			b.WriteString(`\"`)
		default:
			b.WriteRune(r)
		}
	}
	b.WriteByte('"')
	return b.String()
}

func TestParseSSHURLAndKnownHosts(t *testing.T) {
	r, err := ParseSSHURL("git@git.example.com:team/app.git")
	if err != nil || r.String() != "ssh://git@git.example.com/team/app.git" {
		t.Fatalf("%+v %v", r, err)
	}
	r, err = ParseSSHURL("ssh://git@git.example.com:2222/team/app.git")
	if err != nil || r.Port != "2222" || r.String() != "ssh://git@git.example.com:2222/team/app.git" {
		t.Fatalf("%+v %v", r, err)
	}
	for _, bad := range []string{"ssh://git.example.com/x.git", "ssh://git:pw@h/x.git", "ssh://git@h/x'y.git", "ssh://git@h/../x", "git@h", "ftp://git@h/x"} {
		if _, err := ParseSSHURL(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
	if _, err := ParseKnownHosts("|1|abc= ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl"); err == nil {
		t.Error("hashed host names must be refused")
	}
	if _, err := ParseKnownHosts("@cert-authority *.example.com ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl"); err == nil {
		t.Error("markers must be refused")
	}
	if _, err := CanonicalGitURL("http://h/x.git", false); err == nil {
		t.Error("plain http must be refused without the development flag")
	}
	if u, err := CanonicalGitURL("https://h/team/x.git/", false); err != nil || u != "https://h/team/x.git" {
		t.Errorf("%q %v", u, err)
	}
}

func TestPktLines(t *testing.T) {
	adv := "001e# service=git-upload-pack\n0000"
	lines, err := readPktLines(strings.NewReader(adv), 100)
	if err != nil || len(lines) != 1 {
		t.Fatalf("%v %v", lines, err)
	}
	if _, err := readPktLines(strings.NewReader("zzzz"), 100); err == nil {
		t.Fatal("garbage accepted")
	}
	if _, err := readPktLines(io.LimitReader(strings.NewReader("00ff"+strings.Repeat("a", 300)), 1000), 100); err == nil {
		t.Fatal("over-limit advertisement accepted")
	}
	r, err := parseAdvertisement([]string{"0000000000000000000000000000000000000000 capabilities^{}\x00agent=x"})
	if err != nil || len(r.Refs) != 0 {
		t.Fatalf("empty repository: %+v %v", r, err)
	}
	if _, err := parseAdvertisement([]string{"ERR access denied"}); err == nil {
		t.Fatal("ERR line must fail")
	}
}
