package scm

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
)

// A pure-Go equivalent of `git ls-remote` for the Generic Git connector.
//
// The api and jobs images are distroless and have no git binary, so the
// reference advertisement is read with the Git wire protocol directly:
//
//   - HTTPS: the smart HTTP protocol, GET <repo>/info/refs?service=git-upload-pack
//     (https://git-scm.com/docs/http-protocol). The client goes through the
//     connection's NetPolicy client (blocked addresses, per-connection CA).
//   - SSH: `git-upload-pack '<path>'` over an SSH session
//     (https://git-scm.com/docs/pack-protocol). The host key must match a
//     pinned known_hosts entry; there is no trust-on-first-use.
//
// Both read only the reference advertisement (pkt-line format,
// https://git-scm.com/docs/protocol-common) and then end the conversation
// with a flush packet: no objects are transferred.

// ErrHostKeyMismatch means the SSH server presented a host key that is not
// the pinned one (PTH-CONN-1140).
var ErrHostKeyMismatch = errors.New("scm: SSH host key does not match the pinned known_hosts entry")

// ErrGitAuth means the Git server rejected the credential (PTH-CONN-1141).
// It wraps ErrAuth.
var ErrGitAuth = fmt.Errorf("%w (git)", ErrAuth)

// Ref is one advertised reference.
type Ref struct {
	Name string `json:"name"`
	SHA  string `json:"sha"`
}

// RemoteRefs is the result of an ls-remote.
type RemoteRefs struct {
	Refs []Ref `json:"refs"`
	// Head is the branch HEAD points to ("" if the server does not say).
	Head string `json:"head"`
}

const maxAdvertisement = 8 << 20 // refs listing cap

var gitSHARe = regexp.MustCompile(`^[0-9a-f]{40}([0-9a-f]{24})?$`)

// readPktLines reads pkt-lines until a flush packet. It returns the lines
// (without trailing newline) and stops on the first flush.
func readPktLines(r io.Reader, limit int) ([]string, error) {
	var out []string
	total := 0
	hdr := make([]byte, 4)
	for {
		if _, err := io.ReadFull(r, hdr); err != nil {
			return nil, fmt.Errorf("scm: reading the git reference advertisement: %w", err)
		}
		n, err := strconv.ParseUint(string(hdr), 16, 16)
		if err != nil {
			return nil, errors.New("scm: invalid git pkt-line (is this a Git server?)")
		}
		if n == 0 {
			return out, nil
		}
		if n < 4 {
			continue // delim / response-end packets (protocol v2) are not expected here
		}
		total += int(n)
		if total > limit {
			return nil, errors.New("scm: git reference advertisement too large")
		}
		buf := make([]byte, n-4)
		if _, err := io.ReadFull(r, buf); err != nil {
			return nil, fmt.Errorf("scm: reading the git reference advertisement: %w", err)
		}
		out = append(out, strings.TrimSuffix(string(buf), "\n"))
	}
}

// parseAdvertisement parses "<sha> <ref>[\0caps]" lines (protocol v0/v1).
func parseAdvertisement(lines []string) (RemoteRefs, error) {
	out := RemoteRefs{Refs: []Ref{}}
	for i, l := range lines {
		if i == 0 && strings.HasPrefix(l, "version ") {
			continue // protocol v1 announces itself
		}
		if strings.HasPrefix(l, "ERR ") {
			return out, fmt.Errorf("scm: git server error: %s", truncateMsg(strings.TrimPrefix(l, "ERR "), 200))
		}
		line, caps, hasCaps := strings.Cut(l, "\x00")
		sha, name, ok := strings.Cut(line, " ")
		if !ok || !gitSHARe.MatchString(sha) {
			return out, errors.New("scm: unexpected git reference advertisement")
		}
		if hasCaps {
			for _, c := range strings.Fields(caps) {
				if v, ok := strings.CutPrefix(c, "symref=HEAD:"); ok {
					out.Head = strings.TrimPrefix(v, "refs/heads/")
				}
			}
		}
		if name == "capabilities^{}" { // empty repository
			continue
		}
		out.Refs = append(out.Refs, Ref{Name: name, SHA: sha})
	}
	return out, nil
}

func truncateMsg(s string, n int) string {
	if len(s) > n {
		return s[:n]
	}
	return s
}

// lsRemoteHTTP reads the advertisement over smart HTTP.
func lsRemoteHTTP(ctx context.Context, hc *http.Client, repoURL, user, token string) (RemoteRefs, error) {
	u, err := url.Parse(strings.TrimRight(repoURL, "/") + "/info/refs")
	if err != nil {
		return RemoteRefs{}, errors.New("scm: invalid repository URL")
	}
	u.RawQuery = "service=git-upload-pack"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return RemoteRefs{}, errors.New("scm: invalid repository URL")
	}
	req.Header.Set("User-Agent", "git/2.0 (PATHOS-ASPM)")
	if token != "" {
		if user == "" {
			user = "git"
		}
		req.SetBasicAuth(user, token)
	}
	host := u.Host
	resp, err := hc.Do(req)
	if err != nil {
		return RemoteRefs{}, newTransportError(host, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusUnauthorized {
		return RemoteRefs{}, &StatusError{Code: resp.StatusCode, Host: host, kind: ErrGitAuth}
	}
	if err := statusError(resp, host); err != nil {
		return RemoteRefs{}, err
	}
	if ct := resp.Header.Get("Content-Type"); ct != "application/x-git-upload-pack-advertisement" {
		return RemoteRefs{}, fmt.Errorf("scm: %s does not speak the smart HTTP Git protocol (content type %q); check the repository URL", host, truncateMsg(ct, 80))
	}
	body := bufio.NewReader(io.LimitReader(resp.Body, maxAdvertisement+4096))
	first, err := readPktLines(body, 4096)
	if err != nil {
		return RemoteRefs{}, err
	}
	if len(first) != 1 || first[0] != "# service=git-upload-pack" {
		return RemoteRefs{}, errors.New("scm: unexpected smart HTTP service announcement")
	}
	lines, err := readPktLines(body, maxAdvertisement)
	if err != nil {
		return RemoteRefs{}, err
	}
	return parseAdvertisement(lines)
}

// SSHKnownHost is a parsed, pinned host key.
type SSHKnownHost struct {
	Hosts       []string `json:"hosts"`
	KeyType     string   `json:"key_type"`
	Fingerprint string   `json:"fingerprint"` // SHA256:<base64>, as ssh-keygen -lf prints
	key         ssh.PublicKey
}

// ParseKnownHosts parses known_hosts lines (as printed by ssh-keyscan or
// copied from ~/.ssh/known_hosts). Hashed host names (|1|...) and markers
// (@cert-authority, @revoked) are refused: PATHOS pins plain host keys.
func ParseKnownHosts(text string) ([]SSHKnownHost, error) {
	var out []SSHKnownHost
	rest := []byte(text)
	for len(bytes.TrimSpace(rest)) > 0 {
		marker, hosts, key, _, next, err := ssh.ParseKnownHosts(rest)
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("known_hosts: %v", err)
		}
		if marker != "" {
			return nil, fmt.Errorf("known_hosts: @%s entries are not supported; pin the host key itself", marker)
		}
		for _, h := range hosts {
			if strings.HasPrefix(h, "|") {
				return nil, errors.New("known_hosts: hashed host names are not supported; use the plain host name (ssh-keyscan without -H)")
			}
		}
		out = append(out, SSHKnownHost{Hosts: hosts, KeyType: key.Type(), Fingerprint: ssh.FingerprintSHA256(key), key: key})
		rest = next
		if len(out) > 20 {
			return nil, errors.New("known_hosts: at most 20 entries")
		}
	}
	if len(out) == 0 {
		return nil, errors.New("known_hosts: no host key found")
	}
	return out, nil
}

// knownHostAddr is the known_hosts form of host:port.
func knownHostAddr(host, port string) string {
	if port == "" || port == "22" {
		return host
	}
	return "[" + host + "]:" + port
}

// hostKeyCallback accepts only a pinned key for host:port. *mismatch is set
// when the server offered another key.
func hostKeyCallback(pinned []SSHKnownHost, host, port string, mismatch *bool) (ssh.HostKeyCallback, []string) {
	want := knownHostAddr(host, port)
	var keys []ssh.PublicKey
	algos := map[string]bool{}
	for _, k := range pinned {
		for _, h := range k.Hosts {
			if strings.EqualFold(h, want) {
				keys = append(keys, k.key)
				switch k.key.Type() {
				case ssh.KeyAlgoRSA:
					algos[ssh.KeyAlgoRSASHA512], algos[ssh.KeyAlgoRSASHA256] = true, true
				default:
					algos[k.key.Type()] = true
				}
			}
		}
	}
	var list []string
	for a := range algos {
		list = append(list, a)
	}
	return func(_ string, _ net.Addr, key ssh.PublicKey) error {
		for _, k := range keys {
			if bytes.Equal(k.Marshal(), key.Marshal()) {
				return nil
			}
		}
		*mismatch = true
		return ErrHostKeyMismatch
	}, list
}

// SSHRepo is a parsed ssh:// repository URL.
type SSHRepo struct {
	User, Host, Port, Path string
}

// ParseSSHURL parses ssh://user@host[:port]/path or the scp-like form
// user@host:path (converted to an absolute path, which Git hosting servers
// resolve identically).
func ParseSSHURL(raw string) (SSHRepo, error) {
	raw = strings.TrimSpace(raw)
	if !strings.Contains(raw, "://") {
		at := strings.Index(raw, "@")
		colon := strings.Index(raw, ":")
		if at <= 0 || colon < at {
			return SSHRepo{}, errors.New("SSH repository URL must be ssh://user@host[:port]/path or user@host:path")
		}
		raw = "ssh://" + raw[:colon] + "/" + strings.TrimPrefix(raw[colon+1:], "/")
	}
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "ssh" || u.Hostname() == "" || u.User == nil || u.User.Username() == "" || u.RawQuery != "" || u.Fragment != "" {
		return SSHRepo{}, errors.New("SSH repository URL must be ssh://user@host[:port]/path with a user name")
	}
	if _, hasPass := u.User.Password(); hasPass {
		return SSHRepo{}, errors.New("SSH repository URL must not contain a password")
	}
	p := u.Path
	if p == "" || p == "/" || strings.Contains(p, "..") || strings.ContainsAny(p, "'\\\x00\n") {
		return SSHRepo{}, errors.New("SSH repository URL has an invalid path")
	}
	return SSHRepo{User: u.User.Username(), Host: u.Hostname(), Port: u.Port(), Path: p}, nil
}

// String is the canonical ssh:// URL.
func (r SSHRepo) String() string {
	host := r.Host
	if strings.Contains(host, ":") {
		host = "[" + host + "]"
	}
	if r.Port != "" && r.Port != "22" {
		host += ":" + r.Port
	}
	return "ssh://" + url.PathEscape(r.User) + "@" + host + r.Path
}

// SSHCredential is the stored form of a Generic Git SSH credential (JSON in
// secrets). The known_hosts entry is configuration (scm_connections.ssh_known_hosts).
type SSHCredential struct {
	PrivateKey string `json:"private_key"`
	Passphrase string `json:"passphrase,omitempty"`
}

// ParseSSHSigner parses an OpenSSH or PEM private key.
func ParseSSHSigner(c SSHCredential) (ssh.Signer, error) {
	var (
		s   ssh.Signer
		err error
	)
	if c.Passphrase != "" {
		s, err = ssh.ParsePrivateKeyWithPassphrase([]byte(c.PrivateKey), []byte(c.Passphrase))
	} else {
		s, err = ssh.ParsePrivateKey([]byte(c.PrivateKey))
	}
	if err != nil {
		var missing *ssh.PassphraseMissingError
		if errors.As(err, &missing) {
			return nil, errors.New("the SSH private key is encrypted; give its passphrase")
		}
		return nil, errors.New("the SSH private key does not parse (OpenSSH or PEM format expected)")
	}
	return s, nil
}

// lsRemoteSSH reads the advertisement over SSH with a pinned host key.
func lsRemoteSSH(ctx context.Context, dial func(context.Context, string) (net.Conn, error), repo SSHRepo, signer ssh.Signer, pinned []SSHKnownHost) (RemoteRefs, error) {
	port := repo.Port
	if port == "" {
		port = "22"
	}
	addr := net.JoinHostPort(repo.Host, port)
	var mismatch bool
	cb, algos := hostKeyCallback(pinned, repo.Host, repo.Port, &mismatch)
	if len(algos) == 0 {
		return RemoteRefs{}, fmt.Errorf("%w: no known_hosts entry for %s", ErrHostKeyMismatch, knownHostAddr(repo.Host, repo.Port))
	}
	conn, err := dial(ctx, addr)
	if err != nil {
		return RemoteRefs{}, newTransportError(addr, err)
	}
	defer conn.Close()
	if dl, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(dl)
	} else {
		_ = conn.SetDeadline(time.Now().Add(30 * time.Second))
	}
	cfg := &ssh.ClientConfig{
		User: repo.User, Auth: []ssh.AuthMethod{ssh.PublicKeys(signer)},
		HostKeyCallback: cb, HostKeyAlgorithms: algos, Timeout: 15 * time.Second,
		ClientVersion: "SSH-2.0-PATHOS",
	}
	cc, chans, reqs, err := ssh.NewClientConn(conn, addr, cfg)
	if err != nil {
		switch {
		case mismatch:
			return RemoteRefs{}, fmt.Errorf("%w (%s)", ErrHostKeyMismatch, addr)
		case strings.Contains(err.Error(), "unable to authenticate"):
			return RemoteRefs{}, fmt.Errorf("%w: %s rejected the SSH key", ErrGitAuth, addr)
		}
		return RemoteRefs{}, newTransportError(addr, err)
	}
	client := ssh.NewClient(cc, chans, reqs)
	defer client.Close()
	sess, err := client.NewSession()
	if err != nil {
		return RemoteRefs{}, newTransportError(addr, err)
	}
	defer sess.Close()
	stdout, err := sess.StdoutPipe()
	if err != nil {
		return RemoteRefs{}, err
	}
	stdin, err := sess.StdinPipe()
	if err != nil {
		return RemoteRefs{}, err
	}
	var stderr bytes.Buffer
	sess.Stderr = &limitedBuffer{buf: &stderr, max: 4096}
	// The path never contains a single quote (ParseSSHURL).
	if err := sess.Start("git-upload-pack '" + repo.Path + "'"); err != nil {
		return RemoteRefs{}, newTransportError(addr, err)
	}
	lines, err := readPktLines(bufio.NewReader(stdout), maxAdvertisement)
	_, _ = stdin.Write([]byte("0000")) // end the negotiation: no wants
	_ = stdin.Close()
	if err != nil {
		msg := strings.ToLower(stderr.String())
		if strings.Contains(msg, "not found") || strings.Contains(msg, "does not exist") || strings.Contains(msg, "does not appear to be a git repository") {
			return RemoteRefs{}, fmt.Errorf("%w: %s", ErrNotFound, repo.Path)
		}
		if strings.Contains(msg, "denied") || strings.Contains(msg, "permission") {
			return RemoteRefs{}, fmt.Errorf("%w: %s", ErrForbidden, repo.Path)
		}
		return RemoteRefs{}, err
	}
	return parseAdvertisement(lines)
}

type limitedBuffer struct {
	buf *bytes.Buffer
	max int
}

func (l *limitedBuffer) Write(p []byte) (int, error) {
	if room := l.max - l.buf.Len(); room > 0 {
		if len(p) > room {
			l.buf.Write(p[:room])
		} else {
			l.buf.Write(p)
		}
	}
	return len(p), nil
}

// FingerprintSHA256 is ssh-keygen's SHA256:<base64> fingerprint of a
// marshalled public key (exported for tests and the API).
func FingerprintSHA256(pub []byte) string {
	sum := sha256.Sum256(pub)
	return "SHA256:" + base64.RawStdEncoding.EncodeToString(sum[:])
}
