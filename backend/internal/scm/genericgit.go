package scm

import (
	"context"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"net"
	"net/url"
	"path"
	"strings"

	"golang.org/x/crypto/ssh"
)

// GenericGit is any Git server reached over HTTPS or SSH without a vendor
// API (PATHOS 3.0, M2). One connection is one repository: the base URL is
// the repository URL, so a deploy key or a repository-scoped token maps to
// exactly one connection. Discovery returns that repository; health and
// sync are `git ls-remote` (gitremote.go).
const GenericGit = "generic_git"

type genericGit struct {
	cfg    Config
	https  bool
	repo   string // canonical repository URL (no credentials)
	ssh    SSHRepo
	user   string
	token  string
	signer ssh.Signer
	hosts  []SSHKnownHost
	keyPEM string
	// dial overrides the policy dialer (tests).
	dial func(ctx context.Context, addr string) (net.Conn, error)
}

// CanonicalGitURL validates and canonicalises a Generic Git repository URL:
// https://host/path (http only with the development flag) or
// ssh://user@host[:port]/path (scp-like user@host:path is accepted).
func CanonicalGitURL(raw string, allowHTTP bool) (string, error) {
	raw = strings.TrimSpace(raw)
	if strings.HasPrefix(raw, "https://") || strings.HasPrefix(raw, "http://") {
		u, err := url.Parse(raw)
		if err != nil || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
			return "", errors.New("repository URL must be https://host/path without credentials, query or fragment")
		}
		if u.Scheme == "http" && !allowHTTP {
			return "", errors.New("repository URL must use https or ssh")
		}
		if u.Path == "" || u.Path == "/" || strings.Contains(u.Path, "..") {
			return "", errors.New("repository URL must include the repository path")
		}
		return strings.TrimRight(u.String(), "/"), nil
	}
	r, err := ParseSSHURL(raw)
	if err != nil {
		return "", err
	}
	return r.String(), nil
}

func newGenericGit(cfg Config) (*genericGit, error) {
	g := &genericGit{cfg: cfg}
	switch cfg.AuthType {
	case AuthAPIToken: // HTTPS user name + token (or password)
		u, err := url.Parse(cfg.BaseURL)
		if err != nil || (u.Scheme != "https" && u.Scheme != "http") {
			return nil, errors.New("scm: HTTPS credentials need an https:// repository URL")
		}
		var c APITokenCredential
		if err := json.Unmarshal(cfg.Secret, &c); err != nil || c.Token == "" {
			return nil, errors.New("scm: Generic Git over HTTPS requires a token")
		}
		if cfg.HTTP == nil {
			return nil, errors.New("scm: HTTP client required")
		}
		g.https, g.repo, g.user, g.token = true, strings.TrimRight(cfg.BaseURL, "/"), c.Username, c.Token
	case AuthSSHKey:
		r, err := ParseSSHURL(cfg.BaseURL)
		if err != nil {
			return nil, fmt.Errorf("scm: %v", err)
		}
		var c SSHCredential
		if err := json.Unmarshal(cfg.Secret, &c); err != nil || c.PrivateKey == "" {
			return nil, errors.New("scm: Generic Git over SSH requires a private key")
		}
		signer, err := ParseSSHSigner(c)
		if err != nil {
			return nil, fmt.Errorf("scm: %v", err)
		}
		hosts, err := ParseKnownHosts(cfg.KnownHosts)
		if err != nil {
			return nil, fmt.Errorf("scm: %v", err)
		}
		keyPEM := c.PrivateKey
		if c.Passphrase != "" {
			// The worker's ssh cannot prompt: hand it the decrypted key
			// (it lives only in the job's 0600 file during the clone).
			raw, err := ssh.ParseRawPrivateKeyWithPassphrase([]byte(c.PrivateKey), []byte(c.Passphrase))
			if err != nil {
				return nil, errors.New("scm: the SSH private key does not decrypt with the passphrase")
			}
			blk, err := ssh.MarshalPrivateKey(raw, "")
			if err != nil {
				return nil, errors.New("scm: the SSH private key type is not supported")
			}
			keyPEM = string(pem.EncodeToMemory(blk))
		}
		g.ssh, g.repo, g.signer, g.hosts, g.keyPEM = r, r.String(), signer, hosts, keyPEM
	default:
		return nil, fmt.Errorf("scm: unsupported auth type %q for Generic Git", cfg.AuthType)
	}
	return g, nil
}

// LsRemote lists the repository's references.
func (g *genericGit) LsRemote(ctx context.Context) (RemoteRefs, error) {
	if g.https {
		return lsRemoteHTTP(ctx, g.cfg.HTTP, g.repo, g.user, g.token)
	}
	dial := g.dial
	if dial == nil {
		d := g.cfg.Net.Dialer()
		dial = func(ctx context.Context, addr string) (net.Conn, error) { return d.DialContext(ctx, "tcp", addr) }
	}
	return lsRemoteSSH(ctx, dial, g.ssh, g.signer, g.hosts)
}

func (g *genericGit) remote(refs RemoteRefs) RemoteRepo {
	host, p := "", ""
	if g.https {
		u, _ := url.Parse(g.repo)
		host, p = u.Host, u.Path
	} else {
		host, p = g.ssh.Host, g.ssh.Path
	}
	full := host + strings.TrimSuffix(p, ".git")
	name := strings.TrimSuffix(path.Base(p), ".git")
	return RemoteRepo{
		ExternalID: g.repo, FullName: strings.TrimSuffix(full, "/"), Name: name, URL: g.repo, CloneURL: g.repo,
		DefaultBranch: refs.Head, Visibility: "private",
	}
}

// Check runs ls-remote and reports the reference count and HEAD.
func (g *genericGit) Check(ctx context.Context) (string, error) {
	refs, err := g.LsRemote(ctx)
	if err != nil {
		return "", err
	}
	branches := 0
	for _, r := range refs.Refs {
		if strings.HasPrefix(r.Name, "refs/heads/") {
			branches++
		}
	}
	msg := fmt.Sprintf("ls-remote: %d branches", branches)
	if refs.Head != "" {
		msg += ", HEAD → " + refs.Head
	}
	return msg, nil
}

func (g *genericGit) ListRepositories(ctx context.Context) ([]RemoteRepo, error) {
	refs, err := g.LsRemote(ctx)
	if err != nil {
		return nil, err
	}
	return []RemoteRepo{g.remote(refs)}, nil
}

func (g *genericGit) ListOrganizations(context.Context) ([]Organization, error) {
	return nil, ErrNotSupported
}

func (g *genericGit) ListProjects(context.Context, string) ([]Project, error) {
	return nil, ErrNotSupported
}

func (g *genericGit) ListRepositoriesPage(ctx context.Context, q RepoQuery) (RepoPage, error) {
	if q.PageToken != "" {
		return RepoPage{}, ErrInvalidPageToken
	}
	repos, err := g.ListRepositories(ctx)
	if err != nil {
		return RepoPage{}, err
	}
	out := RepoPage{Items: []RemoteRepo{}}
	for _, r := range repos {
		if matchesSearch(r, q.Search) {
			out.Items = append(out.Items, r)
		}
	}
	return out, nil
}

// GetRepository accepts the connection's repository only (by external ID,
// URL or full name).
func (g *genericGit) GetRepository(ctx context.Context, ref RepoRef) (RemoteRepo, error) {
	refs, err := g.LsRemote(ctx)
	if err != nil {
		return RemoteRepo{}, err
	}
	rr := g.remote(refs)
	if ref.ExternalID != "" && ref.ExternalID != rr.ExternalID {
		return RemoteRepo{}, fmt.Errorf("%w: a Generic Git connection serves only %s", ErrNotFound, rr.FullName)
	}
	if ref.ExternalID == "" && ref.FullName != "" && ref.FullName != rr.FullName && ref.FullName != rr.CloneURL {
		return RemoteRepo{}, fmt.Errorf("%w: a Generic Git connection serves only %s", ErrNotFound, rr.FullName)
	}
	return rr, nil
}

func (g *genericGit) ListBranchHeads(ctx context.Context, _ RepoRef) ([]Branch, error) {
	refs, err := g.LsRemote(ctx)
	if err != nil {
		return nil, err
	}
	var out []Branch
	for _, r := range refs.Refs {
		if name, ok := strings.CutPrefix(r.Name, "refs/heads/"); ok {
			out = append(out, Branch{Name: name, CommitSHA: r.SHA, Default: name == refs.Head})
		}
	}
	return out, nil
}

func (g *genericGit) ListBranches(ctx context.Context, _ RemoteRepo) ([]string, error) {
	heads, err := g.ListBranchHeads(ctx, RepoRef{})
	if err != nil {
		return nil, err
	}
	out := make([]string, 0, len(heads))
	for _, h := range heads {
		out = append(out, h.Name)
	}
	return out, nil
}

// LatestCommit returns the head SHA only: ls-remote has no commit metadata.
func (g *genericGit) LatestCommit(ctx context.Context, _ RepoRef, branch string) (Commit, error) {
	refs, err := g.LsRemote(ctx)
	if err != nil {
		return Commit{}, err
	}
	if branch == "" {
		branch = refs.Head
	}
	for _, r := range refs.Refs {
		if r.Name == "refs/heads/"+branch {
			return Commit{SHA: r.SHA}, nil
		}
	}
	return Commit{}, ErrNotFound
}

func (g *genericGit) Languages(context.Context, RepoRef) (map[string]int64, error) {
	return map[string]int64{}, nil
}

func (g *genericGit) Revoke(context.Context) error { return nil }

// CloneCredential returns the HTTPS token, or the SSH key with the pinned
// known_hosts entries.
func (g *genericGit) CloneCredential(context.Context) (Credential, error) {
	if g.https {
		user := g.user
		if user == "" {
			user = "git"
		}
		return Credential{Username: user, Token: g.token}, nil
	}
	return Credential{Username: g.ssh.User, SSHPrivateKey: g.keyPEM, SSHKnownHosts: g.cfg.KnownHosts}, nil
}
