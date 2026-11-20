package repos

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"time"

	"pathos/internal/platform/httpx"
	"pathos/internal/scm"
)

// Anonymous (token-less) import of PUBLIC repositories by URL
// (VALIDATION_REPORT O1). GitHub, GitLab.com, Bitbucket Cloud and Azure
// DevOps public projects are checked through their public APIs without
// credentials; any other HTTPS git URL through the smart HTTP protocol
// (info/refs). The repository is registered with source_type "git": no
// SCM connection and no credential, so workers clone it anonymously.
// Anything the provider does not show to an anonymous caller (private,
// internal or missing) is refused with PTH-ONB-1102; a credential is never
// tried or stored.

// Source providers of anonymous repositories (repositories.source_provider).
const (
	AnonGitHub    = "github"
	AnonGitLab    = "gitlab"
	AnonBitbucket = "bitbucket"
	AnonAzure     = "azure_devops"
	AnonGit       = "git"
)

// Diagnostic codes of the anonymous import (see docs/api-reference).
const (
	DiagAnonInvalidURL  = "PTH-ONB-1101"
	DiagAnonNotPublic   = "PTH-ONB-1102"
	DiagAnonRateLimited = "PTH-ONB-1103"
	DiagAnonUnreachable = "PTH-ONB-1104"
	DiagAnonDuplicate   = "PTH-ONB-1105"
	DiagAnonBlocked     = "PTH-ONB-1106"
)

// PublicRepo is what an anonymous probe learned about a public repository.
type PublicRepo struct {
	Provider      string     `json:"provider"`
	ExternalID    string     `json:"external_id"`
	FullName      string     `json:"full_name"`
	Name          string     `json:"name"`
	URL           string     `json:"url"`
	CloneURL      string     `json:"clone_url"`
	DefaultBranch string     `json:"default_branch"`
	Description   string     `json:"description"`
	Language      string     `json:"language,omitempty"`
	Organization  string     `json:"scm_organization,omitempty"`
	Project       string     `json:"scm_project,omitempty"`
	Archived      bool       `json:"archived"`
	PushedAt      *time.Time `json:"pushed_at,omitempty"`
}

// PublicProbe checks repositories anonymously. The API bases are the
// public SaaS endpoints; tests point them at a local server.
type PublicProbe struct {
	HTTP         *http.Client
	Net          scm.NetPolicy
	GitHubAPI    string // https://api.github.com
	GitLabAPI    string // https://gitlab.com/api/v4
	BitbucketAPI string // https://api.bitbucket.org/2.0
	AzureBase    string // https://dev.azure.com
}

func (p *PublicProbe) base(v, def string) string {
	if v != "" {
		return strings.TrimRight(v, "/")
	}
	return def
}

func anonErr(status int, code, diag, msg string) *httpx.Error {
	return httpx.E(status, code, msg).WithErrorCode(diag)
}

func errNotPublic(what string) *httpx.Error {
	return anonErr(http.StatusUnprocessableEntity, "repository_not_public", DiagAnonNotPublic,
		what+" is private, internal or does not exist. Anonymous import works only for public repositories; "+
			"import private repositories through an SCM connection with a token.")
}

func errAnonURL(msg string) *httpx.Error {
	return anonErr(http.StatusBadRequest, "invalid_repository_url", DiagAnonInvalidURL, msg)
}

// rateLimited builds the PTH-ONB-1103 error from the provider's headers.
func rateLimited(provider string, h http.Header) *httpx.Error {
	e := anonErr(http.StatusTooManyRequests, "provider_rate_limited", DiagAnonRateLimited,
		"the "+provider+" rate limit for anonymous requests was reached; try again later or use an SCM connection with a token")
	retry := 0
	if v, err := strconv.Atoi(h.Get("Retry-After")); err == nil && v > 0 {
		retry = v
	} else if v, err := strconv.ParseInt(firstHeader(h, "X-RateLimit-Reset", "RateLimit-Reset"), 10, 64); err == nil && v > 0 {
		if d := time.Until(time.Unix(v, 0)); d > 0 {
			retry = int(d.Seconds()) + 1
		}
	}
	if retry > 0 {
		e.Details = map[string]any{"retry_after_seconds": retry}
	}
	return e
}

func firstHeader(h http.Header, keys ...string) string {
	for _, k := range keys {
		if v := h.Get(k); v != "" {
			return v
		}
	}
	return ""
}

func errUnreachable(provider string, err error) *httpx.Error {
	msg := "the " + provider + " API could not be reached anonymously"
	if errors.Is(err, scm.ErrBlockedAddress) {
		return anonErr(http.StatusBadRequest, "blocked_address", DiagAnonBlocked,
			"the repository host resolves to an address that is not allowed (internal or reserved network)")
	}
	if err != nil {
		msg += ": " + truncate(err.Error(), 200)
	}
	return anonErr(http.StatusBadGateway, "provider_unreachable", DiagAnonUnreachable, msg)
}

// parsedRepoURL is a repository URL split by provider.
type parsedRepoURL struct {
	Provider string
	URL      *url.URL // https, no user info, query or fragment, no trailing ".git"/"/"
	Parts    []string // provider path segments (owner/repo, group/.../project, org/project/repo)
}

// parsePublicURL validates and classifies a repository URL.
func parsePublicURL(raw string, allowHTTP bool) (parsedRepoURL, error) {
	raw = strings.TrimSpace(raw)
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" || len(raw) > 2000 {
		return parsedRepoURL{}, errAnonURL("enter the repository's https:// URL, for example https://github.com/owner/repo")
	}
	if u.Scheme != "https" && !(allowHTTP && u.Scheme == "http") {
		return parsedRepoURL{}, errAnonURL("the repository URL must use https://")
	}
	if u.User != nil {
		if _, hasPass := u.User.Password(); hasPass {
			return parsedRepoURL{}, errAnonURL("the URL must not contain credentials; anonymous import never uses a token or password")
		}
		u.User = nil // Azure DevOps copies "org@dev.azure.com"
	}
	if u.RawQuery != "" || u.Fragment != "" {
		return parsedRepoURL{}, errAnonURL("the repository URL must not have a query or fragment")
	}
	if ip, err := netip.ParseAddr(u.Hostname()); err == nil && !(scm.NetPolicy{}).Allowed(ip) {
		return parsedRepoURL{}, anonErr(http.StatusBadRequest, "blocked_address", DiagAnonBlocked, "the repository host is a loopback, link-local or reserved address")
	}
	host := strings.ToLower(u.Hostname())
	path := strings.Trim(u.EscapedPath(), "/")
	if path == "" {
		return parsedRepoURL{}, errAnonURL("the URL has no repository path")
	}
	segs := []string{}
	for _, s := range strings.Split(path, "/") {
		v, err := url.PathUnescape(s)
		if err != nil || v == "" || v == "." || v == ".." {
			return parsedRepoURL{}, errAnonURL("the repository path is not valid")
		}
		segs = append(segs, v)
	}
	out := parsedRepoURL{Provider: AnonGit}
	clean := &url.URL{Scheme: u.Scheme, Host: u.Host}
	switch host {
	case "github.com", "www.github.com":
		if len(segs) < 2 {
			return out, errAnonURL("a GitHub URL looks like https://github.com/owner/repo")
		}
		out.Provider, out.Parts = AnonGitHub, []string{segs[0], strings.TrimSuffix(segs[1], ".git")}
		clean.Host = "github.com"
	case "gitlab.com", "www.gitlab.com":
		// Group/subgroup/project, then optional "/-/tree/..." etc.
		parts := segs
		for i, s := range segs {
			if s == "-" {
				parts = segs[:i]
				break
			}
		}
		if len(parts) < 2 {
			return out, errAnonURL("a GitLab URL looks like https://gitlab.com/group/project")
		}
		parts[len(parts)-1] = strings.TrimSuffix(parts[len(parts)-1], ".git")
		out.Provider, out.Parts = AnonGitLab, parts
		clean.Host = "gitlab.com"
	case "bitbucket.org", "www.bitbucket.org":
		if len(segs) < 2 {
			return out, errAnonURL("a Bitbucket URL looks like https://bitbucket.org/workspace/repository")
		}
		out.Provider, out.Parts = AnonBitbucket, []string{segs[0], strings.TrimSuffix(segs[1], ".git")}
		clean.Host = "bitbucket.org"
	case "dev.azure.com":
		// org/project/_git/repo
		if len(segs) < 4 || segs[2] != "_git" {
			return out, errAnonURL("an Azure DevOps URL looks like https://dev.azure.com/organization/project/_git/repository")
		}
		out.Provider, out.Parts = AnonAzure, []string{segs[0], segs[1], segs[3]}
	default:
		if strings.HasSuffix(host, ".visualstudio.com") {
			return out, errAnonURL("use the dev.azure.com form of the Azure DevOps URL")
		}
		segs[len(segs)-1] = strings.TrimSuffix(segs[len(segs)-1], "/")
		out.Parts = segs
	}
	for _, s := range out.Parts {
		if s == "" || strings.ContainsAny(s, "\\\x00\r\n") {
			return out, errAnonURL("the repository path is not valid")
		}
	}
	escaped := make([]string, len(out.Parts))
	for i, s := range out.Parts {
		escaped[i] = url.PathEscape(s)
	}
	switch out.Provider {
	case AnonAzure:
		clean.RawPath = "/" + escaped[0] + "/" + escaped[1] + "/_git/" + escaped[2]
	default:
		clean.RawPath = "/" + strings.Join(escaped, "/")
	}
	clean.Path, _ = url.PathUnescape(clean.RawPath)
	out.URL = clean
	return out, nil
}

// Probe checks raw anonymously and returns the public repository.
func (p *PublicProbe) Probe(ctx context.Context, raw string) (PublicRepo, error) {
	u, err := parsePublicURL(raw, p.Net.AllowHTTP)
	if err != nil {
		return PublicRepo{}, err
	}
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	switch u.Provider {
	case AnonGitHub:
		return p.github(ctx, u)
	case AnonGitLab:
		return p.gitlab(ctx, u)
	case AnonBitbucket:
		return p.bitbucket(ctx, u)
	case AnonAzure:
		return p.azure(ctx, u)
	}
	return p.generic(ctx, u)
}

const maxProbeBody = 1 << 20

// get performs one anonymous GET. It never sends credentials.
func (p *PublicProbe) get(ctx context.Context, provider, rawURL, accept string) (*http.Response, []byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, nil, errAnonURL("the repository URL is not valid")
	}
	req.Header.Set("Accept", accept)
	req.Header.Set("User-Agent", "PATHOS-anonymous-import")
	client := p.HTTP
	if client == nil {
		client = p.Net.Client()
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, nil, errUnreachable(provider, err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxProbeBody))
	if err != nil {
		return nil, nil, errUnreachable(provider, err)
	}
	return resp, body, nil
}

// classify maps a non-200 provider status.
func classify(provider string, resp *http.Response, what string) error {
	switch {
	case resp.StatusCode == http.StatusTooManyRequests,
		resp.StatusCode == http.StatusForbidden && resp.Header.Get("X-RateLimit-Remaining") == "0":
		return rateLimited(provider, resp.Header)
	case resp.StatusCode == http.StatusNotFound, resp.StatusCode == http.StatusUnauthorized, resp.StatusCode == http.StatusForbidden:
		return errNotPublic(what)
	}
	return errUnreachable(provider, fmt.Errorf("HTTP %d", resp.StatusCode))
}

func isJSON(resp *http.Response) bool {
	return strings.Contains(strings.ToLower(resp.Header.Get("Content-Type")), "json")
}

func (p *PublicProbe) github(ctx context.Context, u parsedRepoURL) (PublicRepo, error) {
	api := p.base(p.GitHubAPI, "https://api.github.com") + "/repos/" + url.PathEscape(u.Parts[0]) + "/" + url.PathEscape(u.Parts[1])
	resp, body, err := p.get(ctx, "GitHub", api, "application/vnd.github+json")
	if err != nil {
		return PublicRepo{}, err
	}
	what := "The GitHub repository " + u.Parts[0] + "/" + u.Parts[1]
	if resp.StatusCode != http.StatusOK {
		return PublicRepo{}, classify("GitHub", resp, what)
	}
	var r struct {
		ID            int64      `json:"id"`
		FullName      string     `json:"full_name"`
		Name          string     `json:"name"`
		HTMLURL       string     `json:"html_url"`
		CloneURL      string     `json:"clone_url"`
		DefaultBranch string     `json:"default_branch"`
		Private       bool       `json:"private"`
		Visibility    string     `json:"visibility"`
		Description   string     `json:"description"`
		Language      string     `json:"language"`
		Archived      bool       `json:"archived"`
		PushedAt      *time.Time `json:"pushed_at"`
		Owner         struct {
			Login string `json:"login"`
		} `json:"owner"`
	}
	if err := json.Unmarshal(body, &r); err != nil || r.FullName == "" {
		return PublicRepo{}, errUnreachable("GitHub", errors.New("unexpected response"))
	}
	if r.Private || (r.Visibility != "" && r.Visibility != "public") {
		return PublicRepo{}, errNotPublic(what)
	}
	clone, err := providerCloneURL(r.CloneURL, "github.com")
	if err != nil {
		return PublicRepo{}, err
	}
	return PublicRepo{Provider: AnonGitHub, ExternalID: strconv.FormatInt(r.ID, 10), FullName: r.FullName, Name: r.Name,
		URL: firstNonEmptyStr(r.HTMLURL, "https://github.com/"+r.FullName), CloneURL: clone, DefaultBranch: r.DefaultBranch,
		Description: r.Description, Language: r.Language, Organization: r.Owner.Login, Archived: r.Archived, PushedAt: r.PushedAt}, nil
}

func (p *PublicProbe) gitlab(ctx context.Context, u parsedRepoURL) (PublicRepo, error) {
	path := strings.Join(u.Parts, "/")
	api := p.base(p.GitLabAPI, "https://gitlab.com/api/v4") + "/projects/" + url.PathEscape(path)
	resp, body, err := p.get(ctx, "GitLab", api, "application/json")
	if err != nil {
		return PublicRepo{}, err
	}
	what := "The GitLab project " + path
	if resp.StatusCode != http.StatusOK {
		return PublicRepo{}, classify("GitLab", resp, what)
	}
	var r struct {
		ID                int64      `json:"id"`
		PathWithNamespace string     `json:"path_with_namespace"`
		Name              string     `json:"name"`
		WebURL            string     `json:"web_url"`
		HTTPURL           string     `json:"http_url_to_repo"`
		DefaultBranch     string     `json:"default_branch"`
		Visibility        string     `json:"visibility"`
		Description       string     `json:"description"`
		Archived          bool       `json:"archived"`
		LastActivityAt    *time.Time `json:"last_activity_at"`
		Namespace         struct {
			FullPath string `json:"full_path"`
		} `json:"namespace"`
	}
	if err := json.Unmarshal(body, &r); err != nil || r.PathWithNamespace == "" {
		return PublicRepo{}, errUnreachable("GitLab", errors.New("unexpected response"))
	}
	if r.Visibility != "public" {
		return PublicRepo{}, errNotPublic(what)
	}
	clone, err := providerCloneURL(r.HTTPURL, "gitlab.com")
	if err != nil {
		return PublicRepo{}, err
	}
	return PublicRepo{Provider: AnonGitLab, ExternalID: strconv.FormatInt(r.ID, 10), FullName: r.PathWithNamespace, Name: r.Name,
		URL: firstNonEmptyStr(r.WebURL, "https://gitlab.com/"+r.PathWithNamespace), CloneURL: clone, DefaultBranch: r.DefaultBranch,
		Description: r.Description, Organization: r.Namespace.FullPath, Archived: r.Archived, PushedAt: r.LastActivityAt}, nil
}

func (p *PublicProbe) bitbucket(ctx context.Context, u parsedRepoURL) (PublicRepo, error) {
	api := p.base(p.BitbucketAPI, "https://api.bitbucket.org/2.0") + "/repositories/" + url.PathEscape(u.Parts[0]) + "/" + url.PathEscape(u.Parts[1])
	resp, body, err := p.get(ctx, "Bitbucket", api, "application/json")
	if err != nil {
		return PublicRepo{}, err
	}
	what := "The Bitbucket repository " + u.Parts[0] + "/" + u.Parts[1]
	if resp.StatusCode != http.StatusOK {
		return PublicRepo{}, classify("Bitbucket", resp, what)
	}
	var r struct {
		UUID       string     `json:"uuid"`
		FullName   string     `json:"full_name"`
		Name       string     `json:"name"`
		IsPrivate  *bool      `json:"is_private"`
		Desc       string     `json:"description"`
		Language   string     `json:"language"`
		UpdatedOn  *time.Time `json:"updated_on"`
		MainBranch *struct {
			Name string `json:"name"`
		} `json:"mainbranch"`
		Links struct {
			HTML struct {
				Href string `json:"href"`
			} `json:"html"`
			Clone []struct {
				Name string `json:"name"`
				Href string `json:"href"`
			} `json:"clone"`
		} `json:"links"`
		Workspace struct {
			Slug string `json:"slug"`
		} `json:"workspace"`
	}
	if err := json.Unmarshal(body, &r); err != nil || r.FullName == "" {
		return PublicRepo{}, errUnreachable("Bitbucket", errors.New("unexpected response"))
	}
	if r.IsPrivate == nil || *r.IsPrivate {
		return PublicRepo{}, errNotPublic(what)
	}
	clone := ""
	for _, l := range r.Links.Clone {
		if l.Name == "https" {
			clone = l.Href
		}
	}
	if clone == "" {
		clone = "https://bitbucket.org/" + r.FullName + ".git"
	}
	clone, err = providerCloneURL(clone, "bitbucket.org")
	if err != nil {
		return PublicRepo{}, err
	}
	branch := ""
	if r.MainBranch != nil {
		branch = r.MainBranch.Name
	}
	return PublicRepo{Provider: AnonBitbucket, ExternalID: firstNonEmptyStr(r.UUID, r.FullName), FullName: r.FullName, Name: r.Name,
		URL: firstNonEmptyStr(r.Links.HTML.Href, "https://bitbucket.org/"+r.FullName), CloneURL: clone, DefaultBranch: branch,
		Description: r.Desc, Language: r.Language, Organization: r.Workspace.Slug, PushedAt: r.UpdatedOn}, nil
}

func (p *PublicProbe) azure(ctx context.Context, u parsedRepoURL) (PublicRepo, error) {
	org, project, repo := u.Parts[0], u.Parts[1], u.Parts[2]
	api := p.base(p.AzureBase, "https://dev.azure.com") + "/" + url.PathEscape(org) + "/" + url.PathEscape(project) +
		"/_apis/git/repositories/" + url.PathEscape(repo) + "?api-version=7.1"
	resp, body, err := p.get(ctx, "Azure DevOps", api, "application/json")
	if err != nil {
		return PublicRepo{}, err
	}
	what := "The Azure DevOps repository " + org + "/" + project + "/" + repo
	// Azure DevOps answers anonymous requests for private projects with
	// 401, or with 203 and a sign-in page.
	if resp.StatusCode == http.StatusOK && !isJSON(resp) || resp.StatusCode == http.StatusNonAuthoritativeInfo {
		return PublicRepo{}, errNotPublic(what)
	}
	if resp.StatusCode != http.StatusOK {
		return PublicRepo{}, classify("Azure DevOps", resp, what)
	}
	var r struct {
		ID            string `json:"id"`
		Name          string `json:"name"`
		RemoteURL     string `json:"remoteUrl"`
		WebURL        string `json:"webUrl"`
		DefaultBranch string `json:"defaultBranch"`
		IsDisabled    bool   `json:"isDisabled"`
		Project       struct {
			Name       string `json:"name"`
			Visibility string `json:"visibility"`
		} `json:"project"`
	}
	if err := json.Unmarshal(body, &r); err != nil || r.Name == "" {
		return PublicRepo{}, errUnreachable("Azure DevOps", errors.New("unexpected response"))
	}
	if !strings.EqualFold(r.Project.Visibility, "public") {
		return PublicRepo{}, errNotPublic(what)
	}
	clone := r.RemoteURL
	if clone == "" {
		clone = u.URL.String()
	}
	clone, err = providerCloneURL(clone, "dev.azure.com")
	if err != nil {
		return PublicRepo{}, err
	}
	return PublicRepo{Provider: AnonAzure, ExternalID: firstNonEmptyStr(r.ID, org+"/"+project+"/"+r.Name),
		FullName: project + "/" + r.Name, Name: r.Name, URL: firstNonEmptyStr(r.WebURL, u.URL.String()), CloneURL: clone,
		DefaultBranch: strings.TrimPrefix(r.DefaultBranch, "refs/heads/"), Organization: org, Project: firstNonEmptyStr(r.Project.Name, project),
		Archived: r.IsDisabled}, nil
}

// generic probes any HTTPS git server with the smart HTTP protocol. A
// public repository answers info/refs without credentials; the advertised
// HEAD symref gives the default branch.
func (p *PublicProbe) generic(ctx context.Context, u parsedRepoURL) (PublicRepo, error) {
	if !p.Net.AllowHTTP && u.URL.Scheme != "https" {
		return PublicRepo{}, errAnonURL("the repository URL must use https://")
	}
	repoURL := u.URL.String()
	resp, body, err := p.get(ctx, u.URL.Host, repoURL+"/info/refs?service=git-upload-pack", "application/x-git-upload-pack-advertisement")
	if err != nil {
		return PublicRepo{}, err
	}
	what := "The git repository " + repoURL
	if resp.StatusCode != http.StatusOK {
		if resp.StatusCode >= 300 && resp.StatusCode < 400 {
			return PublicRepo{}, errAnonURL("the git server redirects to another host; enter the final repository URL")
		}
		return PublicRepo{}, classify(u.URL.Host, resp, what)
	}
	if !strings.HasPrefix(resp.Header.Get("Content-Type"), "application/x-git-upload-pack-advertisement") {
		// A login page or a dumb-HTTP server: not something we can clone
		// anonymously with the smart protocol.
		return PublicRepo{}, errNotPublic(what)
	}
	branch, ok := advertisedHead(body)
	if !ok {
		return PublicRepo{}, errUnreachable(u.URL.Host, errors.New("not a git smart-HTTP response"))
	}
	// Same-host redirects were followed: register the final URL.
	if fin := resp.Request.URL; fin != nil {
		f := *fin
		f.RawQuery = ""
		f.Path = strings.TrimSuffix(f.Path, "/info/refs")
		f.RawPath = ""
		repoURL = f.String()
	}
	name := strings.TrimSuffix(u.Parts[len(u.Parts)-1], ".git")
	full := strings.TrimSuffix(strings.Join(u.Parts, "/"), ".git")
	return PublicRepo{Provider: AnonGit, ExternalID: strings.ToLower(repoURL), FullName: truncate(u.URL.Hostname()+"/"+full, 200), Name: name,
		URL: strings.TrimSuffix(repoURL, ".git"), CloneURL: repoURL, DefaultBranch: branch}, nil
}

// advertisedHead parses a git-upload-pack advertisement (protocol v0/v1)
// and returns the branch HEAD points to ("" when HEAD is detached or the
// repository is empty).
func advertisedHead(body []byte) (string, bool) {
	r := bufio.NewReader(bytes.NewReader(body))
	sawService := false
	for {
		var hdr [4]byte
		if _, err := io.ReadFull(r, hdr[:]); err != nil {
			return "", sawService
		}
		n, err := strconv.ParseUint(string(hdr[:]), 16, 16)
		if err != nil {
			return "", false
		}
		if n == 0 { // flush-pkt
			if sawService {
				continue
			}
			return "", false
		}
		if n < 4 {
			return "", false
		}
		line := make([]byte, n-4)
		if _, err := io.ReadFull(r, line); err != nil {
			return "", false
		}
		s := strings.TrimSuffix(string(line), "\n")
		if strings.HasPrefix(s, "# service=") {
			sawService = true
			continue
		}
		if !sawService {
			return "", false
		}
		refPart, caps, _ := strings.Cut(s, "\x00")
		for _, c := range strings.Fields(caps) {
			if v, ok := strings.CutPrefix(c, "symref=HEAD:refs/heads/"); ok {
				return v, true
			}
		}
		// No symref capability: HEAD's commit tells nothing about the name.
		_ = refPart
		return "", true
	}
}

// providerCloneURL validates a provider's clone URL against its host and
// strips user info.
func providerCloneURL(raw, host string) (string, error) {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" || !strings.EqualFold(u.Hostname(), host) || u.RawQuery != "" || u.Fragment != "" {
		return "", errUnreachable(host, errors.New("unexpected clone URL"))
	}
	u.User = nil
	return u.String(), nil
}

func firstNonEmptyStr(v ...string) string {
	for _, s := range v {
		if s != "" {
			return s
		}
	}
	return ""
}
