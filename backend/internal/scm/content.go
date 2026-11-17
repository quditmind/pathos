package scm

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// MaxFileBytes bounds a file read through ContentReader.
const MaxFileBytes = 1 << 20

// ErrTooLarge means the file exceeds MaxFileBytes.
var ErrTooLarge = errors.New("scm: file is too large to display")

// ContentReader reads repository content at an exact commit. Every provider
// client implements it; callers must never substitute a branch head for the
// commit that was scanned.
type ContentReader interface {
	// FileAt returns the content of path at commit (a full or abbreviated
	// SHA). ErrNotFound when the file does not exist at that commit.
	FileAt(ctx context.Context, ref RepoRef, commit, path string) ([]byte, error)
	// FileHistory returns up to limit commits that touched path, newest
	// first, reachable from commit ("" = default branch).
	FileHistory(ctx context.Context, ref RepoRef, commit, path string, limit int) ([]Commit, error)
}

var (
	shaRe = regexp.MustCompile(`^[0-9a-fA-F]{7,64}$`)
)

// ValidCommit reports whether s looks like a commit SHA.
func ValidCommit(s string) bool { return shaRe.MatchString(s) }

// ValidRepoPath accepts slash-separated relative paths without "." or ".."
// components, backslashes or control characters.
func ValidRepoPath(p string) bool {
	if p == "" || len(p) > 1000 || strings.HasPrefix(p, "/") || strings.ContainsRune(p, '\\') {
		return false
	}
	for _, r := range p {
		if r < 0x20 || r == 0x7f {
			return false
		}
	}
	for _, c := range strings.Split(p, "/") {
		if c == "" || c == "." || c == ".." {
			return false
		}
	}
	return true
}

func checkContentArgs(commit, path string) error {
	if commit != "" && !ValidCommit(commit) {
		return errors.New("scm: invalid commit")
	}
	if !ValidRepoPath(path) {
		return errors.New("scm: invalid path")
	}
	return nil
}

func escapePath(p string) string {
	parts := strings.Split(p, "/")
	for i, s := range parts {
		parts[i] = url.PathEscape(s)
	}
	return strings.Join(parts, "/")
}

func decodeBase64Content(enc, content string) ([]byte, error) {
	if enc != "" && enc != "base64" {
		return nil, fmt.Errorf("scm: unsupported content encoding %q", enc)
	}
	b, err := base64.StdEncoding.DecodeString(strings.ReplaceAll(content, "\n", ""))
	if err != nil {
		return nil, errors.New("scm: invalid file content")
	}
	if len(b) > MaxFileBytes {
		return nil, ErrTooLarge
	}
	return b, nil
}

func clampLimit(n int) int {
	if n <= 0 || n > 50 {
		return 20
	}
	return n
}

// getRaw GETs rawURL and returns at most limit bytes of the body (any
// content type). Authentication and the single 401 retry match api.do.
func (a *api) getRaw(ctx context.Context, rawURL string, limit int64) ([]byte, error) {
	for attempt := 0; ; attempt++ {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
		if err != nil {
			return nil, errors.New("scm: invalid request URL")
		}
		for k, v := range a.headers {
			req.Header.Set(k, v)
		}
		req.Header.Set("User-Agent", "PATHOS-ASPM")
		if err := a.auth.authorize(ctx, req); err != nil {
			return nil, err
		}
		host := req.URL.Host
		resp, err := a.hc.Do(req)
		if err != nil {
			return nil, newTransportError(host, err)
		}
		if resp.StatusCode == http.StatusUnauthorized && attempt == 0 {
			_ = resp.Body.Close()
			retry, rerr := a.auth.unauthorized(ctx, req)
			if rerr != nil {
				return nil, rerr
			}
			if retry {
				continue
			}
			return nil, statusError(resp, host)
		}
		if serr := statusError(resp, host); serr != nil {
			_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10))
			_ = resp.Body.Close()
			return nil, serr
		}
		b, err := io.ReadAll(io.LimitReader(resp.Body, limit+1))
		_ = resp.Body.Close()
		if err != nil {
			return nil, newTransportError(host, err)
		}
		if int64(len(b)) > limit {
			return nil, ErrTooLarge
		}
		return b, nil
	}
}

// --- GitHub ------------------------------------------------------------------

func (g *gitHub) repoPathFor(ctx context.Context, ref RepoRef) (string, error) {
	if ref.FullName != "" {
		return ghFullPath(ref.FullName)
	}
	return ghRepoPath(ref)
}

func (g *gitHub) FileAt(ctx context.Context, ref RepoRef, commit, path string) ([]byte, error) {
	if err := checkContentArgs(commit, path); err != nil {
		return nil, err
	}
	p, err := g.repoPathFor(ctx, ref)
	if err != nil {
		return nil, err
	}
	var out struct {
		Type     string `json:"type"`
		Encoding string `json:"encoding"`
		Content  string `json:"content"`
		Size     int64  `json:"size"`
	}
	u := p + "/contents/" + escapePath(path)
	if commit != "" {
		u += "?ref=" + url.QueryEscape(commit)
	}
	if _, err := g.get(ctx, u, &out); err != nil {
		return nil, err
	}
	if out.Type != "" && out.Type != "file" {
		return nil, ErrNotFound
	}
	if out.Size > MaxFileBytes {
		return nil, ErrTooLarge
	}
	return decodeBase64Content(out.Encoding, out.Content)
}

func (g *gitHub) FileHistory(ctx context.Context, ref RepoRef, commit, path string, limit int) ([]Commit, error) {
	if err := checkContentArgs(commit, path); err != nil {
		return nil, err
	}
	p, err := g.repoPathFor(ctx, ref)
	if err != nil {
		return nil, err
	}
	q := url.Values{"path": {path}, "per_page": {strconv.Itoa(clampLimit(limit))}}
	if commit != "" {
		q.Set("sha", commit)
	}
	var page []struct {
		SHA    string `json:"sha"`
		Commit struct {
			Message string `json:"message"`
			Author  struct {
				Name string     `json:"name"`
				Date *time.Time `json:"date"`
			} `json:"author"`
			Committer struct {
				Date *time.Time `json:"date"`
			} `json:"committer"`
		} `json:"commit"`
	}
	if _, err := g.get(ctx, p+"/commits?"+q.Encode(), &page); err != nil {
		return nil, err
	}
	out := make([]Commit, 0, len(page))
	for _, c := range page {
		at := c.Commit.Committer.Date
		if at == nil {
			at = c.Commit.Author.Date
		}
		out = append(out, Commit{SHA: c.SHA, Message: firstLine(c.Commit.Message), Author: c.Commit.Author.Name, CommittedAt: at})
	}
	return out, nil
}

// --- GitLab ------------------------------------------------------------------

func (g *gitLab) FileAt(ctx context.Context, ref RepoRef, commit, path string) ([]byte, error) {
	if err := checkContentArgs(commit, path); err != nil {
		return nil, err
	}
	p, err := glProjectPath(ref)
	if err != nil {
		return nil, err
	}
	if commit == "" {
		proj, err := g.project(ctx, ref, false)
		if err != nil {
			return nil, err
		}
		commit = proj.DefaultBranch
	}
	var out struct {
		Size     int64  `json:"size"`
		Encoding string `json:"encoding"`
		Content  string `json:"content"`
	}
	if _, err := g.get(ctx, p+"/repository/files/"+url.PathEscape(path)+"?ref="+url.QueryEscape(commit), &out); err != nil {
		return nil, err
	}
	if out.Size > MaxFileBytes {
		return nil, ErrTooLarge
	}
	return decodeBase64Content(out.Encoding, out.Content)
}

func (g *gitLab) FileHistory(ctx context.Context, ref RepoRef, commit, path string, limit int) ([]Commit, error) {
	if err := checkContentArgs(commit, path); err != nil {
		return nil, err
	}
	p, err := glProjectPath(ref)
	if err != nil {
		return nil, err
	}
	q := url.Values{"path": {path}, "per_page": {strconv.Itoa(clampLimit(limit))}}
	if commit != "" {
		q.Set("ref_name", commit)
	}
	var page []struct {
		ID            string     `json:"id"`
		Title         string     `json:"title"`
		Message       string     `json:"message"`
		AuthorName    string     `json:"author_name"`
		CommittedDate *time.Time `json:"committed_date"`
	}
	if _, err := g.get(ctx, p+"/repository/commits?"+q.Encode(), &page); err != nil {
		return nil, err
	}
	out := make([]Commit, 0, len(page))
	for _, c := range page {
		msg := c.Title
		if msg == "" {
			msg = c.Message
		}
		out = append(out, Commit{SHA: c.ID, Message: firstLine(msg), Author: c.AuthorName, CommittedAt: c.CommittedDate})
	}
	return out, nil
}

// --- Bitbucket Cloud ---------------------------------------------------------

func (b *bitbucket) FileAt(ctx context.Context, ref RepoRef, commit, path string) ([]byte, error) {
	if err := checkContentArgs(commit, path); err != nil {
		return nil, err
	}
	p, err := bbRepoPath(ref)
	if err != nil {
		return nil, err
	}
	if commit == "" {
		r, _, err := b.repo(ctx, ref)
		if err != nil {
			return nil, err
		}
		if r.MainBranch == nil {
			return nil, ErrNotFound
		}
		commit = r.MainBranch.Name
	}
	var meta struct {
		Type string `json:"type"`
		Size int64  `json:"size"`
	}
	base := b.root + p + "/src/" + url.PathEscape(commit) + "/" + escapePath(path)
	if _, err := b.api.get(ctx, base+"?format=meta", &meta); err != nil {
		return nil, err
	}
	if meta.Type != "" && meta.Type != "commit_file" {
		return nil, ErrNotFound
	}
	if meta.Size > MaxFileBytes {
		return nil, ErrTooLarge
	}
	return b.api.getRaw(ctx, base, MaxFileBytes)
}

func (b *bitbucket) FileHistory(ctx context.Context, ref RepoRef, commit, path string, limit int) ([]Commit, error) {
	if err := checkContentArgs(commit, path); err != nil {
		return nil, err
	}
	p, err := bbRepoPath(ref)
	if err != nil {
		return nil, err
	}
	u := p + "/commits"
	if commit != "" {
		u += "/" + url.PathEscape(commit)
	}
	u += "?" + url.Values{"path": {path}, "pagelen": {strconv.Itoa(clampLimit(limit))}}.Encode()
	var out bbPage[struct {
		Hash    string     `json:"hash"`
		Message string     `json:"message"`
		Date    *time.Time `json:"date"`
		Author  struct {
			Raw  string `json:"raw"`
			User *struct {
				DisplayName string `json:"display_name"`
			} `json:"user"`
		} `json:"author"`
	}]
	if _, err := b.get(ctx, u, &out); err != nil {
		return nil, err
	}
	res := make([]Commit, 0, len(out.Values))
	for _, c := range out.Values {
		author := c.Author.Raw
		if c.Author.User != nil && c.Author.User.DisplayName != "" {
			author = c.Author.User.DisplayName
		}
		res = append(res, Commit{SHA: c.Hash, Message: firstLine(c.Message), Author: author, CommittedAt: c.Date})
	}
	return res, nil
}

// --- Azure DevOps ------------------------------------------------------------

func (a *azureDevOps) FileAt(ctx context.Context, ref RepoRef, commit, path string) ([]byte, error) {
	if err := checkContentArgs(commit, path); err != nil {
		return nil, err
	}
	rb, err := a.repoBase(ref)
	if err != nil {
		return nil, err
	}
	q := url.Values{"path": {"/" + path}, "includeContent": {"true"}, "$format": {"json"}}
	if commit != "" {
		q.Set("versionDescriptor.version", commit)
		q.Set("versionDescriptor.versionType", "commit")
	}
	var out struct {
		IsFolder bool   `json:"isFolder"`
		Content  string `json:"content"`
		Meta     struct {
			IsBinary bool `json:"isBinary"`
		} `json:"contentMetadata"`
	}
	if _, err := a.call(ctx, rb+"/items?"+q.Encode(), &out); err != nil {
		return nil, err
	}
	if out.IsFolder {
		return nil, ErrNotFound
	}
	if len(out.Content) > MaxFileBytes {
		return nil, ErrTooLarge
	}
	return []byte(out.Content), nil
}

func (a *azureDevOps) FileHistory(ctx context.Context, ref RepoRef, commit, path string, limit int) ([]Commit, error) {
	if err := checkContentArgs(commit, path); err != nil {
		return nil, err
	}
	rb, err := a.repoBase(ref)
	if err != nil {
		return nil, err
	}
	q := url.Values{"searchCriteria.itemPath": {"/" + path}, "searchCriteria.$top": {strconv.Itoa(clampLimit(limit))}}
	if commit != "" {
		q.Set("searchCriteria.itemVersion.version", commit)
		q.Set("searchCriteria.itemVersion.versionType", "commit")
	}
	var out struct {
		Value []struct {
			CommitID string `json:"commitId"`
			Comment  string `json:"comment"`
			Author   struct {
				Name string     `json:"name"`
				Date *time.Time `json:"date"`
			} `json:"author"`
			Committer struct {
				Date *time.Time `json:"date"`
			} `json:"committer"`
		} `json:"value"`
	}
	if _, err := a.call(ctx, rb+"/commits?"+q.Encode(), &out); err != nil {
		return nil, err
	}
	res := make([]Commit, 0, len(out.Value))
	for _, c := range out.Value {
		at := c.Committer.Date
		if at == nil {
			at = c.Author.Date
		}
		res = append(res, Commit{SHA: c.CommitID, Message: firstLine(c.Comment), Author: c.Author.Name, CommittedAt: at})
	}
	return res, nil
}

var (
	_ ContentReader = (*gitHub)(nil)
	_ ContentReader = (*gitLab)(nil)
	_ ContentReader = (*bitbucket)(nil)
	_ ContentReader = (*azureDevOps)(nil)
)
