package scm

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"mime/multipart"
	"net/http"
	"net/url"
	"strconv"
	"strings"
)

// Fix pull requests: PATHOS creates a branch, commits changed files to it
// and opens a pull (merge) request. It only ever writes to branches under
// FixBranchPrefix, so it can never push to a default or protected branch;
// every write method enforces this.

// FixBranchPrefix prefixes every branch PATHOS creates.
const FixBranchPrefix = "pathos/fix/"

// Limits for one change set.
const (
	MaxChangeFiles     = 20
	MaxChangeFileBytes = 5 << 20
)

// Pull request states (normalized).
const (
	PROpen   = "open"
	PRMerged = "merged"
	PRClosed = "closed"
)

// ErrConflict means the branch or pull request already exists, or the
// branch moved since the base commit.
var ErrConflict = errors.New("scm: conflict (the branch or pull request already exists, or the branch changed)")

// FileChange is the new content of an existing file.
type FileChange struct {
	Path    string
	Content []byte
}

// PullRequestSpec describes a pull request to open.
type PullRequestSpec struct {
	Branch     string // source branch (FixBranchPrefix…)
	BaseBranch string // target branch
	Title      string
	Body       string
}

// PullRequest is a created or fetched pull/merge request.
type PullRequest struct {
	ID    string `json:"id"` // number (GitHub, Bitbucket, Azure DevOps) or iid (GitLab)
	URL   string `json:"url"`
	State string `json:"state"` // open | merged | closed
}

// PullRequestWriter is implemented by every provider client. The credential
// needs write access to repository contents and pull requests (GitHub
// "Contents: write" + "Pull requests: write", GitLab api scope with
// Developer role, Bitbucket repository:write + pullrequest:write, Azure
// DevOps Code (read & write)).
type PullRequestWriter interface {
	// CreateBranch creates branch at commit fromCommit.
	CreateBranch(ctx context.Context, ref RepoRef, branch, fromCommit string) error
	// CommitFiles commits files on top of parentCommit, the current head of
	// branch, and returns the new commit SHA ("" if the provider does not
	// report it).
	CommitFiles(ctx context.Context, ref RepoRef, branch, parentCommit, message string, files []FileChange) (string, error)
	CreatePullRequest(ctx context.Context, ref RepoRef, spec PullRequestSpec) (PullRequest, error)
	GetPullRequest(ctx context.Context, ref RepoRef, id string) (PullRequest, error)
}

// ValidFixBranch reports whether b is a branch PATHOS may write to: under
// FixBranchPrefix and a valid git ref name.
func ValidFixBranch(b string) bool {
	if !strings.HasPrefix(b, FixBranchPrefix) || len(b) > 200 || len(b) == len(FixBranchPrefix) {
		return false
	}
	if strings.Contains(b, "..") || strings.Contains(b, "//") || strings.Contains(b, "@{") ||
		strings.HasSuffix(b, "/") || strings.HasSuffix(b, ".") || strings.HasSuffix(b, ".lock") {
		return false
	}
	for _, r := range b {
		if r <= 0x20 || r == 0x7f || strings.ContainsRune(`~^:?*[\`, r) {
			return false
		}
	}
	for _, c := range strings.Split(b, "/") {
		if strings.HasPrefix(c, ".") {
			return false
		}
	}
	return true
}

func validBaseBranch(b string) bool {
	if b == "" || len(b) > 255 || strings.Contains(b, "..") || strings.HasPrefix(b, "/") {
		return false
	}
	for _, r := range b {
		if r <= 0x20 || r == 0x7f || strings.ContainsRune(`~^:?*[\`, r) {
			return false
		}
	}
	return true
}

func fullCommit(s string) bool { return ValidCommit(s) && (len(s) == 40 || len(s) == 64) }

func checkCommitArgs(branch, parent, message string, files []FileChange) error {
	if !ValidFixBranch(branch) {
		return errors.New("scm: PATHOS only writes to " + FixBranchPrefix + "* branches")
	}
	if !fullCommit(parent) {
		return errors.New("scm: invalid parent commit")
	}
	if strings.TrimSpace(message) == "" || len(message) > 10000 {
		return errors.New("scm: invalid commit message")
	}
	if len(files) == 0 || len(files) > MaxChangeFiles {
		return fmt.Errorf("scm: a change set has 1 to %d files", MaxChangeFiles)
	}
	seen := map[string]bool{}
	for _, f := range files {
		if !ValidRepoPath(f.Path) || seen[f.Path] {
			return errors.New("scm: invalid file path in change set")
		}
		seen[f.Path] = true
		if len(f.Content) > MaxChangeFileBytes {
			return ErrTooLarge
		}
	}
	return nil
}

func checkPRSpec(s PullRequestSpec) error {
	if !ValidFixBranch(s.Branch) {
		return errors.New("scm: PATHOS only opens pull requests from " + FixBranchPrefix + "* branches")
	}
	if !validBaseBranch(s.BaseBranch) || s.BaseBranch == s.Branch {
		return errors.New("scm: invalid target branch")
	}
	if strings.TrimSpace(s.Title) == "" {
		return errors.New("scm: pull request title required")
	}
	return nil
}

func checkPRID(id string) error {
	if n, err := strconv.ParseInt(id, 10, 64); err != nil || n <= 0 {
		return errors.New("scm: invalid pull request id")
	}
	return nil
}

func clipRunes(s string, n int) string {
	r := []rune(s)
	if len(r) > n {
		return string(r[:n-1]) + "…"
	}
	return s
}

// conflictErr maps 409/422 responses onto ErrConflict.
func conflictErr(err error) error {
	var se *StatusError
	if errors.As(err, &se) && (se.Code == http.StatusConflict || se.Code == http.StatusUnprocessableEntity) {
		return fmt.Errorf("%w (HTTP %d from %s)", ErrConflict, se.Code, se.Host)
	}
	return err
}

// --- GitHub ------------------------------------------------------------------

func (g *gitHub) CreateBranch(ctx context.Context, ref RepoRef, branch, from string) error {
	if !ValidFixBranch(branch) || !fullCommit(from) {
		return errors.New("scm: invalid branch or commit")
	}
	p, err := g.repoPathFor(ctx, ref)
	if err != nil {
		return err
	}
	_, err = g.api.do(ctx, http.MethodPost, g.cfg.BaseURL+p+"/git/refs",
		jsonBody(map[string]string{"ref": "refs/heads/" + branch, "sha": from}), "application/json", nil)
	return conflictErr(err)
}

func (g *gitHub) CommitFiles(ctx context.Context, ref RepoRef, branch, parent, message string, files []FileChange) (string, error) {
	if err := checkCommitArgs(branch, parent, message, files); err != nil {
		return "", err
	}
	p, err := g.repoPathFor(ctx, ref)
	if err != nil {
		return "", err
	}
	base := g.cfg.BaseURL + p
	var pc struct {
		Tree struct {
			SHA string `json:"sha"`
		} `json:"tree"`
	}
	if _, err := g.get(ctx, p+"/git/commits/"+url.PathEscape(parent), &pc); err != nil {
		return "", err
	}
	if !fullCommit(pc.Tree.SHA) {
		return "", errors.New("scm: invalid tree in provider response")
	}
	type entry struct {
		Path string `json:"path"`
		Mode string `json:"mode"`
		Type string `json:"type"`
		SHA  string `json:"sha"`
	}
	entries := make([]entry, 0, len(files))
	for _, f := range files {
		var blob struct {
			SHA string `json:"sha"`
		}
		if _, err := g.api.do(ctx, http.MethodPost, base+"/git/blobs", jsonBody(map[string]string{
			"content": base64.StdEncoding.EncodeToString(f.Content), "encoding": "base64"}), "application/json", &blob); err != nil {
			return "", err
		}
		entries = append(entries, entry{Path: f.Path, Mode: "100644", Type: "blob", SHA: blob.SHA})
	}
	var tree struct {
		SHA string `json:"sha"`
	}
	if _, err := g.api.do(ctx, http.MethodPost, base+"/git/trees", jsonBody(map[string]any{"base_tree": pc.Tree.SHA, "tree": entries}),
		"application/json", &tree); err != nil {
		return "", err
	}
	var commit struct {
		SHA string `json:"sha"`
	}
	if _, err := g.api.do(ctx, http.MethodPost, base+"/git/commits", jsonBody(map[string]any{
		"message": message, "tree": tree.SHA, "parents": []string{parent}}), "application/json", &commit); err != nil {
		return "", err
	}
	if !fullCommit(commit.SHA) {
		return "", errors.New("scm: invalid commit in provider response")
	}
	// Fast-forward only: fails if the branch moved.
	if _, err := g.api.do(ctx, http.MethodPatch, base+"/git/refs/heads/"+escapeRef(branch),
		jsonBody(map[string]any{"sha": commit.SHA, "force": false}), "application/json", nil); err != nil {
		return "", conflictErr(err)
	}
	return commit.SHA, nil
}

type ghPull struct {
	Number   int64   `json:"number"`
	HTMLURL  string  `json:"html_url"`
	State    string  `json:"state"`
	Merged   bool    `json:"merged"`
	MergedAt *string `json:"merged_at"`
}

func (p ghPull) normalized() PullRequest {
	st := PROpen
	switch {
	case p.Merged || p.MergedAt != nil:
		st = PRMerged
	case p.State == "closed":
		st = PRClosed
	}
	return PullRequest{ID: strconv.FormatInt(p.Number, 10), URL: p.HTMLURL, State: st}
}

func (g *gitHub) CreatePullRequest(ctx context.Context, ref RepoRef, s PullRequestSpec) (PullRequest, error) {
	if err := checkPRSpec(s); err != nil {
		return PullRequest{}, err
	}
	p, err := g.repoPathFor(ctx, ref)
	if err != nil {
		return PullRequest{}, err
	}
	var out ghPull
	_, err = g.api.do(ctx, http.MethodPost, g.cfg.BaseURL+p+"/pulls", jsonBody(map[string]any{
		"title": clipRunes(s.Title, 250), "head": s.Branch, "base": s.BaseBranch, "body": clipRunes(s.Body, 60000), "maintainer_can_modify": true}),
		"application/json", &out)
	if err != nil {
		return PullRequest{}, conflictErr(err)
	}
	return out.normalized(), nil
}

func (g *gitHub) GetPullRequest(ctx context.Context, ref RepoRef, id string) (PullRequest, error) {
	if err := checkPRID(id); err != nil {
		return PullRequest{}, err
	}
	p, err := g.repoPathFor(ctx, ref)
	if err != nil {
		return PullRequest{}, err
	}
	var out ghPull
	if _, err := g.get(ctx, p+"/pulls/"+id, &out); err != nil {
		return PullRequest{}, err
	}
	return out.normalized(), nil
}

// --- GitLab ------------------------------------------------------------------

func (g *gitLab) CreateBranch(ctx context.Context, ref RepoRef, branch, from string) error {
	if !ValidFixBranch(branch) || !fullCommit(from) {
		return errors.New("scm: invalid branch or commit")
	}
	p, err := glProjectPath(ref)
	if err != nil {
		return err
	}
	q := url.Values{"branch": {branch}, "ref": {from}}
	_, err = g.api.do(ctx, http.MethodPost, g.root+p+"/repository/branches?"+q.Encode(), nil, "", nil)
	return conflictErr(err)
}

func (g *gitLab) CommitFiles(ctx context.Context, ref RepoRef, branch, parent, message string, files []FileChange) (string, error) {
	if err := checkCommitArgs(branch, parent, message, files); err != nil {
		return "", err
	}
	p, err := glProjectPath(ref)
	if err != nil {
		return "", err
	}
	actions := make([]map[string]string, 0, len(files))
	for _, f := range files {
		actions = append(actions, map[string]string{"action": "update", "file_path": f.Path,
			"content": base64.StdEncoding.EncodeToString(f.Content), "encoding": "base64"})
	}
	var out struct {
		ID string `json:"id"`
	}
	// The branch was just created at parent; GitLab commits on its head.
	_, err = g.api.do(ctx, http.MethodPost, g.root+p+"/repository/commits", jsonBody(map[string]any{
		"branch": branch, "commit_message": message, "actions": actions}), "application/json", &out)
	if err != nil {
		return "", conflictErr(err)
	}
	return out.ID, nil
}

type glMR struct {
	IID    int64  `json:"iid"`
	WebURL string `json:"web_url"`
	State  string `json:"state"` // opened | closed | locked | merged
}

func (m glMR) normalized() PullRequest {
	st := PROpen
	switch m.State {
	case "merged":
		st = PRMerged
	case "closed":
		st = PRClosed
	}
	return PullRequest{ID: strconv.FormatInt(m.IID, 10), URL: m.WebURL, State: st}
}

func (g *gitLab) CreatePullRequest(ctx context.Context, ref RepoRef, s PullRequestSpec) (PullRequest, error) {
	if err := checkPRSpec(s); err != nil {
		return PullRequest{}, err
	}
	p, err := glProjectPath(ref)
	if err != nil {
		return PullRequest{}, err
	}
	var out glMR
	_, err = g.api.do(ctx, http.MethodPost, g.root+p+"/merge_requests", jsonBody(map[string]any{
		"source_branch": s.Branch, "target_branch": s.BaseBranch, "title": clipRunes(s.Title, 250),
		"description": clipRunes(s.Body, 60000), "remove_source_branch": true}), "application/json", &out)
	if err != nil {
		return PullRequest{}, conflictErr(err)
	}
	return out.normalized(), nil
}

func (g *gitLab) GetPullRequest(ctx context.Context, ref RepoRef, id string) (PullRequest, error) {
	if err := checkPRID(id); err != nil {
		return PullRequest{}, err
	}
	p, err := glProjectPath(ref)
	if err != nil {
		return PullRequest{}, err
	}
	var out glMR
	if _, err := g.api.get(ctx, g.root+p+"/merge_requests/"+id, &out); err != nil {
		return PullRequest{}, err
	}
	return out.normalized(), nil
}

// --- Bitbucket Cloud -----------------------------------------------------------

func (b *bitbucket) CreateBranch(ctx context.Context, ref RepoRef, branch, from string) error {
	if !ValidFixBranch(branch) || !fullCommit(from) {
		return errors.New("scm: invalid branch or commit")
	}
	p, err := bbRepoPath(ref)
	if err != nil {
		return err
	}
	_, err = b.api.do(ctx, http.MethodPost, b.root+p+"/refs/branches",
		jsonBody(map[string]any{"name": branch, "target": map[string]string{"hash": from}}), "application/json", nil)
	return conflictErr(err)
}

func (b *bitbucket) CommitFiles(ctx context.Context, ref RepoRef, branch, parent, message string, files []FileChange) (string, error) {
	if err := checkCommitArgs(branch, parent, message, files); err != nil {
		return "", err
	}
	p, err := bbRepoPath(ref)
	if err != nil {
		return "", err
	}
	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	_ = mw.WriteField("message", message)
	_ = mw.WriteField("branch", branch)
	// parents makes the commit fail if the branch moved.
	_ = mw.WriteField("parents", parent)
	for _, f := range files {
		fw, err := mw.CreateFormFile(f.Path, f.Path)
		if err != nil {
			return "", err
		}
		if _, err := fw.Write(f.Content); err != nil {
			return "", err
		}
	}
	if err := mw.Close(); err != nil {
		return "", err
	}
	resp, err := b.api.do(ctx, http.MethodPost, b.root+p+"/src", buf.Bytes(), mw.FormDataContentType(), nil)
	if err != nil {
		return "", conflictErr(err)
	}
	// Location: …/commit/<sha>
	if resp != nil {
		loc := resp.Header.Get("Location")
		if i := strings.LastIndex(loc, "/"); i >= 0 && fullCommit(loc[i+1:]) {
			return loc[i+1:], nil
		}
	}
	return "", nil
}

type bbPull struct {
	ID    int64  `json:"id"`
	State string `json:"state"` // OPEN | MERGED | DECLINED | SUPERSEDED
	Links struct {
		HTML struct {
			Href string `json:"href"`
		} `json:"html"`
	} `json:"links"`
}

func (p bbPull) normalized() PullRequest {
	st := PROpen
	switch p.State {
	case "MERGED":
		st = PRMerged
	case "DECLINED", "SUPERSEDED":
		st = PRClosed
	}
	return PullRequest{ID: strconv.FormatInt(p.ID, 10), URL: p.Links.HTML.Href, State: st}
}

func (b *bitbucket) CreatePullRequest(ctx context.Context, ref RepoRef, s PullRequestSpec) (PullRequest, error) {
	if err := checkPRSpec(s); err != nil {
		return PullRequest{}, err
	}
	p, err := bbRepoPath(ref)
	if err != nil {
		return PullRequest{}, err
	}
	var out bbPull
	_, err = b.api.do(ctx, http.MethodPost, b.root+p+"/pullrequests", jsonBody(map[string]any{
		"title": clipRunes(s.Title, 250), "description": clipRunes(s.Body, 30000), "close_source_branch": true,
		"source":      map[string]any{"branch": map[string]string{"name": s.Branch}},
		"destination": map[string]any{"branch": map[string]string{"name": s.BaseBranch}},
	}), "application/json", &out)
	if err != nil {
		return PullRequest{}, conflictErr(err)
	}
	return out.normalized(), nil
}

func (b *bitbucket) GetPullRequest(ctx context.Context, ref RepoRef, id string) (PullRequest, error) {
	if err := checkPRID(id); err != nil {
		return PullRequest{}, err
	}
	p, err := bbRepoPath(ref)
	if err != nil {
		return PullRequest{}, err
	}
	var out bbPull
	if _, err := b.api.get(ctx, b.root+p+"/pullrequests/"+id, &out); err != nil {
		return PullRequest{}, err
	}
	return out.normalized(), nil
}

// --- Azure DevOps --------------------------------------------------------------

const zeroObjectID = "0000000000000000000000000000000000000000"

func (a *azureDevOps) CreateBranch(ctx context.Context, ref RepoRef, branch, from string) error {
	if !ValidFixBranch(branch) || !fullCommit(from) {
		return errors.New("scm: invalid branch or commit")
	}
	rb, err := a.repoBase(ref)
	if err != nil {
		return err
	}
	var out struct {
		Value []struct {
			Success      bool   `json:"success"`
			UpdateStatus string `json:"updateStatus"`
		} `json:"value"`
	}
	if _, err := a.api.do(ctx, http.MethodPost, rb+"/refs?api-version="+adoAPIVersion, jsonBody([]map[string]string{{
		"name": "refs/heads/" + branch, "oldObjectId": zeroObjectID, "newObjectId": from}}), "application/json", &out); err != nil {
		return conflictErr(err)
	}
	if len(out.Value) != 1 || !out.Value[0].Success {
		return fmt.Errorf("%w (branch not created)", ErrConflict)
	}
	return nil
}

func (a *azureDevOps) CommitFiles(ctx context.Context, ref RepoRef, branch, parent, message string, files []FileChange) (string, error) {
	if err := checkCommitArgs(branch, parent, message, files); err != nil {
		return "", err
	}
	rb, err := a.repoBase(ref)
	if err != nil {
		return "", err
	}
	changes := make([]map[string]any, 0, len(files))
	for _, f := range files {
		changes = append(changes, map[string]any{"changeType": "edit", "item": map[string]string{"path": "/" + f.Path},
			"newContent": map[string]string{"content": base64.StdEncoding.EncodeToString(f.Content), "contentType": "base64encoded"}})
	}
	var out struct {
		Commits []struct {
			CommitID string `json:"commitId"`
		} `json:"commits"`
	}
	// oldObjectId makes the push fail if the branch moved.
	if _, err := a.api.do(ctx, http.MethodPost, rb+"/pushes?api-version="+adoAPIVersion, jsonBody(map[string]any{
		"refUpdates": []map[string]string{{"name": "refs/heads/" + branch, "oldObjectId": parent}},
		"commits":    []map[string]any{{"comment": message, "changes": changes}},
	}), "application/json", &out); err != nil {
		return "", conflictErr(err)
	}
	if len(out.Commits) > 0 && fullCommit(out.Commits[0].CommitID) {
		return out.Commits[0].CommitID, nil
	}
	return "", nil
}

type adoPull struct {
	PullRequestID int64  `json:"pullRequestId"`
	Status        string `json:"status"` // active | abandoned | completed
	Repository    struct {
		WebURL string `json:"webUrl"`
	} `json:"repository"`
}

func (p adoPull) normalized() PullRequest {
	st := PROpen
	switch p.Status {
	case "completed":
		st = PRMerged
	case "abandoned":
		st = PRClosed
	}
	id := strconv.FormatInt(p.PullRequestID, 10)
	link := ""
	if u, err := url.Parse(p.Repository.WebURL); err == nil && (u.Scheme == "https" || u.Scheme == "http") && u.Host != "" {
		link = strings.TrimRight(p.Repository.WebURL, "/") + "/pullrequest/" + id
	}
	return PullRequest{ID: id, URL: link, State: st}
}

func (a *azureDevOps) CreatePullRequest(ctx context.Context, ref RepoRef, s PullRequestSpec) (PullRequest, error) {
	if err := checkPRSpec(s); err != nil {
		return PullRequest{}, err
	}
	rb, err := a.repoBase(ref)
	if err != nil {
		return PullRequest{}, err
	}
	var out adoPull
	if _, err := a.api.do(ctx, http.MethodPost, rb+"/pullrequests?api-version="+adoAPIVersion, jsonBody(map[string]any{
		"sourceRefName": "refs/heads/" + s.Branch, "targetRefName": "refs/heads/" + s.BaseBranch,
		"title": clipRunes(s.Title, 250), "description": clipRunes(s.Body, 4000),
	}), "application/json", &out); err != nil {
		return PullRequest{}, conflictErr(err)
	}
	return out.normalized(), nil
}

func (a *azureDevOps) GetPullRequest(ctx context.Context, ref RepoRef, id string) (PullRequest, error) {
	if err := checkPRID(id); err != nil {
		return PullRequest{}, err
	}
	rb, err := a.repoBase(ref)
	if err != nil {
		return PullRequest{}, err
	}
	var out adoPull
	if _, err := a.api.get(ctx, rb+"/pullrequests/"+id+"?api-version="+adoAPIVersion, &out); err != nil {
		return PullRequest{}, err
	}
	return out.normalized(), nil
}

var (
	_ PullRequestWriter = (*gitHub)(nil)
	_ PullRequestWriter = (*gitLab)(nil)
	_ PullRequestWriter = (*bitbucket)(nil)
	_ PullRequestWriter = (*azureDevOps)(nil)
)
