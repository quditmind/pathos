package scm

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
)

// Commit statuses: PATHOS reports the result of a pull request scan on
// the PR's head commit, where the provider shows it as a check and branch
// protection can require it.

// Status states (mapped to each provider's vocabulary).
const (
	CommitPending = "pending"
	CommitSuccess = "success"
	CommitFailure = "failure"
	CommitError   = "error"
)

// CommitStatus is one status on a commit.
type CommitStatus struct {
	State       string
	Context     string // stable name, e.g. "PATHOS / security"
	Description string // ≤ 140 characters
	TargetURL   string // link back to PATHOS (absolute http(s) URL or empty)
}

// StatusWriter sets commit statuses. Every provider client implements it;
// the credential needs the provider's status permission (GitHub
// "Commit statuses: write", GitLab api scope, Bitbucket repository:write,
// Azure DevOps Code (status)).
type StatusWriter interface {
	SetCommitStatus(ctx context.Context, ref RepoRef, commit string, st CommitStatus) error
}

func (st CommitStatus) valid(commit string) error {
	if !ValidCommit(commit) {
		return errors.New("scm: invalid commit")
	}
	switch st.State {
	case CommitPending, CommitSuccess, CommitFailure, CommitError:
	default:
		return errors.New("scm: invalid status state")
	}
	if st.Context == "" {
		return errors.New("scm: status context required")
	}
	if st.TargetURL != "" {
		if u, err := url.Parse(st.TargetURL); err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" {
			return errors.New("scm: invalid status URL")
		}
	}
	return nil
}

func clipDesc(s string) string {
	r := []rune(s)
	if len(r) > 140 {
		return string(r[:139]) + "…"
	}
	return s
}

func jsonBody(v any) []byte {
	b, _ := json.Marshal(v)
	return b
}

func (g *gitHub) SetCommitStatus(ctx context.Context, ref RepoRef, commit string, st CommitStatus) error {
	if err := st.valid(commit); err != nil {
		return err
	}
	p, err := g.repoPathFor(ctx, ref)
	if err != nil {
		return err
	}
	body := map[string]string{"state": st.State, "context": st.Context, "description": clipDesc(st.Description)}
	if st.TargetURL != "" {
		body["target_url"] = st.TargetURL
	}
	_, err = g.api.do(ctx, http.MethodPost, g.cfg.BaseURL+p+"/statuses/"+url.PathEscape(commit), jsonBody(body), "application/json", nil)
	return err
}

func (g *gitLab) SetCommitStatus(ctx context.Context, ref RepoRef, commit string, st CommitStatus) error {
	if err := st.valid(commit); err != nil {
		return err
	}
	p, err := glProjectPath(ref)
	if err != nil {
		return err
	}
	state := map[string]string{CommitPending: "running", CommitSuccess: "success", CommitFailure: "failed", CommitError: "failed"}[st.State]
	body := map[string]string{"state": state, "name": st.Context, "description": clipDesc(st.Description)}
	if st.TargetURL != "" {
		body["target_url"] = st.TargetURL
	}
	_, err = g.api.do(ctx, http.MethodPost, g.root+p+"/statuses/"+url.PathEscape(commit), jsonBody(body), "application/json", nil)
	return err
}

func (b *bitbucket) SetCommitStatus(ctx context.Context, ref RepoRef, commit string, st CommitStatus) error {
	if err := st.valid(commit); err != nil {
		return err
	}
	p, err := bbRepoPath(ref)
	if err != nil {
		return err
	}
	state := map[string]string{CommitPending: "INPROGRESS", CommitSuccess: "SUCCESSFUL", CommitFailure: "FAILED", CommitError: "FAILED"}[st.State]
	// Bitbucket requires a URL and a key of at most 40 characters.
	key := st.Context
	if len(key) > 40 {
		key = key[:40]
	}
	link := st.TargetURL
	if link == "" {
		link = "https://bitbucket.org/" + ref.FullName
	}
	body := map[string]string{"key": key, "state": state, "name": st.Context, "description": clipDesc(st.Description), "url": link}
	_, err = b.api.do(ctx, http.MethodPost, b.root+p+"/commit/"+url.PathEscape(commit)+"/statuses/build", jsonBody(body), "application/json", nil)
	return err
}

func (a *azureDevOps) SetCommitStatus(ctx context.Context, ref RepoRef, commit string, st CommitStatus) error {
	if err := st.valid(commit); err != nil {
		return err
	}
	rb, err := a.repoBase(ref)
	if err != nil {
		return err
	}
	state := map[string]string{CommitPending: "pending", CommitSuccess: "succeeded", CommitFailure: "failed", CommitError: "error"}[st.State]
	body := map[string]any{"state": state, "description": clipDesc(st.Description),
		"context": map[string]string{"name": st.Context, "genre": "security"}}
	if st.TargetURL != "" {
		body["targetUrl"] = st.TargetURL
	}
	_, err = a.api.do(ctx, http.MethodPost, rb+"/commits/"+url.PathEscape(commit)+"/statuses?api-version="+adoAPIVersion, jsonBody(body), "application/json", nil)
	return err
}

var (
	_ StatusWriter = (*gitHub)(nil)
	_ StatusWriter = (*gitLab)(nil)
	_ StatusWriter = (*bitbucket)(nil)
	_ StatusWriter = (*azureDevOps)(nil)
)
