package worker

import (
	"context"
	"encoding/base64"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"pathos/internal/depfix"
)

// Fix jobs: clone the repository's branch, update one dependency in its
// manifests with a text edit (internal/depfix) and report the edited files.
// No package manager, build tool, hook or other repository code runs; the
// clone uses the same hardening as scans. The API creates the branch and
// pull request; the worker never pushes.

// FixJob mirrors scans.LeasedFix.
type FixJob struct {
	FixID      string `json:"fix_id"`
	FullName   string `json:"full_name"`
	CloneURL   string `json:"clone_url"`
	Ref        string `json:"ref"`
	Credential *struct {
		Username string `json:"username"`
		Token    string `json:"token"`
		Scheme   string `json:"scheme"`
	} `json:"credential"`
	Public         bool   `json:"public"`
	Ecosystem      string `json:"ecosystem"`
	PackageName    string `json:"package_name"`
	CurrentVersion string `json:"current_version"`
	TargetVersion  string `json:"target_version"`
	ManifestHint   string `json:"manifest_hint"`
	TimeoutSeconds int    `json:"timeout_seconds"`
}

// fixResult mirrors scans.FixResult.
type fixResult struct {
	Status     string    `json:"status"`
	Error      string    `json:"error,omitempty"`
	BaseCommit string    `json:"base_commit,omitempty"`
	Files      []fixFile `json:"files,omitempty"`
	Notes      []string  `json:"notes,omitempty"`
}

type fixFile struct {
	Path          string `json:"path"`
	ContentBase64 string `json:"content_base64"`
}

var fixIDRe = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

// tryFix leases and runs one fix job; it reports whether one was found.
func (a *Agent) tryFix(ctx context.Context) bool {
	var job FixJob
	status, err := a.call(ctx, http.MethodPost, "/internal/worker/v1/fix-lease", a.token, map[string]any{}, &job)
	if err != nil || status != http.StatusOK || !fixIDRe.MatchString(job.FixID) {
		var ae *apiError
		if err != nil && !(errors.As(err, &ae) && ae.Status == http.StatusNotFound) {
			a.log.Debug("fix lease failed", "err", err)
		}
		return false
	}
	res := a.runFix(ctx, job)
	if _, err := a.call(ctx, http.MethodPost, "/internal/worker/v1/fix-jobs/"+job.FixID+"/result", a.token, res, nil); err != nil {
		a.log.Error("fix result upload failed", "fix_id", job.FixID, "err", err, "error_code", "PTH-WORK-1005")
	}
	return true
}

func (a *Agent) runFix(parent context.Context, job FixJob) fixResult {
	log := a.log.With("fix_id", job.FixID, "repository", job.FullName)
	timeout := time.Duration(job.TimeoutSeconds) * time.Second
	if timeout <= 0 {
		timeout = 5 * time.Minute
	}
	ctx, cancel := context.WithTimeout(parent, timeout)
	defer cancel()
	ws := filepath.Join(a.cfg.WorkDir, "fix-"+job.FixID)
	defer func() {
		if err := os.RemoveAll(ws); err != nil {
			log.Error("workspace cleanup failed", "err", err)
		}
	}()
	src := filepath.Join(ws, "src")
	cj := Job{JobID: job.FixID, FullName: job.FullName, CloneURL: job.CloneURL, Ref: job.Ref, Public: job.Public}
	token := ""
	if job.Credential != nil {
		token = job.Credential.Token
		cj.Credential = &JobCredential{Username: job.Credential.Username, Token: job.Credential.Token, Scheme: job.Credential.Scheme}
	}
	job.Credential = nil
	commit, err := clone(ctx, cj, src, filepath.Join(ws, "git"), a.cfg.MaxRepoBytes)
	if err != nil && cj.Public && cj.Credential != nil && ctx.Err() == nil {
		cj.Credential = nil
		_ = os.RemoveAll(src)
		commit, err = clone(ctx, cj, src, filepath.Join(ws, "git"), a.cfg.MaxRepoBytes)
	}
	cj.Credential = nil
	if err != nil {
		log.Warn("fix clone failed", "err", err)
		return fixResult{Status: "failed", Error: "clone failed: " + clipStr(redactToken(err.Error(), token), 900)}
	}
	return applyFix(src, commit, job)
}

// applyFix runs the text edit on a checkout and builds the result.
func applyFix(src, commit string, job FixJob) fixResult {
	r, err := depfix.Apply(src, depfix.Request{Ecosystem: job.Ecosystem, Package: job.PackageName, Current: job.CurrentVersion,
		Target: job.TargetVersion, ManifestHint: job.ManifestHint})
	switch {
	case depfix.IsNotSupported(err):
		return fixResult{Status: "not_supported", Error: clipStr(err.Error(), 900)}
	case err != nil:
		return fixResult{Status: "failed", Error: clipStr(err.Error(), 900)}
	}
	out := fixResult{Status: "ok", BaseCommit: commit, Notes: r.Notes}
	for _, c := range r.Changes {
		out.Files = append(out.Files, fixFile{Path: c.Path, ContentBase64: base64.StdEncoding.EncodeToString(c.Content)})
	}
	return out
}

func clipStr(s string, n int) string {
	if len(s) > n {
		return s[:n]
	}
	return s
}

// redactToken removes the clone credential from a message; lines that
// may carry an authorization header are withheld entirely.
func redactToken(msg, token string) string {
	lower := strings.ToLower(msg)
	for _, m := range sensitiveMarkers {
		if strings.Contains(lower, m) {
			return "[message withheld]"
		}
	}
	if token != "" {
		msg = strings.ReplaceAll(msg, token, "[REDACTED]")
	}
	return credRe.ReplaceAllString(msg, "$1$2[REDACTED]")
}
