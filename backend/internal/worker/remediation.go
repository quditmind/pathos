package worker

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"pathos/internal/aifix"
)

// Fix verification jobs (remediation workspace, PATHOS 3.0 M8): a targeted
// rescan of the files a remediation item affects, with the scanners that
// reported its findings. The worker clones the repository twice — at the
// commit where the findings were last reported (before) and at the head of
// the scan branch (after) — and runs each scanner on the affected files
// only, in fresh directories, with the same scanFiles step as AI fix
// verification. It reports the results in those files; the API compares
// them and decides. The worker never changes anything in the repository.

// RemediationJob mirrors remediation.LeasedVerification.
type RemediationJob struct {
	VerificationID string         `json:"verification_id"`
	FullName       string         `json:"full_name"`
	CloneURL       string         `json:"clone_url"`
	Ref            string         `json:"ref"`
	BeforeCommit   string         `json:"before_commit"`
	Credential     *JobCredential `json:"credential"`
	Public         bool           `json:"public"`
	// Scanners: key → configuration from the scan profile.
	Scanners       map[string]json.RawMessage `json:"scanners"`
	Files          []string                   `json:"files"`
	TimeoutSeconds int                        `json:"timeout_seconds"`
}

type remediationResults struct {
	Before []aifix.Result `json:"before"`
	After  []aifix.Result `json:"after"`
}

// remediationReport mirrors remediation.VerificationResult.
type remediationReport struct {
	Status        string                        `json:"status"`
	FailureReason string                        `json:"failure_reason,omitempty"`
	BeforeCommit  string                        `json:"before_commit,omitempty"`
	AfterCommit   string                        `json:"after_commit,omitempty"`
	Versions      map[string]string             `json:"scanner_versions"`
	Results       map[string]remediationResults `json:"results"`
}

// tryRemediation leases and runs one fix verification; it reports whether
// one was found.
func (a *Agent) tryRemediation(ctx context.Context) bool {
	var job RemediationJob
	status, err := a.call(ctx, http.MethodPost, "/internal/worker/v1/remediation-lease", a.token, map[string]any{}, &job)
	if err != nil || status != http.StatusOK || !fixIDRe.MatchString(job.VerificationID) {
		var ae *apiError
		if err != nil && !(errors.As(err, &ae) && ae.Status == http.StatusNotFound) {
			a.log.Debug("fix verification lease failed", "err", err)
		}
		return false
	}
	res := a.runRemediation(ctx, job)
	if _, err := a.call(ctx, http.MethodPost, "/internal/worker/v1/remediation-jobs/"+job.VerificationID+"/result", a.token, res, nil); err != nil {
		a.log.Error("fix verification result upload failed", "verification_id", job.VerificationID, "err", err, "error_code", "PTH-WORK-1005")
	}
	return true
}

func (a *Agent) runRemediation(parent context.Context, job RemediationJob) remediationReport {
	log := a.log.With("verification_id", job.VerificationID, "repository", job.FullName)
	rep := remediationReport{Status: "failed", Versions: map[string]string{}, Results: map[string]remediationResults{}}
	timeout := time.Duration(job.TimeoutSeconds) * time.Second
	if timeout <= 0 {
		timeout = 15 * time.Minute
	}
	ctx, cancel := context.WithTimeout(parent, timeout)
	defer cancel()
	ws := filepath.Join(a.cfg.WorkDir, "remediation-"+job.VerificationID)
	defer func() {
		if err := os.RemoveAll(ws); err != nil {
			log.Error("workspace cleanup failed", "err", err)
		}
	}()
	token := ""
	if job.Credential != nil {
		token = job.Credential.Token
	}
	// checkout clones the repository at commit ("" = head of the ref) and
	// reads the affected files that exist there.
	checkout := func(name, commit string) (string, map[string][]byte, error) {
		cj := Job{JobID: job.VerificationID, FullName: job.FullName, CloneURL: job.CloneURL, Ref: job.Ref, CommitSHA: commit, Public: job.Public,
			Credential: job.Credential}
		src, gitDir := filepath.Join(ws, name, "src"), filepath.Join(ws, name, "git")
		got, err := clone(ctx, cj, src, gitDir, a.cfg.MaxRepoBytes)
		if err != nil && cj.Public && cj.Credential != nil && ctx.Err() == nil {
			cj.Credential = nil
			_ = os.RemoveAll(filepath.Join(ws, name))
			got, err = clone(ctx, cj, src, gitDir, a.cfg.MaxRepoBytes)
		}
		if err != nil {
			return "", nil, errors.New("clone failed: " + clipStr(redactToken(err.Error(), token), 900))
		}
		files := map[string][]byte{}
		root := filepath.Clean(src) + string(filepath.Separator)
		for _, p := range job.Files {
			full := filepath.Join(src, filepath.FromSlash(p))
			if !strings.HasPrefix(full, root) {
				return "", nil, errors.New("invalid file path " + p)
			}
			info, err := os.Lstat(full)
			if err != nil || !info.Mode().IsRegular() {
				continue // removed, renamed or not a regular file: nothing to report there
			}
			// #nosec G304 -- path is confined to the checkout above
			b, err := os.ReadFile(full)
			if err != nil {
				return "", nil, err
			}
			files[p] = b
		}
		return got, files, nil
	}
	before, beforeFiles, err := checkout("b", job.BeforeCommit)
	if err != nil {
		rep.FailureReason = "before: " + err.Error()
		return rep
	}
	after, afterFiles, err := checkout("a", "")
	job.Credential = nil
	if err != nil {
		rep.FailureReason = "after: " + err.Error()
		return rep
	}
	rep.BeforeCommit, rep.AfterCommit = before, after
	for key, cfg := range job.Scanners {
		tool, ok := a.tools[key]
		if !ok {
			rep.FailureReason = "scanner " + key + " is not available in this worker image"
			return rep
		}
		version, _ := tool.Version(ctx)
		rep.Versions[key] = version
		fj := AIFixJob{ScannerKey: key, ScannerConfig: cfg}
		var rs remediationResults
		run := func(dir string, files map[string][]byte) ([]aifix.Result, error) {
			if len(files) == 0 {
				return []aifix.Result{}, nil
			}
			out, _, err := a.scanFiles(ctx, tool, fj, filepath.Join(ws, dir), files)
			return out, err
		}
		if rs.Before, err = run("scan-b-"+key, beforeFiles); err == nil {
			rs.After, err = run("scan-a-"+key, afterFiles)
		}
		if err != nil {
			rep.FailureReason = key + " could not scan the files: " + clipStr(err.Error(), 900)
			return rep
		}
		rep.Results[key] = rs
	}
	rep.Status = "completed"
	log.Info("fix verification finished", "before", before, "after", after)
	return rep
}
