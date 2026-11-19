package worker

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"pathos/internal/aifix"
	"pathos/internal/platform/logging"
	"pathos/internal/scanners"
)

// AI fix verification jobs. The API leases two phases:
//
//   - verify (any worker that has the finding's scanner): clone the
//     scanned commit, apply the AI's diff (internal/aifix: strict context
//     match, no links, confined to the allowed files), run the scanner on
//     the changed files before and after the change and compare;
//   - test (worker-fuzz only, when an administrator enabled a test runner
//     for the repository): run the repository's tests with and without the
//     change through the sandbox helper (pathos-fixtest: no network, CPU,
//     memory, file size and time limits).
//
// The worker reports evidence; the API records the verdict. The worker
// never pushes: a pull request is opened later by the API, when a person
// asks for it.

// AIFixJob mirrors scans.LeasedAIFix.
type AIFixJob struct {
	FixID      string `json:"fix_id"`
	Phase      string `json:"phase"`
	FullName   string `json:"full_name"`
	CloneURL   string `json:"clone_url"`
	Ref        string `json:"ref"`
	CommitSHA  string `json:"commit_sha"`
	Credential *struct {
		Username string `json:"username"`
		Token    string `json:"token"`
		Scheme   string `json:"scheme"`
	} `json:"credential"`
	Public         bool            `json:"public"`
	ScannerKey     string          `json:"scanner_key"`
	ScannerConfig  json.RawMessage `json:"scanner_config"`
	RuleID         string          `json:"rule_id"`
	FilePath       string          `json:"file_path"`
	StartLine      int             `json:"start_line"`
	Diff           string          `json:"diff"`
	TestRunner     string          `json:"test_runner"`
	TimeoutSeconds int             `json:"timeout_seconds"`
}

// aiFixStep mirrors scans.AIFixStep.
type aiFixStep struct {
	Key    string `json:"key"`
	Status string `json:"status"`
	Detail string `json:"detail"`
}

// aiFixReport mirrors scans.AIFixResult.
type aiFixReport struct {
	Phase            string        `json:"phase"`
	Status           string        `json:"status"`
	FailureReason    string        `json:"failure_reason,omitempty"`
	BaseCommit       string        `json:"base_commit,omitempty"`
	Steps            []aiFixStep   `json:"steps"`
	ScanEvidence     *scanEvidence `json:"scan_evidence,omitempty"`
	BeforeReportGzip string        `json:"before_report_gzip,omitempty"`
	AfterReportGzip  string        `json:"after_report_gzip,omitempty"`
	Files            []fixFile     `json:"files,omitempty"`
	TestLog          string        `json:"test_log,omitempty"`
}

// scanEvidence is what the scan step compared.
type scanEvidence struct {
	Scanner        string        `json:"scanner"`
	ScannerVersion string        `json:"scanner_version"`
	Files          []string      `json:"files"`
	Verdict        aifix.Verdict `json:"verdict"`
}

// fixTestCommand is the test helper of the worker-fuzz image; it runs in
// the sandbox runner (same image). fixTestTimeout bounds one test run.
var (
	fixTestCommand = "/opt/pathos/fuzz/bin/pathos-fixtest"
	fixTestTimeout = 10 * time.Minute
)

// tryAIFix leases and runs one AI fix job; it reports whether one was found.
func (a *Agent) tryAIFix(ctx context.Context) bool {
	var job AIFixJob
	status, err := a.call(ctx, http.MethodPost, "/internal/worker/v1/ai-fix-lease", a.token, map[string]any{}, &job)
	if err != nil || status != http.StatusOK || !fixIDRe.MatchString(job.FixID) {
		var ae *apiError
		if err != nil && !(errors.As(err, &ae) && ae.Status == http.StatusNotFound) {
			a.log.Debug("AI fix lease failed", "err", err)
		}
		return false
	}
	res := a.runAIFix(ctx, job)
	if _, err := a.call(ctx, http.MethodPost, "/internal/worker/v1/ai-fix-jobs/"+job.FixID+"/result", a.token, res, nil); err != nil {
		a.log.Error("AI fix result upload failed", "ai_fix_id", job.FixID, "err", err, "error_code", "PTH-WORK-1005")
	}
	return true
}

func (a *Agent) runAIFix(parent context.Context, job AIFixJob) aiFixReport {
	log := a.log.With("ai_fix_id", job.FixID, "repository", job.FullName, "phase", job.Phase)
	timeout := time.Duration(job.TimeoutSeconds) * time.Second
	if timeout <= 0 {
		timeout = 15 * time.Minute
	}
	ctx, cancel := context.WithTimeout(parent, timeout)
	defer cancel()
	ws := filepath.Join(a.cfg.WorkDir, "aifix-"+job.FixID)
	defer func() {
		for _, d := range []string{ws, ws + "-b", ws + "-a"} {
			if err := os.RemoveAll(d); err != nil {
				log.Error("workspace cleanup failed", "err", err)
			}
		}
	}()
	rep := aiFixReport{Phase: job.Phase, Status: "failed"}
	failStep := func(key, msg string) aiFixReport {
		rep.Steps = append(rep.Steps, aiFixStep{Key: key, Status: "failed", Detail: msg})
		rep.FailureReason = msg
		return rep
	}
	firstStep := map[string]string{"verify": "apply", "test": "tests"}[job.Phase]
	if firstStep == "" {
		rep.FailureReason = "unknown phase"
		return rep
	}
	src := filepath.Join(ws, "src")
	cj := Job{JobID: job.FixID, FullName: job.FullName, CloneURL: job.CloneURL, Ref: job.Ref, CommitSHA: job.CommitSHA, Public: job.Public}
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
		log.Warn("AI fix clone failed", "err", err)
		return failStep(firstStep, "clone failed: "+clipStr(redactToken(err.Error(), token), 900))
	}
	if job.Phase == "test" && !strings.HasPrefix(commit, job.CommitSHA) {
		return failStep("tests", "the commit the fix was verified on ("+job.CommitSHA+") is no longer available")
	}
	rep.BaseCommit = commit
	switch job.Phase {
	case "verify":
		return a.verifyAIFix(ctx, job, src, ws, rep)
	default:
		return a.testAIFix(ctx, job, src, ws, rep)
	}
}

// applyAIFix re-checks and applies the diff to the checkout (in memory).
func applyAIFix(job AIFixJob, src string) ([]aifix.Applied, error) {
	d, err := aifix.Parse(job.Diff)
	if err != nil {
		return nil, err
	}
	if err := (aifix.Policy{FindingFile: job.FilePath}).Check(d); err != nil {
		return nil, err
	}
	return aifix.Apply(src, d)
}

// writeTree writes files under root (a fresh directory).
func writeTree(root string, files map[string][]byte) error {
	for p, b := range files {
		full := filepath.Join(root, filepath.FromSlash(p))
		if !strings.HasPrefix(full, filepath.Clean(root)+string(filepath.Separator)) {
			return fmt.Errorf("invalid path %q", p)
		}
		if err := os.MkdirAll(filepath.Dir(full), 0o700); err != nil {
			return err
		}
		if err := os.WriteFile(full, b, 0o600); err != nil {
			return err
		}
	}
	return nil
}

func (a *Agent) verifyAIFix(ctx context.Context, job AIFixJob, src, ws string, rep aiFixReport) aiFixReport {
	applied, err := applyAIFix(job, src)
	if err != nil {
		rep.Steps = append(rep.Steps, aiFixStep{Key: "apply", Status: "failed", Detail: "the diff could not be applied: " + err.Error()},
			aiFixStep{Key: "scan", Status: "skipped", Detail: "the diff was not applied"})
		rep.FailureReason = "the diff could not be applied: " + err.Error()
		return rep
	}
	paths := make([]string, len(applied))
	before, after := map[string][]byte{}, map[string][]byte{}
	var target *aifix.Applied
	for i, f := range applied {
		paths[i] = f.Path
		before[f.Path], after[f.Path] = f.Original, f.Patched
		rep.Files = append(rep.Files, fixFile{Path: f.Path, ContentBase64: base64.StdEncoding.EncodeToString(f.Patched)})
		if f.Path == job.FilePath {
			target = &applied[i]
		}
	}
	hunks := 0
	for _, f := range applied {
		hunks += len(f.Spans)
	}
	rep.Steps = append(rep.Steps, aiFixStep{Key: "apply", Status: "passed",
		Detail: fmt.Sprintf("%d hunk(s) applied to %s at commit %s", hunks, strings.Join(paths, ", "), rep.BaseCommit)})

	tool, ok := a.tools[job.ScannerKey]
	if !ok {
		rep.Steps = append(rep.Steps, aiFixStep{Key: "scan", Status: "failed", Detail: "scanner " + job.ScannerKey + " is not available in this worker image"})
		rep.FailureReason = "scanner " + job.ScannerKey + " is not available in this worker image"
		return rep
	}
	version, _ := tool.Version(ctx)
	// The scanner runs on the changed files only (restricted to them), in
	// two fresh directories: the original files and the fixed files.
	rb, rawBefore, err := a.scanFiles(ctx, tool, job, ws+"-b", before)
	if err == nil {
		var ra []aifix.Result
		ra, rawAfter, aerr := a.scanFiles(ctx, tool, job, ws+"-a", after)
		err = aerr
		if err == nil {
			v := aifix.Compare(rb, ra, aifix.Target{RuleID: truncateRule(job.RuleID), File: job.FilePath, Line: job.StartLine}, target)
			rep.ScanEvidence = &scanEvidence{Scanner: job.ScannerKey, ScannerVersion: version, Files: paths, Verdict: v}
			rep.BeforeReportGzip, rep.AfterReportGzip = gzipB64(rawBefore), gzipB64(rawAfter)
			if v.Verified() {
				rep.Steps = append(rep.Steps, aiFixStep{Key: "scan", Status: "passed", Detail: fmt.Sprintf(
					"%s %s reported rule %s %d time(s) in %s before the fix and not after; no new results in the changed files",
					job.ScannerKey, version, job.RuleID, countRule(rb, job), job.FilePath)})
				rep.Status = "passed"
				return rep
			}
			rep.Steps = append(rep.Steps, aiFixStep{Key: "scan", Status: "failed", Detail: v.Reason})
			rep.FailureReason = v.Reason
			return rep
		}
	}
	msg := job.ScannerKey + " could not scan the files: " + err.Error()
	rep.Steps = append(rep.Steps, aiFixStep{Key: "scan", Status: "failed", Detail: msg})
	rep.FailureReason = msg
	return rep
}

func truncateRule(r string) string {
	if len(r) > 300 {
		return r[:300]
	}
	return r
}

func countRule(rs []aifix.Result, job AIFixJob) int {
	n := 0
	for _, r := range rs {
		if r.RuleID == truncateRule(job.RuleID) && r.File == job.FilePath {
			n++
		}
	}
	return n
}

// scanFiles runs tool on a directory holding only files and returns its
// results in those files (paths relative to the directory) and its raw
// report.
func (a *Agent) scanFiles(ctx context.Context, tool Tool, job AIFixJob, dir string, files map[string][]byte) ([]aifix.Result, []byte, error) {
	root := filepath.Join(dir, "src")
	if err := writeTree(root, files); err != nil {
		return nil, nil, err
	}
	out := filepath.Join(dir, "report.out")
	skipped, err := tool.Run(ctx, RunInput{Src: root, Out: out, Config: job.ScannerConfig})
	switch {
	case skipped != "":
		return nil, nil, errors.New("skipped: " + skipped)
	case err != nil:
		return nil, nil, err
	}
	// #nosec G304 -- report path is created by the worker in its job directory
	raw, err := os.ReadFile(out)
	if err != nil {
		return nil, nil, err
	}
	var fs []scanners.Finding
	if p, ok := a.manifestParser(job.ScannerKey); ok {
		fs, err = scanners.ParseToolOutput(job.ScannerKey, p, raw)
	} else {
		fs, err = scanners.Parse(job.ScannerKey, raw)
	}
	if err != nil && len(fs) == 0 && len(strings.TrimSpace(string(raw))) > 0 {
		return nil, raw, fmt.Errorf("parsing the report: %w", err)
	}
	prefix := filepath.ToSlash(root) + "/"
	results := []aifix.Result{}
	for _, f := range fs {
		p := filepath.ToSlash(f.FilePath)
		p = strings.TrimPrefix(p, prefix)
		p = strings.TrimPrefix(p, strings.TrimPrefix(prefix, "/"))
		p = scanners.NormalizePath(p)
		if _, ok := files[p]; !ok {
			continue // results outside the changed files are not compared
		}
		line := 0
		if f.StartLine != nil {
			line = *f.StartLine
		}
		results = append(results, aifix.Result{RuleID: truncateRule(f.RuleID), File: p, Line: line, Title: clipStr(logging.RedactString(f.Title), 300)})
	}
	return results, raw, nil
}

// testAIFix runs the repository's tests without and with the fix. The
// tests are repository code: they run only in the sandbox runner
// (Sandbox.RunUntrusted: no network, another UID, no worker token, its own
// limits), through the pathos-fixtest helper of the fuzz image. Without a
// runner the step is skipped and the code is not run anywhere.
func (a *Agent) testAIFix(ctx context.Context, job AIFixJob, src, ws string, rep aiFixReport) aiFixReport {
	fail := func(msg string) aiFixReport {
		rep.Steps = append(rep.Steps, aiFixStep{Key: "tests", Status: "failed", Detail: msg})
		rep.FailureReason = msg
		return rep
	}
	skip := func(msg string) aiFixReport {
		rep.Steps = append(rep.Steps, aiFixStep{Key: "tests", Status: "skipped", Detail: msg})
		rep.Status = "passed" // the scanner verification stands; the step says the tests did not run
		return rep
	}
	if job.TestRunner != "go" && job.TestRunner != "python" {
		return skip("tests not run: toolchain not available in the sandbox")
	}
	if a.sandbox == nil {
		return skip("tests not run: no sandbox")
	}
	applied, err := applyAIFix(job, src)
	if err != nil {
		return fail("the diff could not be applied: " + err.Error())
	}
	if err := os.MkdirAll(ws, 0o700); err != nil {
		return fail(err.Error())
	}
	var log strings.Builder
	run := func(label, name string) (UntrustedResult, error) {
		logFile := filepath.Join(ws, "test-"+name+".log")
		timeout := fixTestTimeout
		if dl, ok := ctx.Deadline(); ok && time.Until(dl) < timeout {
			timeout = time.Until(dl)
		}
		res, err := a.sandbox.RunUntrusted(ctx, UntrustedJob{Source: src, Command: fixTestCommand,
			Args: []string{job.TestRunner, "{source}", "{output}", "{tmp}"}, Timeout: timeout, Output: logFile, MaxOutputBytes: 1 << 20})
		if err != nil {
			return res, err
		}
		// #nosec G304 -- log path is created by the worker in its job directory
		out, _ := os.ReadFile(logFile)
		if len(out) == 0 {
			out = res.Log
		}
		fmt.Fprintf(&log, "=== tests %s (exit %d, %s) ===\n%s\n", label, res.ExitCode, res.Duration.Round(time.Millisecond), clipStr(string(out), 120<<10))
		return res, nil
	}
	verdict := func(res UntrustedResult) string {
		switch {
		case res.TimedOut:
			return "timeout"
		case res.Canceled:
			return "canceled"
		case res.ExitCode == 0:
			return "pass"
		case res.ExitCode == 1:
			return "fail"
		case res.ExitCode == 2:
			return "n/a"
		}
		return "error"
	}
	res, err := run("without the fix", "before")
	if errors.Is(err, ErrNoSandbox) {
		return skip("tests not run: no sandbox")
	}
	if err != nil {
		rep.TestLog = log.String()
		return fail("the test sandbox did not complete the run: " + err.Error())
	}
	switch verdict(res) {
	case "pass":
	case "n/a":
		rep.TestLog = log.String()
		return fail("the " + job.TestRunner + " test runner does not apply to this repository: " + lastTestLine(log.String()))
	case "fail":
		rep.TestLog = log.String()
		return fail("the tests already fail without the fix, so they cannot verify it")
	case "timeout":
		rep.TestLog = log.String()
		return fail("the tests did not finish within the time limit without the fix")
	default:
		rep.TestLog = log.String()
		return fail(fmt.Sprintf("the test sandbox failed (exit %d %s)", res.ExitCode, res.Signal))
	}
	patched := map[string][]byte{}
	for _, f := range applied {
		patched[f.Path] = f.Patched
	}
	if err := writeTree(src, patched); err != nil {
		return fail("writing the fixed files: " + err.Error())
	}
	res, err = run("with the fix", "after")
	rep.TestLog = log.String()
	if err != nil {
		return fail("the test sandbox did not complete the run: " + err.Error())
	}
	switch verdict(res) {
	case "pass":
		rep.Steps = append(rep.Steps, aiFixStep{Key: "tests", Status: "passed", Detail: "the " + job.TestRunner + " tests pass without and with the fix (sandboxed)"})
		rep.Status = "passed"
		return rep
	case "timeout":
		return fail("the tests pass without the fix and do not finish within the time limit with it")
	case "fail", "n/a":
		return fail(fmt.Sprintf("the tests pass without the fix and fail with it (exit %d)", res.ExitCode))
	}
	return fail(fmt.Sprintf("the test sandbox failed with the fix (exit %d %s)", res.ExitCode, res.Signal))
}

func lastTestLine(s string) string {
	lines := strings.Split(strings.TrimSpace(s), "\n")
	for i := len(lines) - 1; i >= 0; i-- {
		if l := strings.TrimSpace(lines[i]); l != "" && !strings.HasPrefix(l, "===") {
			return clipStr(l, 300)
		}
	}
	return ""
}
