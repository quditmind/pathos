package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"text/tabwriter"
	"time"
)

// maxUpload is the server's report limit.
const maxUpload = 64 << 20

// scanJob is the part of a scan execution the CLI uses.
type scanJob struct {
	ID             string `json:"id"`
	ScanKey        string `json:"scan_key"`
	RepositoryName string `json:"repository_name"`
	Status         string `json:"status"`
	Stage          string `json:"stage"`
	Progress       int    `json:"progress"`
	Error          string `json:"error"`
	FindingsNew    int    `json:"findings_new"`
	FindingsFixed  int    `json:"findings_fixed"`
	FindingsTotal  int    `json:"findings_total"`
	GateFailed     bool   `json:"gate_failed"`
}

func (j scanJob) finished() bool {
	return j.Status != "queued" && j.Status != "running" && j.Status != ""
}

// printJSON writes v as indented JSON on stdout.
func (a *app) printJSON(v any) error {
	enc := json.NewEncoder(a.stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(v)
}

// --- import -------------------------------------------------------------------

var (
	commitRe = regexp.MustCompile(`^[0-9a-fA-F]{7,64}$`)
	branchRe = regexp.MustCompile(`^[A-Za-z0-9._/@+-]{1,200}$`)
)

// ciCommit and ciBranch read the commit and branch of common CI systems.
func (a *app) ciCommit() string {
	for _, k := range []string{"GITHUB_SHA", "CI_COMMIT_SHA", "BUILD_SOURCEVERSION", "BITBUCKET_COMMIT", "GIT_COMMIT"} {
		if v := strings.TrimSpace(a.getenv(k)); commitRe.MatchString(v) {
			return v
		}
	}
	return ""
}

func (a *app) ciBranch() string {
	for _, k := range []string{"GITHUB_HEAD_REF", "GITHUB_REF_NAME", "CI_COMMIT_REF_NAME", "BUILD_SOURCEBRANCHNAME", "BITBUCKET_BRANCH", "GIT_BRANCH"} {
		v := strings.TrimSpace(a.getenv(k))
		v = strings.TrimPrefix(strings.TrimPrefix(v, "refs/heads/"), "origin/")
		if branchRe.MatchString(v) && !strings.Contains(v, "..") {
			return v
		}
	}
	return ""
}

func (a *app) cmdImport(args []string) error {
	fs := a.commandFlags("import", "pathos import --repo <repository> --file <path> [--format ID] [--tool NAME] [--category CAT] [--commit SHA] [--branch NAME] [--complete] [--sbom] [--no-wait]")
	repoRef := fs.String("repo", "", "repository: UUID, Repository ID (QD-REPO-000042) or full name (owner/name)")
	file := fs.String("file", "", "results file or SBOM (gzip accepted, at most 64 MiB)")
	format := fs.String("format", "", "result format (detected when omitted), e.g. sarif, semgrep, trivy, gitleaks")
	tool := fs.String("tool", "", "tool that produced the results (default: the format's name)")
	category := fs.String("category", "", "sast, sca, secrets, iac, container, license, dast or other (default: the format's)")
	commit := fs.String("commit", "", "commit SHA the tool analysed (default: from the CI environment)")
	branch := fs.String("branch", "", "branch the tool analysed (default: from the CI environment)")
	complete := fs.Bool("complete", false, "the file is the tool's complete result: findings it no longer reports are marked fixed")
	sbom := fs.Bool("sbom", false, "the file is a CycloneDX or SPDX JSON SBOM")
	noWait := fs.Bool("no-wait", false, "do not wait for the import's scan execution to finish")
	waitTimeout := fs.Duration("wait-timeout", 10*time.Minute, "how long to wait for the execution")
	if err := parse(fs, args); err != nil {
		return err
	}
	if *file == "" {
		return usagef("--file is required")
	}
	if *commit != "" && !commitRe.MatchString(*commit) {
		return usagef("--commit must be a commit SHA")
	}
	c, err := a.newClient()
	if err != nil {
		return err
	}
	ctx := context.Background()
	repoID, err := c.resolveRepo(ctx, *repoRef)
	if err != nil {
		return err
	}
	f, err := os.Open(*file)
	if err != nil {
		return fmt.Errorf("cannot open the file: %w", err)
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return err
	}
	if st.Size() > maxUpload {
		return errors.New("the file is larger than 64 MiB")
	}
	var body bytes.Buffer
	mw := multipart.NewWriter(&body)
	fields := map[string]string{"repository_id": repoID}
	set := func(k, v string) {
		if v = strings.TrimSpace(v); v != "" {
			fields[k] = v
		}
	}
	set("tool", *tool)
	path := "/api/v1/imports/sbom"
	if !*sbom {
		path = "/api/v1/imports/results"
		set("format", *format)
		set("category", *category)
		if *commit == "" {
			*commit = a.ciCommit()
		}
		if *branch == "" {
			*branch = a.ciBranch()
		}
		set("commit_sha", *commit)
		set("branch", *branch)
		if *complete {
			fields["resolve_missing"] = "true"
		}
	}
	for _, k := range []string{"repository_id", "tool", "format", "category", "commit_sha", "branch", "resolve_missing"} {
		if v, ok := fields[k]; ok {
			if err := mw.WriteField(k, v); err != nil {
				return err
			}
		}
	}
	fw, err := mw.CreateFormFile("file", filepath.Base(*file))
	if err != nil {
		return err
	}
	if _, err := io.Copy(fw, io.LimitReader(f, maxUpload+1)); err != nil {
		return fmt.Errorf("cannot read the file: %w", err)
	}
	if err := mw.Close(); err != nil {
		return err
	}
	a.progress("uploading %s (%d bytes)", filepath.Base(*file), st.Size())
	data, _, err := c.do(ctx, http.MethodPost, path, nil, &body, mw.FormDataContentType(), maxJSONResponse)
	if err != nil {
		var ae *apiError
		if errors.As(err, &ae) && ae.Status == http.StatusUnprocessableEntity {
			return fmt.Errorf("the server rejected the file: %s", ae.Message)
		}
		return err
	}
	var rec struct {
		ID        string  `json:"id"`
		Status    string  `json:"status"`
		Records   int     `json:"records"`
		Format    string  `json:"format"`
		ScanJobID *string `json:"scan_job_id"`
		ScanKey   *string `json:"scan_key"`
		Error     string  `json:"error"`
	}
	if err := decode(data, &rec); err != nil {
		return err
	}
	var job *scanJob
	if rec.ScanJobID != nil && !*noWait {
		j, err := a.waitScan(ctx, c, *rec.ScanJobID, *waitTimeout)
		if err != nil {
			return err
		}
		job = &j
	}
	if a.cfg.JSON {
		out := map[string]any{"import": json.RawMessage(data)}
		if job != nil {
			out["scan"] = job
		}
		if err := a.printJSON(out); err != nil {
			return err
		}
	} else {
		what := "findings"
		if *sbom {
			what = "components"
		}
		fmt.Fprintf(a.stdout, "Imported %d %s (format %s)", rec.Records, what, rec.Format)
		if rec.ScanKey != nil {
			fmt.Fprintf(a.stdout, " as %s", *rec.ScanKey)
		}
		fmt.Fprintln(a.stdout)
		if job != nil {
			fmt.Fprintf(a.stdout, "Execution %s: %s, %d new, %d fixed, security gate %s\n", job.ScanKey, job.Status, job.FindingsNew, job.FindingsFixed, gateWord(job.GateFailed))
		}
	}
	if job != nil && job.Status == "failed" {
		return exitErr{exitScanFailed, "the import's execution failed: " + job.Error}
	}
	return nil
}

func gateWord(failed bool) string {
	if failed {
		return "failed"
	}
	return "passed"
}

// --- scan ---------------------------------------------------------------------

func (a *app) cmdScan(args []string) error {
	fs := a.commandFlags("scan", "pathos scan --repo <repository> [--profile UUID] [--name NAME] [--no-wait] [--wait-timeout 30m]")
	repoRef := fs.String("repo", "", "repository: UUID, Repository ID or full name")
	profile := fs.String("profile", "", "scan profile UUID (default: the repository's profile)")
	name := fs.String("name", "", "execution name")
	noWait := fs.Bool("no-wait", false, "print the execution and return without following it")
	waitTimeout := fs.Duration("wait-timeout", 30*time.Minute, "how long to follow the scan")
	if err := parse(fs, args); err != nil {
		return err
	}
	if *profile != "" && !uuidRe.MatchString(*profile) {
		return usagef("--profile must be a scan profile UUID")
	}
	c, err := a.newClient()
	if err != nil {
		return err
	}
	ctx := context.Background()
	repoID, err := c.resolveRepo(ctx, *repoRef)
	if err != nil {
		return err
	}
	req := map[string]any{"repository_ids": []string{repoID}}
	if *profile != "" {
		req["profile_id"] = *profile
	}
	if *name != "" {
		req["name"] = *name
	}
	var resp struct {
		Items []struct {
			JobID     string `json:"job_id"`
			Coalesced bool   `json:"coalesced"`
			Error     string `json:"error"`
		} `json:"items"`
	}
	if err := c.postJSON(ctx, "/api/v1/scans", req, &resp); err != nil {
		return err
	}
	if len(resp.Items) == 0 || resp.Items[0].JobID == "" {
		msg := "the scan was not started"
		if len(resp.Items) > 0 && resp.Items[0].Error != "" {
			msg += ": " + resp.Items[0].Error
		}
		return errors.New(msg)
	}
	id := resp.Items[0].JobID
	if resp.Items[0].Coalesced {
		a.progress("an execution of this repository and profile was already queued; following it")
	}
	var job scanJob
	if *noWait {
		if err := c.getJSON(ctx, "/api/v1/scans/"+url.PathEscape(id), nil, &job); err != nil {
			return err
		}
	} else if job, err = a.waitScan(ctx, c, id, *waitTimeout); err != nil {
		return err
	}
	if a.cfg.JSON {
		if err := a.printJSON(job); err != nil {
			return err
		}
	} else {
		fmt.Fprintf(a.stdout, "%s %s: %s", job.ScanKey, job.ID, job.Status)
		if job.finished() {
			fmt.Fprintf(a.stdout, ", %d new, %d fixed, %d total, security gate %s", job.FindingsNew, job.FindingsFixed, job.FindingsTotal, gateWord(job.GateFailed))
		}
		fmt.Fprintln(a.stdout)
	}
	switch job.Status {
	case "failed", "cancelled":
		msg := "the scan " + job.Status
		if job.Error != "" {
			msg += ": " + job.Error
		}
		return exitErr{exitScanFailed, msg}
	}
	return nil
}

// waitScan polls an execution until it has finished.
func (a *app) waitScan(ctx context.Context, c *client, id string, timeout time.Duration) (scanJob, error) {
	deadline := time.Now().Add(timeout)
	last := ""
	for {
		var j scanJob
		if err := c.getJSON(ctx, "/api/v1/scans/"+url.PathEscape(id), nil, &j); err != nil {
			return j, err
		}
		if s := fmt.Sprintf("%s %s %d%%", j.Status, j.Stage, j.Progress); s != last {
			a.progress("%s: %s (%s, %d%%)", firstNonEmpty(j.ScanKey, id), j.Status, j.Stage, j.Progress)
			last = s
		}
		if j.finished() {
			return j, nil
		}
		if time.Now().After(deadline) {
			return j, exitErr{exitScanFailed, fmt.Sprintf("timed out after %s waiting for %s (still %s)", timeout, firstNonEmpty(j.ScanKey, id), j.Status)}
		}
		time.Sleep(a.pollInterval)
	}
}

func firstNonEmpty(v ...string) string {
	for _, s := range v {
		if s != "" {
			return s
		}
	}
	return ""
}

// --- gate ---------------------------------------------------------------------

type gateResult struct {
	ScanID           string         `json:"scan_id"`
	ScanKey          string         `json:"scan_key"`
	RepositoryName   string         `json:"repository_name"`
	Status           string         `json:"status"`
	GateFailed       bool           `json:"gate_failed"`
	BlockingPolicies []string       `json:"blocking_policies"`
	FailOn           string         `json:"fail_on"`
	Scope            string         `json:"scope"`
	BySeverity       map[string]int `json:"by_severity"`
	ThresholdCount   int            `json:"threshold_count"`
	Passed           bool           `json:"passed"`
	Reasons          []string       `json:"reasons"`
}

func (a *app) cmdGate(args []string) error {
	fs := a.commandFlags("gate", "pathos gate (--scan UUID | --repo <repository>) [--fail-on critical|high|medium|low|none] [--scope new|all] [--allow-partial]")
	scanID := fs.String("scan", "", "scan execution UUID")
	repoRef := fs.String("repo", "", "repository: evaluate its latest finished execution")
	failOn := fs.String("fail-on", "none", "fail when findings at or above this severity exist: critical, high, medium, low or none")
	scope := fs.String("scope", "new", "new: findings first detected by the execution; all: the repository's open findings")
	allowPartial := fs.Bool("allow-partial", false, "a partial execution (some scanners failed) may pass")
	if err := parse(fs, args); err != nil {
		return err
	}
	switch *failOn {
	case "critical", "high", "medium", "low", "none":
	default:
		return usagef("--fail-on must be critical, high, medium, low or none")
	}
	if *scope != "new" && *scope != "all" {
		return usagef("--scope must be new or all")
	}
	if (*scanID == "") == (*repoRef == "") {
		return usagef("give exactly one of --scan or --repo")
	}
	if *scanID != "" && !uuidRe.MatchString(*scanID) {
		return usagef("--scan must be a scan execution UUID")
	}
	c, err := a.newClient()
	if err != nil {
		return err
	}
	ctx := context.Background()
	id := *scanID
	if id == "" {
		repoID, err := c.resolveRepo(ctx, *repoRef)
		if err != nil {
			return err
		}
		var page struct {
			Items []scanJob `json:"items"`
		}
		if err := c.getJSON(ctx, "/api/v1/scans", url.Values{"repository_id": {repoID}}, &page); err != nil {
			return err
		}
		for _, j := range page.Items {
			if j.finished() {
				id = j.ID
				break
			}
		}
		if id == "" {
			return errors.New("the repository has no finished scan execution")
		}
	}
	q := url.Values{"fail_on": {*failOn}, "scope": {*scope}}
	if *allowPartial {
		q.Set("allow_partial", "true")
	}
	var g gateResult
	data, _, err := c.do(ctx, http.MethodGet, "/api/v1/scans/"+url.PathEscape(id)+"/gate", q, nil, "", maxJSONResponse)
	if err != nil {
		return err
	}
	if err := decode(data, &g); err != nil {
		return err
	}
	if a.cfg.JSON {
		if _, err := a.stdout.Write(append(bytes.TrimSpace(data), '\n')); err != nil {
			return err
		}
	} else {
		sev := g.BySeverity
		fmt.Fprintf(a.stdout, "Security gate for %s (%s, %s): %s\n", g.ScanKey, g.RepositoryName, g.Status, map[bool]string{true: "PASSED", false: "FAILED"}[g.Passed])
		fmt.Fprintf(a.stdout, "  %s findings: critical %d, high %d, medium %d, low %d, info %d (fail on: %s)\n",
			g.Scope, sev["critical"], sev["high"], sev["medium"], sev["low"], sev["info"], g.FailOn)
		for _, r := range g.Reasons {
			fmt.Fprintln(a.stdout, "  - "+r)
		}
	}
	if !g.Passed {
		return exitErr{exitGateFailed, ""}
	}
	return nil
}

// --- findings -----------------------------------------------------------------

type finding struct {
	ID          string   `json:"id"`
	Severity    string   `json:"severity"`
	Status      string   `json:"status"`
	Title       string   `json:"title"`
	FilePath    string   `json:"file_path"`
	StartLine   *int     `json:"start_line"`
	ScannerKeys []string `json:"scanner_keys"`
}

func (a *app) cmdFindings(args []string) error {
	fs := a.commandFlags("findings", "pathos findings [--repo <repository>] [--severity critical,high] [--status open] [--category CAT] [--scanner KEY] [--limit 100] [--output table|json]")
	repoRef := fs.String("repo", "", "repository (default: every repository in the token owner's scope)")
	severity := fs.String("severity", "", "comma-separated severities")
	status := fs.String("status", "", "open (default), all, or one stored status")
	category := fs.String("category", "", "one category")
	scanner := fs.String("scanner", "", "reported by this scanner key")
	limit := fs.Int("limit", 100, "maximum number of findings (1-10000)")
	output := fs.String("output", "table", "table or json")
	if err := parse(fs, args); err != nil {
		return err
	}
	if *limit < 1 || *limit > 10000 {
		return usagef("--limit must be between 1 and 10000")
	}
	if *output != "table" && *output != "json" {
		return usagef("--output must be table or json")
	}
	c, err := a.newClient()
	if err != nil {
		return err
	}
	ctx := context.Background()
	q := url.Values{}
	if *repoRef != "" {
		id, err := c.resolveRepo(ctx, *repoRef)
		if err != nil {
			return err
		}
		q.Set("repository_id", id)
	}
	for k, v := range map[string]string{"severity": *severity, "status": *status, "category": *category, "scanner": *scanner} {
		if v != "" {
			q.Set(k, v)
		}
	}
	var items []json.RawMessage
	for len(items) < *limit {
		var page struct {
			Items      []json.RawMessage `json:"items"`
			NextCursor *string           `json:"next_cursor"`
		}
		if err := c.getJSON(ctx, "/api/v1/findings", q, &page); err != nil {
			return err
		}
		items = append(items, page.Items...)
		if page.NextCursor == nil || *page.NextCursor == "" || len(page.Items) == 0 {
			break
		}
		q.Set("cursor", *page.NextCursor)
	}
	if len(items) > *limit {
		items = items[:*limit]
	}
	if a.cfg.JSON || *output == "json" {
		if items == nil {
			items = []json.RawMessage{}
		}
		return a.printJSON(map[string]any{"items": items})
	}
	tw := tabwriter.NewWriter(a.stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "SEVERITY\tSTATUS\tTITLE\tLOCATION\tSCANNER\tID")
	for _, raw := range items {
		var f finding
		if err := json.Unmarshal(raw, &f); err != nil {
			return fmt.Errorf("unexpected response from the server: %w", err)
		}
		loc := f.FilePath
		if f.StartLine != nil {
			loc = fmt.Sprintf("%s:%d", loc, *f.StartLine)
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\n", f.Severity, f.Status, clip(f.Title, 70), clip(loc, 60), strings.Join(f.ScannerKeys, ","), f.ID)
	}
	if err := tw.Flush(); err != nil {
		return err
	}
	a.progress("%d finding(s)", len(items))
	return nil
}

// clip shortens s for a table cell and removes tabs and line breaks.
func clip(s string, n int) string {
	s = strings.Join(strings.Fields(s), " ")
	if r := []rune(s); len(r) > n {
		return string(r[:n-1]) + "…"
	}
	return s
}

// --- sbom export --------------------------------------------------------------

func (a *app) cmdSBOMExport(args []string) error {
	fs := a.commandFlags("sbom export", "pathos sbom export --repo <repository> [--format cyclonedx|spdx] [--output FILE]")
	repoRef := fs.String("repo", "", "repository: UUID, Repository ID or full name")
	format := fs.String("format", "cyclonedx", "cyclonedx or spdx")
	output := fs.String("output", "-", "output file (- for stdout)")
	if err := parse(fs, args); err != nil {
		return err
	}
	if *format != "cyclonedx" && *format != "spdx" {
		return usagef("--format must be cyclonedx or spdx")
	}
	c, err := a.newClient()
	if err != nil {
		return err
	}
	ctx := context.Background()
	repoID, err := c.resolveRepo(ctx, *repoRef)
	if err != nil {
		return err
	}
	data, _, err := c.do(ctx, http.MethodGet, "/api/v1/repositories/"+url.PathEscape(repoID)+"/sbom", url.Values{"format": {*format}}, nil, "", maxSBOMResponse)
	if err != nil {
		return err
	}
	if *output == "-" || *output == "" {
		_, err = a.stdout.Write(data)
		return err
	}
	if err := os.WriteFile(*output, data, 0o600); err != nil {
		return fmt.Errorf("cannot write the SBOM: %w", err)
	}
	a.progress("wrote %s SBOM to %s (%d bytes)", *format, *output, len(data))
	return nil
}
