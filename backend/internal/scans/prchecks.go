package scans

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"pathos/internal/audit"
	"pathos/internal/authz"
	"pathos/internal/gates"
	"pathos/internal/org"
	"pathos/internal/platform/db"
	"pathos/internal/platform/httpx"
	"pathos/internal/platform/logging"
	"pathos/internal/scanners"
	"pathos/internal/scm"
)

// Pull request checks: when enabled for a repository, a pull request event
// queues a scan of the PR head with the repository's profile. Results are
// stored as pr_findings, never as findings, so a PR cannot fix, re-open or
// otherwise change what is tracked for the scan branch. A PR finding is new
// unless the repository already has a finding with the same fingerprint
// that is not fixed (open, in progress, accepted risk, false positive):
// what was already known, triaged or accepted does not fail the PR.

const prStatusContext = "PATHOS / security"

var severityOrder = []string{"critical", "high", "medium", "low", "info"}

func (s *Service) onPullRequest(ctx context.Context, orgID, repoID uuid.UUID, ev scm.WebhookEvent) {
	if ev.PullRequest <= 0 || !scm.ValidCommit(ev.CommitSHA) {
		return
	}
	var enabled bool
	var gate string
	var mode *string
	if err := s.DB.QueryRow(ctx, `SELECT pr_checks_enabled, pr_gate_severity, pr_gate_mode FROM repositories WHERE id = $1 AND organization_id = $2`,
		repoID, orgID).Scan(&enabled, &gate, &mode); err != nil || !enabled {
		return
	}
	gateMode := ""
	if mode != nil {
		gateMode = *mode
	}
	var checkID uuid.UUID
	err := db.InTx(ctx, s.DB, func(tx pgx.Tx) error {
		res, err := EnqueueWith(ctx, tx, orgID, repoID, "pull_request", ev.Ref, ev.CommitSHA, nil, EnqueueOpts{PullRequest: ev.PullRequest})
		if err != nil {
			return err
		}
		// One check per execution; a newer push to the PR while it is
		// queued moves the queued execution (and its check) to the new head.
		return tx.QueryRow(ctx, `INSERT INTO pr_checks (id, organization_id, repository_id, scan_job_id, pull_request, head_ref, head_sha, gate_severity, gate_mode)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
			ON CONFLICT (scan_job_id) DO UPDATE SET head_ref = EXCLUDED.head_ref, head_sha = EXCLUDED.head_sha,
			  gate_severity = EXCLUDED.gate_severity, gate_mode = EXCLUDED.gate_mode, status_posted = '' RETURNING id`,
			uuid.Must(uuid.NewV7()), orgID, repoID, res.JobID, ev.PullRequest, truncate(ev.Ref, 255), ev.CommitSHA, gate, gateMode).Scan(&checkID)
	})
	if err != nil {
		if !errors.Is(err, ErrNotScannable) {
			s.Log.Warn("pull request check not queued", "repository_id", repoID, "pull_request", ev.PullRequest, "err", err)
		}
		return
	}
	s.Log.Info("pull request check queued", "repository_id", repoID, "pull_request", ev.PullRequest, "check_id", checkID)
	s.postCheckStatus(ctx, checkID)
}

func insertPRFindings(ctx context.Context, tx pgx.Tx, jobID uuid.UUID, fs []scanners.Finding) error {
	if len(fs) == 0 {
		return nil
	}
	var checkID uuid.UUID
	if err := tx.QueryRow(ctx, `SELECT id FROM pr_checks WHERE scan_job_id = $1`, jobID).Scan(&checkID); err != nil {
		return err
	}
	b := &pgx.Batch{}
	for _, f := range fs {
		var cve *string
		if f.CVE != "" {
			c := f.CVE
			cve = &c
		}
		// The same finding reported by two scanners keeps the higher severity.
		cwe := f.CWE
		if cwe == nil {
			cwe = []string{}
		}
		b.Queue(`INSERT INTO pr_findings (id, pr_check_id, fingerprint, scanner_key, category, rule_id, title, severity, file_path, start_line, cve, cwe)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
			ON CONFLICT (pr_check_id, fingerprint) DO UPDATE SET severity = CASE
			  WHEN array_position(ARRAY['critical','high','medium','low','info'], EXCLUDED.severity)
			     < array_position(ARRAY['critical','high','medium','low','info'], pr_findings.severity) THEN EXCLUDED.severity
			  ELSE pr_findings.severity END`,
			uuid.Must(uuid.NewV7()), checkID, f.Fingerprint, f.ScannerKey, f.Category, truncate(f.RuleID, 500),
			truncate(logging.RedactString(f.Title), 500), f.Severity, truncate(f.FilePath, 1000), f.StartLine, cve, cwe)
	}
	return tx.SendBatch(ctx, b).Close()
}

// finalizePR classifies a PR scan's findings as new or existing, applies
// the gate and records the check result.
func finalizePR(ctx context.Context, tx pgx.Tx, orgID, jobID, repoID uuid.UUID, status, workerErr string, bad []string, job *Job) error {
	var checkID uuid.UUID
	var gate, headSHA string
	var pr int
	if err := tx.QueryRow(ctx, `SELECT id, gate_severity, pull_request, head_sha FROM pr_checks WHERE scan_job_id = $1`, jobID).Scan(&checkID, &gate, &pr, &headSHA); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `UPDATE pr_findings pf SET is_new = false, existing_finding_id = f.id
		FROM findings f WHERE pf.pr_check_id = $1 AND f.repository_id = $2 AND f.scan_target_id IS NULL
		  AND f.fingerprint = pf.fingerprint AND f.status <> 'fixed'`, checkID, repoID); err != nil {
		return err
	}
	bySev := map[string]int{}
	var newCount, existing int
	rows, err := tx.Query(ctx, `SELECT severity, is_new, count(*) FROM pr_findings WHERE pr_check_id = $1 GROUP BY 1, 2`, checkID)
	if err != nil {
		return err
	}
	for rows.Next() {
		var sev string
		var isNew bool
		var n int
		if err := rows.Scan(&sev, &isNew, &n); err != nil {
			rows.Close()
			return err
		}
		if isNew {
			bySev[sev] += n
			newCount += n
		} else {
			existing += n
		}
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return err
	}
	// The gate decision (internal/gates): the repository's managed pull
	// request gate (its threshold in block or warn mode, decision C6),
	// the organization's pull_request gates and the security policies with
	// the block action. Nothing blocks without a policy (rule 7).
	checkStatus, summary := prOutcome(status, gate, newCount, 0, bySev)
	var decisionID *uuid.UUID
	if status != "failed" {
		repo := repoID
		dec, err := gates.Evaluate(ctx, tx, gates.Input{OrgID: orgID, Stage: gates.StagePullRequest, RepositoryID: &repo,
			PRCheckID: &checkID, ScanJobID: &jobID, CommitSHA: headSHA, PullRequest: pr})
		if err != nil {
			return err
		}
		decisionID = &dec.ID
		checkStatus, summary = prDecisionOutcome(status, gate, newCount, bySev, dec)
	}
	errText := logging.RedactString(truncate(workerErr, 2000))
	if errText == "" && len(bad) > 0 {
		errText = "scanners failed: " + joinSorted(bad)
	}
	sevJSON, _ := json.Marshal(bySev)
	if _, err := tx.Exec(ctx, `UPDATE pr_checks SET status = $2, new_findings = $3, new_by_severity = $4, existing_findings = $5,
		summary = $6, finished_at = now(), gate_decision_id = $7 WHERE id = $1`, checkID, checkStatus, newCount, sevJSON, existing, summary, decisionID); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `UPDATE scan_jobs SET status = $2, finished_at = now(), lease_expires_at = NULL,
		findings_new = $3, findings_fixed = 0, gate_failed = $4, error = $5 WHERE id = $1`,
		jobID, status, newCount, checkStatus == "failed", errText); err != nil {
		return err
	}
	job.Status, job.FindingsNew, job.GateFailed, job.PullRequest = status, newCount, checkStatus == "failed", pr
	return nil
}

// prOutcome decides a check's status and one-line summary.
func prOutcome(scanStatus, gate string, newCount, blocking int, bySev map[string]int) (string, string) {
	if scanStatus == "failed" {
		return "error", "The security scan could not run"
	}
	var parts []string
	for _, sv := range severityOrder {
		if n := bySev[sv]; n > 0 {
			parts = append(parts, fmt.Sprintf("%d %s", n, sv))
		}
	}
	detail := "no new findings"
	if newCount > 0 {
		detail = strconv.Itoa(newCount) + " new: " + strings.Join(parts, ", ")
	}
	suffix := ""
	if scanStatus == "partial" {
		suffix = " (some scanners failed)"
	}
	if blocking > 0 {
		return "failed", fmt.Sprintf("Blocked: %s (gate: %s and above)%s", detail, gate, suffix)
	}
	if scanStatus == "partial" {
		// Incomplete results cannot vouch for the PR.
		return "error", "Incomplete scan: " + detail + suffix
	}
	return "passed", "Passed: " + detail
}

// prDecisionOutcome turns a gate decision into the check's status and
// summary, keeping the wording of the checks before the gates engine:
// "Blocked: … (gate: high and above)" for the repository's threshold and
// "Blocked by policy …" for other policies.
func prDecisionOutcome(scanStatus, gate string, newCount int, bySev map[string]int, dec gates.Decision) (string, string) {
	threshold := 0
	var blockedBy, approvalBy, warnBy, exceptedBy []string
	for _, g := range dec.Gates {
		switch {
		case g.Managed && g.Effect == gates.OutcomeBlock:
			threshold = g.Count
		case g.Effect == gates.OutcomeBlock:
			blockedBy = appendUnique(blockedBy, g.Policy.Name)
		case g.Effect == gates.OutcomeApproval:
			approvalBy = appendUnique(approvalBy, g.Policy.Name)
		case g.Effect == gates.OutcomeWarn:
			warnBy = appendUnique(warnBy, g.Policy.Name)
		case g.Effect == gates.OutcomeExceptionApplied:
			exceptedBy = appendUnique(exceptedBy, g.Policy.Name)
		}
	}
	checkStatus, summary := prOutcome(scanStatus, gate, newCount, threshold, bySev)
	rest := func() string { return strings.TrimPrefix(strings.TrimPrefix(summary, "Passed: "), "Blocked: ") }
	switch {
	case len(blockedBy) > 0:
		checkStatus, summary = "failed", truncate("Blocked by policy "+strings.Join(blockedBy, ", ")+": "+rest(), 500)
	case checkStatus == "failed":
	case len(approvalBy) > 0:
		checkStatus, summary = "failed", truncate("Approval required by policy "+strings.Join(approvalBy, ", ")+": "+rest(), 500)
	case checkStatus == "passed" && len(warnBy) > 0:
		summary = truncate("Passed with warnings (policy "+strings.Join(warnBy, ", ")+"): "+rest(), 500)
	case checkStatus == "passed" && len(exceptedBy) > 0:
		summary = truncate("Passed by approved exception (policy "+strings.Join(exceptedBy, ", ")+"): "+rest(), 500)
	}
	return checkStatus, summary
}

func appendUnique(list []string, v string) []string {
	for _, x := range list {
		if x == v {
			return list
		}
	}
	return append(list, v)
}

// postPRStatus posts the final status of the check of a finished job.
func (s *Service) postPRStatus(ctx context.Context, jobID uuid.UUID) {
	var checkID uuid.UUID
	if err := s.DB.QueryRow(ctx, `SELECT id FROM pr_checks WHERE scan_job_id = $1`, jobID).Scan(&checkID); err != nil {
		return
	}
	s.postCheckStatus(ctx, checkID)
}

// postCheckStatus posts a check's current state as a commit status on the
// PR head. Failures are recorded on the check, never fatal.
func (s *Service) postCheckStatus(ctx context.Context, checkID uuid.UUID) {
	var orgID, repoID uuid.UUID
	var sha, status, summary string
	if err := s.DB.QueryRow(ctx, `SELECT organization_id, repository_id, head_sha, status, summary FROM pr_checks WHERE id = $1`, checkID).
		Scan(&orgID, &repoID, &sha, &status, &summary); err != nil {
		return
	}
	record := func(posted, msg string) {
		_, _ = s.DB.Exec(context.WithoutCancel(ctx), `UPDATE pr_checks SET status_posted = $2, status_error = $3 WHERE id = $1`,
			checkID, posted, truncate(msg, 500))
	}
	if s.StatusWriter == nil {
		record("not_supported", "commit statuses are not configured")
		return
	}
	w, ref, err := s.StatusWriter(ctx, orgID, repoID)
	if err != nil {
		record("failed", safeErr(err))
		return
	}
	st := scm.CommitStatus{Context: prStatusContext, Description: summary}
	posted := "final"
	switch status {
	case "pending":
		st.State, st.Description, posted = scm.CommitPending, "Security scan queued", "pending"
	case "passed":
		st.State = scm.CommitSuccess
	case "failed":
		st.State = scm.CommitFailure
	default:
		st.State = scm.CommitError
	}
	if s.PublicURL != "" {
		st.TargetURL = strings.TrimRight(s.PublicURL, "/") + "/pull-requests?check=" + checkID.String()
	}
	cctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	if err := w.SetCommitStatus(cctx, ref, sha, st); err != nil {
		s.Log.Warn("commit status not posted", "check_id", checkID, "err", err)
		record("failed", safeErr(err))
		return
	}
	record(posted, "")
}

// --- API -------------------------------------------------------------------

// PRCheck is one pull request check.
type PRCheck struct {
	ID              uuid.UUID      `json:"id"`
	RepositoryID    uuid.UUID      `json:"repository_id"`
	RepositoryName  string         `json:"repository_name"`
	ScanJobID       uuid.UUID      `json:"scan_job_id"`
	ScanStatus      string         `json:"scan_status"`
	PullRequest     int            `json:"pull_request"`
	HeadRef         string         `json:"head_ref"`
	HeadSHA         string         `json:"head_sha"`
	Status          string         `json:"status"`
	GateSeverity    string         `json:"gate_severity"`
	GateMode        string         `json:"gate_mode"`
	GateDecisionID  *uuid.UUID     `json:"gate_decision_id"`
	NewFindings     int            `json:"new_findings"`
	NewBySeverity   map[string]int `json:"new_by_severity"`
	ExistingFinding int            `json:"existing_findings"`
	Summary         string         `json:"summary"`
	StatusPosted    string         `json:"status_posted"`
	StatusError     string         `json:"status_error"`
	CreatedAt       time.Time      `json:"created_at"`
	FinishedAt      *time.Time     `json:"finished_at"`
}

// PRFinding is a finding reported on a pull request.
type PRFinding struct {
	ID                uuid.UUID  `json:"id"`
	Title             string     `json:"title"`
	Severity          string     `json:"severity"`
	Category          string     `json:"category"`
	ScannerKey        string     `json:"scanner_key"`
	RuleID            string     `json:"rule_id"`
	FilePath          string     `json:"file_path"`
	StartLine         *int       `json:"start_line"`
	CVE               *string    `json:"cve"`
	IsNew             bool       `json:"is_new"`
	ExistingFindingID *uuid.UUID `json:"existing_finding_id"`
	// Policies this finding violates.
	Policies []string `json:"policies"`
}

func (s *Service) registerPRChecks(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/v1/pr-checks", s.listPRChecks)
	mux.HandleFunc("GET /api/v1/pr-checks/{id}", s.getPRCheck)
	mux.HandleFunc("POST /api/v1/pr-checks/{id}/repost", s.repostPRCheck)
	mux.HandleFunc("GET /api/v1/repositories/{id}/pr-settings", s.getPRSettings)
	mux.HandleFunc("PUT /api/v1/repositories/{id}/pr-settings", s.putPRSettings)
}

const prCheckSelect = `SELECT c.id, c.repository_id, COALESCE(NULLIF(r.display_name, ''), r.full_name), c.scan_job_id, j.status, c.pull_request,
	c.head_ref, c.head_sha, c.status, c.gate_severity, c.new_findings, c.new_by_severity, c.existing_findings, c.summary,
	c.status_posted, c.status_error, c.created_at, c.finished_at, c.gate_mode, c.gate_decision_id
	FROM pr_checks c JOIN repositories r ON r.id = c.repository_id JOIN scan_jobs j ON j.id = c.scan_job_id`

func scanPRCheck(row pgx.Row) (PRCheck, error) {
	var c PRCheck
	var sev []byte
	err := row.Scan(&c.ID, &c.RepositoryID, &c.RepositoryName, &c.ScanJobID, &c.ScanStatus, &c.PullRequest, &c.HeadRef, &c.HeadSHA,
		&c.Status, &c.GateSeverity, &c.NewFindings, &sev, &c.ExistingFinding, &c.Summary, &c.StatusPosted, &c.StatusError,
		&c.CreatedAt, &c.FinishedAt, &c.GateMode, &c.GateDecisionID)
	if err == nil {
		c.NewBySeverity = map[string]int{}
		_ = json.Unmarshal(sev, &c.NewBySeverity)
	}
	return c, err
}

func (s *Service) listPRChecks(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	p := s.Principal(ctx)
	f := authz.FilterFor(p, authz.PermScansRead)
	if f.None() {
		s.fail(w, r, authz.ErrForbidden)
		return
	}
	scope, sargs := org.ScopeSQL(f, "r.id", "r.business_unit_id", "r.country_id", 2)
	args := append([]any{p.OrganizationID}, sargs...)
	where := []string{"c.organization_id = $1", scope}
	q := r.URL.Query()
	if v := q.Get("repository_id"); v != "" {
		id, err := uuid.Parse(v)
		if err != nil {
			s.fail(w, r, httpx.BadRequest("invalid repository_id"))
			return
		}
		args = append(args, id)
		where = append(where, fmt.Sprintf("c.repository_id = $%d", len(args)))
	}
	if v := q.Get("status"); v != "" {
		args = append(args, v)
		where = append(where, fmt.Sprintf("c.status = $%d", len(args)))
	}
	rows, err := s.DB.Query(ctx, prCheckSelect+" WHERE "+strings.Join(where, " AND ")+" ORDER BY c.created_at DESC LIMIT 200", args...)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	items, err := pgx.CollectRows(rows, func(r pgx.CollectableRow) (PRCheck, error) { return scanPRCheck(r) })
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if items == nil {
		items = []PRCheck{}
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"items": items})
}

func (s *Service) loadPRCheck(ctx context.Context, p *authz.Principal, id uuid.UUID) (PRCheck, error) {
	c, err := scanPRCheck(s.DB.QueryRow(ctx, prCheckSelect+" WHERE c.organization_id = $1 AND c.id = $2", p.OrganizationID, id))
	if errors.Is(err, pgx.ErrNoRows) {
		return c, httpx.E(http.StatusNotFound, "not_found", "pull request check not found")
	}
	if err != nil {
		return c, err
	}
	if err := s.requireRepo(ctx, p, authz.PermScansRead, c.RepositoryID); err != nil {
		return c, err
	}
	return c, nil
}

func (s *Service) getPRCheck(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	p := s.Principal(ctx)
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		s.fail(w, r, httpx.E(http.StatusNotFound, "not_found", "pull request check not found"))
		return
	}
	c, err := s.loadPRCheck(ctx, p, id)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	rows, err := s.DB.Query(ctx, `SELECT id, title, severity, category, scanner_key, rule_id, file_path, start_line, cve, is_new, existing_finding_id,
		  COALESCE((SELECT array_agg(p.name ORDER BY p.name) FROM security_policies p WHERE p.id = ANY(pr_findings.policy_ids)), '{}')
		FROM pr_findings WHERE pr_check_id = $1
		ORDER BY is_new DESC, array_position(ARRAY['critical','high','medium','low','info'], severity), file_path, start_line LIMIT 1000`, id)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	fs, err := pgx.CollectRows(rows, func(r pgx.CollectableRow) (PRFinding, error) {
		var f PRFinding
		return f, r.Scan(&f.ID, &f.Title, &f.Severity, &f.Category, &f.ScannerKey, &f.RuleID, &f.FilePath, &f.StartLine, &f.CVE, &f.IsNew, &f.ExistingFindingID, &f.Policies)
	})
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if fs == nil {
		fs = []PRFinding{}
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"check": c, "findings": fs})
}

func (s *Service) repostPRCheck(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	p := s.Principal(ctx)
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		s.fail(w, r, httpx.E(http.StatusNotFound, "not_found", "pull request check not found"))
		return
	}
	c, err := s.loadPRCheck(ctx, p, id)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if err := s.requireRepo(ctx, p, authz.PermScansRun, c.RepositoryID); err != nil {
		s.fail(w, r, err)
		return
	}
	s.postCheckStatus(ctx, id)
	c, err = s.loadPRCheck(ctx, p, id)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, c)
}

type prSettings struct {
	Enabled      bool   `json:"enabled"`
	GateSeverity string `json:"gate_severity"`
	// GateMode is the explicit choice (decision C6): block the pull
	// request or warn only. Required to enable pull request checks.
	GateMode *string `json:"gate_mode"`
	// PolicyID and GateID are the managed security policy and gate that
	// carry the threshold (read-only).
	PolicyID *uuid.UUID `json:"policy_id"`
	GateID   *uuid.UUID `json:"gate_id"`
	// Webhooks reports whether the repository's connection can deliver
	// pull request events.
	Source string `json:"source_type"`
}

func (s *Service) getPRSettings(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	p := s.Principal(ctx)
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		s.fail(w, r, errNotFound)
		return
	}
	if err := s.requireRepo(ctx, p, authz.PermScansRead, id); err != nil {
		s.fail(w, r, err)
		return
	}
	var st prSettings
	if err := s.DB.QueryRow(ctx, `SELECT pr_checks_enabled, pr_gate_severity, pr_gate_mode, source_type FROM repositories WHERE organization_id = $1 AND id = $2`,
		p.OrganizationID, id).Scan(&st.Enabled, &st.GateSeverity, &st.GateMode, &st.Source); err != nil {
		s.fail(w, r, err)
		return
	}
	g, err := gates.RepositoryPRGate(ctx, s.DB, p.OrganizationID, id)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	st.PolicyID, st.GateID = g.PolicyID, g.GateID
	httpx.WriteJSON(w, http.StatusOK, st)
}

func (s *Service) putPRSettings(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	p := s.Principal(ctx)
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		s.fail(w, r, errNotFound)
		return
	}
	if err := s.requireRepo(ctx, p, authz.PermReposManage, id); err != nil {
		s.fail(w, r, err)
		return
	}
	var req prSettings
	if err := httpx.DecodeJSON(w, r, &req); err != nil {
		s.fail(w, r, err)
		return
	}
	switch req.GateSeverity {
	case "critical", "high", "medium", "low", "none":
	default:
		s.fail(w, r, httpx.BadRequest("gate_severity must be critical, high, medium, low or none"))
		return
	}
	if req.GateMode != nil && *req.GateMode != "block" && *req.GateMode != "warn" {
		s.fail(w, r, httpx.BadRequest("gate_mode must be block or warn"))
		return
	}
	err = db.InTx(ctx, s.DB, func(tx pgx.Tx) error {
		var source string
		var mode *string
		if err := tx.QueryRow(ctx, `SELECT source_type, pr_gate_mode FROM repositories WHERE organization_id = $1 AND id = $2 FOR UPDATE`,
			p.OrganizationID, id).Scan(&source, &mode); err != nil {
			return err
		}
		if req.GateMode != nil {
			mode = req.GateMode
		}
		if req.Enabled && (source == "upload" || source == "git") {
			return httpx.BadRequest("uploaded and anonymous repositories have no SCM connection for pull request checks")
		}
		// Decision C6: no default that blocks. Enabling needs an explicit
		// block or warn; a "none" threshold cannot block, so it is report
		// only (warn) without a choice.
		if req.Enabled && mode == nil {
			if req.GateSeverity != "none" {
				return gates.ErrPRModeRequired
			}
			warn := "warn"
			mode = &warn
		}
		if _, err := tx.Exec(ctx, `UPDATE repositories SET pr_checks_enabled = $3, pr_gate_severity = $4, pr_gate_mode = $5
			WHERE organization_id = $1 AND id = $2`, p.OrganizationID, id, req.Enabled, req.GateSeverity, mode); err != nil {
			return err
		}
		m := ""
		if mode != nil {
			m = *mode
		}
		g, err := gates.SyncRepositoryPRGate(ctx, tx, p.OrganizationID, id, req.Enabled, m, req.GateSeverity, &p.UserID)
		if err != nil {
			return err
		}
		return audit.Write(ctx, tx, audit.Entry{OrganizationID: p.OrganizationID, ActorID: &p.UserID, ActorEmail: p.Email,
			Action: "repository.pr_checks", TargetType: "repository", TargetID: id.String(),
			Metadata: map[string]any{"enabled": req.Enabled, "gate_severity": req.GateSeverity, "gate_mode": m, "policy_id": g.PolicyID, "gate_id": g.GateID}})
	})
	if err != nil {
		s.fail(w, r, err)
		return
	}
	s.getPRSettings(w, r)
}
