package scans

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"path"
	"slices"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"pathos/internal/ai"
	"pathos/internal/aifix"
	"pathos/internal/audit"
	"pathos/internal/authz"
	"pathos/internal/platform/db"
	"pathos/internal/platform/httpx"
	"pathos/internal/platform/logging"
	"pathos/internal/scanners"
	"pathos/internal/scm"
)

// Verified AI fixes. A user with ai.fix on the repository asks for a fix
// of a SAST, secrets or IaC finding. PATHOS sends the finding and the
// region of its file around it (redacted) to the organization's default AI
// configuration, which returns a unified diff. The diff is checked
// (internal/aifix: confined to the finding's file or files next to it,
// size limits, no CI files, build scripts or manifests unless the finding
// is in them) and then verified by a worker:
//
//  1. the diff is applied to a fresh checkout of the scanned commit;
//  2. the scanner that reported the finding runs on the changed files
//     before and after the change: the finding must be reported before,
//     gone after, with no new results in the changed files;
//  3. when an administrator enabled a test runner for the repository, the
//     repository's tests run in the sandboxed worker-fuzz image (no
//     network, CPU, memory and time limits), before and after the change.
//
// Only a verified fix can become a pull request, opened by a person with
// the fix pull request machinery (branch prefix pathos/fix/). Nothing is
// merged automatically and the finding is resolved only by a later scan.

// AIFixer proposes fixes (ai.Service).
type AIFixer interface {
	FixAvailable(ctx context.Context, orgID uuid.UUID) error
	ProposeFix(ctx context.Context, orgID uuid.UUID, in ai.FixInput) (ai.FixResult, error)
}

// SourceFileFunc reads a repository file at a commit through the SCM
// connection (repos.Service.ReadSourceFile).
type SourceFileFunc func(ctx context.Context, orgID, repoID uuid.UUID, commit, path string) ([]byte, error)

// Rate limits on AI fix requests (each one is a provider call).
const (
	aiFixPerUserHour = 10
	aiFixPerOrgDay   = 200
)

const (
	aiFixLeaseDuration = 20 * time.Minute
	aiFixMaxAttempts   = 3
	maxAIFixResultBody = 16 << 20
	maxAIFixReport     = 8 << 20
	maxAIFixTestLog    = 256 << 10
)

// aiFixCategories can receive AI fixes.
var aiFixCategories = []string{"sast", "secrets", "iac"}

// aiFixTestRunners an administrator can enable per repository.
var aiFixTestRunners = []string{"", "go", "python"}

// AIFixStep is one verification step as shown to users.
type AIFixStep struct {
	Key    string `json:"key"` // policy | apply | scan | tests
	Label  string `json:"label"`
	Status string `json:"status"` // pending | running | passed | failed | skipped
	Detail string `json:"detail"`
}

// AIFix is a proposal as returned by the API.
type AIFix struct {
	ID              uuid.UUID       `json:"id"`
	FindingID       uuid.UUID       `json:"finding_id"`
	RepositoryID    uuid.UUID       `json:"repository_id"`
	Status          string          `json:"status"`
	FailureReason   string          `json:"failure_reason"`
	ScannerKey      string          `json:"scanner_key"`
	RuleID          string          `json:"rule_id"`
	FilePath        string          `json:"file_path"`
	CommitSHA       string          `json:"commit_sha"`
	BaseCommit      string          `json:"base_commit"`
	TestRunner      string          `json:"test_runner"`
	Provider        string          `json:"provider"`
	Model           string          `json:"model"`
	TransmittedSHA  string          `json:"transmitted_sha256"`
	Summary         string          `json:"summary"`
	Diff            string          `json:"diff"`
	ChangedFiles    []string        `json:"changed_files"`
	Steps           []AIFixStep     `json:"steps"`
	ScanEvidence    json.RawMessage `json:"scan_evidence"`
	TestLog         string          `json:"test_log,omitempty"`
	HasReports      bool            `json:"has_reports"`
	FixPullRequest  *FixPR          `json:"pull_request"`
	RequestedBy     string          `json:"requested_by"`
	CreatedAt       time.Time       `json:"created_at"`
	UpdatedAt       time.Time       `json:"updated_at"`
	FinishedAt      *time.Time      `json:"finished_at"`
	fixPullRequestI *uuid.UUID
}

const aiFixCols = `x.id, x.finding_id, x.repository_id, x.status, x.failure_reason, x.scanner_key, x.rule_id, x.file_path, x.commit_sha,
	x.base_commit, x.test_runner, x.provider, x.model, x.transmitted_sha256, x.summary, x.diff, x.changed_files, x.steps, x.scan_evidence,
	x.test_log, x.before_report_gzip IS NOT NULL, COALESCE(u.email, ''), x.created_at, x.updated_at, x.finished_at, x.fix_pull_request_id
	FROM ai_fix_proposals x LEFT JOIN users u ON u.id = x.requested_by`

func scanAIFix(row pgx.Row) (AIFix, error) {
	var f AIFix
	var steps, ev []byte
	err := row.Scan(&f.ID, &f.FindingID, &f.RepositoryID, &f.Status, &f.FailureReason, &f.ScannerKey, &f.RuleID, &f.FilePath, &f.CommitSHA,
		&f.BaseCommit, &f.TestRunner, &f.Provider, &f.Model, &f.TransmittedSHA, &f.Summary, &f.Diff, &f.ChangedFiles, &steps, &ev,
		&f.TestLog, &f.HasReports, &f.RequestedBy, &f.CreatedAt, &f.UpdatedAt, &f.FinishedAt, &f.fixPullRequestI)
	if err != nil {
		return f, err
	}
	_ = json.Unmarshal(steps, &f.Steps)
	if f.Steps == nil {
		f.Steps = []AIFixStep{}
	}
	if f.ChangedFiles == nil {
		f.ChangedFiles = []string{}
	}
	f.ScanEvidence = ev
	return f, nil
}

func (s *Service) loadAIFixPR(ctx context.Context, f *AIFix) {
	if f.fixPullRequestI == nil {
		return
	}
	if pr, err := scanFixPR(s.DB.QueryRow(ctx, `SELECT `+fixPRCols+` WHERE x.id = $1`, *f.fixPullRequestI)); err == nil {
		f.FixPullRequest = &pr
	}
}

func (s *Service) registerAIFixes(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/v1/findings/{id}/ai-fixes", s.findingAIFixes)
	mux.HandleFunc("POST /api/v1/findings/{id}/ai-fixes", s.requestAIFix)
	mux.HandleFunc("GET /api/v1/ai-fixes/{id}", s.getAIFix)
	mux.HandleFunc("GET /api/v1/ai-fixes/{id}/reports/{which}", s.aiFixReport)
	mux.HandleFunc("POST /api/v1/ai-fixes/{id}/pull-request", s.openAIFixPR)
	mux.HandleFunc("GET /api/v1/repositories/{id}/ai-fix-settings", s.getAIFixSettings)
	mux.HandleFunc("PUT /api/v1/repositories/{id}/ai-fix-settings", s.putAIFixSettings)
}

func (s *Service) registerAIFixWorker(mux *http.ServeMux) {
	mux.HandleFunc("POST /internal/worker/v1/ai-fix-lease", s.aiFixLease)
	mux.HandleFunc("POST /internal/worker/v1/ai-fix-jobs/{id}/result", s.aiFixResult)
}

// --- settings ------------------------------------------------------------------

type aiFixSettings struct {
	TestRunner string `json:"test_runner"`
}

func (s *Service) getAIFixSettings(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	p := s.Principal(ctx)
	id, err := pathID(r, "id")
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if err := s.requireRepo(ctx, p, authz.PermScansRead, id); err != nil {
		s.fail(w, r, err)
		return
	}
	var st aiFixSettings
	if err := s.DB.QueryRow(ctx, `SELECT ai_fix_test_runner FROM repositories WHERE organization_id = $1 AND id = $2`, p.OrganizationID, id).
		Scan(&st.TestRunner); err != nil {
		s.fail(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, st)
}

// putAIFixSettings chooses the test runner AI fix verification may use.
// Running tests executes the repository's code (in the sandboxed fuzz
// worker), so it is an explicit per-repository decision.
func (s *Service) putAIFixSettings(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	p := s.Principal(ctx)
	id, err := pathID(r, "id")
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if err := s.requireRepo(ctx, p, authz.PermReposManage, id); err != nil {
		s.fail(w, r, err)
		return
	}
	var req aiFixSettings
	if err := httpx.DecodeJSON(w, r, &req); err != nil {
		s.fail(w, r, err)
		return
	}
	if !slices.Contains(aiFixTestRunners, req.TestRunner) {
		s.fail(w, r, httpx.BadRequest("test_runner must be empty (off), go or python"))
		return
	}
	err = db.InTx(ctx, s.DB, func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx, `UPDATE repositories SET ai_fix_test_runner = $3 WHERE organization_id = $1 AND id = $2`, p.OrganizationID, id, req.TestRunner)
		if err != nil {
			return err
		}
		if tag.RowsAffected() == 0 {
			return errNotFound
		}
		return audit.Write(ctx, tx, audit.Entry{OrganizationID: p.OrganizationID, ActorID: &p.UserID, ActorEmail: p.Email,
			Action: "repository.ai_fix_tests", TargetType: "repository", TargetID: id.String(),
			Metadata: map[string]any{"test_runner": req.TestRunner}})
	})
	if err != nil {
		s.fail(w, r, err)
		return
	}
	s.getAIFixSettings(w, r)
}

// --- eligibility ---------------------------------------------------------------

type aiFixFinding struct {
	ID, RepoID         uuid.UUID
	Category, Status   string
	RuleID, File       string
	Title, Description string
	Severity           string
	CWE, ScannerKeys   []string
	StartLine, EndLine *int
	TargetScan         bool
	RepoSource         string
	FixPRsEnabled      bool
	TestRunner         string
	LastJob            *uuid.UUID
	Commit             string
}

func (s *Service) loadAIFixFinding(ctx context.Context, orgID, id uuid.UUID) (aiFixFinding, error) {
	var f aiFixFinding
	err := s.DB.QueryRow(ctx, `SELECT f.id, f.repository_id, f.category, f.status, f.rule_id, f.file_path, f.title, f.description, f.severity,
		f.cwe, f.scanner_keys, f.start_line, f.end_line, f.scan_target_id IS NOT NULL, r.source_type, r.fix_prs_enabled, r.ai_fix_test_runner,
		f.last_scan_job_id, COALESCE(j.commit_sha, '')
		FROM findings f JOIN repositories r ON r.id = f.repository_id LEFT JOIN scan_jobs j ON j.id = f.last_scan_job_id
		WHERE f.organization_id = $1 AND f.id = $2`, orgID, id).
		Scan(&f.ID, &f.RepoID, &f.Category, &f.Status, &f.RuleID, &f.File, &f.Title, &f.Description, &f.Severity, &f.CWE, &f.ScannerKeys,
			&f.StartLine, &f.EndLine, &f.TargetScan, &f.RepoSource, &f.FixPRsEnabled, &f.TestRunner, &f.LastJob, &f.Commit)
	return f, err
}

// verifyScanner is the tool that re-runs: the first of the finding's
// scanners a worker can run (imported reports cannot be re-run).
func verifyScanner(keys []string) string {
	for _, k := range keys {
		if k == "" || scanners.IsImportKey(k) || scanners.IsTargetOnly(k) {
			continue
		}
		if _, ok := scanners.Lookup(k); ok || scanners.IsPluginKey(k) {
			return k
		}
	}
	return ""
}

// AIFixEligibility tells the UI whether "Propose fix" can be offered.
type AIFixEligibility struct {
	Available     bool    `json:"available"`
	Reason        string  `json:"reason,omitempty"`
	Scanner       string  `json:"scanner"`
	TestRunner    string  `json:"test_runner"`
	FixPRsEnabled bool    `json:"fix_prs_enabled"`
	CanRequest    bool    `json:"can_request"`
	CanOpenPR     bool    `json:"can_open_pr"`
	Proposals     []AIFix `json:"proposals"`
}

func (s *Service) aiFixEligibility(ctx context.Context, orgID uuid.UUID, f aiFixFinding) AIFixEligibility {
	e := AIFixEligibility{Scanner: verifyScanner(f.ScannerKeys), TestRunner: f.TestRunner, FixPRsEnabled: f.FixPRsEnabled, Proposals: []AIFix{}}
	switch {
	case !slices.Contains(aiFixCategories, f.Category):
		e.Reason = "AI fixes are available for SAST, secrets and IaC findings"
	case f.TargetScan:
		e.Reason = "this finding comes from a scan target, not from the repository's source"
	case f.RepoSource == "upload":
		e.Reason = "uploaded repositories have no SCM connection to check out and verify a fix"
	case f.Status != "open" && f.Status != "in_progress" && f.Status != "needs_review":
		e.Reason = "the finding is not open"
	case f.File == "" || !scm.ValidRepoPath(f.File):
		e.Reason = "the finding has no file location"
	case e.Scanner == "":
		e.Reason = "the finding comes only from an imported report; PATHOS cannot re-run that tool to verify a fix"
	case f.Commit == "" || !scm.ValidCommit(f.Commit):
		e.Reason = "the finding's last scan did not record a commit, so the scanned code cannot be checked out"
	case s.AIFix == nil || s.ReadSource == nil:
		e.Reason = "AI fixes are not available in this deployment"
	default:
		switch err := s.AIFix.FixAvailable(ctx, orgID); {
		case errors.Is(err, ai.ErrNotConfigured):
			e.Reason = "No AI provider is configured. AI fixes stay off until an administrator adds a provider and a default configuration under AI settings."
		case errors.Is(err, ai.ErrCodeNotAllowed):
			e.Reason = "The default AI configuration does not allow sending source code to the provider; AI fixes need it (AI settings, \"Send code context\")."
		case err != nil:
			e.Reason = "AI fixes are not available: " + safeErr(err)
		default:
			e.Available = true
		}
	}
	return e
}

func (s *Service) findingAIFixes(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	p := s.Principal(ctx)
	id, err := pathID(r, "id")
	if err != nil {
		s.fail(w, r, err)
		return
	}
	f, err := s.loadAIFixFinding(ctx, p.OrganizationID, id)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if err := s.requireRepo(ctx, p, authz.PermFindingsRead, f.RepoID); err != nil {
		s.fail(w, r, err)
		return
	}
	e := s.aiFixEligibility(ctx, p.OrganizationID, f)
	scope := authz.Scope{Type: authz.ScopeRepository, ID: f.RepoID}
	e.CanRequest = s.Authz.Require(ctx, p, authz.PermAIFix, scope) == nil
	e.CanOpenPR = e.CanRequest && s.canRequestFix(ctx, p, f.RepoID)
	rows, err := s.DB.Query(ctx, `SELECT `+aiFixCols+` WHERE x.organization_id = $1 AND x.finding_id = $2 ORDER BY x.created_at DESC LIMIT 10`,
		p.OrganizationID, id)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	e.Proposals, err = pgx.CollectRows(rows, func(row pgx.CollectableRow) (AIFix, error) { return scanAIFix(row) })
	if err != nil {
		s.fail(w, r, err)
		return
	}
	for i := range e.Proposals {
		e.Proposals[i].TestLog = "" // in the detail view only
		s.loadAIFixPR(ctx, &e.Proposals[i])
	}
	if e.Proposals == nil {
		e.Proposals = []AIFix{}
	}
	httpx.WriteJSON(w, http.StatusOK, e)
}

// --- request -------------------------------------------------------------------

func aiFixSteps(scanner, runner string) []AIFixStep {
	tests := AIFixStep{Key: "tests", Label: "Repository tests", Status: "skipped",
		Detail: "no test runner is enabled for this repository (repository settings, AI fixes)"}
	if runner != "" {
		tests.Label, tests.Status, tests.Detail = "Repository tests ("+runner+", sandboxed)", "pending", ""
	}
	return []AIFixStep{
		{Key: "policy", Label: "Diff confined to the finding's file", Status: "pending"},
		{Key: "apply", Label: "Applied to a fresh checkout", Status: "pending"},
		{Key: "scan", Label: "Scanner " + scanner + " re-run on the changed files", Status: "pending"},
		tests,
	}
}

func setStep(steps []AIFixStep, key, status, detail string) []AIFixStep {
	for i := range steps {
		if steps[i].Key == key {
			steps[i].Status, steps[i].Detail = status, cleanText(truncate(detail, 2000))
		}
	}
	return steps
}

// scannerConfig is the finding's scanner configuration in the profile of
// its last scan (with the custom rules pinned to that scan for Opengrep).
func (s *Service) scannerConfig(ctx context.Context, jobID *uuid.UUID, key string) json.RawMessage {
	cfg := json.RawMessage(`{}`)
	if jobID == nil {
		return cfg
	}
	var pv *uuid.UUID
	if err := s.DB.QueryRow(ctx, `SELECT profile_version_id FROM scan_jobs WHERE id = $1`, *jobID).Scan(&pv); err != nil || pv == nil {
		return cfg
	}
	v, err := scanVersion(s.DB.QueryRow(ctx, versionSelect+` WHERE v.id = $1`, *pv))
	if err != nil {
		return cfg
	}
	for _, sc := range v.Scanners {
		if sc.Key == key && len(sc.Config) > 0 && string(sc.Config) != "null" {
			cfg = sc.Config
		}
	}
	if key == scanners.Opengrep {
		if rules, err := customRulesFor(ctx, s.DB, jobID.String()); err == nil && len(rules) > 0 {
			m := map[string]any{}
			_ = json.Unmarshal(cfg, &m)
			m["custom_rules"] = rules
			cfg, _ = json.Marshal(m)
		}
	}
	return cfg
}

func (s *Service) requestAIFix(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	p := s.Principal(ctx)
	id, err := pathID(r, "id")
	if err != nil {
		s.fail(w, r, err)
		return
	}
	f, err := s.loadAIFixFinding(ctx, p.OrganizationID, id)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if err := s.requireRepo(ctx, p, authz.PermAIFix, f.RepoID); err != nil {
		s.fail(w, r, err)
		return
	}
	e := s.aiFixEligibility(ctx, p.OrganizationID, f)
	if !e.Available {
		s.fail(w, r, httpx.E(http.StatusUnprocessableEntity, "ai_fix_not_available", e.Reason))
		return
	}
	var mine, org int
	if err := s.DB.QueryRow(ctx, `SELECT count(*) FILTER (WHERE requested_by = $2 AND created_at > now() - interval '1 hour'), count(*)
		FROM ai_fix_proposals WHERE organization_id = $1 AND created_at > now() - interval '24 hours'`, p.OrganizationID, p.UserID).Scan(&mine, &org); err != nil {
		s.fail(w, r, err)
		return
	}
	if mine >= aiFixPerUserHour || org >= aiFixPerOrgDay {
		msg := fmt.Sprintf("the limit of %d AI fix requests per user per hour was reached; try again later", aiFixPerUserHour)
		if org >= aiFixPerOrgDay {
			msg = fmt.Sprintf("the organization's limit of %d AI fix requests per day was reached; try again later", aiFixPerOrgDay)
		}
		_ = audit.Write(ctx, s.DB, audit.Entry{OrganizationID: p.OrganizationID, ActorID: &p.UserID, ActorEmail: p.Email,
			Action: "ai_fix.rate_limited", TargetType: "finding", TargetID: f.ID.String(), Metadata: map[string]any{"user_last_hour": mine, "org_last_day": org}})
		s.fail(w, r, httpx.E(http.StatusTooManyRequests, "rate_limited", msg).WithDiag("PTH-AI-1008"))
		return
	}
	src, err := s.ReadSource(ctx, p.OrganizationID, f.RepoID, f.Commit, f.File)
	if err != nil {
		s.fail(w, r, httpx.E(http.StatusBadGateway, "source_unavailable", "could not read "+f.File+" at the scanned commit: "+safeErr(err)))
		return
	}
	start, end := 0, 0
	if f.StartLine != nil {
		start = *f.StartLine
	}
	if f.EndLine != nil {
		end = *f.EndLine
	}
	in := ai.FixInput{
		Finding: ai.FixFinding{Scanner: e.Scanner, Category: f.Category, RuleID: f.RuleID, Title: f.Title, Description: f.Description,
			Severity: f.Severity, CWE: f.CWE, FilePath: f.File, StartLine: start, EndLine: end},
		File: ai.BuildFixRegion(f.File, src, start, end),
	}
	fixID := uuid.Must(uuid.NewV7())
	steps, _ := json.Marshal(aiFixSteps(e.Scanner, f.TestRunner))
	cfg := s.scannerConfig(ctx, f.LastJob, e.Scanner)
	err = db.InTx(ctx, s.DB, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `INSERT INTO ai_fix_proposals (id, organization_id, repository_id, finding_id, scanner_key, scanner_config, rule_id,
			file_path, start_line, commit_sha, test_runner, steps, requested_by) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)`,
			fixID, p.OrganizationID, f.RepoID, f.ID, e.Scanner, cfg, truncate(f.RuleID, 500), f.File, f.StartLine, f.Commit, f.TestRunner,
			steps, p.UserID); err != nil {
			if db.IsUniqueViolation(err) {
				return httpx.Conflict("an AI fix for this finding is already being prepared or verified")
			}
			return err
		}
		return audit.Write(ctx, tx, audit.Entry{OrganizationID: p.OrganizationID, ActorID: &p.UserID, ActorEmail: p.Email,
			Action: "ai_fix.request", TargetType: "finding", TargetID: f.ID.String(),
			Metadata: map[string]any{"ai_fix_id": fixID.String(), "repository_id": f.RepoID.String(), "file": f.File, "rule_id": f.RuleID,
				"scanner": e.Scanner, "commit": f.Commit, "lines_sent": fmt.Sprintf("%d-%d", in.File.FirstLine, in.File.LastLine),
				"test_runner": f.TestRunner}})
	})
	if err != nil {
		s.fail(w, r, err)
		return
	}
	// The provider call can take minutes (self-hosted models on CPU): it
	// runs in the background and the UI polls the proposal.
	fid := f.ID
	actx := ai.WithSubject(context.WithoutCancel(ctx), ai.Subject{Kind: "finding", ID: &fid, FindingID: &fid, RequestedBy: &p.UserID,
		Related: map[string]any{"findings": []string{fid.String()}, "ai_fix_id": fixID.String(), "file": f.File, "commit": f.Commit}})
	go s.generateAIFix(actx, p.OrganizationID, fixID, f.ID, in)
	out, err := scanAIFix(s.DB.QueryRow(ctx, `SELECT `+aiFixCols+` WHERE x.id = $1`, fixID))
	if err != nil {
		s.fail(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusAccepted, out)
}

// aiFixError explains a provider failure.
func aiFixError(err error) string {
	switch {
	case errors.Is(err, ai.ErrNotConfigured):
		return "no AI provider is configured"
	case errors.Is(err, ai.ErrCodeNotAllowed):
		return "the AI configuration does not allow sending source code"
	case errors.Is(err, ai.ErrRateLimited):
		return "the AI provider rate limit was reached; try again later"
	case errors.Is(err, ai.ErrRefused):
		return "the AI provider declined this request"
	case errors.Is(err, ai.ErrAuth):
		return "the AI provider rejected the API key"
	case errors.Is(err, ai.ErrTruncated):
		return "the AI response was cut off at the output token limit"
	}
	return "the AI provider did not return a usable fix: " + truncate(logging.RedactString(err.Error()), 600)
}

func (s *Service) generateAIFix(ctx context.Context, orgID, fixID, findingID uuid.UUID, in ai.FixInput) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Minute)
	defer cancel()
	res, err := s.AIFix.ProposeFix(ctx, orgID, in)
	steps := aiFixSteps(in.Finding.Scanner, "")
	var current []byte
	if s.DB.QueryRow(ctx, `SELECT steps FROM ai_fix_proposals WHERE id = $1`, fixID).Scan(&current) == nil {
		_ = json.Unmarshal(current, &steps)
	}
	finish := func(status, reason string, d *aifix.Diff) {
		var files []string
		if d != nil {
			files = d.Paths()
		}
		if files == nil {
			files = []string{}
		}
		stepsJSON, _ := json.Marshal(steps)
		if _, err := s.DB.Exec(ctx, `UPDATE ai_fix_proposals SET status = $2, failure_reason = $3, provider = $4, model = $5, config_version_id = $6,
			transmitted_sha256 = $7, input_tokens = $8, output_tokens = $9, summary = $10, diff = $11, changed_files = $12, steps = $13, updated_at = now(),
			finished_at = CASE WHEN $2 IN ('failed', 'rejected') THEN now() END, evidence_record_id = $14 WHERE id = $1 AND status = 'generating'`,
			fixID, status, cleanText(truncate(reason, 2000)), res.Provider, cleanText(truncate(res.Model, 200)), nullUUID(res.ConfigVersionID), res.SHA256,
			res.InputTokens, res.OutputTokens, cleanText(truncate(res.Proposal.Summary, 8000)), cleanText(truncate(res.Proposal.Diff, 40000)), files,
			stepsJSON, nullUUID(res.EvidenceID)); err != nil {
			s.Log.Error("AI fix not recorded", "ai_fix_id", fixID, "err", err)
		}
		action := map[string]string{"queued": "ai_fix.proposed", "rejected": "ai_fix.rejected", "failed": "ai_fix.failed"}[status]
		_ = audit.Write(ctx, s.DB, audit.Entry{OrganizationID: orgID, Action: action, TargetType: "finding", TargetID: findingID.String(),
			Metadata: map[string]any{"ai_fix_id": fixID.String(), "provider": res.Provider, "model": res.Model, "transmitted_sha256": res.SHA256,
				"input_tokens": res.InputTokens, "output_tokens": res.OutputTokens, "files": files, "reason": truncate(reason, 500)}})
	}
	if err != nil {
		steps = setStep(steps, "policy", "skipped", "")
		finish("failed", aiFixError(err), nil)
		return
	}
	d, err := aifix.Parse(res.Proposal.Diff)
	if err == nil {
		err = aifix.Policy{FindingFile: in.Finding.FilePath}.Check(d)
	}
	if err != nil {
		steps = setStep(steps, "policy", "failed", err.Error())
		finish("rejected", "the proposed diff was rejected: "+err.Error(), nil)
		return
	}
	steps = setStep(steps, "policy", "passed", fmt.Sprintf("changes %s (+%d −%d lines)", strings.Join(d.Paths(), ", "), d.Added, d.Removed))
	finish("queued", "", &d)
}

func nullUUID(id uuid.UUID) *uuid.UUID {
	if id == uuid.Nil {
		return nil
	}
	return &id
}

// --- read ----------------------------------------------------------------------

func (s *Service) loadAIFixFor(ctx context.Context, p *authz.Principal, perm authz.Permission, id uuid.UUID) (AIFix, error) {
	f, err := scanAIFix(s.DB.QueryRow(ctx, `SELECT `+aiFixCols+` WHERE x.organization_id = $1 AND x.id = $2`, p.OrganizationID, id))
	if err != nil {
		return f, err
	}
	return f, s.requireRepo(ctx, p, perm, f.RepositoryID)
}

func (s *Service) getAIFix(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	p := s.Principal(ctx)
	id, err := pathID(r, "id")
	if err != nil {
		s.fail(w, r, err)
		return
	}
	f, err := s.loadAIFixFor(ctx, p, authz.PermFindingsRead, id)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	s.loadAIFixPR(ctx, &f)
	httpx.WriteJSON(w, http.StatusOK, f)
}

// aiFixReport returns the scanner's raw report on the original (before) or
// fixed (after) files: the evidence behind the scan step.
func (s *Service) aiFixReport(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	p := s.Principal(ctx)
	id, err := pathID(r, "id")
	if err != nil {
		s.fail(w, r, err)
		return
	}
	col := map[string]string{"before": "before_report_gzip", "after": "after_report_gzip"}[r.PathValue("which")]
	if col == "" {
		s.fail(w, r, errNotFound)
		return
	}
	if _, err := s.loadAIFixFor(ctx, p, authz.PermFindingsRead, id); err != nil {
		s.fail(w, r, err)
		return
	}
	var gz []byte
	if err := s.DB.QueryRow(ctx, `SELECT `+col+` FROM ai_fix_proposals WHERE id = $1`, id).Scan(&gz); err != nil || gz == nil {
		s.fail(w, r, errNotFound)
		return
	}
	raw, err := gunzipLimited(gz, maxAIFixReport)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	httpx.Download(w, "application/octet-stream", fmt.Sprintf("ai-fix-%s-%s.json", id, r.PathValue("which")))
	_, _ = w.Write(raw)
}

// --- pull request --------------------------------------------------------------

// AIFixBranchName builds the branch of a verified AI fix.
func AIFixBranchName(id uuid.UUID, rule string) string {
	if i := strings.LastIndexAny(rule, "./:"); i >= 0 && i < len(rule)-1 {
		rule = rule[i+1:]
	}
	part := strings.Trim(fixBranchUnsafe.ReplaceAllString(strings.ToLower(rule), "-"), "-.")
	if len(part) > 50 {
		part = strings.Trim(part[:50], "-.")
	}
	if part == "" {
		part = "finding"
	}
	return strings.ReplaceAll(scm.FixBranchPrefix+"ai-"+part+"-"+strings.ReplaceAll(id.String(), "-", "")[20:], "..", ".")
}

func (s *Service) openAIFixPR(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	p := s.Principal(ctx)
	id, err := pathID(r, "id")
	if err != nil {
		s.fail(w, r, err)
		return
	}
	fx, err := s.loadAIFixFor(ctx, p, authz.PermAIFix, id)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	// Opening a pull request writes to the repository with the connection's
	// credential: the same rights as a dependency fix pull request.
	if !s.canRequestFix(ctx, p, fx.RepositoryID) {
		s.fail(w, r, authz.ErrForbidden)
		return
	}
	f, err := s.loadAIFixFinding(ctx, p.OrganizationID, fx.FindingID)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	switch {
	case fx.Status != "verified":
		s.fail(w, r, httpx.E(http.StatusUnprocessableEntity, "not_verified", "only a verified fix can become a pull request (this one is "+fx.Status+")"))
		return
	case !f.FixPRsEnabled:
		s.fail(w, r, httpx.E(http.StatusUnprocessableEntity, "fix_pr_not_available",
			"fix pull requests are not enabled for this repository (repository settings, Fix pull requests)"))
		return
	case f.Status != "open" && f.Status != "in_progress" && f.Status != "needs_review":
		s.fail(w, r, httpx.E(http.StatusUnprocessableEntity, "fix_pr_not_available", "the finding is not open"))
		return
	case s.FixPRTarget == nil:
		s.fail(w, r, httpx.E(http.StatusServiceUnavailable, "unavailable", "pull request creation is not configured"))
		return
	}
	var stored []FixFile
	if err := s.DB.QueryRow(ctx, `SELECT patched_files FROM ai_fix_proposals WHERE id = $1`, id).Scan(&stored); err != nil {
		s.fail(w, r, err)
		return
	}
	files, err := decodeFixFiles(stored)
	if err != nil {
		s.fail(w, r, httpx.E(http.StatusUnprocessableEntity, "invalid_fix", "the verified files cannot be committed: "+err.Error()))
		return
	}
	prID := uuid.Must(uuid.NewV7())
	err = db.InTx(ctx, s.DB, func(tx pgx.Tx) error {
		var linked *uuid.UUID
		if err := tx.QueryRow(ctx, `SELECT fix_pull_request_id FROM ai_fix_proposals WHERE id = $1 FOR UPDATE`, id).Scan(&linked); err != nil {
			return err
		}
		if linked != nil {
			var st, url string
			if err := tx.QueryRow(ctx, `SELECT status, pr_url FROM fix_pull_requests WHERE id = $1`, *linked).Scan(&st, &url); err == nil && st != "failed" {
				msg := "a pull request was already opened for this fix"
				if url != "" {
					msg += ": " + url
				}
				return httpx.Conflict(msg)
			}
			// The earlier attempt failed: a new one replaces it.
			if _, err := tx.Exec(ctx, `UPDATE fix_pull_requests SET ai_fix_id = NULL WHERE id = $1`, *linked); err != nil {
				return err
			}
		}
		if _, err := tx.Exec(ctx, `INSERT INTO fix_pull_requests (id, organization_id, repository_id, kind, ai_fix_id, ecosystem, package_name,
			current_version, target_version, manifest_hint, grouping, status, base_commit, requested_by)
			VALUES ($1, $2, $3, 'ai_code', $4, '', $5, '', 'ai-fix', $6, 'finding', 'creating', $7, $8)`,
			prID, p.OrganizationID, fx.RepositoryID, id, truncate(fx.FilePath, 300), truncate(fx.FilePath, 1000), fx.BaseCommit, p.UserID); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `INSERT INTO fix_pull_request_findings (fix_pull_request_id, finding_id) VALUES ($1, $2)`, prID, fx.FindingID); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `UPDATE ai_fix_proposals SET fix_pull_request_id = $2, updated_at = now() WHERE id = $1`, id, prID); err != nil {
			return err
		}
		return audit.Write(ctx, tx, audit.Entry{OrganizationID: p.OrganizationID, ActorID: &p.UserID, ActorEmail: p.Email,
			Action: "ai_fix.pull_request", TargetType: "finding", TargetID: fx.FindingID.String(),
			Metadata: map[string]any{"ai_fix_id": id.String(), "fix_pr_id": prID.String(), "repository_id": fx.RepositoryID.String(),
				"files": fx.ChangedFiles, "base_commit": fx.BaseCommit}})
	})
	if err != nil {
		s.fail(w, r, err)
		return
	}
	go s.publishAIFixPR(context.WithoutCancel(ctx), p.OrganizationID, prID, fx, f, files)
	out, err := scanFixPR(s.DB.QueryRow(ctx, `SELECT `+fixPRCols+` WHERE x.id = $1`, prID))
	if err != nil {
		s.fail(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusAccepted, out)
}

func (s *Service) publishAIFixPR(ctx context.Context, orgID, prID uuid.UUID, fx AIFix, f aiFixFinding, files []scm.FileChange) {
	ctx, cancel := context.WithTimeout(ctx, 3*time.Minute)
	defer cancel()
	title := truncate(fmt.Sprintf("Fix %s in %s (AI-proposed, verified by PATHOS)", strings.TrimSpace(truncate(f.Title, 120)), path.Base(fx.FilePath)), 250)
	commit := title + "\n\n" + fmt.Sprintf("Fixes %s (%s, rule %s) in %s.\n", truncate(f.Title, 200), f.Severity, truncate(fx.RuleID, 200), fx.FilePath) +
		"\nProposed by AI (" + fx.Provider + " " + fx.Model + ") and verified by PATHOS: the scanner " + fx.ScannerKey +
		" no longer reports the finding.\n\nGenerated by PATHOS."
	s.publishFixPR(ctx, orgID, prID, fx.RepositoryID, fx.BaseCommit, AIFixBranchName(prID, fx.RuleID), title, commit, files,
		func(baseBranch string) string { return aiFixPRBody(fx, f, baseBranch, s.PublicURL) })
}

// noMention keeps AI text from notifying people on the SCM.
var noMention = strings.NewReplacer("@", "@​")

func aiFixPRBody(fx AIFix, f aiFixFinding, baseBranch, publicURL string) string {
	var b strings.Builder
	link := ""
	if publicURL != "" {
		link = fmt.Sprintf(" ([PATHOS](%s/findings?finding=%s))", strings.TrimRight(publicURL, "/"), f.ID)
	}
	fmt.Fprintf(&b, "PATHOS opened this pull request with an **AI-proposed fix** for a %s finding, after verifying it.\n\n", mdEscape(f.Category))
	fmt.Fprintf(&b, "### Finding\n\n- **%s** %s%s\n- Rule `%s` reported by `%s` in `%s`\n\n", f.Severity, mdEscape(truncate(f.Title, 200)), link,
		mdEscape(truncate(fx.RuleID, 200)), mdEscape(fx.ScannerKey), mdEscape(fx.FilePath))
	if fx.Summary != "" {
		fmt.Fprintf(&b, "### Proposed change\n\n> %s\n\n", noMention.Replace(mdEscape(truncate(fx.Summary, 1500))))
	}
	b.WriteString("### Verification\n\n")
	for _, st := range fx.Steps {
		mark := map[string]string{"passed": "✅", "failed": "❌", "skipped": "⏭️"}[st.Status]
		line := fmt.Sprintf("- %s %s: %s", mark, mdEscape(st.Label), st.Status)
		if st.Detail != "" {
			line += " — " + noMention.Replace(mdEscape(truncate(st.Detail, 300)))
		}
		b.WriteString(line + "\n")
	}
	fmt.Fprintf(&b, "\nVerified at commit `%s`. AI provider: %s (%s).\n", mdEscape(fx.BaseCommit), mdEscape(fx.Provider), mdEscape(fx.Model))
	b.WriteString("\n### Changed files\n\n")
	for _, p := range fx.ChangedFiles {
		fmt.Fprintf(&b, "- `%s`\n", mdEscape(p))
	}
	fmt.Fprintf(&b, "\n### Before merging\n\n"+
		"- The change was written by an AI model. Review it like any other contribution; PATHOS never merges it.\n"+
		"- Verification shows that the scanner no longer reports the finding in the changed file and reports nothing new there. It does not prove the change is correct in every case.\n"+
		"- PATHOS marks the finding fixed only when a later scan of `%s` no longer detects it, not when this pull request is merged.\n",
		mdEscape(baseBranch))
	return b.String()
}

// --- worker protocol -----------------------------------------------------------

// LeasedAIFix is an AI fix verification job as a worker receives it.
// Phase "verify" applies the diff and re-runs the scanner; phase "test"
// runs the repository's tests (fuzz workers only).
type LeasedAIFix struct {
	FixID          uuid.UUID       `json:"fix_id"`
	Phase          string          `json:"phase"`
	FullName       string          `json:"full_name"`
	CloneURL       string          `json:"clone_url"`
	Ref            string          `json:"ref"`
	CommitSHA      string          `json:"commit_sha"`
	Credential     *scm.Credential `json:"credential,omitempty"`
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

func requeueExpiredAIFixes(ctx context.Context, q db.Querier) error {
	_, err := q.Exec(ctx, `UPDATE ai_fix_proposals SET
		status = CASE WHEN attempts >= $1 THEN 'failed' WHEN status = 'running' THEN 'queued' ELSE 'tests_queued' END,
		failure_reason = CASE WHEN attempts >= $1 THEN 'the worker lease expired ' || attempts || ' times' ELSE failure_reason END,
		finished_at = CASE WHEN attempts >= $1 THEN now() ELSE NULL END,
		leased_by = NULL, lease_expires_at = NULL, updated_at = now()
		WHERE status IN ('running', 'testing') AND lease_expires_at < now()`, aiFixMaxAttempts)
	if err != nil {
		return err
	}
	// Proposals whose AI call was interrupted (API restart) fail.
	_, err = q.Exec(ctx, `UPDATE ai_fix_proposals SET status = 'failed', failure_reason = 'the AI request was interrupted; request a fix again',
		finished_at = now(), updated_at = now() WHERE status = 'generating' AND created_at < now() - interval '20 minutes'`)
	return err
}

func (s *Service) aiFixLease(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	wk := workerFrom(ctx)
	if err := requeueExpiredAIFixes(ctx, s.DB); err != nil {
		httpx.WriteError(w, r, s.Log, err)
		return
	}
	keys := make([]string, 0, len(wk.Scanners))
	for k := range wk.Scanners {
		keys = append(keys, k)
	}
	var job LeasedAIFix
	var connID *uuid.UUID
	var visibility, scanBranch, defBranch, status, base string
	var start *int
	// Verification needs the finding's scanner; tests need the sandboxed
	// fuzz worker (it has the language toolchains and runs repository code
	// without network access).
	err := s.DB.QueryRow(ctx, `
		UPDATE ai_fix_proposals x SET status = CASE WHEN x.status = 'queued' THEN 'running' ELSE 'testing' END, leased_by = $2,
		       lease_expires_at = now() + $3::interval, attempts = attempts + 1, updated_at = now()
		FROM repositories r
		WHERE r.id = x.repository_id AND x.id = (
		  SELECT q.id FROM ai_fix_proposals q WHERE q.organization_id = $1
		    AND ((q.status = 'queued' AND q.scanner_key = ANY($4)) OR (q.status = 'tests_queued' AND $5))
		  ORDER BY q.created_at FOR UPDATE SKIP LOCKED LIMIT 1)
		RETURNING x.id, x.status, r.full_name, r.clone_url, r.scm_connection_id, r.visibility, r.scan_branch, r.default_branch,
		  x.commit_sha, x.base_commit, x.scanner_key, x.scanner_config, x.rule_id, x.file_path, x.start_line, x.diff, x.test_runner`,
		wk.orgID, wk.ID, aiFixLeaseDuration.String(), keys, wk.Family == "fuzz").Scan(&job.FixID, &status, &job.FullName, &job.CloneURL, &connID,
		&visibility, &scanBranch, &defBranch, &job.CommitSHA, &base, &job.ScannerKey, &job.ScannerConfig, &job.RuleID, &job.FilePath, &start,
		&job.Diff, &job.TestRunner)
	if errors.Is(err, pgx.ErrNoRows) {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	if err != nil {
		httpx.WriteError(w, r, s.Log, err)
		return
	}
	job.Phase = "verify"
	if status == "testing" {
		job.Phase = "test"
		job.CommitSHA = base // the commit the fix was verified on
	}
	if start != nil {
		job.StartLine = *start
	}
	job.Ref = scanBranch
	if job.Ref == "" {
		job.Ref = defBranch
	}
	job.Public = visibility == "public"
	job.TimeoutSeconds = int(aiFixLeaseDuration.Seconds()) - 120
	fail := func(msg string) {
		_, _ = s.DB.Exec(ctx, `UPDATE ai_fix_proposals SET status = 'failed', failure_reason = $2, finished_at = now(), updated_at = now(),
			leased_by = NULL, lease_expires_at = NULL WHERE id = $1`, job.FixID, truncate(msg, 2000))
		w.WriteHeader(http.StatusNoContent)
	}
	if connID == nil || job.CloneURL == "" {
		fail("the repository has no SCM connection")
		return
	}
	if s.CloneCredential != nil {
		cred, err := s.CloneCredential(ctx, wk.orgID, *connID)
		if err != nil {
			fail("could not obtain a clone credential: " + safeErr(err))
			return
		}
		job.Credential = &cred
	}
	s.Log.Info("AI fix verification leased", "ai_fix_id", job.FixID, "phase", job.Phase, "repository", job.FullName, "worker", wk.Name)
	httpx.WriteJSON(w, http.StatusOK, job)
}

// AIFixResult is what a worker reports for one phase.
type AIFixResult struct {
	Phase            string          `json:"phase"`
	Status           string          `json:"status"` // passed | failed
	FailureReason    string          `json:"failure_reason"`
	BaseCommit       string          `json:"base_commit"`
	Steps            []AIFixStep     `json:"steps"`
	ScanEvidence     json.RawMessage `json:"scan_evidence"`
	BeforeReportGzip string          `json:"before_report_gzip"`
	AfterReportGzip  string          `json:"after_report_gzip"`
	Files            []FixFile       `json:"files"`
	TestLog          string          `json:"test_log"`
}

func decodeReport(s string) ([]byte, error) {
	if s == "" {
		return nil, nil
	}
	gz, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return nil, errors.New("report is not base64")
	}
	if _, err := gunzipLimited(gz, maxAIFixReport); err != nil {
		return nil, errors.New("report is not valid gzip within the size limit")
	}
	return gz, nil
}

func (s *Service) aiFixResult(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	wk := workerFrom(ctx)
	id, err := pathID(r, "id")
	if err != nil {
		httpx.WriteError(w, r, s.Log, httpx.ErrNotFound)
		return
	}
	var status, runner, findingID string
	var leasedBy *uuid.UUID
	var changed []string
	var stepsRaw []byte
	if err := s.DB.QueryRow(ctx, `SELECT status, leased_by, test_runner, changed_files, steps, finding_id::text FROM ai_fix_proposals
		WHERE id = $1 AND organization_id = $2`, id, wk.orgID).Scan(&status, &leasedBy, &runner, &changed, &stepsRaw, &findingID); err != nil {
		httpx.WriteError(w, r, s.Log, httpx.ErrNotFound)
		return
	}
	if (status != "running" && status != "testing") || leasedBy == nil || *leasedBy != wk.ID {
		httpx.WriteError(w, r, s.Log, httpx.E(http.StatusConflict, "lease_lost", "this AI fix job is not leased by this worker"))
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxAIFixResultBody)
	var res AIFixResult
	if err := json.NewDecoder(r.Body).Decode(&res); err != nil {
		httpx.WriteError(w, r, s.Log, httpx.BadRequest("invalid AI fix result"))
		return
	}
	wantPhase := map[string]string{"running": "verify", "testing": "test"}[status]
	if res.Phase != wantPhase || (res.Status != "passed" && res.Status != "failed") {
		httpx.WriteError(w, r, s.Log, httpx.BadRequest("invalid AI fix result phase or status"))
		return
	}
	var steps []AIFixStep
	_ = json.Unmarshal(stepsRaw, &steps)
	allowed := map[string][]string{"verify": {"apply", "scan"}, "test": {"tests"}}[wantPhase]
	for _, st := range res.Steps {
		if slices.Contains(allowed, st.Key) && slices.Contains([]string{"passed", "failed", "skipped"}, st.Status) {
			steps = setStep(steps, st.Key, st.Status, logging.RedactString(st.Detail))
		}
	}
	reason := cleanText(truncate(logging.RedactString(res.FailureReason), 2000))
	next := "failed"
	var files []byte
	var before, after []byte
	evidence := []byte(`{}`)
	if res.Status == "passed" {
		next = "verified"
		if wantPhase == "verify" {
			if runner != "" {
				next = "tests_queued"
				steps = setStep(steps, "tests", "pending", "waiting for a sandboxed (fuzz) worker")
			}
			decoded, err := decodeFixFiles(res.Files)
			if err == nil && (!scm.ValidCommit(res.BaseCommit) || len(res.BaseCommit) < 40) {
				err = errors.New("invalid base commit")
			}
			for _, f := range decoded {
				if err == nil && !slices.Contains(changed, f.Path) {
					err = fmt.Errorf("the worker returned %s, which the diff does not change", f.Path)
				}
			}
			if err != nil {
				next, reason = "failed", "worker result rejected: "+err.Error()
			} else {
				files, _ = json.Marshal(res.Files)
			}
		}
	}
	if wantPhase == "verify" {
		if before, err = decodeReport(res.BeforeReportGzip); err == nil {
			after, err = decodeReport(res.AfterReportGzip)
		}
		if err != nil {
			httpx.WriteError(w, r, s.Log, httpx.BadRequest(err.Error()))
			return
		}
		if len(res.ScanEvidence) > 0 && json.Valid(res.ScanEvidence) && len(res.ScanEvidence) < 1<<20 {
			evidence = res.ScanEvidence
		}
	}
	if next == "failed" && reason == "" {
		reason = "verification failed"
	}
	stepsJSON, _ := json.Marshal(steps)
	log := ""
	if wantPhase == "test" {
		log = cleanText(clipLog(logging.RedactString(res.TestLog), maxAIFixTestLog))
	}
	_, err = s.DB.Exec(ctx, `UPDATE ai_fix_proposals SET status = $2, failure_reason = $3, steps = $4, leased_by = NULL, lease_expires_at = NULL,
		updated_at = now(), finished_at = CASE WHEN $2 IN ('verified', 'failed') THEN now() END,
		base_commit = CASE WHEN $5 = 'verify' THEN $6 ELSE base_commit END,
		scan_evidence = CASE WHEN $5 = 'verify' THEN $7::jsonb ELSE scan_evidence END,
		before_report_gzip = CASE WHEN $5 = 'verify' THEN $8 ELSE before_report_gzip END,
		after_report_gzip = CASE WHEN $5 = 'verify' THEN $9 ELSE after_report_gzip END,
		patched_files = CASE WHEN $10::jsonb IS NOT NULL THEN $10::jsonb ELSE patched_files END,
		test_log = CASE WHEN $5 = 'test' THEN $11 ELSE test_log END
		WHERE id = $1`, id, next, reason, stepsJSON, wantPhase, truncate(res.BaseCommit, 64), evidence, before, after, nullJSON(files), log)
	if err != nil {
		httpx.WriteError(w, r, s.Log, err)
		return
	}
	if next != "tests_queued" {
		_ = audit.Write(ctx, s.DB, audit.Entry{OrganizationID: wk.orgID, Action: "ai_fix." + next, TargetType: "finding", TargetID: findingID,
			Metadata: map[string]any{"ai_fix_id": id.String(), "phase": wantPhase, "worker": wk.Name, "reason": truncate(reason, 500)}})
	}
	s.Log.Info("AI fix verification result", "ai_fix_id", id, "phase", wantPhase, "status", next)
	w.WriteHeader(http.StatusNoContent)
}

func nullJSON(b []byte) any {
	if b == nil {
		return nil
	}
	return string(b)
}

// cleanText makes worker and AI text storable (valid UTF-8, no NUL).
func cleanText(s string) string {
	return strings.ToValidUTF8(strings.ReplaceAll(s, "\x00", ""), "\uFFFD")
}

// clipLog keeps the head and the tail of a long log.
func clipLog(s string, n int) string {
	if len(s) <= n {
		return s
	}
	half := n/2 - 40
	var b bytes.Buffer
	b.WriteString(s[:half])
	fmt.Fprintf(&b, "\n… [%d bytes omitted] …\n", len(s)-2*half)
	b.WriteString(s[len(s)-half:])
	return cleanText(b.String())
}
