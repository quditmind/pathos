// Package gates evaluates security gates at every stage of delivery (IDE,
// pre-commit, pull request, CI, release, deploy) against the
// organization's security policies, and records each decision.
//
// Rule 7 of the lifecycle design ("no blocking without policy") holds by
// construction and is enforced twice:
//
//   - a gate always references a security policy (the database refuses a
//     gate without one), and its mode (block, warn, require_approval) acts
//     only when that enabled policy matches the evidence;
//   - a decision of block or approval_required must carry at least one
//     policy id: Finalize downgrades any such decision without a policy to
//     pass with the reason "no_policy", and the database CHECK
//     gate_decisions_block_needs_policy refuses to store one anyway.
//
// With no gate (and, for pull requests and CI scans, no security policy
// with the block action) the decision is pass, recorded as "no_policy".
package gates

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"pathos/internal/monitoring"
	"pathos/internal/platform/httpx"
	"pathos/internal/policy"
)

// Stages, in delivery order.
const (
	StageIDE         = "ide"
	StagePreCommit   = "pre_commit"
	StagePullRequest = "pull_request"
	StageCI          = "ci"
	StageRelease     = "release"
	StageDeploy      = "deploy"
)

// Stages lists every stage.
var Stages = []string{StageIDE, StagePreCommit, StagePullRequest, StageCI, StageRelease, StageDeploy}

// Modes of a gate.
var Modes = []string{"block", "warn", "require_approval"}

// Outcomes of a decision, from the strongest.
const (
	OutcomeBlock            = "block"
	OutcomeApproval         = "approval_required"
	OutcomeWarn             = "warn"
	OutcomeExceptionApplied = "exception_applied"
	OutcomePass             = "pass"
)

var outcomeRank = map[string]int{OutcomeBlock: 5, OutcomeApproval: 4, OutcomeWarn: 3, OutcomeExceptionApplied: 2, OutcomePass: 1}

// Reason codes.
const (
	ReasonNoPolicy          = "no_policy"
	ReasonPolicyMatched     = "policy_matched"
	ReasonPolicyNotMatched  = "policy_not_matched"
	ReasonPolicyDisabled    = "policy_disabled"
	ReasonConditionNA       = "condition_unavailable"
	ReasonExceptionApplied  = "exception_applied"
	ReasonApprovalGranted   = "approval_granted"
	ReasonSecurityPolicy    = "security_policy_block"
	ReasonRule7Downgraded   = "no_policy_downgraded"
	maxSampleFindings       = 20
	openStatuses            = `('open', 'in_progress', 'needs_review')`
	docsURL                 = "/help/user-guide/remediation#security-gates"
	effectSkipped           = "skipped"
	implicitPolicyGateLabel = "Security policy (block action)"
)

// NormalizeStage accepts the stage names with hyphens too (pre-commit).
func NormalizeStage(s string) (string, bool) {
	s = strings.ReplaceAll(strings.ToLower(strings.TrimSpace(s)), "-", "_")
	return s, slices.Contains(Stages, s)
}

// Input is what a decision is evaluated for.
type Input struct {
	OrgID         uuid.UUID
	Stage         string
	RepositoryID  *uuid.UUID
	ApplicationID *uuid.UUID
	CommitSHA     string
	PullRequest   int
	ScanJobID     *uuid.UUID
	PRCheckID     *uuid.UUID
	RequestedBy   *uuid.UUID
	RequestID     string
}

// PolicyRef identifies a policy version.
type PolicyRef struct {
	ID      uuid.UUID `json:"id"`
	Name    string    `json:"name"`
	Version int       `json:"version"`
}

// GateResult is the evaluation of one gate (or of a security policy with
// the block action, which has no gate: ID nil).
type GateResult struct {
	ID          *uuid.UUID `json:"id"`
	Name        string     `json:"name"`
	Mode        string     `json:"mode"`
	Managed     bool       `json:"managed"`
	Matched     bool       `json:"matched"`
	Count       int        `json:"count"`
	Effect      string     `json:"effect"`
	Policy      PolicyRef  `json:"policy"`
	ExceptionID *uuid.UUID `json:"exception_id,omitempty"`
}

// Reason explains a decision.
type Reason struct {
	Code     string     `json:"code"`
	Message  string     `json:"message"`
	GateID   *uuid.UUID `json:"gate_id,omitempty"`
	PolicyID *uuid.UUID `json:"policy_id,omitempty"`
	Count    int        `json:"count,omitempty"`
}

// Evidence is what the decision looked at.
type Evidence struct {
	// Scope: new (findings first reported by the scan or the pull
	// request) or open (the repository's open findings).
	Scope      string         `json:"scope"`
	Total      int            `json:"total"`
	BySeverity map[string]int `json:"by_severity"`
	FindingIDs []uuid.UUID    `json:"finding_ids"`
	ScanJobID  *uuid.UUID     `json:"scan_job_id"`
	PRCheckID  *uuid.UUID     `json:"pr_check_id,omitempty"`
}

// ExceptionRef is an exception that applied to the decision.
type ExceptionRef struct {
	ID        uuid.UUID `json:"id"`
	Kind      string    `json:"kind"`
	Status    string    `json:"status"`
	ExpiresAt time.Time `json:"expires_at"`
}

// Decision is a recorded gate decision.
type Decision struct {
	ID               uuid.UUID      `json:"id"`
	Stage            string         `json:"stage"`
	Outcome          string         `json:"outcome"`
	RepositoryID     *uuid.UUID     `json:"repository_id"`
	RepositoryName   string         `json:"repository_name"`
	ApplicationID    *uuid.UUID     `json:"application_id"`
	ScanJobID        *uuid.UUID     `json:"scan_job_id"`
	CommitSHA        string         `json:"commit_sha"`
	PullRequest      *int           `json:"pull_request"`
	Gates            []GateResult   `json:"gates"`
	PolicyIDs        []uuid.UUID    `json:"policy_ids"`
	PolicyVersions   []int          `json:"policy_versions"`
	Reasons          []Reason       `json:"reasons"`
	Evidence         Evidence       `json:"evidence"`
	Exceptions       []ExceptionRef `json:"exceptions"`
	RequestedByEmail string         `json:"requested_by_email"`
	CreatedAt        time.Time      `json:"created_at"`
	DocsURL          string         `json:"docs_url"`
}

// Blocks reports whether the decision stops the stage.
func (d Decision) Blocks() bool { return d.Outcome == OutcomeBlock || d.Outcome == OutcomeApproval }

// ErrEvidenceIncomplete: the scan the decision needs has not finished or
// did not succeed (PTH-GATE-1107). It is an error, never a block.
var ErrEvidenceIncomplete = httpx.E(http.StatusConflict, "gate_evidence_incomplete",
	"the scan this gate needs has not finished or did not succeed; no decision was recorded").WithDiag("PTH-GATE-1107")

// Strongest returns the stronger of two outcomes.
func Strongest(a, b string) string {
	if outcomeRank[b] > outcomeRank[a] {
		return b
	}
	return a
}

// EffectOf maps a matched gate's mode to its effect.
func EffectOf(mode string) string {
	switch mode {
	case "block":
		return OutcomeBlock
	case "require_approval":
		return OutcomeApproval
	case "warn":
		return OutcomeWarn
	}
	return OutcomePass
}

// Finalize computes the outcome, the policy ids and the closing reasons of
// a decision from its gate results. It is the service-side check of rule
// 7: a blocking outcome without a policy id becomes pass ("no_policy").
func Finalize(d *Decision) {
	d.Outcome = OutcomePass
	d.PolicyIDs, d.PolicyVersions = []uuid.UUID{}, []int{}
	for _, g := range d.Gates {
		if g.Effect == "" || g.Effect == effectSkipped || g.Effect == OutcomePass {
			continue
		}
		d.Outcome = Strongest(d.Outcome, g.Effect)
		if g.Policy.ID != uuid.Nil && !slices.Contains(d.PolicyIDs, g.Policy.ID) {
			d.PolicyIDs = append(d.PolicyIDs, g.Policy.ID)
			d.PolicyVersions = append(d.PolicyVersions, g.Policy.Version)
		}
	}
	if d.Blocks() && len(d.PolicyIDs) == 0 {
		d.Outcome = OutcomePass
		d.Reasons = append(d.Reasons, Reason{Code: ReasonRule7Downgraded,
			Message: "a blocking result without a policy is not allowed (rule 7); the decision is pass"})
	}
	active := 0
	for _, g := range d.Gates {
		if g.Effect != effectSkipped {
			active++
		}
	}
	if active == 0 {
		d.Reasons = append(d.Reasons, Reason{Code: ReasonNoPolicy,
			Message: "no security gate or blocking security policy applies to this stage; the decision is pass"})
	}
}

// --- evaluation --------------------------------------------------------------

type source struct {
	scope  string
	from   string // FROM ... WHERE base (placeholders $1..$n of args)
	args   []any
	cols   policy.Columns
	idExpr string
	sev    string
}

type gateRow struct {
	id              uuid.UUID
	name, mode      string
	allowExceptions bool
	repositoryID    *uuid.UUID
	managed         bool
	pol             PolicyRef
	polEnabled      bool
	conditions      policy.Conditions
}

// Evaluate evaluates the gates of a stage and records the decision in tx.
func Evaluate(ctx context.Context, tx pgx.Tx, in Input) (Decision, error) {
	stage, ok := NormalizeStage(in.Stage)
	if !ok {
		return Decision{}, httpx.BadRequest("stage must be one of " + strings.Join(Stages, ", "))
	}
	d := Decision{ID: uuid.Must(uuid.NewV7()), Stage: stage, RepositoryID: in.RepositoryID, ApplicationID: in.ApplicationID,
		ScanJobID: in.ScanJobID, CommitSHA: in.CommitSHA, Gates: []GateResult{}, Reasons: []Reason{}, Exceptions: []ExceptionRef{},
		DocsURL: docsURL}
	if in.PullRequest > 0 {
		pr := in.PullRequest
		d.PullRequest = &pr
	}
	// The repositories in scope.
	var repos []uuid.UUID
	switch {
	case in.RepositoryID != nil:
		var app *uuid.UUID
		if err := tx.QueryRow(ctx, `SELECT application_id, COALESCE(NULLIF(display_name, ''), full_name) FROM repositories
			WHERE organization_id = $1 AND id = $2`, in.OrgID, *in.RepositoryID).Scan(&app, &d.RepositoryName); err != nil {
			return d, err
		}
		repos = []uuid.UUID{*in.RepositoryID}
		if d.ApplicationID == nil {
			d.ApplicationID = app
		}
	case in.ApplicationID != nil:
		rows, err := tx.Query(ctx, `SELECT id FROM repositories WHERE organization_id = $1 AND application_id = $2 AND archived_at IS NULL`,
			in.OrgID, *in.ApplicationID)
		if err != nil {
			return d, err
		}
		if repos, err = pgx.CollectRows(rows, pgx.RowTo[uuid.UUID]); err != nil {
			return d, err
		}
	default:
		return d, httpx.BadRequest("repository_id or application_id is required")
	}
	if repos == nil {
		repos = []uuid.UUID{}
	}

	src, implicit, err := evidenceSource(ctx, tx, in, stage, repos, &d)
	if err != nil {
		return d, err
	}
	if err := collectEvidence(ctx, tx, src, &d); err != nil {
		return d, err
	}
	// Security policies with the block action fail pull requests and CI
	// scans by themselves (their documented meaning since 2.0).
	for _, h := range implicit {
		d.Gates = append(d.Gates, GateResult{Name: implicitPolicyGateLabel, Mode: "block", Matched: true, Effect: OutcomeBlock,
			Policy: PolicyRef(h)})
		pid := h.ID
		d.Reasons = append(d.Reasons, Reason{Code: ReasonSecurityPolicy, PolicyID: &pid,
			Message: "blocked by security policy " + h.Name + " (block action)"})
	}

	gates, err := loadGates(ctx, tx, in.OrgID, stage, repos, d.ApplicationID)
	if err != nil {
		return d, err
	}
	if _, err := tx.Exec(ctx, `UPDATE gate_exceptions SET status = 'expired'
		WHERE organization_id = $1 AND status IN ('requested', 'approved') AND expires_at <= now()`, in.OrgID); err != nil {
		return d, err
	}
	for _, g := range gates {
		gid, pid := g.id, g.pol.ID
		res := GateResult{ID: &gid, Name: g.name, Mode: g.mode, Managed: g.managed, Policy: g.pol}
		if !g.polEnabled {
			res.Effect = effectSkipped
			d.Reasons = append(d.Reasons, Reason{Code: ReasonPolicyDisabled, GateID: &gid, PolicyID: &pid,
				Message: fmt.Sprintf("gate %q skipped: its policy %q is disabled", g.name, g.pol.Name)})
			d.Gates = append(d.Gates, res)
			continue
		}
		n, sample, err := countMatches(ctx, tx, src, g)
		if err != nil {
			var na conditionError
			if errors.As(err, &na) {
				res.Effect = effectSkipped
				d.Reasons = append(d.Reasons, Reason{Code: ReasonConditionNA, GateID: &gid, PolicyID: &pid,
					Message: fmt.Sprintf("gate %q skipped: %s at the %s stage", g.name, na.Error(), stage)})
				d.Gates = append(d.Gates, res)
				continue
			}
			return d, err
		}
		res.Count, res.Matched = n, n > 0
		if !res.Matched {
			res.Effect = OutcomePass
			d.Reasons = append(d.Reasons, Reason{Code: ReasonPolicyNotMatched, GateID: &gid, PolicyID: &pid,
				Message: fmt.Sprintf("policy %q matched no finding", g.pol.Name)})
			d.Gates = append(d.Gates, res)
			continue
		}
		res.Effect = EffectOf(g.mode)
		for _, id := range sample {
			if len(d.Evidence.FindingIDs) < maxSampleFindings && !slices.Contains(d.Evidence.FindingIDs, id) {
				d.Evidence.FindingIDs = append(d.Evidence.FindingIDs, id)
			}
		}
		d.Reasons = append(d.Reasons, Reason{Code: ReasonPolicyMatched, GateID: &gid, PolicyID: &pid, Count: n,
			Message: fmt.Sprintf("policy %q matched %d finding(s); gate %q: %s", g.pol.Name, n, g.name, strings.ReplaceAll(g.mode, "_", " "))})
		if (res.Effect == OutcomeBlock || res.Effect == OutcomeApproval) && (g.allowExceptions || res.Effect == OutcomeApproval) {
			ex, err := findException(ctx, tx, in.OrgID, g.id, repos, d.ApplicationID, in.CommitSHA, in.PullRequest, res.Effect)
			if err != nil {
				return d, err
			}
			if ex != nil {
				exID := ex.ID
				res.Effect, res.ExceptionID = OutcomeExceptionApplied, &exID
				d.Exceptions = append(d.Exceptions, *ex)
				code, what := ReasonExceptionApplied, "exception"
				if ex.Kind == "approval" {
					code, what = ReasonApprovalGranted, "approval"
				}
				d.Reasons = append(d.Reasons, Reason{Code: code, GateID: &gid, PolicyID: &pid,
					Message: fmt.Sprintf("approved %s %s applies until %s", what, ex.ID, ex.ExpiresAt.UTC().Format(time.RFC3339))})
			}
		}
		d.Gates = append(d.Gates, res)
	}
	Finalize(&d)
	if err := insert(ctx, tx, in, &d); err != nil {
		return d, err
	}
	if err := developerFeedback(ctx, tx, in, &d); err != nil {
		return d, err
	}
	return d, nil
}

// developerFeedback is feedback loop 6 (PATHOS 3.0 M9, flag
// continuous_monitoring): a decision that blocks or requires approval —
// which, by rule 7, always names the policies that decided — notifies the
// developers through the existing channels (event gate.failed: in-app and
// e-mail rules, outbound webhooks; pull requests also get the check
// result) and appears in the monitoring feed. A decision without a policy
// never blocks, so it never produces feedback.
func developerFeedback(ctx context.Context, tx pgx.Tx, in Input, d *Decision) error {
	if !d.Blocks() || len(d.PolicyIDs) == 0 {
		return nil
	}
	on, err := monitoring.Enabled(ctx, tx, in.OrgID)
	if err != nil || !on {
		return err
	}
	var names []string
	for _, g := range d.Gates {
		if (g.Effect == OutcomeBlock || g.Effect == OutcomeApproval) && g.Policy.Name != "" && !slices.Contains(names, g.Policy.Name) {
			names = append(names, g.Policy.Name)
		}
	}
	policies := `"` + strings.Join(names, `", "`) + `"`
	if len(names) == 0 {
		policies = fmt.Sprintf("%d", len(d.PolicyIDs))
	}
	top := ""
	for _, sv := range []string{"critical", "high", "medium", "low", "info"} {
		if d.Evidence.BySeverity[sv] > 0 {
			top = sv
			break
		}
	}
	var sev *string
	if top != "" {
		sev = &top
	}
	pr := 0
	if d.PullRequest != nil {
		pr = *d.PullRequest
	}
	payload := map[string]any{"stage": d.Stage, "outcome": d.Outcome, "policies": policies, "policy_ids": d.PolicyIDs,
		"commit": d.CommitSHA, "pull_request": pr, "count": d.Evidence.Total, "decision_id": d.ID}
	if in.RequestedBy != nil {
		payload["requested_by"] = *in.RequestedBy
	}
	if _, err := tx.Exec(ctx, `INSERT INTO notification_events (organization_id, event_key, repository_id, severity, subject_id, payload)
		VALUES ($1, 'gate.failed', $2, $3, $4, $5)`, in.OrgID, d.RepositoryID, sev, d.ID, payload); err != nil {
		return err
	}
	evSev := top
	if evSev == "" {
		evSev = "medium"
	}
	where := d.Stage
	if pr > 0 {
		where = fmt.Sprintf("pull request #%d", pr)
	}
	did := d.ID
	_, err = monitoring.Record(ctx, tx, monitoring.Event{OrgID: in.OrgID, ApplicationID: d.ApplicationID, RepositoryID: d.RepositoryID,
		Type: monitoring.TypeGateFailed, Severity: evSev,
		Title:         fmt.Sprintf("Gate %s at %s (policy %s)", strings.ReplaceAll(d.Outcome, "_", " "), where, policies),
		Summary:       fmt.Sprintf("%d matching finding(s). Developers were notified in PATHOS and through subscribed webhooks; pull requests also show the check result.", d.Evidence.Total),
		EvidenceLabel: monitoring.EvidenceVerified,
		Evidence:      map[string]any{"gate_decision_id": d.ID, "policy_ids": d.PolicyIDs, "commit": d.CommitSHA, "scan_job_id": d.ScanJobID},
		SubjectType:   "gate_decision", SubjectID: &did,
		Details: map[string]any{"stage": d.Stage, "outcome": d.Outcome, "by_severity": d.Evidence.BySeverity, "pull_request": pr}})
	return err
}

// evidenceSource chooses the findings the gates look at and the security
// policies that block by themselves.
func evidenceSource(ctx context.Context, tx pgx.Tx, in Input, stage string, repos []uuid.UUID, d *Decision) (source, []policy.PolicyHit, error) {
	checkID := in.PRCheckID
	if stage == StagePullRequest && checkID == nil && len(repos) == 1 && (in.ScanJobID != nil || in.PullRequest > 0) {
		// The latest finished check of the pull request (or of the scan).
		var id uuid.UUID
		err := tx.QueryRow(ctx, `SELECT c.id FROM pr_checks c WHERE c.organization_id = $1 AND c.repository_id = $2
			AND ($3::uuid IS NULL OR c.scan_job_id = $3) AND ($4 = 0 OR c.pull_request = $4) AND ($5 = '' OR c.head_sha = $5)
			AND c.finished_at IS NOT NULL ORDER BY c.created_at DESC LIMIT 1`,
			in.OrgID, repos[0], in.ScanJobID, in.PullRequest, in.CommitSHA).Scan(&id)
		if errors.Is(err, pgx.ErrNoRows) {
			return source{}, nil, ErrEvidenceIncomplete
		}
		if err != nil {
			return source{}, nil, err
		}
		checkID = &id
	}
	if stage == StagePullRequest && checkID != nil {
		var job uuid.UUID
		if err := tx.QueryRow(ctx, `SELECT scan_job_id FROM pr_checks WHERE organization_id = $1 AND id = $2`, in.OrgID, *checkID).Scan(&job); err != nil {
			return source{}, nil, err
		}
		d.ScanJobID = &job
		d.Evidence.PRCheckID = checkID
		var hits []policy.PolicyHit
		var err error
		if in.PRCheckID != nil {
			// Live evaluation of a finishing check: records the policies on
			// the PR findings.
			hits, err = policy.EvaluatePRPolicies(ctx, tx, in.OrgID, *checkID)
		} else {
			hits, err = prPolicyHits(ctx, tx, *checkID)
		}
		if err != nil {
			return source{}, nil, err
		}
		return source{scope: "new", from: `pr_findings pf JOIN pr_checks c ON c.id = pf.pr_check_id JOIN repositories r ON r.id = c.repository_id
			WHERE c.organization_id = $1 AND c.id = $2 AND pf.is_new`, args: []any{in.OrgID, *checkID}, cols: policy.PRColumns,
			idExpr: "pf.id", sev: "pf.severity"}, hits, nil
	}
	if in.ScanJobID != nil {
		var status string
		var repo uuid.UUID
		err := tx.QueryRow(ctx, `SELECT status, repository_id FROM scan_jobs WHERE organization_id = $1 AND id = $2`, in.OrgID, *in.ScanJobID).Scan(&status, &repo)
		if err != nil {
			return source{}, nil, err
		}
		if !slices.Contains(repos, repo) {
			return source{}, nil, httpx.BadRequest("scan_id does not belong to the repository")
		}
		if status != "succeeded" && status != "partial" {
			return source{}, nil, ErrEvidenceIncomplete
		}
		var hits []policy.PolicyHit
		if stage == StageCI {
			if hits, err = policy.BlockingPolicies(ctx, tx, *in.ScanJobID); err != nil {
				return source{}, nil, err
			}
		}
		return source{scope: "new", from: `findings f JOIN repositories r ON r.id = f.repository_id
			WHERE f.organization_id = $1 AND f.first_scan_job_id = $2 AND f.status IN ` + openStatuses,
			args: []any{in.OrgID, *in.ScanJobID}, cols: policy.FindingColumns, idExpr: "f.id", sev: "f.severity"}, hits, nil
	}
	return source{scope: "open", from: `findings f JOIN repositories r ON r.id = f.repository_id
		WHERE f.organization_id = $1 AND f.repository_id = ANY($2::uuid[]) AND f.status IN ` + openStatuses + ` AND r.archived_at IS NULL`,
		args: []any{in.OrgID, repos}, cols: policy.FindingColumns, idExpr: "f.id", sev: "f.severity"}, nil, nil
}

// prPolicyHits reads the blocking policies already recorded on a finished
// check's new findings.
func prPolicyHits(ctx context.Context, tx pgx.Tx, checkID uuid.UUID) ([]policy.PolicyHit, error) {
	rows, err := tx.Query(ctx, `SELECT DISTINCT p.id, p.name, p.version FROM pr_findings pf
		JOIN security_policies p ON p.id = ANY(pf.policy_ids) AND p.enabled AND p.managed_by = '' AND (p.actions->>'block')::boolean
		WHERE pf.pr_check_id = $1 AND pf.is_new ORDER BY 2`, checkID)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, func(r pgx.CollectableRow) (policy.PolicyHit, error) {
		var h policy.PolicyHit
		return h, r.Scan(&h.ID, &h.Name, &h.Version)
	})
}

func collectEvidence(ctx context.Context, tx pgx.Tx, src source, d *Decision) error {
	d.Evidence.Scope = src.scope
	d.Evidence.BySeverity = map[string]int{"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
	d.Evidence.FindingIDs = []uuid.UUID{}
	if d.Evidence.ScanJobID == nil {
		d.Evidence.ScanJobID = d.ScanJobID
	}
	rows, err := tx.Query(ctx, `SELECT `+src.sev+`, count(*) FROM `+src.from+` GROUP BY 1`, src.args...)
	if err != nil {
		return err
	}
	for rows.Next() {
		var sev string
		var n int
		if err := rows.Scan(&sev, &n); err != nil {
			rows.Close()
			return err
		}
		d.Evidence.BySeverity[sev] += n
		d.Evidence.Total += n
	}
	rows.Close()
	return rows.Err()
}

type conditionError struct{ err error }

func (c conditionError) Error() string { return c.err.Error() }

// countMatches counts the evidence rows the gate's policy matches and
// returns a sample of their ids.
func countMatches(ctx context.Context, tx pgx.Tx, src source, g gateRow) (int, []uuid.UUID, error) {
	args := append([]any(nil), src.args...)
	where, err := policy.Where(g.conditions, src.cols, &args)
	if err != nil {
		return 0, nil, conditionError{err}
	}
	q := `SELECT ` + src.idExpr + `, count(*) OVER () FROM ` + src.from + ` AND ` + where
	if g.repositoryID != nil {
		args = append(args, *g.repositoryID)
		q += fmt.Sprintf(" AND r.id = $%d", len(args))
	}
	rows, err := tx.Query(ctx, q+` ORDER BY 1 LIMIT `+fmt.Sprint(maxSampleFindings), args...)
	if err != nil {
		return 0, nil, err
	}
	defer rows.Close()
	var n int
	ids := []uuid.UUID{}
	for rows.Next() {
		var id uuid.UUID
		if err := rows.Scan(&id, &n); err != nil {
			return 0, nil, err
		}
		ids = append(ids, id)
	}
	return n, ids, rows.Err()
}

func loadGates(ctx context.Context, tx pgx.Tx, orgID uuid.UUID, stage string, repos []uuid.UUID, app *uuid.UUID) ([]gateRow, error) {
	rows, err := tx.Query(ctx, `SELECT g.id, g.name, g.mode, g.allow_exceptions, g.repository_id, g.managed,
		p.id, p.name, p.version, p.enabled, p.conditions
		FROM security_gates g JOIN security_policies p ON p.id = g.policy_id
		WHERE g.organization_id = $1 AND g.stage = $2 AND g.enabled
		  AND (g.repository_id IS NULL OR g.repository_id = ANY($3::uuid[]))
		  AND (g.application_id IS NULL OR g.application_id = $4)
		ORDER BY g.created_at, g.id`, orgID, stage, repos, app)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, func(r pgx.CollectableRow) (gateRow, error) {
		var g gateRow
		var cond []byte
		if err := r.Scan(&g.id, &g.name, &g.mode, &g.allowExceptions, &g.repositoryID, &g.managed,
			&g.pol.ID, &g.pol.Name, &g.pol.Version, &g.polEnabled, &cond); err != nil {
			return g, err
		}
		return g, json.Unmarshal(cond, &g.conditions)
	})
}

// findException returns an approved, unexpired exception (or approval for a
// require_approval gate) whose scope covers the evaluation.
func findException(ctx context.Context, tx pgx.Tx, orgID, gateID uuid.UUID, repos []uuid.UUID, app *uuid.UUID, commit string, pr int, effect string) (*ExceptionRef, error) {
	kind := "exception"
	if effect == OutcomeApproval {
		kind = "approval"
	}
	var ex ExceptionRef
	err := tx.QueryRow(ctx, `SELECT id, kind, status, expires_at FROM gate_exceptions
		WHERE organization_id = $1 AND gate_id = $2 AND status = 'approved' AND expires_at > now() AND kind = $3
		  AND (repository_id = ANY($4::uuid[]) OR (repository_id IS NULL AND application_id = $5))
		  AND (NOT scope ? 'commit_sha' OR scope->>'commit_sha' = $6)
		  AND (NOT scope ? 'pull_request' OR (scope->>'pull_request')::int = $7)
		ORDER BY expires_at DESC LIMIT 1`, orgID, gateID, kind, repos, app, commit, pr).Scan(&ex.ID, &ex.Kind, &ex.Status, &ex.ExpiresAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &ex, nil
}

func insert(ctx context.Context, tx pgx.Tx, in Input, d *Decision) error {
	gateIDs := []uuid.UUID{}
	for _, g := range d.Gates {
		if g.ID != nil {
			gateIDs = append(gateIDs, *g.ID)
		}
	}
	gatesJSON, _ := json.Marshal(d.Gates)
	reasons, _ := json.Marshal(d.Reasons)
	evidence, _ := json.Marshal(d.Evidence)
	var pr *int
	if in.PullRequest > 0 {
		pr = &in.PullRequest
	}
	return tx.QueryRow(ctx, `INSERT INTO gate_decisions (id, organization_id, stage, repository_id, application_id, scan_job_id, pr_check_id,
		commit_sha, pull_request, outcome, gate_ids, policy_ids, policy_versions, gates, reasons, evidence, requested_by, request_id)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18) RETURNING created_at`,
		d.ID, in.OrgID, d.Stage, d.RepositoryID, d.ApplicationID, d.ScanJobID, d.Evidence.PRCheckID, truncate(d.CommitSHA, 64), pr,
		d.Outcome, gateIDs, d.PolicyIDs, d.PolicyVersions, gatesJSON, reasons, evidence, in.RequestedBy, truncate(in.RequestID, 100)).Scan(&d.CreatedAt)
}

func truncate(s string, n int) string {
	if len(s) > n {
		return s[:n]
	}
	return s
}
