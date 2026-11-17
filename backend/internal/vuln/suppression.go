package vuln

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"pathos/internal/audit"
	"pathos/internal/authz"
	"pathos/internal/platform/db"
	"pathos/internal/platform/httpx"
)

// Suppression rules: governed, expiring decisions that apply to every
// finding matching a pattern (a rule ID in test code, a vendored path, a
// package an advisory does not affect), instead of one finding at a time.
//
// Safeguards (findings are never hidden or deleted):
//   - a rule is proposed with a justification and an expiry (at most one
//     year) and takes effect only when a different person approves it
//   - matching findings get the status the rule decides (accepted risk or
//     false positive) through the normal lifecycle, with the rule and the
//     approver in their status history; evidence is untouched
//   - findings detected later that match an active rule get the same
//     decision when their scan finishes
//   - at expiry or revocation every finding the rule decided reopens
//   - a rule needs at least one specific criterion (rule ID, path, package
//     or CVE), so a category or scanner alone cannot be suppressed

// SuppressionRule is a rule with its state.
type SuppressionRule struct {
	ID            uuid.UUID  `json:"id"`
	Name          string     `json:"name"`
	ScopeType     string     `json:"scope_type"` // organization | application | repository
	ScopeID       *uuid.UUID `json:"scope_id"`
	ScopeName     *string    `json:"scope_name"`
	MatchRuleID   string     `json:"match_rule_id"`
	MatchPath     string     `json:"match_path"`
	MatchPackage  string     `json:"match_package"`
	MatchCVE      string     `json:"match_cve"`
	MatchScanner  string     `json:"match_scanner"`
	MatchCategory string     `json:"match_category"`
	Decision      string     `json:"decision"` // accepted_risk | false_positive
	Justification string     `json:"justification"`
	ExpiresAt     time.Time  `json:"expires_at"`
	Status        string     `json:"status"` // pending | active | rejected | revoked | expired | withdrawn
	RequestedBy   *string    `json:"requested_by"`
	RequestedByID uuid.UUID  `json:"requested_by_id"`
	RequestedAt   time.Time  `json:"requested_at"`
	DecidedBy     *string    `json:"decided_by"`
	DecidedAt     *time.Time `json:"decided_at"`
	DecisionNote  string     `json:"decision_note"`
	Findings      int        `json:"findings"` // currently decided by the rule
}

const ruleSelect = `
	SELECT s.id, s.name, s.scope_type, s.scope_id, COALESCE(a.name, COALESCE(NULLIF(r.display_name, ''), r.full_name)),
	       s.match_rule_id, s.match_path, s.match_package, s.match_cve, s.match_scanner, s.match_category, s.decision, s.justification,
	       s.expires_at, s.status, COALESCE(NULLIF(ru.display_name, ''), ru.email), s.requested_by, s.requested_at,
	       COALESCE(NULLIF(du.display_name, ''), du.email), s.decided_at, s.decision_note,
	       (SELECT count(*) FROM findings f WHERE f.suppression_rule_id = s.id)
	FROM suppression_rules s
	LEFT JOIN applications a ON s.scope_type = 'application' AND a.id = s.scope_id
	LEFT JOIN repositories r ON s.scope_type = 'repository' AND r.id = s.scope_id
	LEFT JOIN users ru ON ru.id = s.requested_by LEFT JOIN users du ON du.id = s.decided_by`

func scanRule(row pgx.Row) (SuppressionRule, error) {
	var x SuppressionRule
	err := row.Scan(&x.ID, &x.Name, &x.ScopeType, &x.ScopeID, &x.ScopeName, &x.MatchRuleID, &x.MatchPath, &x.MatchPackage, &x.MatchCVE,
		&x.MatchScanner, &x.MatchCategory, &x.Decision, &x.Justification, &x.ExpiresAt, &x.Status, &x.RequestedBy, &x.RequestedByID,
		&x.RequestedAt, &x.DecidedBy, &x.DecidedAt, &x.DecisionNote, &x.Findings)
	if errors.Is(err, pgx.ErrNoRows) {
		return x, errNotFound
	}
	return x, err
}

func (s *Service) registerSuppression(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/v1/suppression-rules", s.listRules)
	mux.HandleFunc("POST /api/v1/suppression-rules", s.createRule)
	mux.HandleFunc("POST /api/v1/suppression-rules/preview", s.previewRule)
	mux.HandleFunc("POST /api/v1/suppression-rules/{id}/{action}", s.decideRule)
}

// globLike turns a glob (* and ?) into a LIKE pattern.
func globLike(g string) string {
	r := strings.NewReplacer(`\`, `\\`, `%`, `\%`, `_`, `\_`, `*`, `%`, `?`, `_`)
	return r.Replace(g)
}

// matchSQL is the condition (alias f, repositories r) of a rule's criteria;
// placeholders start at first.
func matchSQL(x SuppressionRule, first int) (string, []any) {
	var conds []string
	var args []any
	add := func(c string, v any) {
		args = append(args, v)
		conds = append(conds, strings.ReplaceAll(c, "?", fmt.Sprintf("$%d", first+len(args)-1)))
	}
	if x.MatchRuleID != "" {
		add(`f.rule_id LIKE ?`, globLike(x.MatchRuleID))
	}
	if x.MatchPath != "" {
		add(`f.file_path LIKE ?`, globLike(x.MatchPath))
	}
	if x.MatchPackage != "" {
		add(`lower(f.package_name) = lower(?)`, x.MatchPackage)
	}
	if x.MatchCVE != "" {
		add(`f.cve = ?`, x.MatchCVE)
	}
	if x.MatchScanner != "" {
		add(`? = ANY(f.scanner_keys)`, x.MatchScanner)
	}
	if x.MatchCategory != "" {
		add(`f.category = ?`, x.MatchCategory)
	}
	switch x.ScopeType {
	case "application":
		add(`r.application_id = ?`, *x.ScopeID)
	case "repository":
		add(`f.repository_id = ?`, *x.ScopeID)
	}
	return strings.Join(conds, " AND "), args
}

type ruleRequest struct {
	Name          string     `json:"name"`
	ScopeType     string     `json:"scope_type"`
	ScopeID       *uuid.UUID `json:"scope_id"`
	MatchRuleID   string     `json:"match_rule_id"`
	MatchPath     string     `json:"match_path"`
	MatchPackage  string     `json:"match_package"`
	MatchCVE      string     `json:"match_cve"`
	MatchScanner  string     `json:"match_scanner"`
	MatchCategory string     `json:"match_category"`
	Decision      string     `json:"decision"`
	Justification string     `json:"justification"`
	ExpiresAt     time.Time  `json:"expires_at"`
}

func (req ruleRequest) rule() (SuppressionRule, error) {
	x := SuppressionRule{Name: strings.TrimSpace(req.Name), ScopeType: req.ScopeType, ScopeID: req.ScopeID,
		MatchRuleID: strings.TrimSpace(req.MatchRuleID), MatchPath: strings.TrimSpace(req.MatchPath), MatchPackage: strings.TrimSpace(req.MatchPackage),
		MatchCVE: strings.ToUpper(strings.TrimSpace(req.MatchCVE)), MatchScanner: strings.TrimSpace(req.MatchScanner),
		MatchCategory: strings.TrimSpace(req.MatchCategory), Decision: req.Decision, Justification: strings.TrimSpace(req.Justification),
		ExpiresAt: req.ExpiresAt}
	switch {
	case x.Name == "" || len(x.Name) > 200:
		return x, httpx.BadRequest("a name of at most 200 characters is required")
	case x.ScopeType != "organization" && x.ScopeType != "application" && x.ScopeType != "repository":
		return x, httpx.BadRequest("scope_type must be organization, application or repository")
	case x.ScopeType != "organization" && x.ScopeID == nil:
		return x, httpx.BadRequest("scope_id is required for an application or repository scope")
	case x.MatchRuleID == "" && x.MatchPath == "" && x.MatchPackage == "" && x.MatchCVE == "":
		return x, httpx.BadRequest("give at least a rule ID, a path, a package or a CVE: a category or scanner alone is too broad")
	case strings.Trim(x.MatchRuleID+x.MatchPath, "*?/.") == "" && x.MatchPackage == "" && x.MatchCVE == "":
		return x, httpx.BadRequest("the pattern matches everything")
	case x.Decision != "accepted_risk" && x.Decision != "false_positive":
		return x, httpx.BadRequest("decision must be accepted_risk or false_positive")
	case len(x.Justification) < 20 || len(x.Justification) > 4000:
		return x, httpx.BadRequest("a justification of 20 to 4000 characters is required")
	case !x.ExpiresAt.After(time.Now()) || x.ExpiresAt.After(time.Now().AddDate(1, 0, 1)):
		return x, httpx.BadRequest("the expiry must be in the future and at most one year away")
	}
	for _, v := range []string{x.MatchRuleID, x.MatchPath, x.MatchPackage, x.MatchCVE, x.MatchScanner, x.MatchCategory} {
		if len(v) > 300 {
			return x, httpx.BadRequest("match criteria are limited to 300 characters")
		}
	}
	if x.ScopeType == "organization" {
		x.ScopeID = nil
	}
	return x, nil
}

// canOnScope checks perm on a rule's scope: organization and application
// rules need it organization-wide, repository rules on the repository.
func (s *Service) canOnScope(ctx context.Context, p *authz.Principal, perm authz.Permission, x SuppressionRule) error {
	switch x.ScopeType {
	case "repository":
		err := s.Authz.Require(ctx, p, perm, authz.Scope{Type: authz.ScopeRepository, ID: *x.ScopeID})
		if errors.Is(err, authz.ErrForbidden) && !p.HasAnywhere(perm) {
			return err
		}
		if err != nil {
			return errNotFound
		}
		return nil
	default:
		if !p.HasOrgWide(perm) {
			return authz.ErrForbidden
		}
		return nil
	}
}

func (s *Service) matchCount(ctx context.Context, q db.Querier, orgID uuid.UUID, x SuppressionRule) (int, error) {
	cond, args := matchSQL(x, 2)
	var n int
	// #nosec G202 -- cond is built from placeholders
	err := q.QueryRow(ctx, `SELECT count(*) FROM findings f JOIN repositories r ON r.id = f.repository_id
		WHERE f.organization_id = $1 AND f.status IN ('open', 'in_progress', 'needs_review') AND `+cond, append([]any{orgID}, args...)...).Scan(&n)
	return n, err
}

func (s *Service) previewRule(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	p := s.Principal(ctx)
	var req ruleRequest
	if err := httpx.DecodeJSON(w, r, &req); err != nil {
		s.fail(w, r, err)
		return
	}
	if req.ExpiresAt.IsZero() {
		req.ExpiresAt = time.Now().AddDate(0, 3, 0)
	}
	if req.Justification == "" {
		req.Justification = strings.Repeat("x", 20)
	}
	if req.Name == "" {
		req.Name = "preview"
	}
	x, err := req.rule()
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if err := s.canOnScope(ctx, p, authz.PermFindingsTriage, x); err != nil {
		s.fail(w, r, err)
		return
	}
	n, err := s.matchCount(ctx, s.DB, p.OrganizationID, x)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	cond, args := matchSQL(x, 2)
	// #nosec G202 -- cond is built from placeholders
	rows, err := s.DB.Query(ctx, `SELECT f.id, f.title, f.severity, f.file_path, COALESCE(NULLIF(r.display_name, ''), r.full_name)
		FROM findings f JOIN repositories r ON r.id = f.repository_id
		WHERE f.organization_id = $1 AND f.status IN ('open', 'in_progress', 'needs_review') AND `+cond+`
		ORDER BY f.risk_score DESC NULLS LAST LIMIT 20`, append([]any{p.OrganizationID}, args...)...)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	type sample struct {
		ID         uuid.UUID `json:"id"`
		Title      string    `json:"title"`
		Severity   string    `json:"severity"`
		FilePath   string    `json:"file_path"`
		Repository string    `json:"repository_name"`
	}
	samples, err := pgx.CollectRows(rows, func(row pgx.CollectableRow) (sample, error) {
		var x sample
		return x, row.Scan(&x.ID, &x.Title, &x.Severity, &x.FilePath, &x.Repository)
	})
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if samples == nil {
		samples = []sample{}
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"matching_open_findings": n, "examples": samples})
}

func (s *Service) createRule(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	p := s.Principal(ctx)
	var req ruleRequest
	if err := httpx.DecodeJSON(w, r, &req); err != nil {
		s.fail(w, r, err)
		return
	}
	x, err := req.rule()
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if err := s.canOnScope(ctx, p, authz.PermFindingsTriage, x); err != nil {
		s.fail(w, r, err)
		return
	}
	id := uuid.Must(uuid.NewV7())
	err = db.InTx(ctx, s.DB, func(tx pgx.Tx) error {
		if x.ScopeType == "application" {
			var ok bool
			if err := tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM applications WHERE organization_id = $1 AND id = $2)`, p.OrganizationID, *x.ScopeID).
				Scan(&ok); err != nil || !ok {
				return httpx.BadRequest("unknown application")
			}
		}
		if _, err := tx.Exec(ctx, `INSERT INTO suppression_rules (id, organization_id, name, scope_type, scope_id, match_rule_id, match_path,
			match_package, match_cve, match_scanner, match_category, decision, justification, expires_at, requested_by)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15)`,
			id, p.OrganizationID, x.Name, x.ScopeType, x.ScopeID, x.MatchRuleID, x.MatchPath, x.MatchPackage, x.MatchCVE, x.MatchScanner,
			x.MatchCategory, x.Decision, x.Justification, x.ExpiresAt, p.UserID); err != nil {
			return err
		}
		return audit.Write(ctx, tx, audit.Entry{OrganizationID: p.OrganizationID, ActorID: &p.UserID, ActorEmail: p.Email,
			Action: "suppression_rule.request", TargetType: "suppression_rule", TargetID: id.String(),
			Metadata: map[string]any{"name": x.Name, "scope": x.ScopeType, "decision": x.Decision, "expires_at": x.ExpiresAt}})
	})
	if err != nil {
		s.fail(w, r, err)
		return
	}
	out, err := scanRule(s.DB.QueryRow(ctx, ruleSelect+` WHERE s.id = $1`, id))
	if err != nil {
		s.fail(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusCreated, out)
}

func (s *Service) listRules(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	p := s.Principal(ctx)
	if !p.HasAnywhere(authz.PermFindingsRead) {
		s.fail(w, r, authz.ErrForbidden)
		return
	}
	where := "s.organization_id = $1"
	args := []any{p.OrganizationID}
	if st := r.URL.Query().Get("status"); st != "" {
		args = append(args, st)
		where += " AND s.status = $2"
	}
	rows, err := s.DB.Query(ctx, ruleSelect+` WHERE `+where+` ORDER BY (s.status = 'pending') DESC, s.requested_at DESC LIMIT 500`, args...)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	all, err := pgx.CollectRows(rows, func(row pgx.CollectableRow) (SuppressionRule, error) { return scanRule(row) })
	if err != nil {
		s.fail(w, r, err)
		return
	}
	// Repository rules are visible to people who can read that repository.
	out := []SuppressionRule{}
	for _, x := range all {
		if x.ScopeType == "repository" &&
			s.Authz.Require(ctx, p, authz.PermFindingsRead, authz.Scope{Type: authz.ScopeRepository, ID: *x.ScopeID}) != nil {
			continue
		}
		out = append(out, x)
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"items": out})
}

type ruleDecision struct {
	Note string `json:"note"`
}

func (s *Service) decideRule(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	p := s.Principal(ctx)
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		s.fail(w, r, errNotFound)
		return
	}
	action := r.PathValue("action")
	var req ruleDecision
	if r.ContentLength != 0 {
		if err := httpx.DecodeJSON(w, r, &req); err != nil {
			s.fail(w, r, err)
			return
		}
	}
	if len(req.Note) > 2000 {
		s.fail(w, r, httpx.BadRequest("the note is limited to 2000 characters"))
		return
	}
	applied := 0
	err = db.InTx(ctx, s.DB, func(tx pgx.Tx) error {
		x, err := scanRule(tx.QueryRow(ctx, ruleSelect+` WHERE s.organization_id = $1 AND s.id = $2 FOR UPDATE OF s`, p.OrganizationID, id))
		if err != nil {
			return err
		}
		perm := authz.PermFindingsAcceptRisk
		if action == "withdraw" {
			perm = authz.PermFindingsTriage
		}
		if err := s.canOnScope(ctx, p, perm, x); err != nil {
			return err
		}
		var next string
		switch action {
		case "approve":
			if x.Status != "pending" {
				return httpx.Conflict("the rule is " + x.Status)
			}
			if x.RequestedByID == p.UserID {
				return httpx.Conflict("a different person must approve a suppression rule you proposed")
			}
			if !x.ExpiresAt.After(time.Now()) {
				return httpx.Conflict("the rule's expiry date has passed")
			}
			next = "active"
		case "reject":
			if x.Status != "pending" {
				return httpx.Conflict("the rule is " + x.Status)
			}
			next = "rejected"
		case "revoke":
			if x.Status != "active" {
				return httpx.Conflict("only active rules can be revoked")
			}
			next = "revoked"
		case "withdraw":
			if x.Status != "pending" || x.RequestedByID != p.UserID {
				return httpx.Conflict("only the person who proposed a pending rule can withdraw it")
			}
			next = "withdrawn"
		default:
			return errNotFound
		}
		if _, err := tx.Exec(ctx, `UPDATE suppression_rules SET status = $2, decided_by = $3, decided_at = now(), decision_note = $4 WHERE id = $1`,
			id, next, p.UserID, req.Note); err != nil {
			return err
		}
		switch next {
		case "active":
			x.Status = next
			if applied, err = ApplyRule(ctx, tx, p.OrganizationID, x, &p.UserID, p.Email, nil); err != nil {
				return err
			}
		case "revoked":
			if applied, err = releaseRule(ctx, tx, &p.UserID, x, "suppression rule revoked: "+x.Name); err != nil {
				return err
			}
		}
		return audit.Write(ctx, tx, audit.Entry{OrganizationID: p.OrganizationID, ActorID: &p.UserID, ActorEmail: p.Email,
			Action: "suppression_rule." + action, TargetType: "suppression_rule", TargetID: id.String(),
			Metadata: map[string]any{"name": x.Name, "findings": applied, "note": req.Note}})
	})
	if err != nil {
		s.fail(w, r, err)
		return
	}
	out, err := scanRule(s.DB.QueryRow(ctx, ruleSelect+` WHERE s.id = $1`, id))
	if err != nil {
		s.fail(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"rule": out, "findings_changed": applied})
}

// ApplyRule gives the rule's decision to the open findings it matches
// (only repoID's when set). approver is the person who approved the rule.
func ApplyRule(ctx context.Context, tx pgx.Tx, orgID uuid.UUID, x SuppressionRule, approver *uuid.UUID, approverName string, repoID *uuid.UUID) (int, error) {
	reason := fmt.Sprintf("suppression rule %q (approved by %s): %s", x.Name, approverName, x.Justification)
	if err := db.SetChangeContext(ctx, tx, (*[16]byte)(approver), "suppression_rule", truncate(reason, 1000)); err != nil {
		return 0, err
	}
	cond, args := matchSQL(x, 5)
	if repoID != nil {
		args = append(args, *repoID)
		cond += fmt.Sprintf(" AND f.repository_id = $%d", 4+len(args))
	}
	// #nosec G202 -- cond is built from placeholders
	tag, err := tx.Exec(ctx, `UPDATE findings f SET status = $2, suppression_rule_id = $3,
		accepted_until = CASE WHEN $2 = 'accepted_risk' THEN $4::timestamptz ELSE NULL END, updated_at = now()
		FROM repositories r
		WHERE r.id = f.repository_id AND f.organization_id = $1 AND f.status IN ('open', 'in_progress', 'needs_review') AND `+cond,
		append([]any{orgID, x.Decision, x.ID, x.ExpiresAt}, args...)...)
	if err != nil {
		return 0, err
	}
	return int(tag.RowsAffected()), nil
}

// releaseRule reopens the findings a rule decided.
func releaseRule(ctx context.Context, tx pgx.Tx, actor *uuid.UUID, x SuppressionRule, reason string) (int, error) {
	if err := db.SetChangeContext(ctx, tx, (*[16]byte)(actor), "suppression_rule", truncate(reason, 1000)); err != nil {
		return 0, err
	}
	tag, err := tx.Exec(ctx, `UPDATE findings SET status = 'open', suppression_rule_id = NULL, updated_at = now()
		WHERE suppression_rule_id = $1 AND status IN ('accepted_risk', 'false_positive')`, x.ID)
	if err != nil {
		return 0, err
	}
	return int(tag.RowsAffected()), nil
}

// ApplyActiveRules applies every active rule to a repository's open
// findings (after a scan or import).
func ApplyActiveRules(ctx context.Context, tx pgx.Tx, orgID, repoID uuid.UUID) (int, error) {
	rows, err := tx.Query(ctx, ruleSelect+` WHERE s.organization_id = $1 AND s.status = 'active' AND s.expires_at > now()
		AND (s.scope_type = 'organization' OR (s.scope_type = 'repository' AND s.scope_id = $2)
		     OR (s.scope_type = 'application' AND s.scope_id = (SELECT application_id FROM repositories WHERE id = $2)))`, orgID, repoID)
	if err != nil {
		return 0, err
	}
	rules, err := pgx.CollectRows(rows, func(row pgx.CollectableRow) (SuppressionRule, error) { return scanRule(row) })
	if err != nil {
		return 0, err
	}
	n := 0
	for _, x := range rules {
		var approver *uuid.UUID
		_ = tx.QueryRow(ctx, `SELECT decided_by FROM suppression_rules WHERE id = $1`, x.ID).Scan(&approver)
		k, err := ApplyRule(ctx, tx, orgID, x, approver, deref(x.DecidedBy), &repoID)
		if err != nil {
			return n, err
		}
		n += k
	}
	return n, nil
}

func deref(s *string) string {
	if s == nil {
		return "unknown"
	}
	return *s
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}

// ExpireSuppressionRules ends rules past their expiry and reopens their
// findings (jobs role).
func ExpireSuppressionRules(ctx context.Context, pool *pgxpool.Pool) (int, error) {
	n := 0
	err := db.InTx(ctx, pool, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, ruleSelect+` WHERE s.status = 'active' AND s.expires_at <= now() FOR UPDATE OF s`)
		if err != nil {
			return err
		}
		rules, err := pgx.CollectRows(rows, func(row pgx.CollectableRow) (SuppressionRule, error) { return scanRule(row) })
		if err != nil {
			return err
		}
		for _, x := range rules {
			if _, err := tx.Exec(ctx, `UPDATE suppression_rules SET status = 'expired' WHERE id = $1`, x.ID); err != nil {
				return err
			}
			k, err := releaseRule(ctx, tx, nil, x, "suppression rule expired: "+x.Name)
			if err != nil {
				return err
			}
			var org uuid.UUID
			_ = tx.QueryRow(ctx, `SELECT organization_id FROM suppression_rules WHERE id = $1`, x.ID).Scan(&org)
			if err := audit.Write(ctx, tx, audit.Entry{OrganizationID: org, Action: "suppression_rule.expire", TargetType: "suppression_rule",
				TargetID: x.ID.String(), Metadata: map[string]any{"name": x.Name, "findings_reopened": k}}); err != nil {
				return err
			}
			n++
		}
		return nil
	})
	return n, err
}
