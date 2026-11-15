// Package vuln implements vulnerability management: the finding lifecycle
// (status transitions with history, assignment), SLA policies, the
// accepted-risk workflow with expiry, SBOM inventory and license policy.
package vuln

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"pathos/internal/audit"
	"pathos/internal/authz"
	"pathos/internal/org"
	"pathos/internal/platform/db"
	"pathos/internal/platform/httpx"
)

// Service holds dependencies.
type Service struct {
	DB        *pgxpool.Pool
	Authz     *authz.Authorizer
	Log       *slog.Logger
	Principal func(context.Context) *authz.Principal
}

// DefaultSLA is seeded per organization (days; 0 = no SLA).
var DefaultSLA = map[string]int{"critical": 7, "high": 30, "medium": 90, "low": 180, "info": 0}

// DefaultLicensePolicy flags strong-copyleft / source-available licenses.
var DefaultLicensePolicy = map[string]string{
	"AGPL-3.0-only": "deny", "AGPL-3.0-or-later": "deny", "SSPL-1.0": "deny", "BUSL-1.1": "review",
	"GPL-2.0-only": "review", "GPL-2.0-or-later": "review", "GPL-3.0-only": "review", "GPL-3.0-or-later": "review",
	"LGPL-3.0-only": "review", "CC-BY-NC-4.0": "deny",
}

// EnsureDefaults seeds SLA and license policies for an organization.
func EnsureDefaults(ctx context.Context, pool *pgxpool.Pool, orgID uuid.UUID) error {
	for sev, days := range DefaultSLA {
		var d *int
		if days > 0 {
			d = &days
		}
		if _, err := pool.Exec(ctx, `INSERT INTO sla_policies (organization_id, severity, days) VALUES ($1, $2, $3) ON CONFLICT DO NOTHING`, orgID, sev, d); err != nil {
			return err
		}
	}
	var any bool
	if err := pool.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM license_policies WHERE organization_id = $1)`, orgID).Scan(&any); err != nil || any {
		return err
	}
	for id, dec := range DefaultLicensePolicy {
		if _, err := pool.Exec(ctx, `INSERT INTO license_policies (organization_id, spdx_id, decision) VALUES ($1, $2, $3) ON CONFLICT DO NOTHING`, orgID, id, dec); err != nil {
			return err
		}
	}
	// Findings created before SLA policies existed get deadlines now.
	_, err := pool.Exec(ctx, `UPDATE findings f SET sla_due_at = f.first_seen_at + make_interval(days => p.days)
		FROM sla_policies p WHERE p.organization_id = f.organization_id AND p.severity = f.severity
		  AND f.organization_id = $1 AND f.sla_due_at IS NULL AND p.days IS NOT NULL`, orgID)
	return err
}

// Register mounts the API.
func (s *Service) Register(mux *http.ServeMux) {
	mux.HandleFunc("POST /api/v1/findings/{id}/status", s.changeStatus)
	mux.HandleFunc("POST /api/v1/findings/{id}/assign", s.assign)
	mux.HandleFunc("POST /api/v1/findings/bulk", s.bulk)
	mux.HandleFunc("GET /api/v1/findings/{id}/history", s.history)
	mux.HandleFunc("POST /api/v1/findings/{id}/risk-acceptance", s.requestAcceptance)
	mux.HandleFunc("GET /api/v1/risk-acceptances", s.listAcceptances)
	mux.HandleFunc("POST /api/v1/risk-acceptances/{id}/{action}", s.decideAcceptance)
	mux.HandleFunc("GET /api/v1/sla-policies", s.getSLA)
	mux.HandleFunc("PUT /api/v1/sla-policies", s.putSLA)
	mux.HandleFunc("GET /api/v1/license-policies", s.getLicenses)
	mux.HandleFunc("PUT /api/v1/license-policies", s.putLicenses)
	mux.HandleFunc("GET /api/v1/sbom/components", s.components)
	mux.HandleFunc("GET /api/v1/repositories/{id}/sbom", s.repoSBOM)
}

var errNotFound = errors.New("not found")

func (s *Service) fail(w http.ResponseWriter, r *http.Request, err error) {
	switch {
	case errors.Is(err, authz.ErrForbidden):
		err = httpx.ErrForbidden
	case errors.Is(err, errNotFound), errors.Is(err, pgx.ErrNoRows), errors.Is(err, org.ErrScopeNotFound):
		err = httpx.ErrNotFound
	case db.IsForeignKeyViolation(err):
		err = httpx.BadRequest("a referenced user or item does not exist")
	}
	httpx.WriteError(w, r, s.Log, err)
}

func pathID(r *http.Request) (uuid.UUID, error) {
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		return uuid.Nil, errNotFound
	}
	return id, nil
}

// finding loads status/severity and checks perm on its repository.
func (s *Service) finding(ctx context.Context, q db.Querier, p *authz.Principal, perm authz.Permission, id uuid.UUID, lock bool) (status, severity string, repo uuid.UUID, err error) {
	sql := `SELECT status, severity, repository_id FROM findings WHERE organization_id = $1 AND id = $2`
	if lock {
		sql += " FOR UPDATE"
	}
	if err = q.QueryRow(ctx, sql, p.OrganizationID, id).Scan(&status, &severity, &repo); err != nil {
		return "", "", repo, errNotFound
	}
	err = s.Authz.Require(ctx, p, perm, authz.Scope{Type: authz.ScopeRepository, ID: repo})
	if errors.Is(err, authz.ErrForbidden) && p.HasAnywhere(perm) && perm == authz.PermFindingsRead {
		err = errNotFound
	}
	return status, severity, repo, err
}

func uid(p *authz.Principal) *[16]byte {
	a := [16]byte(p.UserID)
	return &a
}

// transitions lists manual status changes (findings.triage). Accepted risk
// is reachable only through the approval workflow; "fixed" is normally set
// by scans, but may be set manually with a reason (verified by the next
// scan, which reopens it if still present).
var transitions = map[string][]string{
	"open":           {"in_progress", "needs_review", "false_positive", "fixed"},
	"in_progress":    {"open", "needs_review", "false_positive", "fixed"},
	"needs_review":   {"open", "in_progress", "false_positive", "fixed"},
	"false_positive": {"open"},
	"fixed":          {"open"},
	"accepted_risk":  {},
}

// reasonRequired lists target statuses that need a written reason.
var reasonRequired = []string{"false_positive", "fixed"}

// CanTransition reports whether a manual change from -> to is allowed.
func CanTransition(from, to string) bool { return slices.Contains(transitions[from], to) }

type statusRequest struct {
	Status string `json:"status"`
	Reason string `json:"reason"`
}

func (s *Service) setStatus(ctx context.Context, tx pgx.Tx, p *authz.Principal, id uuid.UUID, req statusRequest) error {
	from, severity, _, err := s.finding(ctx, tx, p, authz.PermFindingsTriage, id, true)
	if err != nil {
		return err
	}
	if !CanTransition(from, req.Status) {
		return httpx.Conflict(fmt.Sprintf("cannot change status from %s to %s", from, req.Status))
	}
	if slices.Contains(reasonRequired, req.Status) && len(strings.TrimSpace(req.Reason)) < 5 {
		return httpx.BadRequest("a reason is required for " + strings.ReplaceAll(req.Status, "_", " "))
	}
	if req.Status == "false_positive" && severity == "critical" && !p.HasAnywhere(authz.PermFindingsAcceptRisk) {
		return httpx.E(http.StatusForbidden, "forbidden", "closing a Critical finding as a false positive requires findings.accept_risk")
	}
	if err := db.SetChangeContext(ctx, tx, uid(p), "user", req.Reason); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `UPDATE findings SET status = $2, updated_at = now() WHERE id = $1`, id, req.Status); err != nil {
		return err
	}
	return audit.Write(ctx, tx, audit.Entry{OrganizationID: p.OrganizationID, ActorID: &p.UserID, ActorEmail: p.Email,
		Action: "finding.status", TargetType: "finding", TargetID: id.String(), Metadata: map[string]any{"from": from, "to": req.Status, "reason": req.Reason}})
}

func (s *Service) changeStatus(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	p := s.Principal(ctx)
	id, err := pathID(r)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	var req statusRequest
	if err := httpx.DecodeJSON(w, r, &req); err != nil {
		s.fail(w, r, err)
		return
	}
	if err := db.InTx(ctx, s.DB, func(tx pgx.Tx) error { return s.setStatus(ctx, tx, p, id, req) }); err != nil {
		s.fail(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

type assignRequest struct {
	AssigneeID *uuid.UUID `json:"assignee_id"` // null = unassign
}

func (s *Service) setAssignee(ctx context.Context, tx pgx.Tx, p *authz.Principal, id uuid.UUID, assignee *uuid.UUID) error {
	if _, _, _, err := s.finding(ctx, tx, p, authz.PermFindingsTriage, id, true); err != nil {
		return err
	}
	if assignee != nil {
		var status string
		if err := tx.QueryRow(ctx, `SELECT status FROM users WHERE organization_id = $1 AND id = $2`, p.OrganizationID, *assignee).Scan(&status); err != nil || status != "active" {
			return httpx.BadRequest("assignee must be an active user")
		}
	}
	// The actor lets the notification trigger skip self-assignment.
	if err := db.SetChangeContext(ctx, tx, uid(p), "user", ""); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `UPDATE findings SET assignee_id = $2, updated_at = now() WHERE id = $1`, id, assignee); err != nil {
		return err
	}
	return audit.Write(ctx, tx, audit.Entry{OrganizationID: p.OrganizationID, ActorID: &p.UserID, ActorEmail: p.Email,
		Action: "finding.assign", TargetType: "finding", TargetID: id.String(), Metadata: map[string]any{"assignee_id": assignee}})
}

func (s *Service) assign(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	p := s.Principal(ctx)
	id, err := pathID(r)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	var req assignRequest
	if err := httpx.DecodeJSON(w, r, &req); err != nil {
		s.fail(w, r, err)
		return
	}
	if err := db.InTx(ctx, s.DB, func(tx pgx.Tx) error { return s.setAssignee(ctx, tx, p, id, req.AssigneeID) }); err != nil {
		s.fail(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

type bulkRequest struct {
	FindingIDs []uuid.UUID `json:"finding_ids"`
	Action     string      `json:"action"` // status | assign
	Status     string      `json:"status"`
	Reason     string      `json:"reason"`
	AssigneeID *uuid.UUID  `json:"assignee_id"`
}

// bulk applies one change to up to 500 findings atomically.
func (s *Service) bulk(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	p := s.Principal(ctx)
	var req bulkRequest
	if err := httpx.DecodeJSON(w, r, &req); err != nil {
		s.fail(w, r, err)
		return
	}
	if len(req.FindingIDs) == 0 || len(req.FindingIDs) > 500 {
		s.fail(w, r, httpx.BadRequest("select 1-500 findings"))
		return
	}
	err := db.InTx(ctx, s.DB, func(tx pgx.Tx) error {
		for _, id := range req.FindingIDs {
			var err error
			switch req.Action {
			case "status":
				err = s.setStatus(ctx, tx, p, id, statusRequest{Status: req.Status, Reason: req.Reason})
			case "assign":
				err = s.setAssignee(ctx, tx, p, id, req.AssigneeID)
			default:
				return httpx.BadRequest("action must be status or assign")
			}
			if err != nil {
				var he *httpx.Error
				if errors.As(err, &he) {
					he.Message = "finding " + id.String() + ": " + he.Message
				}
				return err
			}
		}
		return nil
	})
	if err != nil {
		s.fail(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]int{"updated": len(req.FindingIDs)})
}

// HistoryEntry is one lifecycle event.
type HistoryEntry struct {
	FromStatus *string   `json:"from_status"`
	ToStatus   string    `json:"to_status"`
	Actor      *string   `json:"actor"`
	Source     string    `json:"source"`
	Reason     string    `json:"reason"`
	CreatedAt  time.Time `json:"created_at"`
}

func (s *Service) history(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	p := s.Principal(ctx)
	id, err := pathID(r)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if _, _, _, err := s.finding(ctx, s.DB, p, authz.PermFindingsRead, id, false); err != nil {
		s.fail(w, r, err)
		return
	}
	rows, err := s.DB.Query(ctx, `SELECT h.from_status, h.to_status, COALESCE(NULLIF(u.display_name, ''), u.email), h.source, h.reason, h.created_at
		FROM finding_status_history h LEFT JOIN users u ON u.id = h.actor_id WHERE h.finding_id = $1 ORDER BY h.created_at, h.id LIMIT 500`, id)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	out, err := pgx.CollectRows(rows, pgx.RowToStructByPos[HistoryEntry])
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if out == nil {
		out = []HistoryEntry{}
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"items": out})
}

// --- accepted risk -------------------------------------------------------------

type acceptanceRequest struct {
	Justification string    `json:"justification"`
	ExpiresAt     time.Time `json:"expires_at"`
}

// MaxAcceptance bounds how long a risk may be accepted.
const MaxAcceptance = 365 * 24 * time.Hour

func (s *Service) requestAcceptance(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	p := s.Principal(ctx)
	id, err := pathID(r)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	var req acceptanceRequest
	if err := httpx.DecodeJSON(w, r, &req); err != nil {
		s.fail(w, r, err)
		return
	}
	req.Justification = strings.TrimSpace(req.Justification)
	if len(req.Justification) < 10 || len(req.Justification) > 4000 {
		s.fail(w, r, httpx.BadRequest("justification must be 10-4000 characters"))
		return
	}
	if !req.ExpiresAt.After(time.Now().Add(time.Hour)) || req.ExpiresAt.After(time.Now().Add(MaxAcceptance)) {
		s.fail(w, r, httpx.BadRequest("expires_at must be in the future and at most 365 days away"))
		return
	}
	aid := uuid.Must(uuid.NewV7())
	err = db.InTx(ctx, s.DB, func(tx pgx.Tx) error {
		status, _, _, err := s.finding(ctx, tx, p, authz.PermFindingsTriage, id, true)
		if err != nil {
			return err
		}
		if status != "open" && status != "in_progress" && status != "needs_review" {
			return httpx.Conflict("only open findings can be risk-accepted")
		}
		if _, err := tx.Exec(ctx, `INSERT INTO risk_acceptances (id, organization_id, finding_id, requested_by, justification, expires_at)
			VALUES ($1, $2, $3, $4, $5, $6)`, aid, p.OrganizationID, id, p.UserID, req.Justification, req.ExpiresAt); err != nil {
			if db.IsUniqueViolation(err) {
				return httpx.Conflict("a risk acceptance is already pending or active for this finding")
			}
			return err
		}
		return audit.Write(ctx, tx, audit.Entry{OrganizationID: p.OrganizationID, ActorID: &p.UserID, ActorEmail: p.Email,
			Action: "risk_acceptance.request", TargetType: "finding", TargetID: id.String(),
			Metadata: map[string]any{"acceptance_id": aid, "expires_at": req.ExpiresAt}})
	})
	if err != nil {
		s.fail(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusCreated, map[string]any{"id": aid, "status": "pending"})
}

// Acceptance is the API view.
type Acceptance struct {
	ID              uuid.UUID  `json:"id"`
	FindingID       uuid.UUID  `json:"finding_id"`
	FindingTitle    string     `json:"finding_title"`
	FindingSeverity string     `json:"finding_severity"`
	RepositoryName  string     `json:"repository_name"`
	RequestedBy     string     `json:"requested_by"`
	Justification   string     `json:"justification"`
	ExpiresAt       time.Time  `json:"expires_at"`
	Status          string     `json:"status"`
	DecidedBy       *string    `json:"decided_by"`
	DecidedAt       *time.Time `json:"decided_at"`
	DecisionNote    string     `json:"decision_note"`
	CreatedAt       time.Time  `json:"created_at"`
	requestedByID   uuid.UUID
}

func (s *Service) listAcceptances(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	p := s.Principal(ctx)
	f := authz.FilterFor(p, authz.PermFindingsRead)
	if f.None() {
		s.fail(w, r, authz.ErrForbidden)
		return
	}
	scope, args := org.ScopeSQL(f, "r.id", "r.business_unit_id", "r.country_id", 2)
	args = append([]any{p.OrganizationID}, args...)
	where := "ra.organization_id = $1 AND " + scope
	if st := r.URL.Query().Get("status"); st != "" {
		if !slices.Contains([]string{"pending", "approved", "rejected", "expired", "revoked", "withdrawn"}, st) {
			s.fail(w, r, httpx.BadRequest("invalid status"))
			return
		}
		args = append(args, st)
		where += " AND ra.status = $" + strconv.Itoa(len(args))
	}
	if fid := r.URL.Query().Get("finding_id"); fid != "" {
		id, err := uuid.Parse(fid)
		if err != nil {
			s.fail(w, r, httpx.BadRequest("invalid finding_id"))
			return
		}
		args = append(args, id)
		where += " AND ra.finding_id = $" + strconv.Itoa(len(args))
	}
	rows, err := s.DB.Query(ctx, `SELECT ra.id, ra.finding_id, f.title, f.severity, r.full_name, COALESCE(NULLIF(u1.display_name, ''), u1.email),
		ra.justification, ra.expires_at, ra.status, COALESCE(NULLIF(u2.display_name, ''), u2.email), ra.decided_at, ra.decision_note, ra.created_at, ra.requested_by
		FROM risk_acceptances ra JOIN findings f ON f.id = ra.finding_id JOIN repositories r ON r.id = f.repository_id
		LEFT JOIN countries co ON co.id = r.country_id
		JOIN users u1 ON u1.id = ra.requested_by LEFT JOIN users u2 ON u2.id = ra.decided_by
		WHERE `+where+` ORDER BY ra.created_at DESC LIMIT 200`, args...)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	out, err := pgx.CollectRows(rows, func(row pgx.CollectableRow) (Acceptance, error) {
		var a Acceptance
		err := row.Scan(&a.ID, &a.FindingID, &a.FindingTitle, &a.FindingSeverity, &a.RepositoryName, &a.RequestedBy, &a.Justification,
			&a.ExpiresAt, &a.Status, &a.DecidedBy, &a.DecidedAt, &a.DecisionNote, &a.CreatedAt, &a.requestedByID)
		return a, err
	})
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if out == nil {
		out = []Acceptance{}
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"items": out})
}

// decideAcceptance handles approve | reject | revoke | withdraw.
func (s *Service) decideAcceptance(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	p := s.Principal(ctx)
	id, err := pathID(r)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	action := r.PathValue("action")
	var req struct {
		Note string `json:"note"`
	}
	if r.ContentLength > 0 {
		if err := httpx.DecodeJSON(w, r, &req); err != nil {
			s.fail(w, r, err)
			return
		}
	}
	err = db.InTx(ctx, s.DB, func(tx pgx.Tx) error {
		var findingID, requester uuid.UUID
		var status string
		var expires time.Time
		if err := tx.QueryRow(ctx, `SELECT finding_id, requested_by, status, expires_at FROM risk_acceptances
			WHERE organization_id = $1 AND id = $2 FOR UPDATE`, p.OrganizationID, id).Scan(&findingID, &requester, &status, &expires); err != nil {
			return errNotFound
		}
		perm := authz.PermFindingsAcceptRisk
		if action == "withdraw" {
			perm = authz.PermFindingsTriage
		}
		if _, _, _, err := s.finding(ctx, tx, p, perm, findingID, true); err != nil {
			return err
		}
		var newStatus, findingStatus string
		switch action {
		case "approve":
			if status != "pending" {
				return httpx.Conflict("acceptance is " + status)
			}
			if requester == p.UserID {
				return httpx.Conflict("a different person must approve a risk acceptance you requested")
			}
			if !expires.After(time.Now()) {
				return httpx.Conflict("the requested expiry date has passed")
			}
			newStatus, findingStatus = "approved", "accepted_risk"
		case "reject":
			if status != "pending" {
				return httpx.Conflict("acceptance is " + status)
			}
			newStatus = "rejected"
		case "revoke":
			if status != "approved" {
				return httpx.Conflict("only approved acceptances can be revoked")
			}
			newStatus, findingStatus = "revoked", "open"
		case "withdraw":
			if status != "pending" || requester != p.UserID {
				return httpx.Conflict("only the requester can withdraw a pending acceptance")
			}
			newStatus = "withdrawn"
		default:
			return errNotFound
		}
		if _, err := tx.Exec(ctx, `UPDATE risk_acceptances SET status = $2, decided_by = CASE WHEN $2 = 'withdrawn' THEN decided_by ELSE $3::uuid END,
			decided_at = now(), decision_note = $4 WHERE id = $1`, id, newStatus, p.UserID, req.Note); err != nil {
			return err
		}
		if findingStatus != "" {
			if err := db.SetChangeContext(ctx, tx, uid(p), "user", "risk acceptance "+newStatus+": "+req.Note); err != nil {
				return err
			}
			if _, err := tx.Exec(ctx, `UPDATE findings SET status = $2, accepted_until = CASE WHEN $2 = 'accepted_risk' THEN $3::timestamptz END, updated_at = now()
				WHERE id = $1`, findingID, findingStatus, expires); err != nil {
				return err
			}
		}
		return audit.Write(ctx, tx, audit.Entry{OrganizationID: p.OrganizationID, ActorID: &p.UserID, ActorEmail: p.Email,
			Action: "risk_acceptance." + action, TargetType: "finding", TargetID: findingID.String(),
			Metadata: map[string]any{"acceptance_id": id, "note": req.Note}})
	})
	if err != nil {
		s.fail(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// ExpireAcceptances reopens findings whose accepted risk has expired.
func ExpireAcceptances(ctx context.Context, pool *pgxpool.Pool) (int, error) {
	n := 0
	err := db.InTx(ctx, pool, func(tx pgx.Tx) error {
		if err := db.SetChangeContext(ctx, tx, nil, "expiry", "risk acceptance expired"); err != nil {
			return err
		}
		rows, err := tx.Query(ctx, `UPDATE risk_acceptances SET status = 'expired' WHERE status = 'approved' AND expires_at <= now()
			RETURNING finding_id, organization_id, id`)
		if err != nil {
			return err
		}
		type item struct{ f, o, a uuid.UUID }
		items, err := pgx.CollectRows(rows, func(r pgx.CollectableRow) (item, error) {
			var it item
			return it, r.Scan(&it.f, &it.o, &it.a)
		})
		if err != nil {
			return err
		}
		for _, it := range items {
			if _, err := tx.Exec(ctx, `UPDATE findings SET status = 'open', updated_at = now() WHERE id = $1 AND status = 'accepted_risk'`, it.f); err != nil {
				return err
			}
			if err := audit.Write(ctx, tx, audit.Entry{OrganizationID: it.o, Action: "risk_acceptance.expire", TargetType: "finding",
				TargetID: it.f.String(), Metadata: map[string]any{"acceptance_id": it.a}}); err != nil {
				return err
			}
		}
		n = len(items)
		return nil
	})
	return n, err
}

// --- policies ------------------------------------------------------------------

func (s *Service) requireSettings(r *http.Request) (*authz.Principal, error) {
	p := s.Principal(r.Context())
	return p, s.Authz.Require(r.Context(), p, authz.PermSettingsManage, authz.Scope{Type: authz.ScopeOrganization, ID: p.OrganizationID})
}

func (s *Service) getSLA(w http.ResponseWriter, r *http.Request) {
	p := s.Principal(r.Context())
	if !p.HasAnywhere(authz.PermFindingsRead) {
		s.fail(w, r, authz.ErrForbidden)
		return
	}
	rows, err := s.DB.Query(r.Context(), `SELECT severity, days FROM sla_policies WHERE organization_id = $1`, p.OrganizationID)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	out := map[string]*int{}
	for rows.Next() {
		var sev string
		var d *int
		if err := rows.Scan(&sev, &d); err == nil {
			out[sev] = d
		}
	}
	rows.Close()
	httpx.WriteJSON(w, http.StatusOK, out)
}

// putSLA replaces SLA days and recomputes deadlines of unresolved findings.
func (s *Service) putSLA(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	p, err := s.requireSettings(r)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	var req map[string]*int
	if err := httpx.DecodeJSON(w, r, &req); err != nil {
		s.fail(w, r, err)
		return
	}
	for sev, d := range req {
		if _, ok := DefaultSLA[sev]; !ok || (d != nil && (*d < 1 || *d > 3650)) {
			s.fail(w, r, httpx.BadRequest("SLA days must be 1-3650 (or null) for critical, high, medium, low, info"))
			return
		}
	}
	err = db.InTx(ctx, s.DB, func(tx pgx.Tx) error {
		for sev, d := range req {
			if _, err := tx.Exec(ctx, `INSERT INTO sla_policies (organization_id, severity, days) VALUES ($1, $2, $3)
				ON CONFLICT (organization_id, severity) DO UPDATE SET days = EXCLUDED.days, updated_at = now()`, p.OrganizationID, sev, d); err != nil {
				return err
			}
		}
		if _, err := tx.Exec(ctx, `UPDATE findings f SET sla_due_at = CASE WHEN p.days IS NULL THEN NULL ELSE f.first_seen_at + make_interval(days => p.days) END
			FROM sla_policies p WHERE p.organization_id = f.organization_id AND p.severity = f.severity AND f.organization_id = $1`, p.OrganizationID); err != nil {
			return err
		}
		md, _ := json.Marshal(req)
		return audit.Write(ctx, tx, audit.Entry{OrganizationID: p.OrganizationID, ActorID: &p.UserID, ActorEmail: p.Email,
			Action: "sla_policy.update", TargetType: "organization", TargetID: p.OrganizationID.String(), Metadata: map[string]any{"days": string(md)}})
	})
	if err != nil {
		s.fail(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Service) getLicenses(w http.ResponseWriter, r *http.Request) {
	p := s.Principal(r.Context())
	if !p.HasAnywhere(authz.PermSBOMRead) {
		s.fail(w, r, authz.ErrForbidden)
		return
	}
	rows, err := s.DB.Query(r.Context(), `SELECT spdx_id, decision FROM license_policies WHERE organization_id = $1 ORDER BY spdx_id`, p.OrganizationID)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	type pol struct {
		SPDX     string `json:"spdx_id"`
		Decision string `json:"decision"`
	}
	out, err := pgx.CollectRows(rows, pgx.RowToStructByPos[pol])
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if out == nil {
		out = []pol{}
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"items": out})
}

func (s *Service) putLicenses(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	p, err := s.requireSettings(r)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	var req struct {
		Items []struct {
			SPDX     string `json:"spdx_id"`
			Decision string `json:"decision"`
		} `json:"items"`
	}
	if err := httpx.DecodeJSON(w, r, &req); err != nil {
		s.fail(w, r, err)
		return
	}
	if len(req.Items) > 500 {
		s.fail(w, r, httpx.BadRequest("at most 500 entries"))
		return
	}
	err = db.InTx(ctx, s.DB, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `DELETE FROM license_policies WHERE organization_id = $1`, p.OrganizationID); err != nil {
			return err
		}
		for _, it := range req.Items {
			id := strings.TrimSpace(it.SPDX)
			if id == "" || len(id) > 100 || (it.Decision != "deny" && it.Decision != "review") {
				return httpx.BadRequest("each entry needs an SPDX id and decision deny or review")
			}
			if _, err := tx.Exec(ctx, `INSERT INTO license_policies (organization_id, spdx_id, decision) VALUES ($1, $2, $3) ON CONFLICT DO NOTHING`,
				p.OrganizationID, id, it.Decision); err != nil {
				return err
			}
		}
		return audit.Write(ctx, tx, audit.Entry{OrganizationID: p.OrganizationID, ActorID: &p.UserID, ActorEmail: p.Email,
			Action: "license_policy.update", TargetType: "organization", TargetID: p.OrganizationID.String(), Metadata: map[string]any{"entries": len(req.Items)}})
	})
	if err != nil {
		s.fail(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
