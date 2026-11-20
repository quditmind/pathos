package remediation

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"pathos/internal/audit"
	"pathos/internal/authz"
	"pathos/internal/platform/db"
	"pathos/internal/platform/httpx"
)

// Remediation ↔ threat link (PATHOS 3.0 M9): an item of kind
// threat_mitigation may reference the M5 threat it mitigates. The threat
// must belong to a threat model of the item's application.

// ThreatRef is the threat an item mitigates.
type ThreatRef struct {
	ID                 uuid.UUID `json:"id"`
	Title              string    `json:"title"`
	Severity           string    `json:"severity"`
	Status             string    `json:"status"`
	ThreatModelID      uuid.UUID `json:"threat_model_id"`
	ThreatModelTitle   string    `json:"threat_model_title"`
	ThreatModelVersion int       `json:"threat_model_version"`
}

// ErrThreatNotLinkable: the threat does not exist, belongs to another
// application, or the item is not a threat mitigation.
func ErrThreatNotLinkable(msg string) *httpx.Error {
	return httpx.E(http.StatusUnprocessableEntity, "threat_not_linkable", msg).WithDiag("PTH-REM-1107")
}

// optionalUUID distinguishes an absent field from an explicit null.
type optionalUUID struct {
	Set   bool
	Value *uuid.UUID
}

func (o *optionalUUID) UnmarshalJSON(b []byte) error {
	o.Set = true
	if bytes.Equal(bytes.TrimSpace(b), []byte("null")) {
		o.Value = nil
		return nil
	}
	var id uuid.UUID
	if err := json.Unmarshal(b, &id); err != nil {
		return err
	}
	o.Value = &id
	return nil
}

// threatInfo is a threat with its model's application and repository.
type threatInfo struct {
	ID       uuid.UUID
	Title    string
	Severity string
	AppID    uuid.UUID
	RepoID   *uuid.UUID
}

// loadThreat returns a threat of the organization the caller may read
// (threats.read), or ErrThreatNotLinkable.
func (s *Service) loadThreat(ctx context.Context, q db.Querier, p *authz.Principal, id uuid.UUID) (threatInfo, error) {
	var t threatInfo
	if !p.HasAnywhere(authz.PermThreatsRead) {
		return t, ErrThreatNotLinkable("linking a threat needs the threats.read permission")
	}
	err := q.QueryRow(ctx, `SELECT t.id, t.title, t.severity, m.application_id, m.repository_id FROM threats t
		JOIN threat_models m ON m.id = t.threat_model_id WHERE t.organization_id = $1 AND t.id = $2`, p.OrganizationID, id).
		Scan(&t.ID, &t.Title, &t.Severity, &t.AppID, &t.RepoID)
	if errors.Is(err, pgx.ErrNoRows) {
		return t, ErrThreatNotLinkable("threat_id: no threat with this id")
	}
	if err != nil {
		return t, err
	}
	if err := s.requireApp(ctx, p, authz.PermThreatsRead, t.AppID); err != nil {
		return t, ErrThreatNotLinkable("threat_id: no threat with this id")
	}
	return t, nil
}

// requireApp checks perm on every active repository of an application
// (organization-wide perm for an application without repositories).
func (s *Service) requireApp(ctx context.Context, p *authz.Principal, perm authz.Permission, appID uuid.UUID) error {
	if p.HasOrgWide(perm) {
		return nil
	}
	rows, err := s.DB.Query(ctx, `SELECT id FROM repositories WHERE organization_id = $1 AND application_id = $2 AND archived_at IS NULL`,
		p.OrganizationID, appID)
	if err != nil {
		return err
	}
	repos, err := pgx.CollectRows(rows, pgx.RowTo[uuid.UUID])
	if err != nil {
		return err
	}
	if len(repos) == 0 {
		return httpx.ErrNotFound
	}
	for _, r := range repos {
		if err := s.requireRepo(ctx, p, perm, r); err != nil {
			return err
		}
	}
	return nil
}

// createForThreat creates one application-level item for a threat (no
// findings): POST /api/v1/remediation/items with threat_id and no
// finding_ids.
func (s *Service) createForThreat(ctx context.Context, p *authz.Principal, in createInput) (uuid.UUID, error) {
	t, err := s.loadThreat(ctx, s.DB, p, *in.ThreatID)
	if err != nil {
		return uuid.Nil, err
	}
	if in.Kind != "" && in.Kind != "threat_mitigation" {
		return uuid.Nil, ErrThreatNotLinkable("an item linked to a threat has the kind threat_mitigation")
	}
	if t.RepoID != nil {
		if err := s.requireRepo(ctx, p, authz.PermRemediationManage, *t.RepoID); err != nil {
			return uuid.Nil, err
		}
	} else if err := s.requireApp(ctx, p, authz.PermRemediationManage, t.AppID); err != nil {
		return uuid.Nil, err
	}
	if in.OwnerID != nil {
		if err := s.checkOwner(ctx, p.OrganizationID, *in.OwnerID); err != nil {
			return uuid.Nil, err
		}
	}
	title := in.Title
	if title == "" {
		title = "Mitigate: " + t.Title
	}
	prio := in.Priority
	if prio == "" {
		prio = PriorityFor(t.Severity)
	}
	source := "none"
	if in.DueAt != nil {
		source = "manual"
	}
	id := uuid.Must(uuid.NewV7())
	err = db.InTx(ctx, s.DB, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `INSERT INTO remediation_items (id, organization_id, application_id, repository_id, title, kind, priority,
			root_cause, owner_id, due_at, due_source, created_by, threat_id) VALUES ($1, $2, $3, $4, $5, 'threat_mitigation', $6, $7, $8, $9, $10, $11, $12)`,
			id, p.OrganizationID, t.AppID, t.RepoID, truncate(title, 300), prio, in.RootCause, in.OwnerID, in.DueAt, source, p.UserID, t.ID); err != nil {
			return err
		}
		return writeAudit(ctx, tx, p, "remediation_item.create", id, map[string]any{"threat_id": t.ID, "kind": "threat_mitigation", "priority": prio})
	})
	return id, err
}

// checkThreatLink validates linking threat t to an item of application app.
func checkThreatLink(t threatInfo, app *uuid.UUID, kind string) error {
	if kind != "threat_mitigation" {
		return ErrThreatNotLinkable("only items of kind threat_mitigation can be linked to a threat")
	}
	if app == nil || *app != t.AppID {
		return ErrThreatNotLinkable("the threat belongs to a threat model of another application")
	}
	return nil
}

func writeAudit(ctx context.Context, q db.Querier, p *authz.Principal, action string, id uuid.UUID, meta map[string]any) error {
	return audit.Write(ctx, q, audit.Entry{OrganizationID: p.OrganizationID, ActorID: &p.UserID, ActorEmail: p.Email,
		Action: action, TargetType: "remediation_item", TargetID: id.String(), Metadata: meta})
}
