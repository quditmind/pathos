package org

import (
	"context"
	"errors"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"pathos/internal/authz"
	"pathos/internal/platform/db"
)

// ErrScopeNotFound means the target scope does not exist in the organization.
var ErrScopeNotFound = errors.New("scope not found")

// Hierarchy resolves scope ancestors from the database.
type Hierarchy struct {
	DB    db.Querier
	OrgID uuid.UUID
}

// Ancestors implements authz.Hierarchy.
//
// Repository scopes are resolved once the repositories table exists
// (Phase 3); until then a repository scope resolves to itself plus the
// organization.
func (h *Hierarchy) Ancestors(ctx context.Context, s authz.Scope) ([]authz.Scope, error) {
	orgScope := authz.Scope{Type: authz.ScopeOrganization, ID: h.OrgID}
	switch s.Type {
	case authz.ScopeOrganization:
		return []authz.Scope{s}, nil
	case authz.ScopeRegion:
		return []authz.Scope{s, orgScope}, nil
	case authz.ScopeBusinessUnit:
		chain, err := h.businessUnitChain(ctx, s.ID)
		if err != nil {
			return nil, err
		}
		return append(chain, orgScope), nil
	case authz.ScopeRepository:
		return []authz.Scope{s, orgScope}, nil
	}
	return nil, ErrScopeNotFound
}

func (h *Hierarchy) businessUnitChain(ctx context.Context, id uuid.UUID) ([]authz.Scope, error) {
	rows, err := h.DB.Query(ctx, `
		WITH RECURSIVE chain AS (
		    SELECT id, parent_id, 0 AS depth FROM business_units WHERE id = $1 AND organization_id = $2
		    UNION ALL
		    SELECT b.id, b.parent_id, c.depth + 1 FROM business_units b
		    JOIN chain c ON b.id = c.parent_id
		    WHERE c.depth < 32
		)
		SELECT id FROM chain ORDER BY depth`, id, h.OrgID)
	if err != nil {
		return nil, err
	}
	ids, err := pgx.CollectRows(rows, pgx.RowTo[uuid.UUID])
	if err != nil {
		return nil, err
	}
	if len(ids) == 0 {
		return nil, ErrScopeNotFound
	}
	out := make([]authz.Scope, len(ids))
	for i, bid := range ids {
		out[i] = authz.Scope{Type: authz.ScopeBusinessUnit, ID: bid}
	}
	return out, nil
}

// ScopeExists reports whether a scope target exists within the organization.
func ScopeExists(ctx context.Context, q db.Querier, orgID uuid.UUID, s authz.Scope) (bool, error) {
	var query string
	switch s.Type {
	case authz.ScopeOrganization:
		return s.ID == orgID, nil
	case authz.ScopeRegion:
		query = `SELECT EXISTS (SELECT 1 FROM regions WHERE id = $1 AND organization_id = $2)`
	case authz.ScopeBusinessUnit:
		query = `SELECT EXISTS (SELECT 1 FROM business_units WHERE id = $1 AND organization_id = $2 AND archived_at IS NULL)`
	case authz.ScopeRepository:
		// Repositories arrive in Phase 3.
		return false, nil
	default:
		return false, nil
	}
	var ok bool
	err := q.QueryRow(ctx, query, s.ID, orgID).Scan(&ok)
	return ok, err
}
