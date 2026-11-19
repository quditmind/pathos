package org

import (
	"context"
	"errors"
	"strconv"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"pathos/internal/authz"
	"pathos/internal/platform/db"
	"pathos/internal/platform/tenant"
)

// ErrScopeNotFound means the target scope does not exist in the organization.
var ErrScopeNotFound = errors.New("scope not found")

// Hierarchy resolves scope ancestors from the database.
type Hierarchy struct {
	DB db.Querier
	// OrgID is the fallback organization when the context carries none
	// (single-organization installs). With multi-tenancy the organization
	// always comes from the request context (tenant.WithOrg).
	OrgID uuid.UUID
}

func (h *Hierarchy) org(ctx context.Context) uuid.UUID {
	if id, ok := tenant.OrgFrom(ctx); ok {
		return id
	}
	return h.OrgID
}

// Ancestors implements authz.Hierarchy. A repository's chain is
// [repository, its business unit and that unit's ancestors, the region of
// its country, organization].
func (h *Hierarchy) Ancestors(ctx context.Context, s authz.Scope) ([]authz.Scope, error) {
	orgID := h.org(ctx)
	orgScope := authz.Scope{Type: authz.ScopeOrganization, ID: orgID}
	switch s.Type {
	case authz.ScopeOrganization:
		return []authz.Scope{s}, nil
	case authz.ScopeRegion:
		var ok bool
		if err := h.DB.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM regions WHERE id = $1 AND organization_id = $2)`, s.ID, orgID).Scan(&ok); err != nil {
			return nil, err
		}
		if !ok {
			return nil, ErrScopeNotFound
		}
		return []authz.Scope{s, orgScope}, nil
	case authz.ScopeBusinessUnit:
		chain, err := h.businessUnitChain(ctx, orgID, s.ID)
		if err != nil {
			return nil, err
		}
		return append(chain, orgScope), nil
	case authz.ScopeRepository:
		var bu, region *uuid.UUID
		err := h.DB.QueryRow(ctx, `
			SELECT r.business_unit_id, c.region_id FROM repositories r
			LEFT JOIN countries c ON c.id = r.country_id
			WHERE r.id = $1 AND r.organization_id = $2`, s.ID, orgID).Scan(&bu, &region)
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrScopeNotFound
		}
		if err != nil {
			return nil, err
		}
		chain := []authz.Scope{s}
		if bu != nil {
			buChain, err := h.businessUnitChain(ctx, orgID, *bu)
			if err != nil {
				return nil, err
			}
			chain = append(chain, buChain...)
		}
		if region != nil {
			chain = append(chain, authz.Scope{Type: authz.ScopeRegion, ID: *region})
		}
		return append(chain, orgScope), nil
	}
	return nil, ErrScopeNotFound
}

func (h *Hierarchy) businessUnitChain(ctx context.Context, orgID, id uuid.UUID) ([]authz.Scope, error) {
	rows, err := h.DB.Query(ctx, `
		WITH RECURSIVE chain AS (
		    SELECT id, parent_id, 0 AS depth FROM business_units WHERE id = $1 AND organization_id = $2
		    UNION ALL
		    SELECT b.id, b.parent_id, c.depth + 1 FROM business_units b
		    JOIN chain c ON b.id = c.parent_id
		    WHERE c.depth < 32
		)
		SELECT id FROM chain ORDER BY depth`, id, orgID)
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
		query = `SELECT EXISTS (SELECT 1 FROM repositories WHERE id = $1 AND organization_id = $2 AND archived_at IS NULL)`
	default:
		return false, nil
	}
	var ok bool
	err := q.QueryRow(ctx, query, s.ID, orgID).Scan(&ok)
	return ok, err
}

// ScopeSQL returns a SQL boolean expression restricting rows to the
// filter's scopes, plus its arguments. Columns are given for the row's
// repository id, business unit and country; argument placeholders start
// at $first. BU grants include all descendant business units; region
// grants match through the country's region.
func ScopeSQL(f authz.Filter, repoCol, buCol, countryCol string, first int) (string, []any) {
	if f.All {
		return "true", nil
	}
	if f.None() {
		return "false", nil
	}
	p := func(i int) string { return "$" + strconv.Itoa(first+i) }
	expr := "(" + repoCol + " = ANY(" + p(0) + "::uuid[])" +
		" OR " + buCol + " IN (WITH RECURSIVE d AS (SELECT id FROM business_units WHERE id = ANY(" + p(1) + "::uuid[])" +
		" UNION ALL SELECT b.id FROM business_units b JOIN d ON b.parent_id = d.id) SELECT id FROM d)" +
		" OR " + countryCol + " IN (SELECT id FROM countries WHERE region_id = ANY(" + p(2) + "::uuid[])))"
	nz := func(ids []uuid.UUID) []uuid.UUID {
		if ids == nil {
			return []uuid.UUID{}
		}
		return ids
	}
	return expr, []any{nz(f.RepositoryIDs), nz(f.BusinessUnits), nz(f.RegionIDs)}
}
