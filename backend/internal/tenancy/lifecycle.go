package tenancy

import (
	"context"
	"errors"
	"strings"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"pathos/internal/authz"
	"pathos/internal/identity"
	"pathos/internal/org"
	"pathos/internal/platform/db"
	"pathos/internal/platform/tenant"
)

// ErrSlugTaken means another organization uses the slug.
var ErrSlugTaken = errors.New("organization slug already in use")

// SeedFunc seeds a new organization's defaults (scan profile, SLA and
// licence policies, notification rules, MCP registry, asset
// classifications). ctx is scoped to the new organization.
type SeedFunc func(ctx context.Context, orgID uuid.UUID) error

// CreateOrganization creates an organization with the default regions,
// seeds its defaults and, when adminEmail is set, invites that person as
// the organization's super administrator (linked at their first login
// with a verified email).
func CreateOrganization(ctx context.Context, pool *pgxpool.Pool, name, slug, adminEmail string, seed SeedFunc) (Organization, *identity.User, error) {
	var o Organization
	if _, err := GetOrganizationBySlug(ctx, pool, slug); err == nil {
		return o, nil, ErrSlugTaken
	} else if !errors.Is(err, ErrNotFound) {
		return o, nil, err
	}
	id, created, err := org.EnsureOrganization(tenant.WithSystem(ctx), pool, name, slug)
	if err != nil {
		if db.IsUniqueViolation(err) {
			return o, nil, ErrSlugTaken
		}
		return o, nil, err
	}
	if !created {
		return o, nil, ErrSlugTaken
	}
	octx := tenant.WithOrg(ctx, id)
	if seed != nil {
		if err := seed(octx, id); err != nil {
			return o, nil, err
		}
	}
	var admin *identity.User
	if adminEmail = strings.ToLower(strings.TrimSpace(adminEmail)); adminEmail != "" {
		err := db.InTx(octx, pool, func(tx pgx.Tx) error {
			u, err := identity.CreateUser(octx, tx, identity.User{OrganizationID: id, Email: adminEmail, Status: identity.StatusInvited})
			if err != nil {
				return err
			}
			admin = &u
			_, err = tx.Exec(octx, `INSERT INTO role_assignments (id, organization_id, user_id, role_id, scope_type, scope_id)
				SELECT $1, $2, $3, id, 'organization', $2 FROM roles WHERE key = $4 AND is_system`,
				uuid.Must(uuid.NewV7()), id, u.ID, authz.RoleSuperAdmin)
			return err
		})
		if err != nil {
			return o, nil, err
		}
	}
	o, err = GetOrganization(ctx, pool, id)
	return o, admin, err
}

// ObjectKeys lists the object-storage keys an organization's rows point
// to: scan artifacts (artifact store) and source snapshots, upload parts
// and review evidence (source store). Every key is under a prefix that
// contains the organization id.
func ObjectKeys(ctx context.Context, q db.Querier, orgID uuid.UUID) (artifacts, sources []string, err error) {
	sctx := tenant.WithOrg(ctx, orgID)
	rows, err := q.Query(sctx, `SELECT object_key FROM scan_artifacts WHERE organization_id = $1 AND object_key IS NOT NULL`, orgID)
	if err != nil {
		return nil, nil, err
	}
	if artifacts, err = pgx.CollectRows(rows, pgx.RowTo[string]); err != nil {
		return nil, nil, err
	}
	rows, err = q.Query(sctx, `SELECT object_key FROM source_snapshots WHERE organization_id = $1
		UNION ALL SELECT p.object_key FROM source_upload_parts p JOIN source_uploads u ON u.id = p.upload_id WHERE u.organization_id = $1
		UNION ALL SELECT object_key FROM human_review_evidence WHERE organization_id = $1 AND object_key IS NOT NULL`, orgID)
	if err != nil {
		return nil, nil, err
	}
	sources, err = pgx.CollectRows(rows, pgx.RowTo[string])
	return artifacts, sources, err
}

// DeleteOrganization deletes every row of a suspended organization
// (pathos_delete_organization). The caller removes the object-storage
// keys collected with ObjectKeys first.
func DeleteOrganization(ctx context.Context, q db.Querier, orgID uuid.UUID) (int64, error) {
	o, err := GetOrganization(ctx, q, orgID)
	if err != nil {
		return 0, err
	}
	if o.Status != StatusSuspended {
		return 0, errors.New("organization must be suspended before it is deleted")
	}
	var n int64
	err = q.QueryRow(tenant.WithSystem(ctx), `SELECT pathos_delete_organization($1)`, orgID).Scan(&n)
	return n, err
}
