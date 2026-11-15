// Package org manages organizations, regions, countries and business units,
// and seeds the RBAC catalog and default organization structure.
package org

import (
	"context"
	"fmt"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"pathos/internal/authz"
	"pathos/internal/platform/db"
)

type seedRegion struct {
	Code, Name string
	Countries  [][2]string // ISO alpha-2, name
}

// DefaultRegions seeds a new organization. Everything is editable afterwards.
var DefaultRegions = []seedRegion{
	{"AMER", "Americas", [][2]string{
		{"US", "United States"}, {"CA", "Canada"}, {"MX", "Mexico"}, {"BR", "Brazil"},
		{"AR", "Argentina"}, {"CL", "Chile"}, {"CO", "Colombia"}, {"PE", "Peru"},
	}},
	{"EMEA", "Europe, Middle East & Africa", [][2]string{
		{"GB", "United Kingdom"}, {"IE", "Ireland"}, {"DE", "Germany"}, {"FR", "France"},
		{"NL", "Netherlands"}, {"BE", "Belgium"}, {"ES", "Spain"}, {"PT", "Portugal"},
		{"IT", "Italy"}, {"CH", "Switzerland"}, {"AT", "Austria"}, {"SE", "Sweden"},
		{"NO", "Norway"}, {"DK", "Denmark"}, {"FI", "Finland"}, {"PL", "Poland"},
		{"CZ", "Czechia"}, {"RO", "Romania"}, {"IL", "Israel"}, {"AE", "United Arab Emirates"},
		{"SA", "Saudi Arabia"}, {"TR", "Türkiye"}, {"EG", "Egypt"}, {"ZA", "South Africa"},
		{"NG", "Nigeria"}, {"KE", "Kenya"}, {"MA", "Morocco"},
	}},
	{"APAC", "Asia Pacific", [][2]string{
		{"IN", "India"}, {"CN", "China"}, {"JP", "Japan"}, {"KR", "South Korea"},
		{"SG", "Singapore"}, {"MY", "Malaysia"}, {"ID", "Indonesia"}, {"TH", "Thailand"},
		{"VN", "Vietnam"}, {"PH", "Philippines"}, {"HK", "Hong Kong"}, {"TW", "Taiwan"},
		{"AU", "Australia"}, {"NZ", "New Zealand"},
	}},
}

// SyncCatalog upserts the permission catalog and system roles from Go code.
// It is idempotent and runs on every `pathosctl migrate`.
func SyncCatalog(ctx context.Context, pool *pgxpool.Pool) error {
	return db.InTx(ctx, pool, func(tx pgx.Tx) error {
		keys := make([]string, 0, len(authz.Permissions))
		for i, p := range authz.Permissions {
			keys = append(keys, string(p.Key))
			if _, err := tx.Exec(ctx, `
				INSERT INTO permissions (key, category, description, org_only, sort_order)
				VALUES ($1, $2, $3, $4, $5)
				ON CONFLICT (key) DO UPDATE SET category = EXCLUDED.category,
				  description = EXCLUDED.description, org_only = EXCLUDED.org_only,
				  sort_order = EXCLUDED.sort_order`,
				p.Key, p.Category, p.Description, p.OrgOnly, i); err != nil {
				return fmt.Errorf("upsert permission %s: %w", p.Key, err)
			}
		}
		if _, err := tx.Exec(ctx, `DELETE FROM permissions WHERE key <> ALL($1)`, keys); err != nil {
			return err
		}
		for _, r := range authz.SystemRoles {
			var id uuid.UUID
			err := tx.QueryRow(ctx, `
				INSERT INTO roles (id, organization_id, key, name, description, is_system)
				VALUES ($1, NULL, $2, $3, $4, true)
				ON CONFLICT (COALESCE(organization_id, '00000000-0000-0000-0000-000000000000'::uuid), key)
				DO UPDATE SET name = EXCLUDED.name, description = EXCLUDED.description, updated_at = now()
				RETURNING id`, uuid.Must(uuid.NewV7()), r.Key, r.Name, r.Description).Scan(&id)
			if err != nil {
				return fmt.Errorf("upsert role %s: %w", r.Key, err)
			}
			perms := make([]string, len(r.Permissions))
			for i, p := range r.Permissions {
				perms[i] = string(p)
			}
			if _, err := tx.Exec(ctx, `DELETE FROM role_permissions WHERE role_id = $1 AND permission_key <> ALL($2)`, id, perms); err != nil {
				return err
			}
			if _, err := tx.Exec(ctx, `
				INSERT INTO role_permissions (role_id, permission_key)
				SELECT $1, unnest($2::text[]) ON CONFLICT DO NOTHING`, id, perms); err != nil {
				return err
			}
		}
		return nil
	})
}

// EnsureOrganization creates the organization identified by slug if it does
// not exist, seeding default regions and countries. Returns its ID.
func EnsureOrganization(ctx context.Context, pool *pgxpool.Pool, name, slug string) (uuid.UUID, bool, error) {
	var id uuid.UUID
	created := false
	err := db.InTx(ctx, pool, func(tx pgx.Tx) error {
		err := tx.QueryRow(ctx, `SELECT id FROM organizations WHERE slug = $1`, slug).Scan(&id)
		if err == nil {
			return nil
		}
		if err != pgx.ErrNoRows {
			return err
		}
		created = true
		id = uuid.Must(uuid.NewV7())
		if _, err := tx.Exec(ctx, `INSERT INTO organizations (id, name, slug) VALUES ($1, $2, $3)`, id, name, slug); err != nil {
			return err
		}
		for _, r := range DefaultRegions {
			rid := uuid.Must(uuid.NewV7())
			if _, err := tx.Exec(ctx, `INSERT INTO regions (id, organization_id, name, code) VALUES ($1, $2, $3, $4)`,
				rid, id, r.Name, r.Code); err != nil {
				return err
			}
			for _, c := range r.Countries {
				if _, err := tx.Exec(ctx, `
					INSERT INTO countries (id, organization_id, region_id, code, name) VALUES ($1, $2, $3, $4, $5)`,
					uuid.Must(uuid.NewV7()), id, rid, c[0], c[1]); err != nil {
					return err
				}
			}
		}
		return nil
	})
	return id, created, err
}
