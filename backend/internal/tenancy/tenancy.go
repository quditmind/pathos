// Package tenancy implements multi-tenancy: the installation mode,
// organization lifecycle (create, list, suspend, resume, delete),
// memberships of one person (OIDC subject) in several organizations, and
// installation administrators. See docs/MULTI_TENANCY.md.
//
// Every function here that reads across organizations runs its queries in
// system scope (tenant.WithSystem). Callers must have authorized the
// caller first (installation administrator, or the person's own subject).
package tenancy

import (
	"context"
	"encoding/json"
	"errors"
	"net/netip"
	"regexp"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"pathos/internal/audit"
	"pathos/internal/platform/db"
	"pathos/internal/platform/tenant"
)

// Organization status values.
const (
	StatusActive    = "active"
	StatusSuspended = "suspended"
)

var (
	ErrNotFound  = errors.New("organization not found")
	ErrSuspended = errors.New("organization suspended")
	slugRe       = regexp.MustCompile(`^[a-z0-9-]{1,63}$`)
)

// ValidSlug reports whether s is a valid organization slug.
func ValidSlug(s string) bool { return slugRe.MatchString(s) }

// MultiTenant reports whether multi-tenancy is enabled
// (installation_settings.multi_tenant, set by `pathosctl multi-tenancy`).
func MultiTenant(ctx context.Context, q db.Querier) (bool, error) {
	var on bool
	err := q.QueryRow(tenant.WithSystem(ctx), `SELECT multi_tenant FROM installation_settings`).Scan(&on)
	return on, err
}

// RLSGaps lists tenant tables that would not be isolated (no policy, or row
// level security off while multi-tenancy is enabled).
func RLSGaps(ctx context.Context, q db.Querier) ([]string, error) {
	rows, err := q.Query(tenant.WithSystem(ctx), `SELECT pathos_tenant_rls_gaps()`)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, pgx.RowTo[string])
}

// CheckStartup validates the tenancy mode for the API, jobs and scheduler
// roles. Multi-tenant: every tenant table must enforce row-level security.
// Single-organization: exactly the configured organization may exist.
func CheckStartup(ctx context.Context, q db.Querier) (multi bool, err error) {
	multi, err = MultiTenant(ctx, q)
	if err != nil {
		return false, err
	}
	if multi {
		gaps, err := RLSGaps(ctx, q)
		if err != nil {
			return true, err
		}
		if len(gaps) > 0 {
			return true, errors.New("multi-tenancy is enabled but these tables do not enforce row-level security: " +
				strings.Join(gaps, ", ") + "; run `pathosctl migrate`")
		}
		return true, nil
	}
	var n int
	if err := q.QueryRow(tenant.WithSystem(ctx), `SELECT count(*) FROM organizations`).Scan(&n); err != nil {
		return false, err
	}
	if n > 1 {
		return false, errors.New("more than one organization exists but multi-tenancy is disabled; run `pathosctl multi-tenancy enable`")
	}
	return false, nil
}

// Organization is one tenant.
type Organization struct {
	ID              uuid.UUID  `json:"id"`
	Name            string     `json:"name"`
	Slug            string     `json:"slug"`
	Status          string     `json:"status"`
	SuspendedAt     *time.Time `json:"suspended_at"`
	SuspendedReason string     `json:"suspended_reason"`
	CreatedAt       time.Time  `json:"created_at"`
	// Counts (list only).
	Users        int `json:"users"`
	Repositories int `json:"repositories"`
}

const orgCols = `o.id, o.name, o.slug, o.status, o.suspended_at, o.suspended_reason, o.created_at`

func scanOrg(row pgx.Row, extra ...any) (Organization, error) {
	var o Organization
	err := row.Scan(append([]any{&o.ID, &o.Name, &o.Slug, &o.Status, &o.SuspendedAt, &o.SuspendedReason, &o.CreatedAt}, extra...)...)
	if errors.Is(err, pgx.ErrNoRows) {
		return o, ErrNotFound
	}
	return o, err
}

// ListOrganizations returns every organization with user and repository
// counts (installation administrators only).
func ListOrganizations(ctx context.Context, q db.Querier) ([]Organization, error) {
	rows, err := q.Query(tenant.WithSystem(ctx), `SELECT `+orgCols+`,
		(SELECT count(*) FROM users u WHERE u.organization_id = o.id AND u.status <> 'deactivated'),
		(SELECT count(*) FROM repositories r WHERE r.organization_id = o.id AND r.archived_at IS NULL)
		FROM organizations o ORDER BY o.created_at, o.slug`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Organization{}
	for rows.Next() {
		var users, repos int
		o, err := scanOrg(rows, &users, &repos)
		if err != nil {
			return nil, err
		}
		o.Users, o.Repositories = users, repos
		out = append(out, o)
	}
	return out, rows.Err()
}

// GetOrganization loads one organization in system scope.
func GetOrganization(ctx context.Context, q db.Querier, id uuid.UUID) (Organization, error) {
	return scanOrg(q.QueryRow(tenant.WithSystem(ctx), `SELECT `+orgCols+` FROM organizations o WHERE o.id = $1`, id))
}

// GetOrganizationBySlug loads one organization in system scope.
func GetOrganizationBySlug(ctx context.Context, q db.Querier, slug string) (Organization, error) {
	return scanOrg(q.QueryRow(tenant.WithSystem(ctx), `SELECT `+orgCols+` FROM organizations o WHERE o.slug = $1`, slug))
}

// SetStatus suspends or resumes an organization.
func SetStatus(ctx context.Context, q db.Querier, id uuid.UUID, status, reason string) (Organization, error) {
	if status == StatusActive {
		reason = ""
	}
	return scanOrg(q.QueryRow(tenant.WithSystem(ctx), `UPDATE organizations o SET status = $2,
		suspended_at = CASE WHEN $2 = 'suspended' THEN COALESCE(o.suspended_at, now()) ELSE NULL END,
		suspended_reason = $3, updated_at = now() WHERE o.id = $1 RETURNING `+orgCols, id, status, reason))
}

// Membership is one organization a person belongs to.
type Membership struct {
	OrganizationID uuid.UUID `json:"organization_id"`
	Name           string    `json:"name"`
	Slug           string    `json:"slug"`
	Status         string    `json:"status"` // organization status
	UserID         uuid.UUID `json:"user_id"`
	UserStatus     string    `json:"user_status"`
}

// Memberships lists the organizations where subject has a users row
// (system scope: the subject comes from a verified ID token or the
// caller's own session, never from client input).
func Memberships(ctx context.Context, q db.Querier, subject string) ([]Membership, error) {
	if subject == "" {
		return []Membership{}, nil
	}
	rows, err := q.Query(tenant.WithSystem(ctx), `SELECT o.id, o.name, o.slug, o.status, u.id, u.status
		FROM users u JOIN organizations o ON o.id = u.organization_id
		WHERE u.keycloak_subject = $1 ORDER BY o.name, o.slug`, subject)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, func(r pgx.CollectableRow) (Membership, error) {
		var m Membership
		err := r.Scan(&m.OrganizationID, &m.Name, &m.Slug, &m.Status, &m.UserID, &m.UserStatus)
		return m, err
	})
}

// PendingInvites lists organizations with an invitation for email that is
// not linked to an identity yet (linked at login when the IdP verified the
// email).
func PendingInvites(ctx context.Context, q db.Querier, email string) ([]uuid.UUID, error) {
	rows, err := q.Query(tenant.WithSystem(ctx), `SELECT u.organization_id FROM users u
		JOIN organizations o ON o.id = u.organization_id AND o.status = 'active'
		WHERE u.email = $1 AND u.keycloak_subject IS NULL AND u.status = 'invited'`, strings.ToLower(email))
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, pgx.RowTo[uuid.UUID])
}

// OrganizationsBySlug resolves active organizations from slugs (claim
// mapping); unknown slugs are ignored.
func OrganizationsBySlug(ctx context.Context, q db.Querier, slugs []string) ([]uuid.UUID, error) {
	if len(slugs) == 0 {
		return nil, nil
	}
	rows, err := q.Query(tenant.WithSystem(ctx), `SELECT id FROM organizations WHERE slug = ANY($1) AND status = 'active'`, slugs)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, pgx.RowTo[uuid.UUID])
}

// SlugsFromClaim extracts organization slugs from an ID-token claim value
// (a string or a list of strings). Entries must start with prefix (which
// is removed); "-" or "" as prefix takes every entry as a slug. Invalid
// slugs are ignored.
func SlugsFromClaim(v any, prefix string) []string {
	if prefix == "-" {
		prefix = ""
	}
	var raw []string
	switch t := v.(type) {
	case string:
		raw = []string{t}
	case []any:
		for _, e := range t {
			if s, ok := e.(string); ok {
				raw = append(raw, s)
			}
		}
	case []string:
		raw = t
	}
	seen := map[string]bool{}
	var out []string
	for _, s := range raw {
		if prefix != "" {
			var ok bool
			if s, ok = strings.CutPrefix(s, prefix); !ok {
				continue
			}
		}
		s = strings.ToLower(strings.TrimSpace(s))
		if ValidSlug(s) && !seen[s] && len(out) < 100 {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}

// IsInstallationAdmin reports whether subject is a installation administrator.
func IsInstallationAdmin(ctx context.Context, q db.Querier, subject string) (bool, error) {
	if subject == "" {
		return false, nil
	}
	var ok bool
	err := q.QueryRow(tenant.WithSystem(ctx), `SELECT EXISTS (SELECT 1 FROM installation_admins WHERE keycloak_subject = $1)`, subject).Scan(&ok)
	return ok, err
}

// GrantInstallationAdmin makes subject a installation administrator (idempotent).
func GrantInstallationAdmin(ctx context.Context, q db.Querier, subject, email, by string) (bool, error) {
	tag, err := q.Exec(tenant.WithSystem(ctx), `INSERT INTO installation_admins (keycloak_subject, email, created_by) VALUES ($1, $2, $3)
		ON CONFLICT (keycloak_subject) DO NOTHING`, subject, strings.ToLower(email), by)
	return tag.RowsAffected() == 1, err
}

// RevokeInstallationAdmin removes a installation administrator.
func RevokeInstallationAdmin(ctx context.Context, q db.Querier, subject string) (bool, error) {
	tag, err := q.Exec(tenant.WithSystem(ctx), `DELETE FROM installation_admins WHERE keycloak_subject = $1`, subject)
	return tag.RowsAffected() == 1, err
}

// InstallationAdmin is one installation administrator.
type InstallationAdmin struct {
	Subject   string    `json:"subject"`
	Email     string    `json:"email"`
	CreatedBy string    `json:"created_by"`
	CreatedAt time.Time `json:"created_at"`
}

// ListInstallationAdmins returns every installation administrator.
func ListInstallationAdmins(ctx context.Context, q db.Querier) ([]InstallationAdmin, error) {
	rows, err := q.Query(tenant.WithSystem(ctx), `SELECT keycloak_subject, email, created_by, created_at FROM installation_admins ORDER BY created_at`)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, func(r pgx.CollectableRow) (InstallationAdmin, error) {
		var a InstallationAdmin
		err := r.Scan(&a.Subject, &a.Email, &a.CreatedBy, &a.CreatedAt)
		return a, err
	})
}

// InstallationAuditEntry is one installation-level audit record.
type InstallationAuditEntry struct {
	ID             uuid.UUID      `json:"id"`
	ActorSubject   string         `json:"actor_subject"`
	ActorEmail     string         `json:"actor_email"`
	Action         string         `json:"action"`
	OrganizationID *uuid.UUID     `json:"organization_id"`
	Outcome        string         `json:"outcome"`
	RequestID      string         `json:"request_id"`
	Metadata       map[string]any `json:"metadata"`
	CreatedAt      time.Time      `json:"created_at"`
}

// WriteInstallationAudit appends to the installation audit log.
func WriteInstallationAudit(ctx context.Context, q db.Querier, e InstallationAuditEntry) error {
	m := audit.MetaFrom(ctx)
	if e.Outcome == "" {
		e.Outcome = audit.Success
	}
	if e.Metadata == nil {
		e.Metadata = map[string]any{}
	}
	md, err := json.Marshal(e.Metadata)
	if err != nil {
		return err
	}
	var ip *string
	if a, err := netip.ParseAddr(m.IP); err == nil {
		s := a.String()
		ip = &s
	}
	_, err = q.Exec(tenant.WithSystem(ctx), `INSERT INTO installation_audit_logs (id, actor_subject, actor_email, action, organization_id, outcome, ip, request_id, metadata)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`, uuid.Must(uuid.NewV7()), e.ActorSubject, e.ActorEmail, e.Action, e.OrganizationID,
		e.Outcome, ip, m.RequestID, md)
	return err
}

// ListInstallationAudit returns the newest installation audit entries.
func ListInstallationAudit(ctx context.Context, q db.Querier, limit int) ([]InstallationAuditEntry, error) {
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	rows, err := q.Query(tenant.WithSystem(ctx), `SELECT id, actor_subject, actor_email, action, organization_id, outcome, request_id, metadata, created_at
		FROM installation_audit_logs ORDER BY created_at DESC LIMIT $1`, limit)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, func(r pgx.CollectableRow) (InstallationAuditEntry, error) {
		var e InstallationAuditEntry
		var md []byte
		err := r.Scan(&e.ID, &e.ActorSubject, &e.ActorEmail, &e.Action, &e.OrganizationID, &e.Outcome, &e.RequestID, &md, &e.CreatedAt)
		if err == nil {
			_ = json.Unmarshal(md, &e.Metadata)
		}
		return e, err
	})
}
