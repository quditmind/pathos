// Package identity manages users, role assignments and just-in-time
// provisioning from OIDC logins.
package identity

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"pathos/internal/authz"
	"pathos/internal/platform/db"
)

var (
	ErrNotFound    = errors.New("not found")
	ErrDeactivated = errors.New("user is deactivated")
	ErrConflict    = errors.New("conflict")
)

// User statuses.
const (
	StatusInvited     = "invited"
	StatusActive      = "active"
	StatusDeactivated = "deactivated"
)

type User struct {
	ID              uuid.UUID  `json:"id"`
	OrganizationID  uuid.UUID  `json:"organization_id"`
	KeycloakSubject *string    `json:"-"`
	Email           string     `json:"email"`
	DisplayName     string     `json:"display_name"`
	Status          string     `json:"status"`
	LastLoginAt     *time.Time `json:"last_login_at"`
	DeactivatedAt   *time.Time `json:"deactivated_at"`
	CreatedAt       time.Time  `json:"created_at"`
	UpdatedAt       time.Time  `json:"updated_at"`
}

const userCols = `id, organization_id, keycloak_subject, email, display_name, status, last_login_at, deactivated_at, created_at, updated_at`

func scanUser(r pgx.Row) (User, error) {
	var u User
	err := r.Scan(&u.ID, &u.OrganizationID, &u.KeycloakSubject, &u.Email, &u.DisplayName, &u.Status,
		&u.LastLoginAt, &u.DeactivatedAt, &u.CreatedAt, &u.UpdatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return u, ErrNotFound
	}
	return u, err
}

// GetUser returns a user in org.
func GetUser(ctx context.Context, q db.Querier, orgID, id uuid.UUID) (User, error) {
	return scanUser(q.QueryRow(ctx, `SELECT `+userCols+` FROM users WHERE organization_id = $1 AND id = $2`, orgID, id))
}

// GetUserForUpdate locks the user row.
func GetUserForUpdate(ctx context.Context, q db.Querier, orgID, id uuid.UUID) (User, error) {
	return scanUser(q.QueryRow(ctx, `SELECT `+userCols+` FROM users WHERE organization_id = $1 AND id = $2 FOR UPDATE`, orgID, id))
}

// ListParams filters the user list.
type ListParams struct {
	Query    string
	Status   string
	AfterID  *uuid.UUID // cursor (users sorted by email, id)
	AfterKey string
	Limit    int
}

// ListUsers returns users ordered by email.
func ListUsers(ctx context.Context, q db.Querier, orgID uuid.UUID, p ListParams) ([]User, error) {
	if p.Limit <= 0 || p.Limit > 200 {
		p.Limit = 50
	}
	like := ""
	if p.Query != "" {
		like = "%" + escapeLike(strings.ToLower(p.Query)) + "%"
	}
	rows, err := q.Query(ctx, `SELECT `+userCols+` FROM users
		WHERE organization_id = $1
		  AND ($2 = '' OR email LIKE $2 OR lower(display_name) LIKE $2)
		  AND ($3 = '' OR status = $3)
		  AND ($4::uuid IS NULL OR (email, id) > ($5, $4::uuid))
		ORDER BY email, id LIMIT $6`, orgID, like, p.Status, p.AfterID, p.AfterKey, p.Limit)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, func(r pgx.CollectableRow) (User, error) { return scanUser(r) })
}

func escapeLike(s string) string {
	return strings.NewReplacer(`\`, `\\`, `%`, `\%`, `_`, `\_`).Replace(s)
}

// CreateUser inserts a user (status invited unless a subject is supplied).
func CreateUser(ctx context.Context, q db.Querier, u User) (User, error) {
	u.ID = uuid.Must(uuid.NewV7())
	u.Email = strings.ToLower(strings.TrimSpace(u.Email))
	if u.Status == "" {
		u.Status = StatusInvited
	}
	created, err := scanUser(q.QueryRow(ctx, `
		INSERT INTO users (id, organization_id, keycloak_subject, email, display_name, status)
		VALUES ($1, $2, $3, $4, $5, $6) RETURNING `+userCols,
		u.ID, u.OrganizationID, u.KeycloakSubject, u.Email, u.DisplayName, u.Status))
	if db.IsUniqueViolation(err) {
		return User{}, fmt.Errorf("%w: a user with this email already exists", ErrConflict)
	}
	return created, err
}

// SetStatus changes a user's status.
func SetStatus(ctx context.Context, q db.Querier, orgID, id uuid.UUID, status string) (User, error) {
	return scanUser(q.QueryRow(ctx, `
		UPDATE users SET status = $3, updated_at = now(),
		  deactivated_at = CASE WHEN $3 = 'deactivated' THEN now() ELSE NULL END
		WHERE organization_id = $1 AND id = $2 RETURNING `+userCols, orgID, id, status))
}

// SetKeycloakSubject links a PATHOS user to a Keycloak user ID.
func SetKeycloakSubject(ctx context.Context, q db.Querier, orgID, id uuid.UUID, sub string) error {
	_, err := q.Exec(ctx, `UPDATE users SET keycloak_subject = $3, updated_at = now() WHERE organization_id = $1 AND id = $2`, orgID, id, sub)
	return err
}

// LoginIdentity is the subset of OIDC claims used for provisioning.
type LoginIdentity struct {
	Subject       string
	Email         string
	EmailVerified bool
	Name          string
}

// ProvisionResult describes what happened during login provisioning.
type ProvisionResult struct {
	User              User
	Created           bool
	Linked            bool // an invited user was linked to the Keycloak subject
	GrantedSuperAdmin bool
}

// ProvisionOnLogin finds or creates the user for an OIDC login (JIT).
//
// Matching order: by Keycloak subject, then (only if the IdP asserts the
// email is verified) by email for a not-yet-linked invited user. The
// bootstrap administrator email gets super_admin at organization scope if
// no active super_admin exists yet.
func ProvisionOnLogin(ctx context.Context, tx pgx.Tx, orgID uuid.UUID, li LoginIdentity, bootstrapEmail string) (ProvisionResult, error) {
	var res ProvisionResult
	email := strings.ToLower(strings.TrimSpace(li.Email))
	if li.Subject == "" || email == "" {
		return res, errors.New("identity: subject and email claims are required")
	}

	// One person (subject) has at most one users row per organization
	// (multi-tenancy: one row in each organization they belong to).
	u, err := scanUser(tx.QueryRow(ctx, `SELECT `+userCols+` FROM users WHERE organization_id = $1 AND keycloak_subject = $2 FOR UPDATE`, orgID, li.Subject))
	switch {
	case err == nil:
	case errors.Is(err, ErrNotFound):
		if li.EmailVerified {
			u, err = scanUser(tx.QueryRow(ctx, `SELECT `+userCols+` FROM users
				WHERE organization_id = $1 AND email = $2 AND keycloak_subject IS NULL FOR UPDATE`, orgID, email))
			if err == nil {
				res.Linked = true
				if err := SetKeycloakSubject(ctx, tx, orgID, u.ID, li.Subject); err != nil {
					return res, err
				}
			} else if !errors.Is(err, ErrNotFound) {
				return res, err
			}
		}
		if !res.Linked {
			sub := li.Subject
			u, err = CreateUser(ctx, tx, User{OrganizationID: orgID, KeycloakSubject: &sub, Email: email, DisplayName: li.Name, Status: StatusActive})
			if err != nil {
				// The email is taken by a user linked to another subject, or
				// by an invited user whose email the IdP did not verify.
				return res, err
			}
			res.Created = true
		}
	default:
		return res, err
	}

	if u.Status == StatusDeactivated {
		return res, ErrDeactivated
	}

	name := u.DisplayName
	if li.Name != "" {
		name = li.Name
	}
	u, err = scanUser(tx.QueryRow(ctx, `
		UPDATE users SET status = 'active', last_login_at = now(), display_name = $3, updated_at = now()
		WHERE organization_id = $1 AND id = $2 RETURNING `+userCols, orgID, u.ID, name))
	if err != nil {
		return res, err
	}
	res.User = u

	if bootstrapEmail != "" && email == strings.ToLower(bootstrapEmail) && li.EmailVerified {
		granted, err := grantBootstrapSuperAdmin(ctx, tx, orgID, u.ID)
		if err != nil {
			return res, err
		}
		res.GrantedSuperAdmin = granted
	}
	return res, nil
}

func grantBootstrapSuperAdmin(ctx context.Context, tx pgx.Tx, orgID, userID uuid.UUID) (bool, error) {
	// Serialize concurrent first logins.
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtext('pathos.bootstrap_admin'))`); err != nil {
		return false, err
	}
	var exists bool
	err := tx.QueryRow(ctx, `
		SELECT EXISTS (
		  SELECT 1 FROM role_assignments ra
		  JOIN roles r ON r.id = ra.role_id AND r.key = $2 AND r.is_system
		  JOIN users u ON u.id = ra.user_id AND u.status = 'active'
		  WHERE ra.organization_id = $1 AND ra.scope_type = 'organization')`, orgID, authz.RoleSuperAdmin).Scan(&exists)
	if err != nil || exists {
		return false, err
	}
	_, err = tx.Exec(ctx, `
		INSERT INTO role_assignments (id, organization_id, user_id, role_id, scope_type, scope_id)
		SELECT $1, $2, $3, id, 'organization', $2 FROM roles WHERE key = $4 AND is_system
		ON CONFLICT DO NOTHING`, uuid.Must(uuid.NewV7()), orgID, userID, authz.RoleSuperAdmin)
	return err == nil, err
}

// LoadGrants resolves all (permission, scope) grants for an active user.
func LoadGrants(ctx context.Context, q db.Querier, userID uuid.UUID) ([]authz.Grant, error) {
	rows, err := q.Query(ctx, `
		SELECT rp.permission_key, ra.scope_type, ra.scope_id
		FROM role_assignments ra
		JOIN role_permissions rp ON rp.role_id = ra.role_id
		WHERE ra.user_id = $1`, userID)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, func(r pgx.CollectableRow) (authz.Grant, error) {
		var g authz.Grant
		var p, st string
		err := r.Scan(&p, &st, &g.Scope.ID)
		g.Permission, g.Scope.Type = authz.Permission(p), authz.ScopeType(st)
		return g, err
	})
}

// Role is a role with its permissions.
type Role struct {
	ID          uuid.UUID          `json:"id"`
	Key         string             `json:"key"`
	Name        string             `json:"name"`
	Description string             `json:"description"`
	IsSystem    bool               `json:"is_system"`
	Permissions []authz.Permission `json:"permissions"`
}

// ListRoles returns system roles and the organization's custom roles.
func ListRoles(ctx context.Context, q db.Querier, orgID uuid.UUID) ([]Role, error) {
	rows, err := q.Query(ctx, `
		SELECT r.id, r.key, r.name, r.description, r.is_system,
		       COALESCE(array_agg(rp.permission_key ORDER BY p.sort_order) FILTER (WHERE rp.permission_key IS NOT NULL), '{}')
		FROM roles r
		LEFT JOIN role_permissions rp ON rp.role_id = r.id
		LEFT JOIN permissions p ON p.key = rp.permission_key
		WHERE r.organization_id IS NULL OR r.organization_id = $1
		GROUP BY r.id
		ORDER BY r.is_system DESC, r.created_at, r.key`, orgID)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, func(r pgx.CollectableRow) (Role, error) {
		var role Role
		var perms []string
		err := r.Scan(&role.ID, &role.Key, &role.Name, &role.Description, &role.IsSystem, &perms)
		for _, p := range perms {
			role.Permissions = append(role.Permissions, authz.Permission(p))
		}
		return role, err
	})
}

// GetRoleByKey returns a role visible to org.
func GetRoleByKey(ctx context.Context, q db.Querier, orgID uuid.UUID, key string) (Role, error) {
	roles, err := ListRoles(ctx, q, orgID)
	if err != nil {
		return Role{}, err
	}
	for _, r := range roles {
		if r.Key == key {
			return r, nil
		}
	}
	return Role{}, ErrNotFound
}

// Assignment is a scoped role assignment.
type Assignment struct {
	ID        uuid.UUID       `json:"id"`
	UserID    uuid.UUID       `json:"user_id"`
	RoleID    uuid.UUID       `json:"role_id"`
	RoleKey   string          `json:"role_key"`
	RoleName  string          `json:"role_name"`
	ScopeType authz.ScopeType `json:"scope_type"`
	ScopeID   uuid.UUID       `json:"scope_id"`
	ScopeName string          `json:"scope_name"`
	CreatedBy *uuid.UUID      `json:"created_by"`
	CreatedAt time.Time       `json:"created_at"`
}

const assignmentSelect = `
	SELECT ra.id, ra.user_id, ra.role_id, r.key, r.name, ra.scope_type, ra.scope_id,
	       COALESCE(CASE ra.scope_type
	         WHEN 'organization' THEN (SELECT name FROM organizations WHERE id = ra.scope_id)
	         WHEN 'region' THEN (SELECT name FROM regions WHERE id = ra.scope_id)
	         WHEN 'business_unit' THEN (SELECT name FROM business_units WHERE id = ra.scope_id)
	       END, ''),
	       ra.created_by, ra.created_at
	FROM role_assignments ra JOIN roles r ON r.id = ra.role_id`

func scanAssignment(r pgx.Row) (Assignment, error) {
	var a Assignment
	var st string
	err := r.Scan(&a.ID, &a.UserID, &a.RoleID, &a.RoleKey, &a.RoleName, &st, &a.ScopeID, &a.ScopeName, &a.CreatedBy, &a.CreatedAt)
	a.ScopeType = authz.ScopeType(st)
	if errors.Is(err, pgx.ErrNoRows) {
		return a, ErrNotFound
	}
	return a, err
}

// ListAssignments returns a user's role assignments.
func ListAssignments(ctx context.Context, q db.Querier, orgID, userID uuid.UUID) ([]Assignment, error) {
	rows, err := q.Query(ctx, assignmentSelect+` WHERE ra.organization_id = $1 AND ra.user_id = $2 ORDER BY ra.created_at`, orgID, userID)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, func(r pgx.CollectableRow) (Assignment, error) { return scanAssignment(r) })
}

// GetAssignment returns one assignment.
func GetAssignment(ctx context.Context, q db.Querier, orgID, id uuid.UUID) (Assignment, error) {
	return scanAssignment(q.QueryRow(ctx, assignmentSelect+` WHERE ra.organization_id = $1 AND ra.id = $2`, orgID, id))
}

// CreateAssignment inserts a role assignment.
func CreateAssignment(ctx context.Context, q db.Querier, orgID, userID, roleID uuid.UUID, s authz.Scope, by *uuid.UUID) (uuid.UUID, error) {
	id := uuid.Must(uuid.NewV7())
	_, err := q.Exec(ctx, `
		INSERT INTO role_assignments (id, organization_id, user_id, role_id, scope_type, scope_id, created_by)
		VALUES ($1, $2, $3, $4, $5, $6, $7)`, id, orgID, userID, roleID, s.Type, s.ID, by)
	if db.IsUniqueViolation(err) {
		return uuid.Nil, fmt.Errorf("%w: the user already has this role at this scope", ErrConflict)
	}
	return id, err
}

// DeleteAssignment removes a role assignment.
func DeleteAssignment(ctx context.Context, q db.Querier, orgID, id uuid.UUID) error {
	tag, err := q.Exec(ctx, `DELETE FROM role_assignments WHERE organization_id = $1 AND id = $2`, orgID, id)
	if err == nil && tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return err
}

// CountActiveOrgSuperAdmins counts active users holding super_admin org-wide,
// optionally excluding one user or one assignment (to check "would this
// change remove the last super admin?").
func CountActiveOrgSuperAdmins(ctx context.Context, q db.Querier, orgID uuid.UUID, excludeUser, excludeAssignment *uuid.UUID) (int, error) {
	var n int
	err := q.QueryRow(ctx, `
		SELECT count(DISTINCT ra.user_id) FROM role_assignments ra
		JOIN roles r ON r.id = ra.role_id AND r.key = $2 AND r.is_system
		JOIN users u ON u.id = ra.user_id AND u.status = 'active'
		WHERE ra.organization_id = $1 AND ra.scope_type = 'organization'
		  AND ($3::uuid IS NULL OR ra.user_id <> $3)
		  AND ($4::uuid IS NULL OR ra.id <> $4)`, orgID, authz.RoleSuperAdmin, excludeUser, excludeAssignment).Scan(&n)
	return n, err
}

// PermissionRow is a catalog entry from the database.
type PermissionRow struct {
	Key         string `json:"key"`
	Category    string `json:"category"`
	Description string `json:"description"`
	OrgOnly     bool   `json:"org_only"`
}

// ListPermissions returns the permission catalog.
func ListPermissions(ctx context.Context, q db.Querier) ([]PermissionRow, error) {
	rows, err := q.Query(ctx, `SELECT key, category, description, org_only FROM permissions ORDER BY sort_order`)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, pgx.RowToStructByPos[PermissionRow])
}
