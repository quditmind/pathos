// Package tenant carries the active organization through a request or a
// background task. The database pool reads it on every connection checkout
// and sets the PostgreSQL session variables that the row-level security
// policies check (see docs/MULTI_TENANCY.md):
//
//	app.organization_id  the organization whose rows are visible
//	app.rls_bypass       "on" only for system work that spans organizations
//
// A context without either value sees no tenant rows at all (fail closed).
package tenant

import (
	"context"

	"github.com/google/uuid"
)

type ctxKey int

const (
	orgKey ctxKey = iota
	systemKey
)

// WithOrg scopes ctx to one organization. It replaces any earlier
// organization and switches system scope off: a narrower scope always wins.
func WithOrg(ctx context.Context, orgID uuid.UUID) context.Context {
	ctx = context.WithValue(ctx, orgKey, orgID)
	return context.WithValue(ctx, systemKey, false)
}

// WithSystem marks ctx as system work that may read and write every
// organization's rows (row-level security bypass). Use it only for code
// that carries the organization of each row itself: scheduled jobs,
// maintenance, and the lookups that authenticate a request before its
// organization is known. Request handlers never use it.
func WithSystem(ctx context.Context) context.Context {
	ctx = context.WithValue(ctx, orgKey, uuid.Nil)
	return context.WithValue(ctx, systemKey, true)
}

// OrgFrom returns the organization ctx is scoped to.
func OrgFrom(ctx context.Context) (uuid.UUID, bool) {
	id, _ := ctx.Value(orgKey).(uuid.UUID)
	return id, id != uuid.Nil
}

// IsSystem reports whether ctx is system scope (and not narrowed to an
// organization).
func IsSystem(ctx context.Context) bool {
	s, _ := ctx.Value(systemKey).(bool)
	return s
}

// Settings returns the values for app.organization_id and app.rls_bypass.
// def is used when ctx carries no scope (uuid.Nil: none, fail closed).
func Settings(ctx context.Context, def uuid.UUID) (org string, bypass string) {
	if id, ok := OrgFrom(ctx); ok {
		return id.String(), "off"
	}
	if IsSystem(ctx) {
		return "", "on"
	}
	if def != uuid.Nil {
		return def.String(), "off"
	}
	return "", "off"
}
