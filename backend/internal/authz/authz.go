package authz

import (
	"context"
	"errors"
	"slices"

	"github.com/google/uuid"
)

// ScopeType is the kind of resource a role assignment applies to.
type ScopeType string

const (
	ScopeOrganization ScopeType = "organization"
	ScopeRegion       ScopeType = "region"
	ScopeBusinessUnit ScopeType = "business_unit"
	ScopeRepository   ScopeType = "repository"
)

func (s ScopeType) Valid() bool {
	switch s {
	case ScopeOrganization, ScopeRegion, ScopeBusinessUnit, ScopeRepository:
		return true
	}
	return false
}

// Scope identifies one resource.
type Scope struct {
	Type ScopeType `json:"type"`
	ID   uuid.UUID `json:"id"`
}

// Grant is one (permission, scope) pair a principal holds.
type Grant struct {
	Permission Permission
	Scope      Scope
}

var (
	ErrForbidden       = errors.New("forbidden")
	ErrUnauthenticated = errors.New("unauthenticated")
)

// Hierarchy resolves the ancestors of a scope, so that a grant on a region
// or business unit also covers resources beneath it. Implementations return
// the full chain including the organization, e.g. for a repository:
// [repository, business_unit, parent business_units..., region, organization].
type Hierarchy interface {
	Ancestors(ctx context.Context, s Scope) ([]Scope, error)
}

// Principal is an authenticated user with their resolved grants.
type Principal struct {
	UserID         uuid.UUID
	OrganizationID uuid.UUID
	// Subject is the person's OIDC subject (the same in every organization
	// the person belongs to); empty for users never linked to the IdP.
	Subject     string
	Email       string
	DisplayName string
	Grants      []Grant
}

// HasOrgWide reports whether p holds perm at organization scope.
func (p *Principal) HasOrgWide(perm Permission) bool {
	for _, g := range p.Grants {
		if g.Permission == perm && g.Scope.Type == ScopeOrganization && g.Scope.ID == p.OrganizationID {
			return true
		}
	}
	return false
}

// HasAnywhere reports whether p holds perm at any scope. Use it to decide
// whether to show an entry point (menu item, list endpoint), never as the
// authorization decision for a specific resource.
func (p *Principal) HasAnywhere(perm Permission) bool {
	for _, g := range p.Grants {
		if g.Permission == perm {
			return true
		}
	}
	return false
}

// EffectivePermissions returns the distinct permissions p holds anywhere.
func (p *Principal) EffectivePermissions() []Permission {
	seen := map[Permission]bool{}
	var out []Permission
	for _, g := range p.Grants {
		if !seen[g.Permission] {
			seen[g.Permission] = true
			out = append(out, g.Permission)
		}
	}
	slices.Sort(out)
	return out
}

// Authorizer checks permissions against a scope hierarchy.
type Authorizer struct {
	H Hierarchy
}

// Can reports whether p holds perm on target (directly or via an ancestor).
func (a *Authorizer) Can(ctx context.Context, p *Principal, perm Permission, target Scope) (bool, error) {
	if p == nil {
		return false, nil
	}
	// A grant never reaches outside the principal's organization.
	if target.Type == ScopeOrganization && target.ID != p.OrganizationID {
		return false, nil
	}
	if info, ok := LookupPermission(perm); ok && info.OrgOnly {
		return p.HasOrgWide(perm), nil
	}
	if !p.HasAnywhere(perm) {
		return false, nil
	}
	chain := []Scope{target}
	if target.Type != ScopeOrganization && a.H != nil {
		// Resolving the ancestors also proves that the target exists in
		// the request's organization (multi-tenancy): an organization-wide
		// grant does not cover another organization's resource.
		anc, err := a.H.Ancestors(ctx, target)
		if err != nil {
			return false, err
		}
		chain = anc
	}
	if p.HasOrgWide(perm) {
		return true, nil
	}
	for _, g := range p.Grants {
		if g.Permission != perm {
			continue
		}
		for _, s := range chain {
			if g.Scope == s {
				return true, nil
			}
		}
	}
	return false, nil
}

// Require is Can that returns ErrForbidden on denial.
func (a *Authorizer) Require(ctx context.Context, p *Principal, perm Permission, target Scope) error {
	ok, err := a.Can(ctx, p, perm, target)
	if err != nil {
		return err
	}
	if !ok {
		return ErrForbidden
	}
	return nil
}

// Filter is the SQL-ready form of a principal's scopes for one permission.
// List queries use it as:
//
//	WHERE ($1::bool OR region_id = ANY($2) OR business_unit_id = ANY($3) OR id = ANY($4))
//
// Business unit IDs must be expanded to descendants by the query (recursive
// CTE) or by the caller. Filtering happens in SQL, never after the fact.
type Filter struct {
	All           bool
	RegionIDs     []uuid.UUID
	BusinessUnits []uuid.UUID
	RepositoryIDs []uuid.UUID
}

// None reports whether the filter matches nothing.
func (f Filter) None() bool {
	return !f.All && len(f.RegionIDs) == 0 && len(f.BusinessUnits) == 0 && len(f.RepositoryIDs) == 0
}

// FilterFor builds the scope filter for perm.
func FilterFor(p *Principal, perm Permission) Filter {
	var f Filter
	if p == nil {
		return f
	}
	for _, g := range p.Grants {
		if g.Permission != perm {
			continue
		}
		switch g.Scope.Type {
		case ScopeOrganization:
			if g.Scope.ID == p.OrganizationID {
				f.All = true
			}
		case ScopeRegion:
			f.RegionIDs = append(f.RegionIDs, g.Scope.ID)
		case ScopeBusinessUnit:
			f.BusinessUnits = append(f.BusinessUnits, g.Scope.ID)
		case ScopeRepository:
			f.RepositoryIDs = append(f.RepositoryIDs, g.Scope.ID)
		}
	}
	if f.All {
		return Filter{All: true}
	}
	if info, ok := LookupPermission(perm); ok && info.OrgOnly {
		return Filter{}
	}
	return f
}

// CanGrantRole reports whether p may assign a role with rolePerms at target.
// To prevent privilege escalation, the granter needs roles.assign at the
// target and must already hold every permission of the role at the target.
func (a *Authorizer) CanGrantRole(ctx context.Context, p *Principal, rolePerms []Permission, target Scope) (bool, error) {
	if ok, err := a.Can(ctx, p, PermRolesAssign, target); err != nil || !ok {
		return false, err
	}
	for _, perm := range rolePerms {
		ok, err := a.Can(ctx, p, perm, target)
		if err != nil || !ok {
			return false, err
		}
	}
	return true, nil
}
