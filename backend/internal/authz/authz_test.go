package authz

import (
	"context"
	"testing"

	"github.com/google/uuid"
)

type fakeHierarchy map[Scope][]Scope

func (f fakeHierarchy) Ancestors(_ context.Context, s Scope) ([]Scope, error) {
	if a, ok := f[s]; ok {
		return a, nil
	}
	return []Scope{s}, nil
}

func grants(role string, s Scope) []Grant {
	r, _ := LookupSystemRole(role)
	var out []Grant
	for _, p := range r.Permissions {
		out = append(out, Grant{p, s})
	}
	return out
}

func TestCatalogIntegrity(t *testing.T) {
	seen := map[Permission]bool{}
	for _, p := range Permissions {
		if seen[p.Key] {
			t.Errorf("duplicate permission %s", p.Key)
		}
		seen[p.Key] = true
	}
	if len(SystemRoles) != 10 {
		t.Errorf("want 10 system roles, got %d", len(SystemRoles))
	}
	roles := map[string]bool{}
	for _, r := range SystemRoles {
		if roles[r.Key] {
			t.Errorf("duplicate role %s", r.Key)
		}
		roles[r.Key] = true
		for _, p := range r.Permissions {
			if !seen[p] {
				t.Errorf("role %s references unknown permission %s", r.Key, p)
			}
		}
	}
	sa, _ := LookupSystemRole(RoleSuperAdmin)
	if len(sa.Permissions) != len(Permissions) {
		t.Errorf("super_admin must hold every permission")
	}
}

func TestSeparationOfDuties(t *testing.T) {
	pa, _ := LookupSystemRole("platform_admin")
	for _, p := range pa.Permissions {
		if p == PermFindingsAcceptRisk || p == PermFindingsTriage {
			t.Errorf("platform_admin must not hold %s", p)
		}
	}
	au, _ := LookupSystemRole("auditor")
	for _, p := range au.Permissions {
		if p == PermUsersManage || p == PermFindingsTriage || p == PermRolesAssign {
			t.Errorf("auditor must be read-only, holds %s", p)
		}
	}
}

func TestScopedAccess(t *testing.T) {
	ctx := context.Background()
	org := uuid.New()
	emea := Scope{ScopeRegion, uuid.New()}
	apac := Scope{ScopeRegion, uuid.New()}
	payments := Scope{ScopeBusinessUnit, uuid.New()}
	repoA := Scope{ScopeRepository, uuid.New()} // in payments BU, EMEA
	repoB := Scope{ScopeRepository, uuid.New()} // APAC
	orgScope := Scope{ScopeOrganization, org}
	h := fakeHierarchy{
		repoA:    {repoA, payments, emea, orgScope},
		repoB:    {repoB, apac, orgScope},
		payments: {payments, emea, orgScope},
	}
	az := &Authorizer{H: h}

	analyst := &Principal{UserID: uuid.New(), OrganizationID: org, Grants: grants("security_analyst", emea)}

	if ok, _ := az.Can(ctx, analyst, PermFindingsTriage, repoA); !ok {
		t.Error("EMEA analyst should triage EMEA repository")
	}
	if ok, _ := az.Can(ctx, analyst, PermFindingsTriage, repoB); ok {
		t.Error("EMEA analyst must not triage APAC repository")
	}
	if ok, _ := az.Can(ctx, analyst, PermFindingsAcceptRisk, repoA); ok {
		t.Error("analyst must not accept risk")
	}

	// Org-only permissions are never granted by a narrow assignment, even if
	// the role contains them.
	mgr := &Principal{UserID: uuid.New(), OrganizationID: org, Grants: grants("security_manager", payments)}
	if ok, _ := az.Can(ctx, mgr, PermUsersRead, orgScope); ok {
		t.Error("BU-scoped manager must not read the org user list")
	}
	if FilterFor(mgr, PermUsersRead).All || !FilterFor(mgr, PermUsersRead).None() {
		t.Error("org-only permission filter must be empty for BU-scoped grant")
	}

	admin := &Principal{UserID: uuid.New(), OrganizationID: org, Grants: grants(RoleSuperAdmin, orgScope)}
	if ok, _ := az.Can(ctx, admin, PermFindingsAcceptRisk, repoB); !ok {
		t.Error("org super admin should have access everywhere")
	}

	// A grant on another organization's ID must not count as org-wide.
	foreign := &Principal{UserID: uuid.New(), OrganizationID: org, Grants: grants(RoleSuperAdmin, Scope{ScopeOrganization, uuid.New()})}
	if ok, _ := az.Can(ctx, foreign, PermUsersRead, orgScope); ok {
		t.Error("grant on a different organization must not apply")
	}
}

func TestFilterFor(t *testing.T) {
	org := uuid.New()
	r1, b1, repo := uuid.New(), uuid.New(), uuid.New()
	p := &Principal{OrganizationID: org, Grants: []Grant{
		{PermFindingsRead, Scope{ScopeRegion, r1}},
		{PermFindingsRead, Scope{ScopeBusinessUnit, b1}},
		{PermFindingsRead, Scope{ScopeRepository, repo}},
		{PermScansRun, Scope{ScopeRegion, uuid.New()}},
	}}
	f := FilterFor(p, PermFindingsRead)
	if f.All || len(f.RegionIDs) != 1 || len(f.BusinessUnits) != 1 || len(f.RepositoryIDs) != 1 {
		t.Fatalf("unexpected filter %+v", f)
	}
	p.Grants = append(p.Grants, Grant{PermFindingsRead, Scope{ScopeOrganization, org}})
	if f := FilterFor(p, PermFindingsRead); !f.All || len(f.RegionIDs) != 0 {
		t.Fatalf("org grant should collapse filter to All: %+v", f)
	}
	if !FilterFor(nil, PermFindingsRead).None() {
		t.Fatal("nil principal must match nothing")
	}
}

func TestNoPrivilegeEscalation(t *testing.T) {
	ctx := context.Background()
	org := uuid.New()
	orgScope := Scope{ScopeOrganization, org}
	az := &Authorizer{}
	mgr := &Principal{OrganizationID: org, Grants: grants("security_manager", orgScope)}

	analyst, _ := LookupSystemRole("security_analyst")
	if ok, _ := az.CanGrantRole(ctx, mgr, analyst.Permissions, orgScope); !ok {
		t.Error("manager should be able to grant analyst (subset of own permissions)")
	}
	sa, _ := LookupSystemRole(RoleSuperAdmin)
	if ok, _ := az.CanGrantRole(ctx, mgr, sa.Permissions, orgScope); ok {
		t.Error("manager must not grant super_admin")
	}
	pa, _ := LookupSystemRole("platform_admin")
	if ok, _ := az.CanGrantRole(ctx, mgr, pa.Permissions, orgScope); ok {
		t.Error("manager must not grant platform_admin (holds permissions the manager lacks)")
	}
	viewer := &Principal{OrganizationID: org, Grants: grants("viewer", orgScope)}
	v, _ := LookupSystemRole("viewer")
	if ok, _ := az.CanGrantRole(ctx, viewer, v.Permissions, orgScope); ok {
		t.Error("viewer lacks roles.assign")
	}
}
