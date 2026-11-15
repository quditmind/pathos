//go:build integration

package integration

import (
	"encoding/json"
	"net/http/httptest"
	"testing"

	"github.com/google/uuid"

	"pathos/internal/audit"
	"pathos/internal/auth"
	"pathos/internal/authz"
	"pathos/internal/dashboard"
	"pathos/internal/identity"
	"pathos/internal/search"
)

func principalWithRole(t *testing.T, role string) *authz.Principal {
	t.Helper()
	r, _ := authz.LookupSystemRole(role)
	p := &authz.Principal{UserID: uuid.New(), OrganizationID: orgID}
	for _, perm := range r.Permissions {
		p.Grants = append(p.Grants, authz.Grant{Permission: perm, Scope: authz.Scope{Type: authz.ScopeOrganization, ID: orgID}})
	}
	return p
}

func TestDashboardSummary(t *testing.T) {
	ctx := t.Context()
	_ = audit.Write(ctx, appPool, audit.Entry{OrganizationID: orgID, Action: "auth.login"})
	_ = audit.Write(ctx, appPool, audit.Entry{OrganizationID: orgID, Action: "authz.denied", Outcome: audit.Denied})
	_ = audit.Write(ctx, appPool, audit.Entry{OrganizationID: orgID, Action: "user.invite"})

	call := func(p *authz.Principal, query string) (int, dashboard.Response) {
		h := &dashboard.Handlers{DB: appPool, Log: log, Principal: auth.PrincipalFrom}
		rec := httptest.NewRecorder()
		req := httptest.NewRequest("GET", "/api/v1/dashboard?"+query, nil)
		req = req.WithContext(auth.WithPrincipal(req.Context(), p))
		mux := newMux(h.Register)
		mux.ServeHTTP(rec, req)
		var resp dashboard.Response
		_ = json.Unmarshal(rec.Body.Bytes(), &resp)
		return rec.Code, resp
	}

	code, resp := call(principalWithRole(t, authz.RoleSuperAdmin), "days=7")
	if code != 200 || len(resp.KPIs) != 24 || len(resp.Charts) != len(dashboard.Charts) {
		t.Fatalf("unexpected response %d kpis=%d", code, len(resp.KPIs))
	}
	byKey := map[string]dashboard.KPI{}
	for _, k := range resp.KPIs {
		byKey[k.Key] = k
	}
	if k := byKey["open_findings"]; k.Status != "not_yet_available" || k.Value != nil || k.Phase != 6 {
		t.Errorf("future KPI must not carry a value: %+v", k)
	}
	if k := byKey["security_events"]; k.Status != "ok" || k.Value == nil || *k.Value < 1 || len(k.Sparkline) < 7 {
		t.Errorf("security_events should count denied events: %+v", k)
	}
	if k := byKey["active_users"]; k.Status != "ok" || k.Value == nil {
		t.Errorf("active_users missing: %+v", k)
	}
	for _, c := range resp.Charts {
		if c.Key == "admin_activity" && (c.Status != "ok" || len(c.Categories) == 0) {
			t.Errorf("admin_activity should have categories: %+v", c)
		}
		if c.Key == "sign_ins" && (len(c.Series) != 2 || len(c.Series[0].Points) < 7) {
			t.Errorf("sign_ins should have two daily series: %+v", c)
		}
	}

	// A viewer sees platform KPIs as restricted, never their values.
	_, vr := call(principalWithRole(t, "viewer"), "")
	for _, k := range vr.KPIs {
		if k.Group == "Platform" && (k.Status != "restricted" || k.Value != nil) {
			t.Errorf("viewer must not see %s: %+v", k.Key, k)
		}
	}

	// Geo filters mark org-wide KPIs.
	_, gr := call(principalWithRole(t, authz.RoleSuperAdmin), "region_id="+uuid.NewString())
	for _, k := range gr.KPIs {
		if k.Key == "active_users" && !k.OrgWide {
			t.Error("active_users should be labelled org-wide when geo filters are set")
		}
	}

	if code, _ := call(&authz.Principal{UserID: uuid.New(), OrganizationID: orgID}, ""); code != 403 {
		t.Errorf("principal without dashboard.read: want 403, got %d", code)
	}
}

func TestGlobalSearch(t *testing.T) {
	type res struct {
		Items []search.Result `json:"items"`
	}
	call := func(p *authz.Principal, q string) res {
		h := &search.Handlers{DB: appPool, Log: log, Principal: auth.PrincipalFrom}
		rec := httptest.NewRecorder()
		req := httptest.NewRequest("GET", "/api/v1/search?q="+q, nil)
		req = req.WithContext(auth.WithPrincipal(req.Context(), p))
		newMux(h.Register).ServeHTTP(rec, req)
		var out res
		_ = json.Unmarshal(rec.Body.Bytes(), &out)
		return out
	}
	if _, err := identity.CreateUser(t.Context(), appPool, identity.User{OrganizationID: orgID, Email: "findme-" + uuid.NewString()[:6] + "@search.test"}); err != nil {
		t.Fatal(err)
	}
	admin := principalWithRole(t, authz.RoleSuperAdmin)
	got := call(admin, "germ")
	if len(got.Items) == 0 || got.Items[0].Type != "country" || got.Items[0].Title != "Germany" {
		t.Errorf("search should find Germany: %+v", got.Items)
	}
	if got := call(admin, "search.test"); len(got.Items) == 0 || got.Items[0].Type != "user" {
		t.Errorf("admin should find users: %+v", got.Items)
	}
	for _, it := range call(principalWithRole(t, "viewer"), "search.test").Items {
		if it.Type == "user" {
			t.Fatal("viewer must not find users")
		}
	}
	if got := call(admin, "%"); len(got.Items) != 0 {
		t.Errorf("single wildcard char must not match everything: %+v", got.Items)
	}
}
