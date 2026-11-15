//go:build integration

package integration

import (
	"encoding/json"
	"net/http/httptest"
	"testing"
	"time"

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
	for _, k := range resp.KPIs {
		if k.Status != "ok" || k.Value == nil {
			t.Errorf("with phases 1-6 delivered every KPI has data: %+v", k)
		}
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

// The open-findings trend uses a single-pass running sum; it must equal the
// direct definition (open at the end of each day) for every day and severity,
// including findings resolved inside, before and after the window.
func TestFindingsTrendMatchesDefinition(t *testing.T) {
	ctx := t.Context()
	repo := createRepo(t, "trend-"+uuid.NewString()[:6])
	sevs := []string{"critical", "high", "medium", "low"}
	for i := range 60 {
		f := insertFinding(t, repo, sevs[i%4], "")
		first := time.Now().Add(-time.Duration(i%45) * 24 * time.Hour).Add(-time.Duration(i) * time.Hour)
		var resolved *time.Time
		if i%3 == 0 {
			r := first.Add(time.Duration(i%20) * 24 * time.Hour)
			resolved = &r
		}
		if _, err := ownerPool.Exec(ctx, `UPDATE findings SET first_seen_at = $2, resolved_at = $3,
			status = CASE WHEN $3::timestamptz IS NULL THEN status ELSE 'fixed' END WHERE id = $1`, f, first, resolved); err != nil {
			t.Fatal(err)
		}
	}
	h := &dashboard.Handlers{DB: appPool, Log: log, Principal: auth.PrincipalFrom}
	rec := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/api/v1/dashboard?days=30", nil)
	req = req.WithContext(auth.WithPrincipal(req.Context(), principalWithRole(t, authz.RoleSuperAdmin)))
	newMux(h.Register).ServeHTTP(rec, req)
	var resp dashboard.Response
	_ = json.Unmarshal(rec.Body.Bytes(), &resp)
	var trend *dashboard.Chart
	for i := range resp.Charts {
		if resp.Charts[i].Key == "findings_trend" {
			trend = &resp.Charts[i]
		}
	}
	if trend == nil || len(trend.Series) != 4 {
		t.Fatalf("findings_trend missing: %+v", trend)
	}
	checked := 0
	for _, s := range trend.Series {
		for _, p := range s.Points {
			var want int64
			if err := appPool.QueryRow(ctx, `SELECT count(*) FROM findings f WHERE f.organization_id = $1 AND f.severity = $2
				AND f.status NOT IN ('false_positive', 'accepted_risk')
				AND f.first_seen_at < $3::date + interval '1 day' AND (f.resolved_at IS NULL OR f.resolved_at >= $3::date + interval '1 day')`,
				orgID, s.Name, p.Date).Scan(&want); err != nil {
				t.Fatal(err)
			}
			if int64(p.Value) != want {
				t.Errorf("%s %s: chart %v, definition %d", s.Name, p.Date, p.Value, want)
			}
			checked++
		}
	}
	if checked < 4*30 {
		t.Errorf("checked only %d points", checked)
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
