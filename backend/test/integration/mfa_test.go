//go:build integration

package integration

import (
	"context"
	"encoding/json"
	"net/http/httptest"
	"testing"

	"github.com/google/uuid"

	"pathos/internal/auth"
	"pathos/internal/authz"
	"pathos/internal/identity"
	"pathos/internal/org"
)

// fakeIdP implements identity.Provisioner and identity.MFAManager.
type fakeIdP struct{ pending, configured, codes map[string]bool }

func (f *fakeIdP) EnsureUser(context.Context, string, string) (string, bool, error) {
	return uuid.NewString(), true, nil
}
func (f *fakeIdP) SetEnabled(context.Context, string, bool) error { return nil }
func (f *fakeIdP) Logout(context.Context, string) error           { return nil }
func (f *fakeIdP) MFAStatus(_ context.Context, sub string) (identity.MFAStatus, error) {
	return identity.MFAStatus{Configured: f.configured[sub], Pending: f.pending[sub], RecoveryPending: f.codes[sub]}, nil
}
func (f *fakeIdP) RequireRecoveryCodes(_ context.Context, sub string) (bool, error) {
	if f.codes[sub] {
		return false, nil
	}
	f.codes[sub] = true
	return true, nil
}
func (f *fakeIdP) RequireMFA(_ context.Context, sub string) (bool, error) {
	if f.configured[sub] || f.pending[sub] {
		return false, nil
	}
	f.pending[sub] = true
	return true, nil
}

func TestMFAManagement(t *testing.T) {
	ctx := t.Context()
	idp := &fakeIdP{pending: map[string]bool{}, configured: map[string]bool{}, codes: map[string]bool{}}
	h := &identity.Handlers{DB: appPool, Authz: &authz.Authorizer{H: &org.Hierarchy{DB: appPool, OrgID: orgID}}, Provisioner: idp, Log: log,
		Principal: auth.PrincipalFrom, CSRFToken: func(context.Context) string { return "" }}
	mux := newMux(h.Register)
	call := func(p *authz.Principal, method, path string) (int, map[string]any) {
		req := httptest.NewRequest(method, path, nil).WithContext(auth.WithPrincipal(ctx, p))
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)
		var out map[string]any
		_ = json.Unmarshal(rec.Body.Bytes(), &out)
		return rec.Code, out
	}
	admin := principalWithRole(t, "platform_admin")
	viewer := principalWithRole(t, "viewer")
	mk := func(sub *string) uuid.UUID {
		u, err := identity.CreateUser(ctx, appPool, identity.User{OrganizationID: orgID, Email: "mfa-" + uuid.NewString()[:8] + "@acme.test", Status: identity.StatusActive, KeycloakSubject: sub})
		if err != nil {
			t.Fatal(err)
		}
		return u.ID
	}
	sub := "kc-" + uuid.NewString()
	linked, unlinked := mk(&sub), mk(nil)

	if code, st := call(admin, "GET", "/api/v1/users/"+linked.String()+"/mfa"); code != 200 || st["configured"] != false || st["pending"] != false {
		t.Fatalf("status: %d %v", code, st)
	}
	if code, _ := call(viewer, "POST", "/api/v1/users/"+linked.String()+"/require-mfa"); code != 403 {
		t.Errorf("viewer lacks users.manage: %d", code)
	}
	code, out := call(admin, "POST", "/api/v1/users/"+linked.String()+"/require-mfa")
	if code != 200 || out["changed"] != true || out["mfa"].(map[string]any)["pending"] != true {
		t.Fatalf("require: %d %v", code, out)
	}
	if _, out := call(admin, "POST", "/api/v1/users/"+linked.String()+"/require-mfa"); out["changed"] != false {
		t.Errorf("second require must be a no-op: %v", out)
	}
	if code, _ := call(admin, "POST", "/api/v1/users/"+unlinked.String()+"/require-mfa"); code != 409 {
		t.Errorf("user without a Keycloak account: want 409, got %d", code)
	}
	var n int
	_ = appPool.QueryRow(ctx, `SELECT count(*) FROM audit_logs WHERE action = 'user.require_mfa' AND target_id = $1`, linked.String()).Scan(&n)
	if n != 2 {
		t.Errorf("each require-mfa call is audited, got %d", n)
	}

	// Recovery codes: administrators for anyone, everyone for themselves.
	if code, _ := call(viewer, "POST", "/api/v1/users/"+linked.String()+"/recovery-codes"); code != 403 {
		t.Errorf("viewer cannot require codes for others: %d", code)
	}
	if code, out := call(admin, "POST", "/api/v1/users/"+linked.String()+"/recovery-codes"); code != 200 || out["changed"] != true ||
		out["mfa"].(map[string]any)["recovery_pending"] != true {
		t.Errorf("admin recovery codes: %d %v", code, out)
	}
	selfSub := "kc-" + uuid.NewString()
	self := mk(&selfSub)
	me := &authz.Principal{UserID: self, OrganizationID: orgID, Email: "self@acme.test"}
	if code, st := call(me, "GET", "/api/v1/me/mfa"); code != 200 || st["recovery_pending"] != false {
		t.Errorf("own status: %d %v", code, st)
	}
	if code, out := call(me, "POST", "/api/v1/me/recovery-codes"); code != 200 || out["changed"] != true || !idp.codes[selfSub] {
		t.Errorf("own recovery codes: %d %v", code, out)
	}
	unlinkedMe := &authz.Principal{UserID: unlinked, OrganizationID: orgID}
	if code, _ := call(unlinkedMe, "POST", "/api/v1/me/recovery-codes"); code != 409 {
		t.Errorf("account without Keycloak: %d", code)
	}
	_ = appPool.QueryRow(ctx, `SELECT count(*) FROM audit_logs WHERE action = 'user.recovery_codes' AND target_id = $1`, self.String()).Scan(&n)
	if n != 1 {
		t.Errorf("self-service is audited: %d", n)
	}

	// Bulk enforcement covers every linked active/invited user once.
	other := "kc-" + uuid.NewString()
	mk(&other)
	before, err := identity.EnforceMFA(ctx, appPool, idp, log)
	if err != nil || before < 1 || !idp.pending[other] {
		t.Fatalf("enforce: %d %v", before, err)
	}
	if again, _ := identity.EnforceMFA(ctx, appPool, idp, log); again != 0 {
		t.Errorf("enforcement must be idempotent, changed %d", again)
	}
}
