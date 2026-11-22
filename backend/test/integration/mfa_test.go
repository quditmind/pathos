//go:build integration

package integration

import (
	"bytes"
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

	// A person who also belongs to another organization: their identity
	// provider account is shared, so this organization may read its MFA
	// status but not change it.
	otherOrg := uuid.Must(uuid.NewV7())
	if _, err := ownerPool.Exec(ctx, `INSERT INTO organizations (id, name, slug) VALUES ($1, 'Other MFA', $2)`, otherOrg, "mfa-"+otherOrg.String()[:8]); err != nil {
		t.Fatal(err)
	}
	shared := "kc-shared-" + uuid.NewString()
	if _, err := ownerPool.Exec(ctx, `INSERT INTO users (id, organization_id, email, status, keycloak_subject) VALUES (gen_random_uuid(), $1, $2, 'active', $3)`,
		otherOrg, "shared-"+uuid.NewString()[:8]+"@other.test", shared); err != nil {
		t.Fatal(err)
	}
	here := mk(&shared)
	// Later tests roll the schema back below multi-tenancy, where a
	// Keycloak subject was unique across the table.
	t.Cleanup(func() {
		_, _ = ownerPool.Exec(context.Background(), `DELETE FROM users WHERE keycloak_subject = $1`, shared)
		_, _ = ownerPool.Exec(context.Background(), `DELETE FROM organizations WHERE id = $1`, otherOrg)
	})
	if code, _ := call(admin, "GET", "/api/v1/users/"+here.String()+"/mfa"); code != 200 {
		t.Errorf("reading the MFA status of a shared account: %d", code)
	}
	for _, path := range []string{"/require-mfa", "/recovery-codes"} {
		if code, out := call(admin, "POST", "/api/v1/users/"+here.String()+path); code != 409 {
			t.Errorf("%s on a shared account: want 409, got %d %v", path, code, out)
		}
	}
	if idp.pending[shared] || idp.codes[shared] {
		t.Error("the shared account was changed")
	}
}

// existingIdP reports every account as already existing in the identity
// provider (created=false).
type existingIdP struct {
	fakeIdP
	sub string
}

func (f *existingIdP) EnsureUser(context.Context, string, string) (string, bool, error) {
	return f.sub, false, nil
}

// With multi-tenancy on (this suite), inviting an email whose identity
// provider account already exists does not link it: the person joins when
// they sign in to the organization, not when another organization's
// administrator types their address.
func TestInviteDoesNotLinkExistingAccountWhenMultiTenant(t *testing.T) {
	ctx := t.Context()
	idp := &existingIdP{fakeIdP: fakeIdP{pending: map[string]bool{}, configured: map[string]bool{}, codes: map[string]bool{}}, sub: "kc-existing-" + uuid.NewString()}
	h := &identity.Handlers{DB: appPool, Authz: &authz.Authorizer{H: &org.Hierarchy{DB: appPool, OrgID: orgID}}, Provisioner: idp, Log: log,
		Principal: auth.PrincipalFrom, CSRFToken: func(context.Context) string { return "" }}
	mux := newMux(h.Register)
	body, _ := json.Marshal(map[string]any{"email": "existing-" + uuid.NewString()[:8] + "@other.test", "display_name": "Existing Person"})
	req := httptest.NewRequest("POST", "/api/v1/users", bytes.NewReader(body)).WithContext(auth.WithPrincipal(ctx, principalWithRole(t, "platform_admin")))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	var out struct {
		User         struct{ ID uuid.UUID `json:"id"` } `json:"user"`
		Provisioning struct{ Status string `json:"status"` } `json:"provisioning"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &out)
	if rec.Code != 201 || out.Provisioning.Status != "invited" {
		t.Fatalf("create: %d %s", rec.Code, rec.Body.String())
	}
	var sub *string
	if err := appPool.QueryRow(ctx, `SELECT keycloak_subject FROM users WHERE id = $1`, out.User.ID).Scan(&sub); err != nil || sub != nil {
		t.Errorf("the existing account must not be linked: %v %v", sub, err)
	}
}
