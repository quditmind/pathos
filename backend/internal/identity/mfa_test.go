package identity

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// fakeKeycloak serves the admin endpoints used for MFA.
type fakeKeycloak struct {
	actions map[string][]string
	otp     map[string]bool
	codes   map[string]bool
	puts    int
}

func (f *fakeKeycloak) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if strings.HasSuffix(r.URL.Path, "/token") {
		_, _ = w.Write([]byte(`{"access_token":"t","token_type":"Bearer","expires_in":300}`))
		return
	}
	parts := strings.Split(strings.TrimSuffix(r.URL.Path, "/credentials"), "/")
	id := parts[len(parts)-1]
	switch {
	case strings.HasSuffix(r.URL.Path, "/credentials"):
		creds := []map[string]string{{"type": "password"}}
		if f.otp[id] {
			creds = append(creds, map[string]string{"type": "otp"})
		}
		if f.codes[id] {
			creds = append(creds, map[string]string{"type": "recovery-authn-codes"})
		}
		_ = json.NewEncoder(w).Encode(creds)
	case r.Method == http.MethodGet:
		_ = json.NewEncoder(w).Encode(map[string]any{"requiredActions": f.actions[id]})
	case r.Method == http.MethodPut:
		var body struct {
			RequiredActions []string `json:"requiredActions"`
		}
		_ = json.NewDecoder(r.Body).Decode(&body)
		f.actions[id] = body.RequiredActions
		f.puts++
		w.WriteHeader(http.StatusNoContent)
	}
}

func TestRequireMFA(t *testing.T) {
	f := &fakeKeycloak{actions: map[string][]string{"invited": {"UPDATE_PASSWORD", "VERIFY_EMAIL"}}, otp: map[string]bool{"enrolled": true}}
	srv := httptest.NewServer(f)
	defer srv.Close()
	k := &KeycloakProvisioner{BaseURL: srv.URL, Realm: "pathos", ClientID: "c", ClientSecret: "s"}
	ctx := context.Background()

	if changed, err := k.RequireMFA(ctx, "invited"); err != nil || !changed {
		t.Fatalf("invited user: changed=%v err=%v", changed, err)
	}
	if got := f.actions["invited"]; strings.Join(got, ",") != "UPDATE_PASSWORD,VERIFY_EMAIL,CONFIGURE_TOTP" {
		t.Errorf("existing required actions must be kept: %v", got)
	}
	if st, _ := k.MFAStatus(ctx, "invited"); !st.Pending || st.Configured {
		t.Errorf("status after require: %+v", st)
	}
	if changed, _ := k.RequireMFA(ctx, "invited"); changed {
		t.Error("second call must be a no-op")
	}
	if changed, _ := k.RequireMFA(ctx, "enrolled"); changed {
		t.Error("users with an authenticator are left alone")
	}
	if st, _ := k.MFAStatus(ctx, "enrolled"); !st.Configured || st.Pending {
		t.Errorf("enrolled status: %+v", st)
	}
	if f.puts != 1 {
		t.Errorf("exactly one update expected, got %d", f.puts)
	}
}

func TestRequireRecoveryCodes(t *testing.T) {
	f := &fakeKeycloak{actions: map[string][]string{"u": {"VERIFY_EMAIL"}}, otp: map[string]bool{"u": true, "v": true}, codes: map[string]bool{"v": true}}
	srv := httptest.NewServer(f)
	defer srv.Close()
	k := &KeycloakProvisioner{BaseURL: srv.URL, Realm: "pathos", ClientID: "c", ClientSecret: "s"}
	ctx := context.Background()
	if st, _ := k.MFAStatus(ctx, "v"); !st.RecoveryCodes || st.RecoveryPending {
		t.Errorf("codes configured: %+v", st)
	}
	if changed, err := k.RequireRecoveryCodes(ctx, "u"); err != nil || !changed {
		t.Fatalf("require: %v %v", changed, err)
	}
	if got := strings.Join(f.actions["u"], ","); got != "VERIFY_EMAIL,CONFIGURE_RECOVERY_AUTHN_CODES" {
		t.Errorf("required actions kept: %s", got)
	}
	if st, _ := k.MFAStatus(ctx, "u"); !st.RecoveryPending || st.RecoveryCodes || !st.Configured {
		t.Errorf("pending: %+v", st)
	}
	if changed, _ := k.RequireRecoveryCodes(ctx, "u"); changed {
		t.Error("idempotent while pending")
	}
	// A user with codes can generate a new set (replacing the old one).
	if changed, _ := k.RequireRecoveryCodes(ctx, "v"); !changed {
		t.Error("regenerating codes is allowed")
	}
}
