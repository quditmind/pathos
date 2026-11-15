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
		if f.otp[id] {
			_, _ = w.Write([]byte(`[{"type":"password"},{"type":"otp"}]`))
		} else {
			_, _ = w.Write([]byte(`[{"type":"password"}]`))
		}
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
