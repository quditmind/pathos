//go:build integration

package integration

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/google/uuid"

	"pathos/internal/auth"
	"pathos/internal/authz"
	"pathos/internal/identity"
	"pathos/internal/mcp"
	"pathos/internal/platform/config"
)

func TestRESTAPITokens(t *testing.T) {
	ctx := t.Context()
	pub, _ := url.Parse("https://pathos.example")
	as := &auth.Service{Cfg: &config.Config{PublicURL: pub}, DB: appPool, Log: log, OrgID: orgID}
	ms := &mcp.Service{DB: appPool, Log: log, Principal: auth.PrincipalFrom, PublicURL: "https://pathos.example"}
	api := http.NewServeMux()
	ms.Register(api)
	api.HandleFunc("GET /api/v1/whoami", func(w http.ResponseWriter, r *http.Request) {
		p := auth.PrincipalFrom(r.Context())
		_ = json.NewEncoder(w).Encode(map[string]any{"email": p.Email, "can_manage_repos": p.HasAnywhere(authz.PermReposManage)})
	})
	api.HandleFunc("POST /api/v1/things", func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusCreated) })
	h := as.Authenticate(as.RequireAuth(api))
	// Outside /api/ (for example the MCP endpoint) bearer tokens are left to
	// the endpoint.
	mcpSeen := ""
	outside := as.Authenticate(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { mcpSeen = r.Header.Get("Authorization") }))

	u, err := identity.CreateUser(ctx, appPool, identity.User{OrganizationID: orgID, Email: "tok-" + uuid.NewString()[:6] + "@acme.test", Status: identity.StatusActive})
	if err != nil {
		t.Fatal(err)
	}
	role, _ := identity.GetRoleByKey(ctx, appPool, orgID, "viewer")
	if _, err := identity.CreateAssignment(ctx, appPool, orgID, u.ID, role.ID, authz.Scope{Type: authz.ScopeOrganization, ID: orgID}, nil); err != nil {
		t.Fatal(err)
	}
	grants, _ := identity.LoadGrants(ctx, appPool, u.ID)
	owner := &authz.Principal{UserID: u.ID, OrganizationID: orgID, Email: u.Email, Grants: grants}
	mint := func(scopes ...string) string {
		raw, _ := json.Marshal(map[string]any{"name": "ci", "days": 7, "scopes": scopes})
		req := httptest.NewRequest("POST", "/api/v1/me/tokens", bytes.NewReader(raw)).WithContext(auth.WithPrincipal(ctx, owner))
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()
		api.ServeHTTP(rec, req)
		var out map[string]any
		_ = json.Unmarshal(rec.Body.Bytes(), &out)
		if rec.Code != 201 {
			t.Fatalf("mint %v: %d %v", scopes, rec.Code, out)
		}
		return out["secret"].(string)
	}
	do := func(method, path, tok string) (int, map[string]any) {
		req := httptest.NewRequest(method, path, nil)
		if tok != "" {
			req.Header.Set("Authorization", "Bearer "+tok)
		}
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		var out map[string]any
		_ = json.Unmarshal(rec.Body.Bytes(), &out)
		return rec.Code, out
	}
	read, write, mcpOnly := mint("api:read"), mint("api:read", "api:write"), mint("mcp")
	{
		req := httptest.NewRequest("POST", "/mcp", nil)
		req.Header.Set("Authorization", "Bearer "+mcpOnly)
		rec := httptest.NewRecorder()
		outside.ServeHTTP(rec, req)
		if rec.Code != 200 || mcpSeen != "Bearer "+mcpOnly {
			t.Errorf("MCP endpoint receives its token untouched: %d", rec.Code)
		}
	}

	if code, out := do("GET", "/api/v1/whoami", read); code != 200 || out["email"] != u.Email || out["can_manage_repos"] != false {
		t.Errorf("read token acts as its owner with the owner's rights: %d %v", code, out)
	}
	if code, _ := do("POST", "/api/v1/things", read); code != 403 {
		t.Errorf("read token cannot write: %d", code)
	}
	if code, _ := do("POST", "/api/v1/things", write); code != 201 {
		t.Errorf("write token, no CSRF needed: %d", code)
	}
	if code, _ := do("GET", "/api/v1/whoami", mcpOnly); code != 401 {
		t.Errorf("MCP-only token is not a REST token: %d", code)
	}
	if code, _ := do("GET", "/api/v1/whoami", "pathos_pat_forged"); code != 401 {
		t.Errorf("unknown token: %d", code)
	}
	if code, _ := do("GET", "/api/v1/whoami", ""); code != 401 {
		t.Errorf("no credentials: %d", code)
	}
	// Tokens cannot mint tokens or touch sign-in security.
	if code, _ := do("POST", "/api/v1/me/tokens", write); code != 403 {
		t.Errorf("token minting with a token: %d", code)
	}
	if code, _ := do("GET", "/api/v1/me/tokens", write); code != 403 {
		t.Errorf("token listing with a token: %d", code)
	}
	// Deactivating the owner stops the token at once.
	if _, err := appPool.Exec(ctx, `UPDATE users SET status = 'deactivated' WHERE id = $1`, u.ID); err != nil {
		t.Fatal(err)
	}
	if code, _ := do("GET", "/api/v1/whoami", read); code != 401 {
		t.Errorf("deactivated owner: %d", code)
	}
	var used int
	_ = appPool.QueryRow(ctx, `SELECT count(*) FROM api_tokens WHERE user_id = $1 AND last_used_at IS NOT NULL`, u.ID).Scan(&used)
	if used < 2 {
		t.Errorf("last use recorded: %d", used)
	}
}
