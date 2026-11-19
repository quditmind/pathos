//go:build integration

package integration

// PATHOS 3.0 enterprise shell, backend part: GET /api/v1/meta, the error
// envelope on every API route, feature flags and troubleshooting. The
// tests run in their own organization (created like a multi-tenant
// install) so they never change the suite's main organization.

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"pathos/internal/ai"
	"pathos/internal/auth"
	"pathos/internal/authz"
	"pathos/internal/diagnostics"
	"pathos/internal/identity"
	"pathos/internal/mcp"
	"pathos/internal/notify"
	"pathos/internal/org"
	"pathos/internal/platform/buildinfo"
	"pathos/internal/platform/config"
	"pathos/internal/platform/crypto"
	"pathos/internal/platform/db"
	"pathos/internal/platform/diag"
	"pathos/internal/platform/sourcestore"
	"pathos/internal/platform/tenant"
	"pathos/internal/repos"
	"pathos/internal/review"
	"pathos/internal/scans"
	"pathos/internal/secrets"
	"pathos/internal/server"
	"pathos/internal/tenancy"
	"pathos/internal/vuln"
)

const diagBootstrap = "diag-bootstrap-token-0123456789abcdefghijklmnop"

type diagUser struct {
	token string
	p     *authz.Principal
}

type diagEnv struct {
	pool   *pgxpool.Pool
	store  *secrets.Store
	org    uuid.UUID
	api    http.Handler
	worker http.Handler
	users  map[string]diagUser // by role key
}

// newDiagEnv creates an organization with a user (and REST token) per
// system role and the full API handler, like a multi-tenant install.
func newDiagEnv(t *testing.T) *diagEnv {
	t.Helper()
	ctx := context.Background()
	pool, err := db.Connect(ctx, appURL, log)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	keys, err := crypto.NewKeyring(map[int][]byte{1: testKey})
	if err != nil {
		t.Fatal(err)
	}
	store := &secrets.Store{Keys: keys}
	seed := func(ctx context.Context, id uuid.UUID) error {
		if err := scans.EnsureDefaultProfile(ctx, pool, id); err != nil {
			return err
		}
		if err := vuln.EnsureDefaults(ctx, pool, id); err != nil {
			return err
		}
		if err := notify.EnsureDefaults(ctx, pool, store, id); err != nil {
			return err
		}
		if err := mcp.EnsureBuiltIn(ctx, pool, id, "https://pathos.example"); err != nil {
			return err
		}
		if err := review.EnsureSettings(ctx, pool, id); err != nil {
			return err
		}
		return repos.EnsureAssetDefaults(ctx, pool, id)
	}
	o, _, err := tenancy.CreateOrganization(ctx, pool, "Diagnostics", "diag-"+uuid.NewString()[:6], "", seed)
	if err != nil {
		t.Fatal(err)
	}
	pub := mustURL("https://pathos.example")
	as := &auth.Service{Cfg: &config.Config{PublicURL: pub, OrgClaim: "groups", OrgGroupPrefix: "/pathos/"}, DB: pool, Log: log, OrgID: orgID, MultiTenant: true}
	sources, err := sourcestore.NewFS(t.TempDir(), keys)
	if err != nil {
		t.Fatal(err)
	}
	h := server.Build(server.Deps{DB: pool, Auth: as, OrgID: orgID, MultiTenant: true, Log: log, Secrets: store,
		PublicURL: "https://pathos.example", WorkerBootstrapToken: diagBootstrap, Offline: true, Sources: sources})
	env := &diagEnv{pool: pool, store: store, org: o.ID, api: h.Public, worker: h.Worker, users: map[string]diagUser{}}
	octx := tenant.WithOrg(ctx, o.ID)
	for _, r := range authz.SystemRoles {
		u, err := identity.CreateUser(octx, pool, identity.User{OrganizationID: o.ID, Email: r.Key + "-" + uuid.NewString()[:6] + "@diag.test", Status: identity.StatusActive})
		if err != nil {
			t.Fatal(err)
		}
		role, err := identity.GetRoleByKey(octx, pool, o.ID, r.Key)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := identity.CreateAssignment(octx, pool, o.ID, u.ID, role.ID, authz.Scope{Type: authz.ScopeOrganization, ID: o.ID}, nil); err != nil {
			t.Fatal(err)
		}
		grants, _ := identity.LoadGrants(octx, pool, u.ID)
		env.users[r.Key] = diagUser{token: mintToken(t, octx, pool, o.ID, u.ID, "api:read", "api:write"),
			p: &authz.Principal{UserID: u.ID, OrganizationID: o.ID, Email: u.Email, Grants: grants}}
	}
	return env
}

func mustURL(s string) *url.URL {
	u, err := url.Parse(s)
	must(err)
	return u
}

func (e *diagEnv) do(h http.Handler, tok, method, path string, body []byte) *httptest.ResponseRecorder {
	var rd io.Reader
	if body != nil {
		rd = bytes.NewReader(body)
	}
	req := httptest.NewRequest(method, path, rd)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if tok != "" {
		req.Header.Set("Authorization", "Bearer "+tok)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func jsonOf(t *testing.T, rec *httptest.ResponseRecorder) map[string]any {
	t.Helper()
	var out map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("not JSON (%d): %s", rec.Code, truncateBody(rec.Body.Bytes()))
	}
	return out
}

var pthRe = regexp.MustCompile(`^PTH-[A-Z]+-[0-9]{4}$`)

// checkEnvelope asserts the PATHOS 3.0 error envelope.
func checkEnvelope(rec *httptest.ResponseRecorder) string {
	var out struct {
		Error     map[string]any `json:"error"`
		RequestID string         `json:"request_id"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil || out.Error == nil {
		return "not a JSON error envelope: " + truncateBody(rec.Body.Bytes())
	}
	e := out.Error
	code, _ := e["error_code"].(string)
	if !pthRe.MatchString(code) {
		return "error.error_code missing or invalid: " + truncateBody(rec.Body.Bytes())
	}
	if _, ok := diag.Lookup(code); !ok {
		return code + " is not in the catalogue"
	}
	if legacy, _ := e["code"].(string); legacy == "" {
		return "the legacy error.code is missing"
	}
	rid := rec.Header().Get("X-Request-Id")
	if rid == "" || out.RequestID != rid || e["request_id"] != rid {
		return "request_id missing at one level"
	}
	for _, k := range []string{"title", "message", "cause", "probable_causes", "impact", "actions", "verify", "docs_url"} {
		if _, ok := e[k]; !ok {
			return "error." + k + " missing"
		}
	}
	return ""
}

// Every API route that answers with an error returns the envelope with a
// catalogue code. Routes are found in the source like the isolation suite
// (scanRoutes) and called unauthenticated, as a viewer and as the
// organization's super administrator, with unknown ids and a malformed
// body, inside a throwaway organization.
func TestEveryRouteErrorHasACode(t *testing.T) {
	env := newDiagEnv(t)
	paramRe := regexp.MustCompile(`\{([a-zA-Z_.]+)\}`)
	routes := scanRoutes(t)
	if len(routes) < 380 {
		t.Fatalf("route scan found only %d routes", len(routes))
	}
	errors4xx5xx, checked := 0, 0
	failures := map[string]bool{}
	callers := []struct{ name, tok string }{{"anonymous", ""}, {"viewer", env.users["viewer"].token}, {"super_admin", env.users[authz.RoleSuperAdmin].token}}
	for _, r := range routes {
		if r.Path == "/mcp" {
			continue
		}
		path := paramRe.ReplaceAllStringFunc(r.Path, func(m string) string {
			name := paramRe.FindStringSubmatch(m)[1]
			if v, ok := literalParams[name]; ok {
				return v
			}
			return uuid.Must(uuid.NewV7()).String()
		})
		methods := []string{r.Method}
		if r.Method == "" {
			methods = []string{"GET", "POST"}
		}
		for _, m := range methods {
			for _, c := range callers {
				var body []byte
				if m == "POST" || m == "PUT" || m == "PATCH" {
					body = []byte(`{"malformed":`)
				}
				rec := env.do(env.api, c.tok, m, path, body)
				checked++
				if rec.Code < 400 {
					continue
				}
				errors4xx5xx++
				if msg := checkEnvelope(rec); msg != "" {
					failures[m+" "+r.Path+" as "+c.name+": "+strconv.Itoa(rec.Code)+" "+msg] = true
				}
			}
		}
	}
	for f := range failures {
		t.Error(f)
	}
	if errors4xx5xx < 900 {
		t.Errorf("only %d of %d calls answered with an error; the probe is too weak", errors4xx5xx, checked)
	}
	t.Logf("%d calls, %d error responses, all with a catalogue code", checked, errors4xx5xx)

	// MCP, the worker API and the unmatched /api paths too.
	for _, c := range []struct {
		h            http.Handler
		method, path string
		body         []byte
	}{
		{env.api, "POST", "/mcp", []byte(`{}`)},
		{env.api, "GET", "/mcp", nil},
		{env.api, "GET", "/api/v1/does-not-exist", nil},
		{env.api, "GET", "/api", nil},
		{env.worker, "POST", "/internal/worker/v1/register", []byte(`{"name":"x"}`)},
		{env.worker, "POST", "/internal/worker/v1/lease", []byte(`{}`)},
	} {
		rec := env.do(c.h, "", c.method, c.path, c.body)
		if rec.Code < 400 {
			t.Errorf("%s %s: %d", c.method, c.path, rec.Code)
			continue
		}
		if msg := checkEnvelope(rec); msg != "" {
			t.Errorf("%s %s: %s", c.method, c.path, msg)
		}
	}
	// A wrong worker bootstrap token names the worker registration code.
	rec := env.do(env.worker, "wrong", "POST", "/internal/worker/v1/register", []byte(`{"name":"w","family":"core"}`))
	if rec.Code != 401 || jsonOf(t, rec)["error"].(map[string]any)["error_code"] != "PTH-WORK-1003" {
		t.Errorf("worker registration: %d %s", rec.Code, rec.Body)
	}
}

func TestMetaAndFeatureFlags(t *testing.T) {
	env := newDiagEnv(t)
	ctx := tenant.WithOrg(context.Background(), env.org)
	admin, viewer := env.users[authz.RoleSuperAdmin], env.users["viewer"]

	// A registered worker, so the live registry is not empty.
	reg := env.do(env.worker, diagBootstrap, "POST", "/internal/worker/v1/register", jsonBody(map[string]any{"name": "diag-core-1", "family": "core",
		"version": "3.0.0-test", "scanners": map[string]string{"opengrep": "1.2.3", "trivy": "0.60.0"}, "organization": orgSlug(t, env)}))
	if reg.Code != 200 && reg.Code != 201 {
		t.Fatalf("register worker: %d %s", reg.Code, reg.Body)
	}
	workerToken, _ := jsonOf(t, reg)["token"].(string)

	// Unauthenticated: product, vendor, version only.
	rec := env.do(env.api, "", "GET", "/api/v1/meta", nil)
	pub := jsonOf(t, rec)
	if rec.Code != 200 || len(pub) != 3 || pub["product"] != "PATHOS" || pub["vendor"] != "Quditmind" || pub["version"] != buildinfo.Version {
		t.Fatalf("unauthenticated meta: %d %v", rec.Code, pub)
	}

	// Authenticated: build metadata, flags (all off), workers and packs.
	rec = env.do(env.api, viewer.token, "GET", "/api/v1/meta", nil)
	m := jsonOf(t, rec)
	if rec.Code != 200 || m["commit"] != buildinfo.Commit || m["build_date"] != buildinfo.BuildDate || m["api_version"] != "v1" || m["version"] != buildinfo.Version {
		t.Fatalf("authenticated meta: %d %v", rec.Code, m)
	}
	flags := m["feature_flags"].(map[string]any)
	if len(flags) != 8 {
		t.Errorf("feature flags: %v", flags)
	}
	for k, v := range flags {
		if v != false {
			t.Errorf("flag %s must default off", k)
		}
	}
	workers := m["workers"].([]any)
	if len(workers) != 1 {
		t.Fatalf("workers: %v", workers)
	}
	w0 := workers[0].(map[string]any)
	if w0["name"] != "diag-core-1" || w0["family"] != "core" || w0["version"] != "3.0.0-test" || w0["scanners"].(map[string]any)["opengrep"] != "1.2.3" {
		t.Errorf("worker: %v", w0)
	}
	if packs := m["scanner_packs"].([]any); len(packs) != 1 || packs[0].(map[string]any)["family"] != "core" || packs[0].(map[string]any)["version"] != "3.0.0-test" {
		t.Errorf("scanner packs: %v", packs)
	}
	// No secrets in either answer.
	for _, body := range []string{env.do(env.api, "", "GET", "/api/v1/meta", nil).Body.String(), rec.Body.String()} {
		for _, secret := range []string{diagBootstrap, viewer.token, admin.token, workerToken, "token", "secret", "password", "master"} {
			if secret != "" && strings.Contains(strings.ToLower(body), strings.ToLower(secret)) {
				t.Errorf("meta contains %q: %s", secret, body)
			}
		}
	}

	// Feature flag administration: settings.manage only, audited.
	if rec := env.do(env.api, viewer.token, "GET", "/api/v1/admin/feature-flags", nil); rec.Code != 403 || jsonOf(t, rec)["error"].(map[string]any)["error_code"] != "PTH-AUTH-1002" {
		t.Errorf("viewer list: %d %s", rec.Code, rec.Body)
	}
	if rec := env.do(env.api, viewer.token, "PUT", "/api/v1/admin/feature-flags", jsonBody(map[string]any{"flags": map[string]bool{"connectors": true}})); rec.Code != 403 {
		t.Errorf("viewer update: %d", rec.Code)
	}
	rec = env.do(env.api, admin.token, "GET", "/api/v1/admin/feature-flags", nil)
	if items := jsonOf(t, rec)["items"].([]any); rec.Code != 200 || len(items) != 8 || items[0].(map[string]any)["enabled"] != false {
		t.Fatalf("admin list: %d %s", rec.Code, rec.Body)
	}
	if rec := env.do(env.api, admin.token, "PUT", "/api/v1/admin/feature-flags", jsonBody(map[string]any{"flags": map[string]bool{"bogus": true}})); rec.Code != 422 {
		t.Errorf("unknown flag: %d", rec.Code)
	}
	rec = env.do(env.api, admin.token, "PUT", "/api/v1/admin/feature-flags", jsonBody(map[string]any{"flags": map[string]bool{"connectors": true, "codegraph": false}}))
	if rec.Code != 200 {
		t.Fatalf("update: %d %s", rec.Code, rec.Body)
	}
	for _, it := range jsonOf(t, rec)["items"].([]any) {
		v := it.(map[string]any)
		if (v["name"] == "connectors") != (v["enabled"] == true) {
			t.Errorf("after update: %v", v)
		}
		if v["name"] == "connectors" && (v["updated_at"] == nil || v["updated_by"] == nil) {
			t.Errorf("who and when: %v", v)
		}
	}
	m = jsonOf(t, env.do(env.api, viewer.token, "GET", "/api/v1/meta", nil))
	if f := m["feature_flags"].(map[string]any); f["connectors"] != true || f["codegraph"] != false {
		t.Errorf("meta flags after update: %v", f)
	}
	var audits int
	_ = env.pool.QueryRow(ctx, `SELECT count(*) FROM audit_logs WHERE organization_id = $1 AND action = 'feature_flag.update' AND target_id = 'connectors'
		AND metadata->>'enabled' = 'true' AND actor_id = $2`, env.org, admin.p.UserID).Scan(&audits)
	if audits != 1 {
		t.Errorf("audit entries for the change: %d (an unchanged flag must not be audited)", audits)
	}
	// Other organizations are not affected.
	if on, err := featureEnabled(ctx, env.pool, orgID, "connectors"); err != nil || on {
		t.Errorf("flag leaked to another organization: %v %v", on, err)
	}
}

func orgSlug(t *testing.T, env *diagEnv) string {
	t.Helper()
	var slug string
	if err := env.pool.QueryRow(tenant.WithOrg(context.Background(), env.org), `SELECT slug FROM organizations WHERE id = $1`, env.org).Scan(&slug); err != nil {
		t.Fatal(err)
	}
	return slug
}

func featureEnabled(ctx context.Context, pool *pgxpool.Pool, org uuid.UUID, name string) (bool, error) {
	var on bool
	err := ownerPool.QueryRow(ctx, `SELECT COALESCE((SELECT enabled FROM feature_flags WHERE organization_id = $1 AND name = $2), false)`, org, name).Scan(&on)
	return on, err
}

func jsonBody(v any) []byte {
	b, err := json.Marshal(v)
	must(err)
	return b
}

// kindProvider is a stub AI provider that records the provider kind the
// request went to. It never calls a real model.
type kindProvider struct {
	mu    *sync.Mutex
	kind  string
	calls *[]string
	sent  *[]ai.Request
}

func (k kindProvider) Kind() string                           { return k.kind }
func (k kindProvider) Validate(context.Context, string) error { return nil }
func (k kindProvider) Review(_ context.Context, req ai.Request) (ai.Response, error) {
	k.mu.Lock()
	defer k.mu.Unlock()
	*k.calls = append(*k.calls, k.kind)
	*k.sent = append(*k.sent, req)
	return ai.Response{JSON: []byte(`{"likely_cause":"The API image lacks the private CA.","probable_causes":["TLS inspection"],"actions":["Install the CA bundle."],"verify":["Test the connection."]}`), Model: "stub-" + k.kind}, nil
}

func TestTroubleshootPrefersLocalModelAndRedacts(t *testing.T) {
	env := newDiagEnv(t)
	admin := env.users[authz.RoleSuperAdmin]
	viewer := env.users["viewer"]
	var mu sync.Mutex
	var calls []string
	var sent []ai.Request
	az := &authz.Authorizer{H: &org.Hierarchy{DB: env.pool}}
	aiSvc := &ai.Service{DB: env.pool, Authz: az, Secrets: env.store, Log: log, Principal: auth.PrincipalFrom,
		NewProvider: func(c ai.Config) (ai.Provider, error) {
			return kindProvider{mu: &mu, kind: c.Kind, calls: &calls, sent: &sent}, nil
		}}
	diagSvc := &diagnostics.Service{DB: env.pool, Log: log, Principal: auth.PrincipalFrom, AI: aiSvc}
	mux := http.NewServeMux()
	aiSvc.Register(mux)
	diagSvc.Register(mux)
	call := func(p *authz.Principal, method, path string, body any) (int, map[string]any) {
		req := httptest.NewRequest(method, path, bytes.NewReader(jsonBody(body)))
		req.Header.Set("Content-Type", "application/json")
		req = req.WithContext(auth.WithPrincipal(req.Context(), p))
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)
		var out map[string]any
		_ = json.Unmarshal(rec.Body.Bytes(), &out)
		return rec.Code, out
	}
	tb := map[string]any{"code": "PTH-CONN-1004", "message": "x509: certificate signed by unknown authority; token ghp_" + strings.Repeat("Z", 36),
		"context": map[string]string{"connection_kind": "github", "log": "password=Sup3rS3cret!"}}

	// No AI configuration: the catalogue answers.
	code, out := call(viewer.p, "POST", "/api/v1/diagnostics/troubleshoot", tb)
	if code != 200 || out["source"] != "catalogue" || len(calls) != 0 {
		t.Fatalf("no AI: %d %v", code, out)
	}

	// A cloud provider as the default and a local model: the local model answers.
	_, cloud := call(admin.p, "POST", "/api/v1/ai/providers", map[string]any{"name": "Cloud", "kind": "anthropic", "api_key": "sk-ant-diag-test"})
	if code, _ := call(admin.p, "POST", "/api/v1/ai/configurations", map[string]any{"name": "Default", "provider_id": cloud["id"], "effort": "medium",
		"approval_policy": "always", "categories": []string{"sast"}, "min_severity": "medium", "redaction_patterns": []string{`Sup3r\S+`}}); code != 201 {
		t.Fatalf("cloud configuration: %d", code)
	}
	code, out = call(viewer.p, "POST", "/api/v1/diagnostics/troubleshoot", tb)
	if code != 200 || out["source"] != "ai" || calls[len(calls)-1] != ai.Anthropic {
		t.Fatalf("default configuration: %d %v %v", code, out, calls)
	}
	_, local := call(admin.p, "POST", "/api/v1/ai/providers", map[string]any{"name": "Local", "kind": "self_hosted", "base_url": "http://10.20.30.40:11434/v1"})
	if code, _ := call(admin.p, "POST", "/api/v1/ai/configurations", map[string]any{"name": "Local", "provider_id": local["id"], "model": "qwen-local",
		"effort": "low", "approval_policy": "always", "categories": []string{"sast"}, "min_severity": "medium"}); code != 201 {
		t.Fatalf("local configuration: %d", code)
	}
	code, out = call(viewer.p, "POST", "/api/v1/diagnostics/troubleshoot", tb)
	if code != 200 || out["source"] != "ai" || calls[len(calls)-1] != ai.SelfHosted || out["model"] != "stub-self_hosted" {
		t.Fatalf("local model preferred: %d %v %v", code, out, calls)
	}
	if c := out["cause"].(map[string]any); c["confirmed"] != false || c["text"] != "The API image lacks the private CA." {
		t.Errorf("AI cause must be unconfirmed: %v", c)
	}
	if out["error_code"] != "PTH-CONN-1004" || out["docs_url"] != "/help/troubleshooting/conn#PTH-CONN-1004" {
		t.Errorf("envelope fields: %v", out)
	}
	for _, req := range sent {
		for _, secret := range []string{"ghp_" + strings.Repeat("Z", 36), "Sup3rS3cret", "sk-ant-diag-test"} {
			if strings.Contains(req.User, secret) || strings.Contains(req.System, secret) {
				t.Errorf("secret %q sent to the model", secret)
			}
		}
		if !strings.Contains(req.User, "untrusted_evidence") {
			t.Error("the evidence must be fenced")
		}
	}
}
