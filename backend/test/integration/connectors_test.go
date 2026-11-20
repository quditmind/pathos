//go:build integration

package integration

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"

	"pathos/internal/ai"
	"pathos/internal/auth"
	"pathos/internal/authz"
	"pathos/internal/connectors"
	"pathos/internal/diagnostics"
	"pathos/internal/notify"
	"pathos/internal/org"
	"pathos/internal/platform/crypto"
	"pathos/internal/platform/objstore"
	"pathos/internal/platform/tenant"
	"pathos/internal/runtimectx"
	"pathos/internal/scm"
	"pathos/internal/secrets"
	"pathos/internal/server"
	"pathos/internal/tenancy"
	"pathos/internal/tickets"
)

// Secrets the fakes accept. None of them may ever appear in an API
// response, a stored check or an AI request.
const (
	connGoodToken   = "ghp_ConnectorGoodToken0123456789abcdefABCD"
	connBadToken    = "ghp_ConnectorRevokedToken0123456789abcdefAB"
	connJiraToken   = "jira-scoped-token-value-77"
	connEntraSecret = "entra-client-secret-value-42"
	connSlackPath   = "/services/T0SECRET/B0SECRET/SlackSecretPart"
	connTeamsSig    = "sig=TeamsWorkflowSignatureSecret"
	connRegistryPW  = "registry-password-value-9"
	connKubeToken   = "kube-service-account-token-value"
	connSMTPPass    = "smtp-password-value-5"
)

// fakeSCMAPI answers the check of every SCM provider (GitHub /user, GitLab
// /api/v4/user, Bitbucket /2.0/user, Azure DevOps /_apis/projects) when the
// request carries the good token, and 401 otherwise.
func fakeSCMAPI(t *testing.T) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cred := r.Header.Get("Authorization") + r.Header.Get("PRIVATE-TOKEN")
		if strings.HasPrefix(cred, "Basic ") {
			raw, _ := base64.StdEncoding.DecodeString(strings.TrimPrefix(cred, "Basic "))
			cred = string(raw)
		}
		if !strings.Contains(cred, connGoodToken) {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"login":"octo","username":"octo","name":"Octo","id":7,"display_name":"Octo","account_id":"a1","nickname":"octo","count":0,"value":[]}`))
	}))
}

// routeTo returns a client that sends every request to srv (whatever the
// URL's host), trusting srv's certificate (valid for example.com).
func routeTo(srv *httptest.Server) *http.Client {
	c := srv.Client()
	tr := c.Transport.(*http.Transport).Clone()
	addr := srv.Listener.Addr().String()
	tr.DialContext = func(ctx context.Context, network, _ string) (net.Conn, error) {
		var d net.Dialer
		return d.DialContext(ctx, network, addr)
	}
	return &http.Client{Transport: tr, Timeout: 10 * time.Second}
}

type fakeObjectStore struct {
	*objstore.Memory
	err error
}

func (f fakeObjectStore) Ping(context.Context) error { return f.err }

type connHarness struct {
	t     *testing.T
	org   uuid.UUID
	octx  context.Context
	store *secrets.Store
	mux   *http.ServeMux
	jobs  *connectors.Background
	admin *authz.Principal
	// AI requests sent by troubleshooting.
	mu   sync.Mutex
	sent []ai.Request
}

func (h *connHarness) call(p *authz.Principal, method, path string, body any) (int, map[string]any) {
	h.t.Helper()
	var rd io.Reader
	if body != nil {
		raw, _ := json.Marshal(body)
		rd = bytes.NewReader(raw)
	}
	req := httptest.NewRequest(method, path, rd)
	req.Header.Set("Content-Type", "application/json")
	req = req.WithContext(tenant.WithOrg(auth.WithPrincipal(h.octx, p), h.org))
	rec := httptest.NewRecorder()
	h.mux.ServeHTTP(rec, req)
	var out map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &out)
	for _, s := range []string{connGoodToken, connBadToken, connJiraToken, connEntraSecret, "T0SECRET", "SlackSecretPart", "TeamsWorkflowSignatureSecret",
		connRegistryPW, connKubeToken, connSMTPPass} {
		if strings.Contains(rec.Body.String(), s) {
			h.t.Errorf("%s %s leaked a secret (%s…)", method, path, s[:6])
		}
	}
	return rec.Code, out
}

func (h *connHarness) principal(perms ...authz.Permission) *authz.Principal {
	p := &authz.Principal{UserID: uuid.New(), OrganizationID: h.org, Email: "conn@acme.test"}
	for _, x := range perms {
		p.Grants = append(p.Grants, authz.Grant{Permission: x, Scope: authz.Scope{Type: authz.ScopeOrganization, ID: h.org}})
	}
	return p
}

func (h *connHarness) secret(kind, value string) uuid.UUID {
	h.t.Helper()
	id, err := h.store.Create(h.octx, appPool, h.org, kind, "conn-test", []byte(value), nil)
	if err != nil {
		h.t.Fatal(err)
	}
	return id
}

func (h *connHarness) exec(sql string, args ...any) {
	h.t.Helper()
	if _, err := appPool.Exec(h.octx, sql, args...); err != nil {
		h.t.Fatalf("%s: %v", sql, err)
	}
}

// byName finds a connector in GET /connectors.
func byName(items []any, name string) map[string]any {
	for _, it := range items {
		m := it.(map[string]any)
		if m["name"] == name {
			return m
		}
	}
	return nil
}

func TestConnectorsHub(t *testing.T) {
	ctx := t.Context()
	o, _, err := tenancy.CreateOrganization(ctx, appPool, "Connectors", "conn-"+uuid.NewString()[:6], "", func(context.Context, uuid.UUID) error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	kr, _ := crypto.NewKeyring(map[int][]byte{1: testKey})
	h := &connHarness{t: t, org: o.ID, octx: tenant.WithOrg(ctx, o.ID), store: &secrets.Store{Keys: kr}}
	h.admin = principalForOrg(o.ID, authz.RoleSuperAdmin)
	// The administrator is a real user of the organization: AI calls write
	// an evidence record whose requester references users (PATHOS 3.0 M7).
	h.exec(`INSERT INTO users (id, organization_id, email, status) VALUES ($1, $2, $3, 'active')`, h.admin.UserID, o.ID, h.admin.Email)
	plain := &http.Client{Timeout: 10 * time.Second}

	// --- local fakes -----------------------------------------------------
	scmSrv := fakeSCMAPI(t)
	defer scmSrv.Close()
	scmBase := "http://localhost:" + strconv.Itoa(scmSrv.Listener.Addr().(*net.TCPAddr).Port)

	tracker := &fakeTracker{}
	trackerSrv := httptest.NewTLSServer(tracker)
	defer trackerSrv.Close()

	// Teams Workflows trigger + Microsoft Entra token endpoint + Slack.
	var hookMu sync.Mutex
	var hookAuth []string
	var tokenForms []url.Values
	hookSrv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hookMu.Lock()
		defer hookMu.Unlock()
		switch {
		case strings.HasSuffix(r.URL.Path, "/oauth2/v2.0/token"):
			_ = r.ParseForm()
			tokenForms = append(tokenForms, r.PostForm)
			if r.PostForm.Get("client_secret") != connEntraSecret || r.PostForm.Get("grant_type") != "client_credentials" {
				w.WriteHeader(http.StatusUnauthorized)
				_, _ = w.Write([]byte(`{"error":"invalid_client","error_codes":[7000215],"error_description":"secret for app 0000 tenant x"}`))
				return
			}
			_, _ = w.Write([]byte(`{"access_token":"entra-access-token","expires_in":3600,"token_type":"Bearer"}`))
		case strings.HasPrefix(r.URL.Path, "/workflows/"):
			hookAuth = append(hookAuth, r.Header.Get("Authorization"))
			if r.Header.Get("Authorization") != "Bearer entra-access-token" {
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			w.WriteHeader(http.StatusAccepted)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer hookSrv.Close()
	notify.HTTPOverride = routeTo(hookSrv)
	notify.EntraAuthorityOverride = "https://example.com/entra"
	smtpSrv := startFakeSMTP(t)
	notify.SMTPProbe = notify.SMTPSender{Dial: smtpSrv.dial}
	defer func() {
		notify.HTTPOverride, notify.EntraAuthorityOverride, notify.SMTPProbe = nil, "", notify.SMTPSender{}
	}()

	// Self-hosted model server.
	aiSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/models" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		_, _ = w.Write([]byte(`{"object":"list","data":[{"id":"qwen-local"},{"id":"llama-local"}]}`))
	}))
	defer aiSrv.Close()

	// Kubernetes API server (ingresses forbidden) and an OCI registry.
	k8sSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer "+connKubeToken {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		switch {
		case r.URL.Path == "/version":
			_, _ = w.Write([]byte(`{"gitVersion":"v1.36.1"}`))
		case strings.HasSuffix(r.URL.Path, "/ingresses"):
			w.WriteHeader(http.StatusForbidden)
			_, _ = w.Write([]byte(`{"message":"forbidden"}`))
		default:
			if r.URL.Query().Get("limit") != "1" {
				t.Errorf("cluster check listed more than one object: %s", r.URL)
			}
			_, _ = w.Write([]byte(`{"items":[],"metadata":{}}`))
		}
	}))
	defer k8sSrv.Close()
	regSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		u, p, ok := r.BasicAuth()
		if !ok || u != "robot" || p != connRegistryPW {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/v2/":
			_, _ = w.Write([]byte(`{}`))
		case "/v2/team/api/tags/list":
			_, _ = w.Write([]byte(`{"name":"team/api","tags":["1.0"]}`))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer regSrv.Close()

	egress, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer egress.Close()
	go func() {
		for {
			c, err := egress.Accept()
			if err != nil {
				return
			}
			buf := make([]byte, 512)
			_, _ = c.Read(buf)
			_, _ = c.Write([]byte("HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n"))
			_ = c.Close()
		}
	}()

	// --- services -------------------------------------------------------
	az := &authz.Authorizer{H: &org.Hierarchy{DB: appPool, OrgID: o.ID}}
	deps := server.Deps{DB: appPool, Log: log, Secrets: h.store, SCMNet: scm.NetPolicy{AllowHTTP: true}, PublicURL: "https://pathos.test",
		EgressProxyURL: "http://" + egress.Addr().String(), ConnectorCheckInterval: time.Hour,
		Artifacts: fakeObjectStore{Memory: objstore.NewMemory()}, ObjectStoreMeta: map[string]string{"host": "http://objectstore:8333", "bucket": "pathos"}}
	repoSvc := server.NewReposService(deps, az)
	repoSvc.HTTP = plain
	var aiMu sync.Mutex
	var aiCalls []string
	aiSvc := &ai.Service{DB: appPool, Authz: az, Secrets: h.store, Log: log, Principal: auth.PrincipalFrom, HTTP: plain, LocalHTTP: plain}
	troubleAI := &ai.Service{DB: appPool, Authz: az, Secrets: h.store, Log: log, Principal: auth.PrincipalFrom,
		NewProvider: func(c ai.Config) (ai.Provider, error) {
			return kindProvider{mu: &aiMu, kind: c.Kind, calls: &aiCalls, sent: &h.sent}, nil
		}}
	rtSvc := &runtimectx.Service{DB: appPool, Secrets: h.store, Log: log, NewHTTP: func(bool, *tls.Config) *http.Client { return plain }}
	apiEnv := server.ConnectorEnv(deps, "api", repoSvc, aiSvc, nil)
	apiEnv.Tickets = &tickets.Service{DB: appPool, Secrets: h.store, Log: log, HTTP: trackerSrv.Client()}
	jobsEnv := server.ConnectorEnv(deps, "jobs", repoSvc, aiSvc, rtSvc)
	h.jobs = &connectors.Background{Env: jobsEnv}
	connSvc := &connectors.Service{Env: apiEnv, Log: log, Principal: auth.PrincipalFrom, Wait: 300 * time.Millisecond}
	diagSvc := &diagnostics.Service{DB: appPool, Log: log, Principal: auth.PrincipalFrom, AI: troubleAI,
		Subjects: map[string]diagnostics.SubjectContext{"connector": connSvc.TroubleshootContext}}
	h.mux = http.NewServeMux()
	connSvc.Register(h.mux)
	diagSvc.Register(h.mux)
	(&notify.Service{DB: appPool, Authz: az, Secrets: h.store, Log: log, Principal: auth.PrincipalFrom, BaseURL: "https://pathos.test"}).Register(h.mux)
	(&tickets.Service{DB: appPool, Authz: az, Secrets: h.store, Log: log, Principal: auth.PrincipalFrom, HTTP: trackerSrv.Client()}).Register(h.mux)

	// --- the flag: off answers feature_disabled ----------------------------
	for _, p := range []string{"/api/v1/connectors", "/api/v1/connectors/kinds", "/api/v1/connectors/" + uuid.NewString()} {
		code, out := h.call(h.admin, "GET", p, nil)
		e, _ := out["error"].(map[string]any)
		if code != 404 || e["code"] != "feature_disabled" || e["error_code"] != "PTH-PLAT-1007" {
			t.Errorf("flag off %s: %d %v", p, code, out)
		}
	}
	// The existing pages keep working without the flag.
	if code, _ := h.call(h.admin, "GET", "/api/v1/ticket-connections", nil); code != 200 {
		t.Errorf("ticket connections without the flag: %d", code)
	}
	h.exec(`INSERT INTO feature_flags (id, organization_id, name, enabled) VALUES ($1, $2, 'connectors', true)`, uuid.Must(uuid.NewV7()), o.ID)

	// --- existing connections of every kind ----------------------------------
	type scmRow struct{ name, provider, base, auth, secret string }
	bbCred, _ := json.Marshal(scm.APITokenCredential{Username: "bot@acme.test", Token: connGoodToken})
	for _, c := range []scmRow{
		{"GH good", "github", scmBase, "pat", connGoodToken},
		{"GH revoked", "github", scmBase, "pat", connBadToken},
		{"GitLab", "gitlab", scmBase + "/api/v4", "pat", connGoodToken},
		{"Bitbucket", "bitbucket", scmBase + "/2.0", "api_token", string(bbCred)},
		{"ADO server", "azure_devops_server", scmBase + "/tfs/Default", "pat", connGoodToken},
	} {
		h.exec(`INSERT INTO scm_connections (id, organization_id, name, provider, base_url, auth_type, secret_id, webhook_secret_id)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`, uuid.Must(uuid.NewV7()), o.ID, c.name, c.provider, c.base, c.auth,
			h.secret(secrets.KindSCM, c.secret), h.secret(secrets.KindWebhook, "wh"))
	}
	// Jira and ServiceNow, created through their own API.
	_, jira := h.call(h.admin, "POST", "/api/v1/ticket-connections", map[string]any{"kind": "jira", "name": "Jira", "base_url": "https://acme.atlassian.example",
		"auth_type": "basic", "username": "bot@acme.test", "secret": "jira-api-token", "config": map[string]any{"project_key": "SEC"}})
	_, sn := h.call(h.admin, "POST", "/api/v1/ticket-connections", map[string]any{"kind": "servicenow", "name": "ServiceNow", "base_url": "https://acme.service-now.example",
		"auth_type": "bearer", "secret": "sn-token", "config": map[string]any{}})
	h.exec(`UPDATE ticket_connections SET base_url = $1 WHERE id IN ($2, $3)`, trackerSrv.URL, jira["id"], sn["id"])
	// Webhooks: Slack (never delivered), Teams with trigger authentication.
	_, slack := h.call(h.admin, "POST", "/api/v1/notifications/webhooks", map[string]any{"name": "Slack", "format": "slack",
		"url": "https://example.com" + connSlackPath, "events": []string{"findings.new"}})
	code, teams := h.call(h.admin, "POST", "/api/v1/notifications/webhooks", map[string]any{"name": "Teams", "format": "teams",
		"url": "https://example.com/workflows/abc/triggers/manual/paths/invoke?" + connTeamsSig, "events": []string{"findings.new"},
		"trigger_auth": map[string]any{"tenant_id": "acme.onmicrosoft.com", "client_id": "11111111-2222-3333-4444-555555555555", "client_secret": connEntraSecret}})
	teamsHook, _ := teams["webhook"].(map[string]any)
	if code != 201 || teamsHook["trigger_auth"] == nil || teamsHook["trigger_auth"].(map[string]any)["audience"] != notify.DefaultTeamsAudience {
		t.Fatalf("teams webhook with trigger auth: %d %v", code, teams)
	}
	// A retired Office 365 connector URL is refused with its code.
	code, out := h.call(h.admin, "POST", "/api/v1/notifications/webhooks", map[string]any{"name": "Old", "format": "teams",
		"url": "https://acme.webhook.office.com/webhookb2/x", "events": []string{"findings.new"}})
	if code != 400 || out["error"].(map[string]any)["error_code"] != "PTH-CONN-1310" {
		t.Errorf("retired teams url: %d %v", code, out)
	}
	// Send test: PATHOS gets an Entra token and sends it to the trigger.
	if code, out := h.call(h.admin, "POST", "/api/v1/notifications/webhooks/"+teamsHook["id"].(string)+"/test", nil); code != 200 || out["ok"] != true {
		t.Errorf("teams send test: %d %v", code, out)
	}
	hookMu.Lock()
	if len(hookAuth) != 1 || hookAuth[0] != "Bearer entra-access-token" || len(tokenForms) != 1 ||
		tokenForms[0].Get("scope") != "https://service.flow.microsoft.com//.default" || tokenForms[0].Get("client_id") != "11111111-2222-3333-4444-555555555555" {
		t.Errorf("teams trigger auth: %v %v", hookAuth, tokenForms)
	}
	hookMu.Unlock()
	// SMTP relay (the fake offers no STARTTLS).
	h.exec(`INSERT INTO smtp_settings (organization_id, enabled, host, port, tls_mode, username, from_address) VALUES ($1, true, 'smtp.acme.test', 25, 'none', '', 'pathos@acme.test')`, o.ID)
	// Kubernetes and a registry.
	kcred, _ := json.Marshal(runtimectx.Credentials{Token: connKubeToken})
	h.exec(`INSERT INTO runtime_clusters (id, organization_id, name, api_server, auth_type, secret_id) VALUES ($1, $2, 'Prod cluster', $3, 'token', $4)`,
		uuid.Must(uuid.NewV7()), o.ID, k8sSrv.URL, h.secret(secrets.KindIntegration, string(kcred)))
	h.exec(`INSERT INTO registry_connections (id, organization_id, name, base_url, repositories, auth_type, username, secret_id) VALUES ($1, $2, 'Harbor', $3, '{team/api}', 'basic', 'robot', $4)`,
		uuid.Must(uuid.NewV7()), o.ID, regSrv.URL, h.secret(secrets.KindIntegration, connRegistryPW))
	// A self-hosted AI provider.
	h.exec(`INSERT INTO ai_providers (id, organization_id, name, kind, base_url, secret_id) VALUES ($1, $2, 'Local model', 'self_hosted', $3, NULL)`,
		uuid.Must(uuid.NewV7()), o.ID, aiSrv.URL+"/v1")
	// Feeds (installation-wide): KEV succeeded now, EPSS failed now.
	h.exec(`INSERT INTO intel_feed_runs (feed, mode, status, records, started_at, finished_at) VALUES ('kev', 'online', 'succeeded', 10, now(), now())`)
	h.exec(`INSERT INTO intel_feed_runs (feed, mode, status, error, started_at, finished_at) VALUES ('epss', 'online', 'failed', 'download failed: HTTP 503 from https://epss.example/x?token=feedsecret', now(), now())`)
	// Secret validation with one provider.
	h.exec(`INSERT INTO secret_validation_settings (organization_id, providers) VALUES ($1, '{github}')`, o.ID)

	// --- catalogue and list ------------------------------------------------
	code, kinds := h.call(h.admin, "GET", "/api/v1/connectors/kinds", nil)
	if code != 200 || len(kinds["items"].([]any)) < 40 || len(kinds["categories"].([]any)) != 9 {
		t.Fatalf("kinds: %d %v", code, kinds)
	}
	code, list := h.call(h.admin, "GET", "/api/v1/connectors", nil)
	if code != 200 {
		t.Fatalf("list: %d %v", code, list)
	}
	items := list["items"].([]any)
	want := []string{"GH good", "GH revoked", "GitLab", "Bitbucket", "ADO server", "Jira", "ServiceNow", "Slack", "Teams", "E-mail (SMTP relay)",
		"Prod cluster", "Harbor", "Local model", "CISA KEV", "EPSS (FIRST)", "Live secret validation", "Object storage (S3)", "Egress proxy"}
	for _, n := range want {
		c := byName(items, n)
		if c == nil {
			t.Errorf("connector %q missing", n)
			continue
		}
		// Real status only: nothing is healthy before a check.
		if c["status"] != "unknown" && c["status"] != "disabled" {
			t.Errorf("%s: %v before any check", n, c["status"])
		}
		if c["source"].(map[string]any)["table"] == "" {
			t.Errorf("%s: no source", n)
		}
	}
	// No credential is duplicated: registry rows carry no secret for the
	// existing kinds.
	var dup int
	_ = appPool.QueryRow(h.octx, `SELECT count(*) FROM connectors WHERE organization_id = $1 AND (secret_id IS NOT NULL OR config <> '{}')`, o.ID).Scan(&dup)
	if dup != 0 {
		t.Errorf("%d registry rows copy settings or credentials", dup)
	}

	// --- checks of every existing kind ----------------------------------------
	type expect struct {
		name, status, code string
		pending            bool
	}
	for _, e := range []expect{
		{"GH good", "healthy", "", false},
		{"GH revoked", "failing", "PTH-CONN-1007", false},
		{"GitLab", "healthy", "", false}, // legacy token: an info warning, not degraded
		{"Bitbucket", "healthy", "", false},
		{"ADO server", "healthy", "", false},
		{"Jira", "healthy", "", false},
		{"ServiceNow", "healthy", "", false},
		{"Slack", "unknown", "", false},
		{"Teams", "unknown", "", false}, // token obtained; nothing delivered by the dispatcher yet
		{"E-mail (SMTP relay)", "healthy", "", false},
		{"Local model", "healthy", "", false},
		{"CISA KEV", "healthy", "", false},
		{"EPSS (FIRST)", "failing", "PTH-SYNC-1020", false},
		{"Live secret validation", "unknown", "", false}, // configuration only, never healthy
		{"Object storage (S3)", "healthy", "", false},
		{"Prod cluster", "", "", true},
		{"Harbor", "", "", true},
		{"Egress proxy", "", "", true},
	} {
		c := byName(items, e.name)
		if c == nil {
			continue
		}
		code, res := h.call(h.admin, "POST", "/api/v1/connectors/"+c["id"].(string)+"/check", nil)
		if e.pending {
			// The API server never calls these: the jobs service does.
			if code != 202 || res["status"] != "pending" {
				t.Errorf("%s: %d %v (want 202 pending)", e.name, code, res)
			}
			continue
		}
		if code != 200 || res["status"] != e.status {
			t.Errorf("%s: %d %v (want %s)", e.name, code, res, e.status)
			continue
		}
		r := res["result"].(map[string]any)
		if e.code == "" && r["error"] != nil && e.status == "healthy" {
			t.Errorf("%s: healthy with an error %v", e.name, r["error"])
		}
		if e.code != "" {
			env, _ := r["error"].(map[string]any)
			if env == nil || env["error_code"] != e.code || env["docs_url"] == "" || env["title"] == "" {
				t.Errorf("%s: envelope %v (want %s)", e.name, r["error"], e.code)
			}
		}
	}
	// Outbound webhook health comes from recorded deliveries (nothing is
	// posted by a check).
	_, js := h.call(h.admin, "POST", "/api/v1/notifications/webhooks", map[string]any{"name": "SIEM", "format": "json",
		"url": "https://example.com/siem", "events": []string{"findings.new"}, "sign": true})
	jsID := js["webhook"].(map[string]any)["id"].(string)
	slackID := slack["webhook"].(map[string]any)["id"].(string)
	h.exec(`INSERT INTO outbound_webhook_deliveries (organization_id, endpoint_id, event_key, status, response_status, delivered_at)
		VALUES ($1, $2, 'findings.new', 'succeeded', 200, now())`, o.ID, jsID)
	h.exec(`INSERT INTO outbound_webhook_deliveries (organization_id, endpoint_id, event_key, status, response_status)
		VALUES ($1, $2, 'findings.new', 'failed', 404)`, o.ID, slackID)
	_, list = h.call(h.admin, "GET", "/api/v1/connectors", nil)
	items = list["items"].([]any)
	hookMu.Lock()
	before := len(hookAuth)
	hookMu.Unlock()
	for name, wantCode := range map[string]string{"SIEM": "", "Slack": "PTH-CONN-1301"} {
		c := byName(items, name)
		code, res := h.call(h.admin, "POST", "/api/v1/connectors/"+c["id"].(string)+"/check", nil)
		st := "healthy"
		if wantCode != "" {
			st = "failing"
		}
		if code != 200 || res["status"] != st || (wantCode != "" && res["result"].(map[string]any)["error"].(map[string]any)["error_code"] != wantCode) {
			t.Errorf("%s: %d %v", name, code, res)
		}
	}
	hookMu.Lock()
	if len(hookAuth) != before {
		t.Error("a webhook check posted a message")
	}
	hookMu.Unlock()

	// No e-mail was sent by the SMTP check.
	smtpSrv.mu.Lock()
	if len(smtpSrv.msgs) != 0 {
		t.Errorf("the SMTP check sent a message: %v", smtpSrv.msgs)
	}
	smtpSrv.mu.Unlock()
	// The feed run's message is redacted (URL reduced to its host).
	epss := byName(items, "EPSS (FIRST)")
	_, epssDetail := h.call(h.admin, "GET", "/api/v1/connectors/"+epss["id"].(string), nil)
	if s := epssDetail["last_check"].(map[string]any)["error"].(map[string]any)["message"].(string); strings.Contains(s, "feedsecret") || !strings.Contains(s, "https://epss.example") {
		t.Errorf("feed message not redacted: %s", s)
	}
	// The SMTP relay with STARTTLS required fails with its code.
	h.exec(`UPDATE smtp_settings SET tls_mode = 'starttls' WHERE organization_id = $1`, o.ID)
	smtpC := byName(items, "E-mail (SMTP relay)")
	if code, res := h.call(h.admin, "POST", "/api/v1/connectors/"+smtpC["id"].(string)+"/check?trigger=verify", nil); code != 200 ||
		res["result"].(map[string]any)["error"].(map[string]any)["error_code"] != "PTH-CONN-1320" || res["result"].(map[string]any)["trigger"] != "verify" {
		t.Errorf("smtp starttls: %d %v", code, res)
	}

	// The jobs service runs the requested checks of the jobs-only kinds.
	if n := h.jobs.RunRequested(tenant.WithSystem(ctx)); n != 3 {
		t.Errorf("jobs ran %d requested checks, want 3", n)
	}
	for name, st := range map[string]string{"Prod cluster": "degraded", "Harbor": "healthy", "Egress proxy": "healthy"} {
		c := byName(items, name)
		code, hist := h.call(h.admin, "GET", "/api/v1/connectors/"+c["id"].(string)+"/checks", nil)
		hi, _ := hist["items"].([]any)
		if code != 200 || len(hi) != 1 || hi[0].(map[string]any)["status"] != st {
			t.Errorf("%s history: %d %v (want %s)", name, code, hist, st)
		}
	}
	cluster := byName(items, "Prod cluster")
	_, cd := h.call(h.admin, "GET", "/api/v1/connectors/"+cluster["id"].(string), nil)
	if cd["status"] != "degraded" || cd["last_error_code"] != "PTH-CONN-1512" || cd["metadata"].(map[string]any)["host"] == "" {
		t.Errorf("cluster detail: %v", cd)
	}

	// --- scheduled checks: everything not checked within the interval ------
	n := h.jobs.RunDue(tenant.WithSystem(ctx))
	// Only what was never checked (the OSV and end-of-life feeds) is due.
	if n > 4 {
		t.Errorf("scheduled checks re-ran %d fresh connectors", n)
	}
	h.exec(`UPDATE connectors SET last_check_at = now() - interval '2 hours' WHERE organization_id = $1`, o.ID)
	if n := h.jobs.RunDue(tenant.WithSystem(ctx)); n < len(want) {
		t.Errorf("scheduled checks ran %d, want at least %d", n, len(want))
	}
	var schedule int
	_ = appPool.QueryRow(h.octx, `SELECT count(*) FROM connector_health_checks WHERE organization_id = $1 AND trigger = 'schedule'`, o.ID).Scan(&schedule)
	if schedule < len(want) {
		t.Errorf("%d scheduled checks recorded", schedule)
	}

	// --- history paging --------------------------------------------------------
	gh := byName(items, "GH revoked")
	for range 3 {
		h.call(h.admin, "POST", "/api/v1/connectors/"+gh["id"].(string)+"/check", nil)
	}
	code, p1 := h.call(h.admin, "GET", "/api/v1/connectors/"+gh["id"].(string)+"/checks?limit=2", nil)
	if code != 200 || len(p1["items"].([]any)) != 2 || p1["next_cursor"] == "" {
		t.Fatalf("history page 1: %d %v", code, p1)
	}
	code, p2 := h.call(h.admin, "GET", "/api/v1/connectors/"+gh["id"].(string)+"/checks?limit=2&cursor="+p1["next_cursor"].(string), nil)
	if code != 200 || len(p2["items"].([]any)) == 0 || p2["items"].([]any)[0].(map[string]any)["id"] == p1["items"].([]any)[1].(map[string]any)["id"] {
		t.Errorf("history page 2: %d %v", code, p2)
	}
	if code, _ := h.call(h.admin, "GET", "/api/v1/connectors/"+gh["id"].(string)+"/checks?limit=500", nil); code != 400 {
		t.Errorf("limit 500: %d", code)
	}

	// --- permissions mirror the existing pages ---------------------------------
	reader := h.principal(authz.PermReposRead)
	code, rl := h.call(reader, "GET", "/api/v1/connectors", nil)
	if code != 200 {
		t.Fatalf("repos reader list: %d", code)
	}
	for _, it := range rl["items"].([]any) {
		if CategoryOfItem(it) != "scm_ide" {
			t.Errorf("repos.read sees %v", it.(map[string]any)["kind"])
		}
	}
	if code, _ := h.call(reader, "POST", "/api/v1/connectors/"+gh["id"].(string)+"/check", nil); code != 403 {
		t.Errorf("repos.read ran a check: %d", code)
	}
	if code, _ := h.call(reader, "GET", "/api/v1/connectors/"+cluster["id"].(string), nil); code != 404 {
		t.Errorf("repos.read read a cluster: %d", code)
	}
	if code, out := h.call(h.principal(), "GET", "/api/v1/connectors", nil); code != 403 || !strings.Contains(out["error"].(map[string]any)["message"].(string), "repos.read") {
		t.Errorf("no permission: %d %v", code, out)
	}
	if code, _ := h.call(h.principal(authz.PermSCMManage, authz.PermReposRead), "POST", "/api/v1/connectors/"+gh["id"].(string)+"/check", nil); code != 200 {
		t.Errorf("scm.manage cannot check: %d", code)
	}

	// --- kinds stored in the registry --------------------------------------
	if code, out := h.call(h.admin, "POST", "/api/v1/connectors", map[string]any{"kind": "github", "name": "x"}); code != 400 ||
		!strings.Contains(out["error"].(map[string]any)["message"].(string), "/admin/scm") {
		t.Errorf("create an existing kind: %d %v", code, out)
	}
	if code, _ := h.call(h.admin, "POST", "/api/v1/connectors", map[string]any{"kind": "aws", "name": "x"}); code != 400 {
		t.Errorf("create a planned kind: %d", code)
	}
	testHubCreatableKinds(t, h)
	if code, _ := h.call(h.admin, "PUT", "/api/v1/connectors/"+gh["id"].(string), map[string]any{"name": "renamed"}); code != 400 {
		t.Errorf("edit an existing kind: %d", code)
	}
	if code, _ := h.call(h.admin, "DELETE", "/api/v1/connectors/"+gh["id"].(string), nil); code != 400 {
		t.Errorf("delete an existing kind: %d", code)
	}
	testRegistryKind(t, h)

	// --- AI troubleshooting with redacted connector context -----------------
	testConnectorTroubleshooting(t, h, gh["id"].(string), byName(items, "Slack")["id"].(string), byName(items, "Teams")["id"].(string))
	if code, _ := h.call(reader, "POST", "/api/v1/diagnostics/troubleshoot", map[string]any{"code": "PTH-CONN-1007",
		"subject": map[string]any{"kind": "connector", "id": cluster["id"]}}); code != 404 {
		t.Errorf("troubleshooting a connector the caller cannot read: %d", code)
	}

	// --- a deleted source disappears with its history --------------------
	h.exec(`UPDATE scm_connections SET archived_at = now() WHERE organization_id = $1 AND name = 'GH revoked'`, o.ID)
	if code, _ := h.call(h.admin, "GET", "/api/v1/connectors/"+gh["id"].(string), nil); code != 404 {
		t.Errorf("archived connection still listed: %d", code)
	}
	var left int
	_ = appPool.QueryRow(h.octx, `SELECT count(*) FROM connector_health_checks WHERE connector_id = $1`, gh["id"]).Scan(&left)
	if left != 0 {
		t.Errorf("%d checks left after the source was removed", left)
	}
}

// CategoryOfItem returns an item's category.
func CategoryOfItem(it any) string { return it.(map[string]any)["category"].(string) }

func principalForOrg(org uuid.UUID, role string) *authz.Principal {
	r, _ := authz.LookupSystemRole(role)
	p := &authz.Principal{UserID: uuid.New(), OrganizationID: org, Email: role + "@conn.test"}
	for _, perm := range r.Permissions {
		p.Grants = append(p.Grants, authz.Grant{Permission: perm, Scope: authz.Scope{Type: authz.ScopeOrganization, ID: org}})
	}
	return p
}

// testRegistryKind covers POST/PUT/DELETE with a creatable kind registered
// for the test (the existing kinds are not creatable here).
func testRegistryKind(t *testing.T, h *connHarness) {
	var seen []string
	var mu sync.Mutex
	connectors.RegisterKind(connectors.Kind{Kind: "zz_it_echo", Category: "apis", Label: "Echo (test)", Status: connectors.KindExisting,
		Direction: connectors.Outbound, OfflineOK: true, Creatable: true, CredentialRequired: true, CheckedBy: connectors.RunsInAPI,
		Validate: func(cfg map[string]any) (map[string]any, error) {
			u, _ := cfg["endpoint"].(string)
			if !strings.HasPrefix(u, "https://") {
				return nil, &httpErr{"endpoint must be an https URL"}
			}
			return map[string]any{"endpoint": u}, nil
		},
		Checker: connectors.CheckFunc(func(ctx context.Context, _ *connectors.Env, tg connectors.Target) connectors.Result {
			cred, err := tg.Credential(ctx)
			mu.Lock()
			seen = append(seen, string(cred))
			mu.Unlock()
			if err != nil || string(cred) != "echo-credential-1" {
				return connectors.Result{Status: connectors.StatusFailing, ErrorCode: "PTH-CONN-1007", Message: "rejected"}
			}
			return connectors.Result{Status: connectors.StatusHealthy, Steps: []connectors.Step{{Check: "authentication", Status: connectors.StepPass}}}
		})})
	if code, out := h.call(h.admin, "POST", "/api/v1/connectors", map[string]any{"kind": "zz_it_echo", "name": "Echo", "config": map[string]any{"endpoint": "ftp://x"},
		"credential": "echo-credential-1"}); code != 422 {
		t.Errorf("invalid config: %d %v", code, out)
	}
	if code, _ := h.call(h.admin, "POST", "/api/v1/connectors", map[string]any{"kind": "zz_it_echo", "name": "Echo", "config": map[string]any{"endpoint": "https://e.example"}}); code != 422 {
		t.Errorf("missing credential: %d", code)
	}
	if code, _ := h.call(h.principal(authz.PermReposRead), "POST", "/api/v1/connectors", map[string]any{"kind": "zz_it_echo", "name": "Echo"}); code != 403 {
		t.Errorf("create without settings.manage: %d", code)
	}
	code, c := h.call(h.admin, "POST", "/api/v1/connectors", map[string]any{"kind": "zz_it_echo", "name": "Echo", "config": map[string]any{"endpoint": "https://e.example"},
		"credential": "echo-credential-1"})
	if code != 201 || c["credential"].(map[string]any)["set"] != true || c["status"] != "unknown" || c["source"].(map[string]any)["table"] != "connectors" {
		t.Fatalf("create: %d %v", code, c)
	}
	if strings.Contains(toJSON(c), "echo-credential-1") {
		t.Error("credential returned")
	}
	id := c["id"].(string)
	if code, _ := h.call(h.admin, "POST", "/api/v1/connectors", map[string]any{"kind": "zz_it_echo", "name": "echo", "config": map[string]any{"endpoint": "https://e.example"},
		"credential": "x"}); code != 409 {
		t.Errorf("duplicate name: %d", code)
	}
	if code, res := h.call(h.admin, "POST", "/api/v1/connectors/"+id+"/check", nil); code != 200 || res["status"] != "healthy" {
		t.Errorf("check: %d %v", code, res)
	}
	if code, u := h.call(h.admin, "PUT", "/api/v1/connectors/"+id, map[string]any{"name": "Echo 2", "config": map[string]any{"endpoint": "https://e2.example"},
		"credential": "echo-credential-2"}); code != 200 || u["status"] != "unknown" || u["name"] != "Echo 2" {
		t.Errorf("update: %d %v", code, u)
	}
	if code, res := h.call(h.admin, "POST", "/api/v1/connectors/"+id+"/check", nil); code != 200 || res["status"] != "failing" {
		t.Errorf("check with the new credential: %d %v", code, res)
	}
	var sid uuid.UUID
	if err := appPool.QueryRow(h.octx, `SELECT secret_id FROM connectors WHERE id = $1`, id).Scan(&sid); err != nil {
		t.Fatal(err)
	}
	if code, _ := h.call(h.admin, "DELETE", "/api/v1/connectors/"+id, nil); code != 204 {
		t.Errorf("delete: %d", code)
	}
	var n int
	_ = appPool.QueryRow(h.octx, `SELECT count(*) FROM secrets WHERE id = $1`, sid).Scan(&n)
	if n != 0 {
		t.Error("the credential survived the delete")
	}
	mu.Lock()
	if len(seen) != 2 || seen[0] != "echo-credential-1" || seen[1] != "echo-credential-2" {
		t.Errorf("credential revealed to the checker: %v", seen)
	}
	mu.Unlock()
}

type httpErr struct{ msg string }

func (e *httpErr) Error() string { return e.msg }

func toJSON(v any) string {
	b, _ := json.Marshal(v)
	return string(b)
}

// testConnectorTroubleshooting checks the context sent to the model is the
// connector's non-secret metadata, built on the server.
func testConnectorTroubleshooting(t *testing.T, h *connHarness, failing, slack, teams string) {
	// An AI configuration so troubleshooting uses the (fake) model.
	pid := uuid.Must(uuid.NewV7())
	h.exec(`INSERT INTO ai_providers (id, organization_id, name, kind, base_url, secret_id) VALUES ($1, $2, 'Troubleshooter', 'self_hosted', 'http://10.0.0.5:11434/v1', NULL)`, pid, h.org)
	cid, vid := uuid.Must(uuid.NewV7()), uuid.Must(uuid.NewV7())
	h.exec(`INSERT INTO ai_configurations (id, organization_id, name, is_default) VALUES ($1, $2, 'Default', true)`, cid, h.org)
	h.exec(`INSERT INTO ai_configuration_versions (id, organization_id, configuration_id, version, provider_id, model, effort, approval_policy, categories, min_severity)
		VALUES ($1, $2, $3, 1, $4, 'qwen-local', 'low', 'always', '{sast}', 'medium')`, vid, h.org, cid, pid)
	h.exec(`UPDATE ai_configurations SET current_version_id = $1 WHERE id = $2`, vid, cid)

	for _, id := range []string{failing, slack, teams} {
		code, out := h.call(h.admin, "POST", "/api/v1/diagnostics/troubleshoot", map[string]any{"code": "PTH-CONN-1007",
			"message": "client text " + connGoodToken, "context": map[string]string{"log": "password=" + connSMTPPass},
			"subject": map[string]any{"kind": "connector", "id": id}})
		if code != 200 {
			t.Fatalf("troubleshoot %s: %d %v", id, code, out)
		}
		if out["source"] != "ai" {
			t.Errorf("troubleshoot %s: not answered by AI: %v", id, out)
		}
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	if len(h.sent) != 3 {
		t.Fatalf("%d AI requests, want 3", len(h.sent))
	}
	for _, req := range h.sent {
		body := req.System + req.User
		for _, s := range []string{connGoodToken, connBadToken, connSMTPPass, connEntraSecret, "T0SECRET", "SlackSecretPart", "TeamsWorkflowSignatureSecret",
			"/workflows/", "client text", "bot@acme.test"} {
			if strings.Contains(body, s) {
				t.Errorf("AI request contains %q", s)
			}
		}
		if !strings.Contains(body, "connector.kind") || !strings.Contains(body, "pathos.version") {
			t.Errorf("AI request lacks the connector context: %s", body)
		}
	}
	if !strings.Contains(h.sent[0].User, "PTH-CONN-1007") || !strings.Contains(h.sent[0].User, "connector.host") {
		t.Errorf("failing connector context: %s", h.sent[0].User)
	}
	if !strings.Contains(h.sent[1].User, "https://example.com") {
		t.Errorf("slack host missing: %s", h.sent[1].User)
	}
	if code, _ := h.call(h.admin, "POST", "/api/v1/diagnostics/troubleshoot", map[string]any{"code": "PTH-CONN-1007",
		"subject": map[string]any{"kind": "spaceship", "id": failing}}); code != 422 {
		t.Errorf("unknown subject kind: %d", code)
	}
	if code, _ := h.call(h.admin, "POST", "/api/v1/diagnostics/troubleshoot", map[string]any{"code": "PTH-CONN-1007",
		"subject": map[string]any{"kind": "connector", "id": uuid.NewString()}}); code != 404 {
		t.Errorf("unknown connector: %d", code)
	}
}

// GitLab webhook signing tokens (Standard Webhooks HMAC) next to the legacy
// token, and the 25 MB inbound limit.
func TestGitLabWebhookSigning(t *testing.T) {
	ctx := t.Context()
	kr, _ := crypto.NewKeyring(map[int][]byte{1: testKey})
	store := &secrets.Store{Keys: kr}
	az := &authz.Authorizer{H: &org.Hierarchy{DB: appPool, OrgID: orgID}}
	repoSvc := server.NewReposService(server.Deps{DB: appPool, Log: log, Secrets: store, PublicURL: "https://pathos.test"}, az)
	mux := http.NewServeMux()
	repoSvc.Register(mux)
	repoSvc.RegisterPublic(mux)
	admin := principalWithRole(t, authz.RoleSuperAdmin)
	octx := tenant.WithOrg(ctx, orgID)
	tokSecret, _ := store.Create(octx, appPool, orgID, secrets.KindSCM, "gl", []byte("glpat-x"), nil)
	whSecret, _ := store.Create(octx, appPool, orgID, secrets.KindWebhook, "gl-wh", []byte("legacy-webhook-token"), nil)
	id := uuid.Must(uuid.NewV7())
	if _, err := appPool.Exec(octx, `INSERT INTO scm_connections (id, organization_id, name, provider, base_url, auth_type, secret_id, webhook_secret_id)
		VALUES ($1, $2, $3, 'gitlab', 'https://gitlab.example/api/v4', 'pat', $4, $5)`, id, orgID, "GitLab signing "+id.String()[:6], tokSecret, whSecret); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = appPool.Exec(octx, `UPDATE scm_connections SET archived_at = now() WHERE organization_id = $1 AND name LIKE '% signing %'`, orgID)
	})
	api := func(method, path string, body any) (int, map[string]any) {
		raw, _ := json.Marshal(body)
		req := httptest.NewRequest(method, path, bytes.NewReader(raw)).WithContext(auth.WithPrincipal(ctx, admin))
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)
		var out map[string]any
		_ = json.Unmarshal(rec.Body.Bytes(), &out)
		return rec.Code, out
	}
	n := 0
	deliver := func(body []byte, hdr map[string]string) (int, string) {
		n++
		req := httptest.NewRequest("POST", "/api/webhooks/gitlab/"+id.String(), bytes.NewReader(body))
		req.Header.Set("X-Gitlab-Event", "Push Hook")
		req.Header.Set("X-Gitlab-Event-UUID", uuid.NewString())
		for k, v := range hdr {
			req.Header.Set(k, v)
		}
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)
		code := ""
		var out map[string]any
		if json.Unmarshal(rec.Body.Bytes(), &out) == nil {
			if e, ok := out["error"].(map[string]any); ok {
				code, _ = e["error_code"].(string)
			}
		}
		return rec.Code, code
	}
	push := []byte(`{"object_kind":"push","ref":"refs/heads/main","before":"0000","after":"abc123","project":{"id":4242}}`)

	if code, _ := deliver(push, map[string]string{"X-Gitlab-Token": "legacy-webhook-token"}); code != 202 {
		t.Fatalf("legacy token: %d", code)
	}
	if code, _ := deliver(push, map[string]string{"X-Gitlab-Token": "wrong"}); code != 401 {
		t.Errorf("wrong legacy token: %d", code)
	}

	key := []byte("gitlab-signing-key-0123456789abcd")
	token := "whsec_" + base64.StdEncoding.EncodeToString(key)
	if code, _ := api("PUT", "/api/v1/scm-connections/"+id.String()+"/webhook-signing-token", map[string]any{"token": "not-a-token"}); code != 422 {
		t.Errorf("malformed signing token: %d", code)
	}
	if code, out := api("PUT", "/api/v1/scm-connections/"+id.String()+"/webhook-signing-token", map[string]any{"token": token}); code != 200 || out["webhook_signed"] != true {
		t.Fatalf("set signing token: %d %v", code, out)
	}
	if _, c := api("GET", "/api/v1/scm-connections/"+id.String(), nil); c["webhook_signed"] != true {
		t.Errorf("connection view: %v", c["webhook_signed"])
	}
	sign := func(msgID string, ts int64, body []byte) map[string]string {
		m := hmac.New(sha256.New, key)
		m.Write([]byte(msgID + "." + strconv.FormatInt(ts, 10) + "."))
		m.Write(body)
		return map[string]string{"webhook-id": msgID, "webhook-timestamp": strconv.FormatInt(ts, 10),
			"webhook-signature": "v1," + base64.StdEncoding.EncodeToString(m.Sum(nil)), "X-Gitlab-Token": "legacy-webhook-token"}
	}
	now := time.Now().Unix()
	if code, _ := deliver(push, sign("msg_1", now, push)); code != 202 {
		t.Errorf("signed delivery: %d", code)
	}
	// With a signing token the legacy token alone is refused.
	if code, _ := deliver(push, map[string]string{"X-Gitlab-Token": "legacy-webhook-token"}); code != 401 {
		t.Errorf("legacy token accepted while a signing token is set: %d", code)
	}
	tampered := sign("msg_2", now, push)
	if code, _ := deliver([]byte(`{"object_kind":"push","ref":"refs/heads/evil","after":"def","project":{"id":4242}}`), tampered); code != 401 {
		t.Errorf("tampered body: %d", code)
	}
	if code, _ := deliver(push, sign("msg_3", now-600, push)); code != 401 {
		t.Errorf("old timestamp: %d", code)
	}
	// 25 MB limit: a 6 MB delivery (refused at 5 MiB before) is accepted,
	// a 26 MB one is refused with its code.
	big := []byte(`{"object_kind":"push","ref":"refs/heads/main","after":"abc124","project":{"id":4242},"pad":"` + strings.Repeat("a", 6<<20) + `"}`)
	if code, _ := deliver(big, sign("msg_4", now, big)); code != 202 {
		t.Errorf("6 MB delivery: %d", code)
	}
	huge := make([]byte, 26<<20)
	if code, ec := deliver(huge, sign("msg_5", now, huge)); code != 413 || ec != "PTH-CONN-1106" {
		t.Errorf("26 MB delivery: %d %s", code, ec)
	}
	var rejected int
	_ = appPool.QueryRow(octx, `SELECT count(*) FROM audit_logs WHERE organization_id = $1 AND action = 'webhook.rejected' AND target_id = $2`, orgID, id.String()).Scan(&rejected)
	if rejected < 4 {
		t.Errorf("%d rejected deliveries audited", rejected)
	}
	// Removing the token goes back to the legacy token.
	if code, out := api("DELETE", "/api/v1/scm-connections/"+id.String()+"/webhook-signing-token", nil); code != 200 || out["webhook_signed"] != false {
		t.Errorf("remove signing token: %d %v", code, out)
	}
	if code, _ := deliver(push, map[string]string{"X-Gitlab-Token": "legacy-webhook-token"}); code != 202 {
		t.Errorf("legacy token after removal: %d", code)
	}
	var left int
	_ = appPool.QueryRow(octx, `SELECT count(*) FROM secrets WHERE organization_id = $1 AND name LIKE 'gitlab webhook signing:%'`, orgID).Scan(&left)
	if left != 0 {
		t.Errorf("signing secret not deleted: %d", left)
	}
	// Only GitLab connections take a signing token.
	gh := uuid.Must(uuid.NewV7())
	s1, _ := store.Create(octx, appPool, orgID, secrets.KindSCM, "gh", []byte("x"), nil)
	s2, _ := store.Create(octx, appPool, orgID, secrets.KindWebhook, "gh-wh", []byte("y"), nil)
	_, _ = appPool.Exec(octx, `INSERT INTO scm_connections (id, organization_id, name, provider, base_url, auth_type, secret_id, webhook_secret_id)
		VALUES ($1, $2, $3, 'github', 'https://api.github.com', 'pat', $4, $5)`, gh, orgID, "GH signing "+gh.String()[:6], s1, s2)
	if code, _ := api("PUT", "/api/v1/scm-connections/"+gh.String()+"/webhook-signing-token", map[string]any{"token": token}); code != 400 {
		t.Errorf("signing token on GitHub: %d", code)
	}
	viewer := scoped("viewer", authz.Scope{Type: authz.ScopeOrganization, ID: orgID})
	req := httptest.NewRequest("DELETE", "/api/v1/scm-connections/"+id.String()+"/webhook-signing-token", nil).WithContext(auth.WithPrincipal(ctx, viewer))
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != 403 {
		t.Errorf("viewer removed the signing token: %d", rec.Code)
	}
}

// Jira Cloud API tokens with scopes go through the Atlassian API gateway
// (api.atlassian.com/ex/jira/{cloudId}); the cloud ID is looked up from the
// site when not configured.
func TestJiraScopedTokens(t *testing.T) {
	ctx := t.Context()
	const cloudID = "0f1e2d3c-4b5a-6978-8a9b-0c1d2e3f4a5b"
	var mu sync.Mutex
	var paths []string
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		paths = append(paths, r.Method+" "+r.URL.Path)
		mu.Unlock()
		u, p, _ := r.BasicAuth()
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.URL.Path == "/site/_edge/tenant_info":
			_, _ = w.Write([]byte(`{"cloudId":"` + cloudID + `"}`))
		case strings.HasPrefix(r.URL.Path, "/site/rest/"):
			// The site refuses scoped tokens.
			w.WriteHeader(http.StatusUnauthorized)
		case u != "bot@acme.test" || p != connJiraToken:
			w.WriteHeader(http.StatusUnauthorized)
		case r.URL.Path == "/ex/jira/"+cloudID+"/rest/api/2/myself":
			_, _ = w.Write([]byte(`{"displayName":"Scoped bot"}`))
		case r.URL.Path == "/ex/jira/"+cloudID+"/rest/api/2/project/SEC":
			_, _ = w.Write([]byte(`{"key":"SEC"}`))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()
	tickets.AtlassianGateway = srv.URL
	defer func() { tickets.AtlassianGateway = "https://api.atlassian.com" }()
	kr, _ := crypto.NewKeyring(map[int][]byte{1: testKey})
	az := &authz.Authorizer{H: &org.Hierarchy{DB: appPool, OrgID: orgID}}
	ts := &tickets.Service{DB: appPool, Authz: az, Secrets: &secrets.Store{Keys: kr}, Log: log, Principal: auth.PrincipalFrom, HTTP: srv.Client()}
	mux := newMux(ts.Register)
	admin := principalWithRole(t, authz.RoleSuperAdmin)
	call := func(method, path string, body any) (int, map[string]any) {
		raw, _ := json.Marshal(body)
		req := httptest.NewRequest(method, path, bytes.NewReader(raw)).WithContext(auth.WithPrincipal(ctx, admin))
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)
		var out map[string]any
		_ = json.Unmarshal(rec.Body.Bytes(), &out)
		return rec.Code, out
	}
	tag := uuid.NewString()[:6]
	base := map[string]any{"kind": "jira", "base_url": "https://acme.atlassian.example", "auth_type": "basic", "username": "bot@acme.test",
		"secret": connJiraToken}
	with := func(name string, cfg map[string]any, extra map[string]any) map[string]any {
		m := map[string]any{"name": name + " " + tag, "config": cfg}
		for k, v := range base {
			m[k] = v
		}
		for k, v := range extra {
			m[k] = v
		}
		return m
	}
	if code, _ := call("POST", "/api/v1/ticket-connections", with("bearer", map[string]any{"project_key": "SEC", "token_type": "scoped"}, map[string]any{"auth_type": "bearer"})); code != 400 {
		t.Errorf("scoped with bearer: %d", code)
	}
	if code, _ := call("POST", "/api/v1/ticket-connections", with("badid", map[string]any{"project_key": "SEC", "token_type": "scoped", "cloud_id": "nope"}, nil)); code != 400 {
		t.Errorf("invalid cloud id: %d", code)
	}
	if code, _ := call("POST", "/api/v1/ticket-connections", with("badtype", map[string]any{"project_key": "SEC", "token_type": "classic"}, nil)); code != 400 {
		t.Errorf("invalid token type: %d", code)
	}
	code, scoped := call("POST", "/api/v1/ticket-connections", with("Scoped", map[string]any{"project_key": "SEC", "token_type": "scoped"}, nil))
	if code != 201 || scoped["config"].(map[string]any)["token_type"] != "scoped" {
		t.Fatalf("create scoped: %d %v", code, scoped)
	}
	code, unscoped := call("POST", "/api/v1/ticket-connections", with("Unscoped", map[string]any{"project_key": "SEC"}, nil))
	if code != 201 {
		t.Fatalf("create unscoped: %d", code)
	}
	_, _ = appPool.Exec(tenant.WithOrg(ctx, orgID), `UPDATE ticket_connections SET base_url = $1 WHERE id IN ($2, $3)`, srv.URL+"/site", scoped["id"], unscoped["id"])

	if code, out := call("POST", "/api/v1/ticket-connections/"+scoped["id"].(string)+"/test", nil); code != 200 || out["ok"] != true || out["identity"] != "Scoped bot" {
		t.Errorf("scoped test: %d %v", code, out)
	}
	mu.Lock()
	if !slices.Contains(paths, "GET /site/_edge/tenant_info") || !slices.Contains(paths, "GET /ex/jira/"+cloudID+"/rest/api/2/myself") {
		t.Errorf("gateway not used: %v", paths)
	}
	mu.Unlock()
	// The same token with the site URL (unscoped type) is refused.
	if code, out := call("POST", "/api/v1/ticket-connections/"+unscoped["id"].(string)+"/test", nil); code != 200 || out["ok"] != false {
		t.Errorf("unscoped with a scoped token: %d %v", code, out)
	}
	// A configured cloud ID skips the lookup.
	code, fixed := call("POST", "/api/v1/ticket-connections", with("Fixed", map[string]any{"project_key": "SEC", "token_type": "scoped", "cloud_id": strings.ToUpper(cloudID)}, nil))
	if code != 201 || fixed["config"].(map[string]any)["cloud_id"] != cloudID {
		t.Fatalf("create with cloud id: %d %v", code, fixed)
	}
	_, _ = appPool.Exec(tenant.WithOrg(ctx, orgID), `UPDATE ticket_connections SET base_url = $1 WHERE id = $2`, srv.URL+"/nosite", fixed["id"])
	if code, out := call("POST", "/api/v1/ticket-connections/"+fixed["id"].(string)+"/test", nil); code != 200 || out["ok"] != true {
		t.Errorf("fixed cloud id: %d %v", code, out)
	}
	for _, id := range []any{scoped["id"], unscoped["id"], fixed["id"]} {
		call("DELETE", "/api/v1/ticket-connections/"+id.(string), nil)
	}
}

// testHubCreatableKinds covers the M2 kinds created through the hub: Vault
// (a registry kind) and Generic Git / Bitbucket Data Center (kept in
// scm_connections, created by the SCM service through Kind.Create).
func testHubCreatableKinds(t *testing.T, h *connHarness) {
	code, kl := h.call(h.admin, "GET", "/api/v1/connectors/kinds", nil)
	if code != 200 {
		t.Fatalf("kinds: %d", code)
	}
	kinds, _ := kl["items"].([]any)
	for _, want := range []string{"generic_git", "bitbucket_data_center", "vault"} {
		var k map[string]any
		for _, it := range kinds {
			if m := it.(map[string]any); m["kind"] == want {
				k = m
			}
		}
		if k == nil || k["creatable"] != true || len(k["config_fields"].([]any)) == 0 || k["docs_slug"] != "connectors#"+want {
			t.Errorf("kind %s: %v", want, k)
		}
	}

	// Vault: invalid configuration, then a valid one (no check on create).
	if code, out := h.call(h.admin, "POST", "/api/v1/connectors", map[string]any{"kind": "vault", "name": "Vault",
		"config": map[string]any{"base_url": "https://vault.example", "auth_method": "approle", "role_id": "r", "proxy_url": "http://p:3128"}, "credential": "sid"}); code != 422 {
		t.Errorf("vault with a proxy: %d %v", code, out)
	}
	code, v := h.call(h.admin, "POST", "/api/v1/connectors", map[string]any{"kind": "vault", "name": "Vault",
		"config": map[string]any{"base_url": "https://vault.example", "auth_method": "approle", "role_id": "r"}, "credential": "vault-secret-id-1"})
	if code != 201 || v["kind"] != "vault" || v["credential"].(map[string]any)["set"] != true || strings.Contains(toJSON(v), "vault-secret-id-1") {
		t.Fatalf("vault create: %d %v", code, v)
	}
	if code, _ := h.call(h.admin, "DELETE", "/api/v1/connectors/"+v["id"].(string), nil); code != 204 {
		t.Errorf("vault delete: %d", code)
	}

	// Generic Git through Kind.Create: the SCM service validates and stores
	// it; the answer is the registry row of the new scm_connections row.
	gg := func(cfg map[string]any) map[string]any {
		return map[string]any{"kind": "generic_git", "name": "Hub Git", "config": cfg}
	}
	if code, out := h.call(h.principal(authz.PermReposRead), "POST", "/api/v1/connectors",
		gg(map[string]any{"base_url": "https://git.example.com/app.git"})); code != 403 {
		t.Errorf("generic git without scm.manage: %d %v", code, out)
	}
	if code, out := h.call(h.admin, "POST", "/api/v1/connectors", gg(map[string]any{"base_url": "https://git.example.com/app.git", "proxy_url": "http://p:3128"})); code != 400 {
		t.Errorf("generic git with a proxy: %d %v", code, out)
	}
	body := gg(map[string]any{"base_url": "https://git.example.com/app.git", "auth_method": "https_token", "credential_ref": "vault:secret/pathos/git#token"})
	body["enabled"] = false
	if code, out := h.call(h.admin, "POST", "/api/v1/connectors", body); code != 422 {
		t.Errorf("generic git created disabled: %d %v", code, out)
	}
	delete(body, "enabled")
	code, c := h.call(h.admin, "POST", "/api/v1/connectors", body)
	if code != 201 || c["kind"] != "generic_git" || c["source"].(map[string]any)["table"] != "scm_connections" || c["credential"].(map[string]any)["set"] != true {
		t.Fatalf("generic git create: %d %v", code, c)
	}
	var stored int
	_ = appPool.QueryRow(h.octx, `SELECT count(*) FROM scm_connections WHERE organization_id = $1 AND id = $2 AND provider = 'generic_git'`,
		h.org, c["source"].(map[string]any)["id"]).Scan(&stored)
	if stored != 1 {
		t.Errorf("the scm_connections row is missing")
	}
	if code, _ := h.call(h.admin, "GET", "/api/v1/connectors/"+c["id"].(string), nil); code != 200 {
		t.Errorf("get the created connector: %d", code)
	}
	h.exec(`UPDATE scm_connections SET archived_at = now() WHERE organization_id = $1 AND id = $2`, h.org, c["source"].(map[string]any)["id"])
}
