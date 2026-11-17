//go:build integration

package integration

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/google/uuid"

	"pathos/internal/auth"
	"pathos/internal/authz"
	"pathos/internal/org"
	"pathos/internal/platform/crypto"
	"pathos/internal/secrets"
	"pathos/internal/tickets"
)

type fakeTracker struct {
	mu      sync.Mutex
	created []map[string]any
	auth    []string
	done    bool
}

func (f *fakeTracker) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.auth = append(f.auth, r.Header.Get("Authorization"))
	w.Header().Set("Content-Type", "application/json")
	switch {
	case r.URL.Path == "/rest/api/2/myself":
		_, _ = w.Write([]byte(`{"displayName":"PATHOS bot"}`))
	case r.URL.Path == "/rest/api/2/project/SEC":
		_, _ = w.Write([]byte(`{"key":"SEC"}`))
	case r.Method == "POST" && r.URL.Path == "/rest/api/2/issue":
		var b map[string]any
		_ = json.NewDecoder(r.Body).Decode(&b)
		f.created = append(f.created, b)
		_, _ = w.Write([]byte(`{"id":"10001","key":"SEC-1"}`))
	case r.URL.Path == "/rest/api/2/issue/SEC-1":
		cat := "indeterminate"
		if f.done {
			cat = "done"
		}
		_, _ = w.Write([]byte(`{"fields":{"status":{"name":"In Progress","statusCategory":{"key":"` + cat + `"}}}}`))
	case r.Method == "GET" && r.URL.Path == "/api/now/table/incident" && r.URL.Query().Get("sysparm_limit") == "1":
		_, _ = w.Write([]byte(`{"result":[]}`))
	case r.Method == "POST" && r.URL.Path == "/api/now/table/incident":
		var b map[string]any
		raw, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(raw, &b)
		f.created = append(f.created, b)
		_, _ = w.Write([]byte(`{"result":{"sys_id":"abc123","number":"INC0010001"}}`))
	case r.URL.Path == "/api/now/table/incident/abc123":
		_, _ = w.Write([]byte(`{"result":{"state":"Resolved"}}`))
	default:
		http.NotFound(w, r)
	}
}

func TestTicketingConnectors(t *testing.T) {
	ctx := t.Context()
	az := &authz.Authorizer{H: &org.Hierarchy{DB: appPool, OrgID: orgID}}
	kr, _ := crypto.NewKeyring(map[int][]byte{1: testKey})
	store := &secrets.Store{Keys: kr}
	tracker := &fakeTracker{}
	srv := httptest.NewTLSServer(tracker)
	defer srv.Close()
	ts := &tickets.Service{DB: appPool, Authz: az, Secrets: store, Log: log, Principal: auth.PrincipalFrom, PublicURL: "https://pathos.test", HTTP: srv.Client()}
	mux := newMux(ts.Register)
	call := func(p *authz.Principal, method, path string, body any) (int, map[string]any) {
		raw, _ := json.Marshal(body)
		req := httptest.NewRequest(method, path, bytes.NewReader(raw)).WithContext(auth.WithPrincipal(ctx, p))
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)
		var out map[string]any
		_ = json.Unmarshal(rec.Body.Bytes(), &out)
		return rec.Code, out
	}
	admin := principalWithRole(t, authz.RoleSuperAdmin)
	viewer := scoped("viewer", authz.Scope{Type: authz.ScopeOrganization, ID: orgID})
	tag := uuid.NewString()[:6]

	if code, _ := call(admin, "POST", "/api/v1/ticket-connections", map[string]any{"kind": "jira", "name": "x" + tag, "base_url": "https://127.0.0.1",
		"auth_type": "bearer", "secret": "t", "config": map[string]any{"project_key": "SEC"}}); code != 400 {
		t.Errorf("loopback base URL: %d", code)
	}
	if code, _ := call(viewer, "POST", "/api/v1/ticket-connections", map[string]any{}); code != 403 {
		t.Errorf("viewer: %d", code)
	}
	code, jira := call(admin, "POST", "/api/v1/ticket-connections", map[string]any{"kind": "jira", "name": "Jira " + tag, "base_url": "https://acme.atlassian.example",
		"auth_type": "basic", "username": "bot@acme.test", "secret": "jira-api-token", "config": map[string]any{"project_key": "sec", "issue_type": "Bug", "labels": []string{"pathos"}}})
	if code != 201 || jira["config"].(map[string]any)["project_key"] != "SEC" || jira["secret"] != nil {
		t.Fatalf("create jira: %d %v", code, jira)
	}
	code, sn := call(admin, "POST", "/api/v1/ticket-connections", map[string]any{"kind": "servicenow", "name": "SN " + tag, "base_url": "https://acme.service-now.example",
		"auth_type": "bearer", "secret": "sn-oauth-token", "config": map[string]any{}})
	if code != 201 || sn["config"].(map[string]any)["table"] != "incident" {
		t.Fatalf("create servicenow: %d %v", code, sn)
	}
	// Point both at the fake tracker.
	_, _ = appPool.Exec(ctx, `UPDATE ticket_connections SET base_url = $1 WHERE id IN ($2, $3)`, srv.URL, jira["id"], sn["id"])

	if code, out := call(admin, "POST", "/api/v1/ticket-connections/"+jira["id"].(string)+"/test", nil); code != 200 || out["ok"] != true || out["identity"] != "PATHOS bot" {
		t.Errorf("jira test: %d %v", code, out)
	}
	if code, out := call(admin, "POST", "/api/v1/ticket-connections/"+sn["id"].(string)+"/test", nil); code != 200 || out["ok"] != true {
		t.Errorf("servicenow test: %d %v", code, out)
	}
	tracker.mu.Lock()
	if tracker.auth[0] != "Basic "+base64.StdEncoding.EncodeToString([]byte("bot@acme.test:jira-api-token")) {
		t.Errorf("jira basic auth: %q", tracker.auth[0])
	}
	if !strings.HasPrefix(tracker.auth[len(tracker.auth)-1], "Bearer sn-oauth-token") {
		t.Errorf("servicenow bearer auth: %q", tracker.auth[len(tracker.auth)-1])
	}
	tracker.mu.Unlock()

	// A finding whose description contains a credential and whose snippet is code.
	repo := createRepo(t, "tick-"+tag)
	fid := uuid.New()
	if _, err := appPool.Exec(ctx, `INSERT INTO findings (id, organization_id, repository_id, fingerprint, category, scanner_keys, rule_id, title, severity, description, snippet, file_path, start_line)
		VALUES ($1, $2, $3, $4, 'secrets', '{gitleaks}', 'aws-key', 'AWS access key', 'high', 'Found AKIAABCDEFGHIJKLMNOP in config', 'aws_key = "AKIAABCDEFGHIJKLMNOP"', 'config/app.env', 3)`,
		fid, orgID, repo, uuid.NewString()); err != nil {
		t.Fatal(err)
	}
	if code, _ := call(viewer, "POST", "/api/v1/findings/"+fid.String()+"/tickets", map[string]any{"connection_id": jira["id"]}); code != 403 && code != 404 {
		t.Errorf("viewer lacks findings.triage: %d", code)
	}
	code, tk := call(admin, "POST", "/api/v1/findings/"+fid.String()+"/tickets", map[string]any{"connection_id": jira["id"]})
	if code != 201 || tk["key"] != "SEC-1" || !strings.HasSuffix(tk["url"].(string), "/browse/SEC-1") {
		t.Fatalf("jira ticket: %d %v", code, tk)
	}
	if code, _ := call(admin, "POST", "/api/v1/findings/"+fid.String()+"/tickets", map[string]any{"connection_id": jira["id"]}); code != 409 {
		t.Errorf("one ticket per finding and connection: %d", code)
	}
	tracker.mu.Lock()
	fields := tracker.created[0]["fields"].(map[string]any)
	desc := fields["description"].(string)
	tracker.mu.Unlock()
	if fields["project"].(map[string]any)["key"] != "SEC" || !strings.HasPrefix(fields["summary"].(string), "[PATHOS] High: AWS access key") {
		t.Errorf("issue fields: %v", fields)
	}
	if strings.Contains(desc, "AKIAABCDEFGHIJKLMNOP") || strings.Contains(desc, "aws_key =") {
		t.Errorf("no secret values or code snippets in the ticket: %s", desc)
	}
	if !strings.Contains(desc, "config/app.env:3") || !strings.Contains(desc, "https://pathos.test/findings?finding="+fid.String()) {
		t.Errorf("location and link: %s", desc)
	}
	code, inc := call(admin, "POST", "/api/v1/findings/"+fid.String()+"/tickets", map[string]any{"connection_id": sn["id"]})
	if code != 201 || inc["key"] != "INC0010001" {
		t.Fatalf("servicenow incident: %d %v", code, inc)
	}
	tracker.mu.Lock()
	if tracker.created[1]["urgency"] != "1" {
		t.Errorf("high severity → urgency 1: %v", tracker.created[1])
	}
	tracker.done = true
	tracker.mu.Unlock()

	// Status sync.
	_, _ = appPool.Exec(ctx, `UPDATE finding_tickets SET synced_at = now() - interval '1 hour' WHERE finding_id = $1`, fid)
	if n, err := ts.Sync(ctx); err != nil || n < 2 {
		t.Fatalf("sync: %d %v", n, err)
	}
	code, list := call(viewer, "GET", "/api/v1/findings/"+fid.String()+"/tickets", nil)
	if code != 200 || len(list["items"].([]any)) != 2 {
		t.Fatalf("list: %d %v", code, list)
	}
	for _, it := range list["items"].([]any) {
		m := it.(map[string]any)
		if m["done"] != true {
			t.Errorf("synced done: %v", m)
		}
	}
	// Triage users see connection names only.
	analyst := scoped("security_analyst", authz.Scope{Type: authz.ScopeOrganization, ID: orgID})
	code, conns := call(analyst, "GET", "/api/v1/ticket-connections", nil)
	if code != 200 || len(conns["items"].([]any)) < 2 || conns["items"].([]any)[0].(map[string]any)["base_url"] != "" {
		t.Errorf("triage view: %d %v", code, conns)
	}
	var audits int
	_ = appPool.QueryRow(ctx, `SELECT count(*) FROM audit_logs WHERE action = 'finding.ticket_create' AND target_id = $1`, fid.String()).Scan(&audits)
	if audits != 2 {
		t.Errorf("ticket creation audited: %d", audits)
	}
}
