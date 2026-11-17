//go:build integration

package integration

import (
	"bytes"
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
	"pathos/internal/notify"
	"pathos/internal/org"
	"pathos/internal/platform/crypto"
	"pathos/internal/secrets"
)

type hookReceiver struct {
	mu      sync.Mutex
	bodies  [][]byte
	headers []http.Header
	status  int
}

func (h *hookReceiver) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	b, _ := io.ReadAll(r.Body)
	h.mu.Lock()
	h.bodies, h.headers = append(h.bodies, b), append(h.headers, r.Header.Clone())
	st := h.status
	h.mu.Unlock()
	w.WriteHeader(st)
}

func TestOutboundWebhooks(t *testing.T) {
	ctx := t.Context()
	az := &authz.Authorizer{H: &org.Hierarchy{DB: appPool, OrgID: orgID}}
	kr, _ := crypto.NewKeyring(map[int][]byte{1: testKey})
	store := &secrets.Store{Keys: kr}
	mux := newMux((&notify.Service{DB: appPool, Authz: az, Secrets: store, Log: log, Principal: auth.PrincipalFrom, BaseURL: "https://pathos.test"}).Register)
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
	recv := &hookReceiver{status: 204}
	srv := httptest.NewTLSServer(recv)
	defer srv.Close()
	notify.HTTPOverride = srv.Client()
	defer func() { notify.HTTPOverride = nil }()
	tag := uuid.NewString()[:6]

	def := map[string]any{"name": "SIEM " + tag, "format": "json", "url": srv.URL + "/hook?token=s3cr3t", "events": []string{"scan.failed"}, "sign": true}
	if code, _ := call(viewer, "POST", "/api/v1/notifications/webhooks", def); code != 403 {
		t.Errorf("viewer: %d", code)
	}
	// Loopback and metadata addresses are refused; private ones need opt-in.
	for _, bad := range []string{"https://127.0.0.1/x", "https://169.254.169.254/latest", "http://example.com/x", "https://user:pw@example.com/x"} {
		d := map[string]any{"name": "bad " + tag, "format": "json", "url": bad, "events": []string{"scan.failed"}}
		if code, _ := call(admin, "POST", "/api/v1/notifications/webhooks", d); code != 400 {
			t.Errorf("%s accepted: %d", bad, code)
		}
	}
	if code, _ := call(admin, "POST", "/api/v1/notifications/webhooks", map[string]any{"name": "p " + tag, "format": "json", "url": "https://10.1.2.3/x", "events": []string{"scan.failed"}}); code != 400 {
		t.Errorf("private address without opt-in: %d", code)
	}
	// The test receiver listens on 127.0.0.1, which policy always blocks;
	// the client override stands in for the network policy here, so the
	// endpoint is registered through the database helper path: host check
	// is exercised above.
	code, created := call(admin, "POST", "/api/v1/notifications/webhooks", map[string]any{"name": "SIEM " + tag, "format": "json",
		"url": "https://siem.example/hook?token=s3cr3t", "events": []string{"scan.failed"}, "sign": true})
	if code != 201 || created["signing_secret"] == nil {
		t.Fatalf("create: %d %v", code, created)
	}
	wh := created["webhook"].(map[string]any)
	if wh["host"] != "siem.example" || strings.Contains(strings.Join([]string{wh["host"].(string)}, ""), "token") {
		t.Errorf("only the host is shown: %v", wh)
	}
	signing := created["signing_secret"].(string)
	// Point it at the test receiver (URL stored encrypted).
	var urlSecret uuid.UUID
	_ = appPool.QueryRow(ctx, `SELECT url_secret_id FROM outbound_webhooks WHERE id = $1`, wh["id"]).Scan(&urlSecret)
	if err := store.Update(ctx, appPool, orgID, urlSecret, secrets.KindIntegration, []byte(srv.URL+"/hook?token=s3cr3t")); err != nil {
		t.Fatal(err)
	}
	var plain int
	_ = appPool.QueryRow(ctx, `SELECT count(*) FROM secrets WHERE id = $1 AND convert_from(ciphertext, 'LATIN1') LIKE '%s3cr3t%'`, urlSecret).Scan(&plain)
	if plain != 0 {
		t.Error("the URL must be stored encrypted")
	}
	slack := map[string]any{"name": "Slack " + tag, "format": "slack", "url": "https://hooks.slack.example/services/T/B/x", "events": []string{"scan.failed"}}
	code, sl := call(admin, "POST", "/api/v1/notifications/webhooks", slack)
	if code != 201 {
		t.Fatalf("slack: %d %v", code, sl)
	}
	_ = appPool.QueryRow(ctx, `SELECT url_secret_id FROM outbound_webhooks WHERE id = $1`, sl["webhook"].(map[string]any)["id"]).Scan(&urlSecret)
	_ = store.Update(ctx, appPool, orgID, urlSecret, secrets.KindIntegration, []byte(srv.URL+"/slack"))

	// An event fans out to both endpoints; deliveries are signed (json).
	repo := createRepo(t, "hook-"+tag)
	jobID := uuid.New()
	if _, err := appPool.Exec(ctx, `INSERT INTO notification_events (organization_id, event_key, repository_id, subject_id, payload) VALUES ($1, 'scan.failed', $2, $3, '{}')`,
		orgID, repo, jobID); err != nil {
		t.Fatal(err)
	}
	disp := &notify.Dispatcher{Pool: appPool, Secrets: store, BaseURL: "https://pathos.test", Log: log}
	if _, err := disp.DispatchEvents(ctx); err != nil {
		t.Fatal(err)
	}
	sent, failed, err := disp.SendWebhooks(ctx)
	if err != nil || sent < 2 {
		t.Fatalf("send: %d sent, %d failed, %v", sent, failed, err)
	}
	var jsonBody, slackBody []byte
	var jsonHdr http.Header
	recv.mu.Lock()
	for i, b := range recv.bodies {
		if strings.Contains(string(b), `"event":"scan.failed"`) {
			jsonBody, jsonHdr = b, recv.headers[i]
		}
		if strings.Contains(string(b), `"text":`) {
			slackBody = b
		}
	}
	recv.mu.Unlock()
	if jsonBody == nil || slackBody == nil {
		t.Fatalf("both formats delivered: %d bodies", len(recv.bodies))
	}
	if got := jsonHdr.Get("X-PATHOS-Signature"); got != notify.Signature(signing, jsonHdr.Get("X-PATHOS-Timestamp"), jsonBody) {
		t.Errorf("signature does not verify: %s", got)
	}
	if jsonHdr.Get("X-PATHOS-Event") != "scan.failed" || jsonHdr.Get("X-PATHOS-Delivery") == "" {
		t.Errorf("headers: %v", jsonHdr)
	}

	// Server errors are retried later; client errors give up at once.
	recv.mu.Lock()
	recv.status = 503
	recv.mu.Unlock()
	_, _ = appPool.Exec(ctx, `INSERT INTO notification_events (organization_id, event_key, repository_id, subject_id, payload) VALUES ($1, 'scan.failed', $2, $3, '{}')`, orgID, repo, uuid.New())
	_, _ = disp.DispatchEvents(ctx)
	_, _, _ = disp.SendWebhooks(ctx)
	var pending int
	_ = appPool.QueryRow(ctx, `SELECT count(*) FROM outbound_webhook_deliveries WHERE endpoint_id = $1 AND status = 'pending' AND attempts = 1 AND next_attempt_at > now()`, wh["id"]).Scan(&pending)
	if pending != 1 {
		t.Errorf("503 is retried with back-off: %d", pending)
	}
	recv.mu.Lock()
	recv.status = 404
	recv.mu.Unlock()
	_, _ = appPool.Exec(ctx, `UPDATE outbound_webhook_deliveries SET next_attempt_at = now() WHERE endpoint_id = $1 AND status = 'pending'`, wh["id"])
	_, _, _ = disp.SendWebhooks(ctx)
	var failedN int
	_ = appPool.QueryRow(ctx, `SELECT count(*) FROM outbound_webhook_deliveries WHERE endpoint_id = $1 AND status = 'failed' AND response_status = 404`, wh["id"]).Scan(&failedN)
	if failedN != 1 {
		t.Errorf("404 is not retried: %d", failedN)
	}
	code, dl := call(admin, "GET", "/api/v1/notifications/webhooks/"+wh["id"].(string)+"/deliveries", nil)
	if code != 200 || len(dl["items"].([]any)) != 2 {
		t.Errorf("delivery log: %d %v", code, dl)
	}
	// Test message on demand.
	recv.mu.Lock()
	recv.status = 200
	recv.mu.Unlock()
	if code, out := call(admin, "POST", "/api/v1/notifications/webhooks/"+wh["id"].(string)+"/test", nil); code != 200 || out["ok"] != true {
		t.Errorf("test: %d %v", code, out)
	}
	// Delete removes the endpoint and its secrets.
	if code, _ := call(admin, "DELETE", "/api/v1/notifications/webhooks/"+wh["id"].(string), nil); code != 204 {
		t.Errorf("delete: %d", code)
	}
	var left int
	_ = appPool.QueryRow(ctx, `SELECT count(*) FROM secrets WHERE name IN ($1, $2)`, "webhook url: SIEM "+tag, "webhook signing: SIEM "+tag).Scan(&left)
	if left != 0 {
		t.Errorf("secrets removed with the endpoint: %d left", left)
	}
	var audits int
	_ = appPool.QueryRow(ctx, `SELECT count(*) FROM audit_logs WHERE action LIKE 'webhook.%' AND target_id = $1`, wh["id"]).Scan(&audits)
	if audits != 3 {
		t.Errorf("create, test, delete audited: %d", audits)
	}
}
