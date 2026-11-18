//go:build integration

package integration

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"math/rand/v2"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	"github.com/google/uuid"

	"pathos/internal/auth"
	"pathos/internal/authz"
	"pathos/internal/notify"
	"pathos/internal/org"
	"pathos/internal/platform/crypto"
	"pathos/internal/pushprotect"
	"pathos/internal/repos"
	"pathos/internal/scm"
	"pathos/internal/secrets"
)

func TestSecretPushProtection(t *testing.T) {
	ctx := t.Context()
	// Built at runtime so secret scanners do not flag this file.
	secretValue := "gh" + "p_" + "Q7xK2mP9vR4tW8yZ3bN6cL1dF5gH0jS2aE7u"
	const before = "1111111111111111111111111111111111111111"
	const head = "2222222222222222222222222222222222222222"
	name := "push-" + uuid.NewString()[:6]
	extID := strconv.Itoa(900000000 + rand.IntN(99999999))

	gh := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/repos/acme/" + name + "/compare/" + before + "..." + head:
			_, _ = w.Write([]byte(`{"total_commits":1,"commits":[{"sha":"` + head + `"}],"files":[]}`))
		case "/repos/acme/" + name + "/commits/" + head:
			patch := "@@ -1,1 +1,2 @@\n line\n+TOKEN = \"" + secretValue + "\""
			_ = json.NewEncoder(w).Encode(map[string]any{"files": []map[string]string{{"filename": "config/app.env", "status": "modified", "patch": patch}}})
		default:
			w.WriteHeader(http.StatusNotFound)
			_, _ = w.Write([]byte(`{}`))
		}
	}))
	defer gh.Close()

	kr, _ := crypto.NewKeyring(map[int][]byte{1: testKey})
	st := &secrets.Store{Keys: kr}
	sec, _ := st.Create(ctx, appPool, orgID, secrets.KindSCM, "x", []byte("t"), nil)
	whSecret := []byte("push-protection-webhook-secret")
	wh, _ := st.Create(ctx, appPool, orgID, secrets.KindWebhook, "w", whSecret, nil)
	conn, repo := uuid.Must(uuid.NewV7()), uuid.Must(uuid.NewV7())
	if _, err := appPool.Exec(ctx, `INSERT INTO scm_connections (id, organization_id, name, provider, base_url, auth_type, secret_id, webhook_secret_id)
		VALUES ($1, $2, $3, 'github', $4, 'pat', $5, $6)`, conn, orgID, "conn-"+name,
		// A host name: loopback IP literals are always refused by the SCM network policy.
		strings.Replace(gh.URL, "127.0.0.1", "localhost", 1), sec, wh); err != nil {
		t.Fatal(err)
	}
	if _, err := appPool.Exec(ctx, `INSERT INTO repositories (id, organization_id, scm_connection_id, external_id, full_name, name, url, clone_url, default_branch)
		VALUES ($1, $2, $3, $4, $5, $6, 'https://github.com/'||$5, 'https://github.com/'||$5||'.git', 'main')`, repo, orgID, conn, extID, "acme/"+name, name); err != nil {
		t.Fatal(err)
	}

	az := &authz.Authorizer{H: &org.Hierarchy{DB: appPool, OrgID: orgID}}
	repoSvc := &repos.Service{DB: appPool, Authz: az, Secrets: st, Log: log, Principal: auth.PrincipalFrom,
		Net: scm.NetPolicy{AllowPrivate: true, AllowHTTP: true}, HTTP: gh.Client()}
	pushSvc := &pushprotect.Service{DB: appPool, Authz: az, Log: log, Principal: auth.PrincipalFrom, Diff: repoSvc.PushDiffReader}
	repoSvc.OnEvent = pushSvc.OnPush
	public := newMux(repoSvc.RegisterPublic)
	api := newMux(pushSvc.Register)
	call := func(p *authz.Principal, method, path string, body any) (int, map[string]any) {
		t.Helper()
		var raw []byte
		if body != nil {
			raw, _ = json.Marshal(body)
		}
		req := httptest.NewRequest(method, path, bytes.NewReader(raw))
		req.Header.Set("Content-Type", "application/json")
		req = req.WithContext(auth.WithPrincipal(req.Context(), p))
		rec := httptest.NewRecorder()
		api.ServeHTTP(rec, req)
		var out map[string]any
		_ = json.Unmarshal(rec.Body.Bytes(), &out)
		return rec.Code, out
	}
	push := func(delivery string) int {
		body := []byte(`{"ref":"refs/heads/main","before":"` + before + `","after":"` + head + `","repository":{"id":` + extID + `}}`)
		mac := hmac.New(sha256.New, whSecret)
		mac.Write(body)
		req := httptest.NewRequest("POST", "/api/webhooks/github/"+conn.String(), bytes.NewReader(body))
		req.Header.Set("X-GitHub-Event", "push")
		req.Header.Set("X-GitHub-Delivery", delivery)
		req.Header.Set("X-Hub-Signature-256", "sha256="+hex.EncodeToString(mac.Sum(nil)))
		rec := httptest.NewRecorder()
		public.ServeHTTP(rec, req)
		return rec.Code
	}
	count := func(q string) int {
		var n int
		if err := appPool.QueryRow(ctx, q, repo).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}

	// Disabled by default: a push queues nothing.
	if code := push("pp-" + uuid.NewString()); code != 202 {
		t.Fatalf("push webhook: %d", code)
	}
	if n := count(`SELECT count(*) FROM push_secret_scans WHERE repository_id = $1`); n != 0 {
		t.Fatal("push protection must be opt-in")
	}

	admin := principalWithRole(t, authz.RoleSuperAdmin)
	viewer := scoped("viewer", authz.Scope{Type: authz.ScopeOrganization, ID: orgID})
	if code, _ := call(viewer, "PUT", "/api/v1/repositories/"+repo.String()+"/push-protection", map[string]any{"enabled": true}); code != 403 {
		t.Errorf("viewer cannot enable push protection: %d", code)
	}
	if code, s := call(admin, "PUT", "/api/v1/repositories/"+repo.String()+"/push-protection", map[string]any{"enabled": true}); code != 200 || s["enabled"] != true || s["supported"] != true {
		t.Fatalf("enable: %d %v", code, s)
	}
	if n := count(`SELECT count(*) FROM audit_logs WHERE action = 'repository.push_protection' AND target_id = $1::text`); n != 1 {
		t.Errorf("enable audited: %d", n)
	}

	if code := push("pp-" + uuid.NewString()); code != 202 {
		t.Fatalf("push webhook: %d", code)
	}
	if n := count(`SELECT count(*) FROM push_secret_scans WHERE repository_id = $1 AND status = 'queued'`); n != 1 {
		t.Fatalf("queued push scans: %d", n)
	}
	for {
		ok, err := pushSvc.ProcessNext(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if !ok {
			break
		}
	}
	var status, scanErr string
	var alerts int
	_ = appPool.QueryRow(ctx, `SELECT status, alerts, error FROM push_secret_scans WHERE repository_id = $1`, repo).Scan(&status, &alerts, &scanErr)
	if status != "done" || alerts != 1 {
		t.Fatalf("push scan: %s, %d alerts (%s)", status, alerts, scanErr)
	}
	var path, commit, rule, digest string
	var line int
	if err := appPool.QueryRow(ctx, `SELECT file_path, line, commit_sha, rule_id, match_digest FROM pushed_secrets WHERE repository_id = $1`, repo).
		Scan(&path, &line, &commit, &rule, &digest); err != nil {
		t.Fatal(err)
	}
	if path != "config/app.env" || line != 2 || commit != head || rule != "github-token" || len(digest) != 16 {
		t.Errorf("alert: %s:%d %s %s %s", path, line, commit, rule, digest)
	}
	// The value is stored nowhere.
	var leaks int
	_ = appPool.QueryRow(ctx, `SELECT (SELECT count(*) FROM pushed_secrets p WHERE p.repository_id = $1 AND row_to_json(p)::text LIKE '%' || $2 || '%')
		+ (SELECT count(*) FROM notification_events e WHERE e.repository_id = $1 AND e.payload::text LIKE '%' || $2 || '%')
		+ (SELECT count(*) FROM audit_logs a WHERE a.target_id = $1::text AND a.metadata::text LIKE '%' || $2 || '%')`, repo, secretValue).Scan(&leaks)
	if leaks != 0 {
		t.Fatal("the secret value was stored")
	}
	if n := count(`SELECT count(*) FROM notification_events WHERE repository_id = $1 AND event_key = 'secret.pushed' AND severity = 'critical'`); n != 1 {
		t.Fatalf("secret.pushed events: %d", n)
	}
	// The event renders (rule, file, line, commit; never the value).
	disp := &notify.Dispatcher{Pool: appPool, Secrets: st, BaseURL: "https://pathos.test", Log: log}
	if _, err := disp.DispatchEvents(ctx); err != nil {
		t.Fatal(err)
	}
	var evErr string
	var processed bool
	_ = appPool.QueryRow(ctx, `SELECT error, processed_at IS NOT NULL FROM notification_events WHERE repository_id = $1 AND event_key = 'secret.pushed'`, repo).Scan(&evErr, &processed)
	if !processed || evErr != "" {
		t.Errorf("secret.pushed dispatch: processed=%v error=%q", processed, evErr)
	}
	var leakedMsg int
	_ = appPool.QueryRow(ctx, `SELECT count(*) FROM notifications WHERE body LIKE '%' || $1 || '%'`, secretValue).Scan(&leakedMsg)
	if leakedMsg != 0 {
		t.Fatal("a notification contains the secret value")
	}
	// The dispatch above also delivered events queued by earlier tests; keep
	// the resulting messages out of later tests' SMTP batches.
	if _, err := appPool.Exec(ctx, `UPDATE notifications SET status = 'suppressed' WHERE status = 'pending'`); err != nil {
		t.Fatal(err)
	}
	code, list := call(admin, "GET", "/api/v1/repositories/"+repo.String()+"/pushed-secrets", nil)
	if code != 200 || len(list["items"].([]any)) != 1 || len(list["scans"].([]any)) != 1 {
		t.Fatalf("list: %d %v", code, list)
	}
	if raw, _ := json.Marshal(list); strings.Contains(string(raw), secretValue) {
		t.Fatal("API returned the secret value")
	}
	// A replayed delivery of the same push is not scanned twice.
	push("pp-" + uuid.NewString())
	if n := count(`SELECT count(*) FROM push_secret_scans WHERE repository_id = $1`); n != 1 {
		t.Errorf("same push re-queued: %d", n)
	}
}
