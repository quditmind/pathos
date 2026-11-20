//go:build integration

package integration

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"io"
	"mime/quotedprintable"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"

	"pathos/internal/auth"
	"pathos/internal/authz"
	"pathos/internal/identity"
	"pathos/internal/notify"
	"pathos/internal/org"
	"pathos/internal/platform/crypto"
	"pathos/internal/schedule"
	"pathos/internal/secrets"
	"pathos/internal/vuln"
)

// fakeSMTP is a minimal SMTP server that records messages. It does not offer
// STARTTLS, which lets the test prove that "starttls" mode refuses to
// downgrade.
type fakeSMTP struct {
	ln   net.Listener
	mu   sync.Mutex
	msgs map[string][]string // recipient -> raw messages
}

func startFakeSMTP(t *testing.T) *fakeSMTP {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	f := &fakeSMTP{ln: ln, msgs: map[string][]string{}}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go f.serve(c)
		}
	}()
	return f
}

func (f *fakeSMTP) serve(c net.Conn) {
	defer c.Close()
	r := bufio.NewReader(c)
	w := func(s string) { _, _ = c.Write([]byte(s + "\r\n")) }
	w("220 fake ESMTP")
	var rcpts []string
	for {
		line, err := r.ReadString('\n')
		if err != nil {
			return
		}
		cmd := strings.ToUpper(strings.TrimSpace(line))
		switch {
		case strings.HasPrefix(cmd, "EHLO"), strings.HasPrefix(cmd, "HELO"):
			w("250-fake")
			w("250 8BITMIME")
		case strings.HasPrefix(cmd, "MAIL"):
			rcpts = nil
			w("250 OK")
		case strings.HasPrefix(cmd, "RCPT"):
			addr := strings.Trim(strings.TrimSpace(line[strings.Index(line, ":")+1:]), "<>")
			rcpts = append(rcpts, strings.ToLower(addr))
			w("250 OK")
		case cmd == "DATA":
			w("354 go ahead")
			var b strings.Builder
			for {
				l, err := r.ReadString('\n')
				if err != nil {
					return
				}
				if l == ".\r\n" {
					break
				}
				b.WriteString(l)
			}
			f.mu.Lock()
			for _, rc := range rcpts {
				f.msgs[rc] = append(f.msgs[rc], b.String())
			}
			f.mu.Unlock()
			w("250 queued")
		case cmd == "QUIT":
			w("221 bye")
			return
		default:
			w("250 OK")
		}
	}
}

func (f *fakeSMTP) dial(ctx context.Context, _ string) (net.Conn, error) {
	var d net.Dialer
	return d.DialContext(ctx, "tcp", f.ln.Addr().String())
}

// to returns messages for addr with the quoted-printable body decoded.
func (f *fakeSMTP) to(addr string) []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []string
	for _, raw := range f.msgs[strings.ToLower(addr)] {
		head, body, _ := strings.Cut(raw, "\r\n\r\n")
		dec, _ := io.ReadAll(quotedprintable.NewReader(strings.NewReader(body)))
		out = append(out, head+"\r\n\r\n"+string(dec))
	}
	return out
}

// realUser creates an active user with a role at a scope and returns a
// principal carrying the real grants.
func realUser(t *testing.T, role string, scope authz.Scope) *authz.Principal {
	t.Helper()
	ctx := t.Context()
	u, err := identity.CreateUser(ctx, appPool, identity.User{OrganizationID: orgID, Email: role + "-" + uuid.NewString()[:8] + "@sn.test", Status: identity.StatusActive})
	if err != nil {
		t.Fatal(err)
	}
	ro, err := identity.GetRoleByKey(ctx, appPool, orgID, role)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := identity.CreateAssignment(ctx, appPool, orgID, u.ID, ro.ID, scope, nil); err != nil {
		t.Fatal(err)
	}
	grants, err := identity.LoadGrants(ctx, appPool, u.ID)
	if err != nil {
		t.Fatal(err)
	}
	return &authz.Principal{UserID: u.ID, OrganizationID: orgID, Email: u.Email, Grants: grants}
}

func TestSchedulesAndScheduler(t *testing.T) {
	ctx := t.Context()
	az := &authz.Authorizer{H: &org.Hierarchy{DB: appPool, OrgID: orgID}}
	mux := newMux((&schedule.Service{DB: appPool, Authz: az, Log: log, Principal: auth.PrincipalFrom}).Register)
	call := func(p *authz.Principal, method, path string, body any) (int, map[string]any) {
		t.Helper()
		raw, _ := json.Marshal(body)
		req := httptest.NewRequest(method, path, bytes.NewReader(raw)).WithContext(auth.WithPrincipal(ctx, p))
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)
		var out map[string]any
		_ = json.Unmarshal(rec.Body.Bytes(), &out)
		return rec.Code, out
	}
	orgScope := authz.Scope{Type: authz.ScopeOrganization, ID: orgID}
	admin := realUser(t, "platform_admin", orgScope)
	repoA := createRepo(t, "sch-a-"+uuid.NewString()[:6])
	repoB := createRepo(t, "sch-b-"+uuid.NewString()[:6])
	repoScoped := realUser(t, "security_manager", authz.Scope{Type: authz.ScopeRepository, ID: repoA})
	dev := realUser(t, "developer", orgScope)

	// Validation and authorization.
	for name, body := range map[string]map[string]any{
		"bad cron":     {"name": "x", "cron": "61 * * * *", "target_type": "organization"},
		"too frequent": {"name": "x", "cron": "*/15 * * * *", "target_type": "organization"},
		"bad zone":     {"name": "x", "cron": "@daily", "timezone": "Mars/Olympus", "target_type": "organization"},
		"no target":    {"name": "x", "cron": "@daily", "target_type": "repository"},
		"ghost target": {"name": "x", "cron": "@daily", "target_type": "repository", "target_id": uuid.NewString()},
		"emergency":    {"name": "x", "cron": "@daily", "target_type": "organization", "priority": 100},
	} {
		if code, out := call(admin, "POST", "/api/v1/schedules", body); code != 400 {
			t.Errorf("%s: want 400, got %d %v", name, code, out)
		}
	}
	if code, _ := call(dev, "POST", "/api/v1/schedules", map[string]any{"name": "x", "cron": "@daily", "target_type": "organization"}); code != 403 {
		t.Errorf("developer lacks schedules.manage: %d", code)
	}
	if code, _ := call(repoScoped, "POST", "/api/v1/schedules", map[string]any{"name": "x", "cron": "@daily", "target_type": "repository", "target_id": repoB}); code != 403 {
		t.Errorf("repo-scoped manager must not schedule another repository: %d", code)
	}
	code, s1 := call(repoScoped, "POST", "/api/v1/schedules", map[string]any{
		"name": "Nightly A", "cron": "0 2 * * *", "timezone": "Europe/Berlin", "target_type": "repository", "target_id": repoA, "priority": 40})
	if code != 201 || s1["target_name"] == "" || s1["next_run_at"] == nil {
		t.Fatalf("create: %d %v", code, s1)
	}
	next, _ := time.Parse(time.RFC3339Nano, s1["next_run_at"].(string))
	if h := next.In(mustZone(t, "Europe/Berlin")).Hour(); h != 2 {
		t.Errorf("next run should be 02:00 Berlin time, got %s", next)
	}

	// Preview: five runs and the number of repositories in the target.
	if code, pv := call(admin, "POST", "/api/v1/schedules/preview", map[string]any{"cron": "@weekly", "target_type": "repository", "target_id": repoA}); code != 200 ||
		len(pv["next_runs"].([]any)) != 5 || pv["repositories"].(float64) != 1 {
		t.Errorf("preview: %d %v", code, pv)
	}

	// Business-unit targets include child units.
	parent, child := uuid.Must(uuid.NewV7()), uuid.Must(uuid.NewV7())
	_, _ = appPool.Exec(ctx, `INSERT INTO business_units (id, organization_id, name) VALUES ($1, $2, $3)`, parent, orgID, "Sched "+parent.String()[:6])
	_, _ = appPool.Exec(ctx, `INSERT INTO business_units (id, organization_id, parent_id, name) VALUES ($1, $2, $3, $4)`, child, orgID, parent, "Sched "+child.String()[:6])
	_, _ = appPool.Exec(ctx, `UPDATE repositories SET business_unit_id = $2 WHERE id = $1`, repoB, child)
	if _, pv := call(admin, "POST", "/api/v1/schedules/preview", map[string]any{"cron": "@daily", "target_type": "business_unit", "target_id": parent}); pv["repositories"].(float64) != 1 {
		t.Errorf("BU target should reach the child unit's repository: %v", pv)
	}

	// The scoped manager sees only their schedule; the org admin sees all.
	_, s2 := call(admin, "POST", "/api/v1/schedules", map[string]any{"name": "Weekly B", "cron": "@weekly", "target_type": "repository", "target_id": repoB})
	_, l := call(repoScoped, "GET", "/api/v1/schedules", nil)
	for _, it := range l["items"].([]any) {
		if it.(map[string]any)["id"] == s2["id"] {
			t.Error("scoped user must not see a schedule outside their scope")
		}
	}

	// Tick runs due schedules once and advances next_run_at.
	id1 := s1["id"].(string)
	_, _ = appPool.Exec(ctx, `UPDATE scan_schedules SET next_run_at = now() - interval '1 minute' WHERE id = $1`, id1)
	st, err := schedule.Tick(ctx, appPool, time.Now(), log)
	if err != nil || st.SchedulesRun < 1 {
		t.Fatalf("tick: %+v %v", st, err)
	}
	var trig string
	var prio int
	var sid *uuid.UUID
	if err := appPool.QueryRow(ctx, `SELECT trigger, priority, schedule_id FROM scan_jobs WHERE repository_id = $1 AND status = 'queued'`, repoA).Scan(&trig, &prio, &sid); err != nil {
		t.Fatal(err)
	}
	if trig != "schedule" || prio != 40 || sid == nil || sid.String() != id1 {
		t.Errorf("scheduled job: trigger=%s priority=%d schedule=%v", trig, prio, sid)
	}
	var nextRun time.Time
	var missed, queued int
	_ = appPool.QueryRow(ctx, `SELECT next_run_at, missed_runs, last_queued FROM scan_schedules WHERE id = $1`, id1).Scan(&nextRun, &missed, &queued)
	if !nextRun.After(time.Now()) || missed != 0 || queued != 1 {
		t.Errorf("after run: next=%s missed=%d queued=%d", nextRun, missed, queued)
	}
	if st, _ := schedule.Tick(ctx, appPool, time.Now(), log); st.SchedulesRun != 0 {
		t.Errorf("a second tick must not run the schedule again: %+v", st)
	}

	// Missed runs: due three days ago means two more daily activations were
	// missed. One catch-up run (coalesced into the queued job) and an event.
	_, _ = appPool.Exec(ctx, `UPDATE scan_schedules SET next_run_at = now() - interval '3 days' WHERE id = $1`, id1)
	if _, err := schedule.Tick(ctx, appPool, time.Now(), log); err != nil {
		t.Fatal(err)
	}
	_ = appPool.QueryRow(ctx, `SELECT missed_runs FROM scan_schedules WHERE id = $1`, id1).Scan(&missed)
	if missed < 2 || missed > 3 {
		t.Errorf("missed runs = %d, want 2-3", missed)
	}
	var n int
	_ = appPool.QueryRow(ctx, `SELECT count(*) FROM scan_jobs WHERE repository_id = $1 AND status = 'queued'`, repoA).Scan(&n)
	if n != 1 {
		t.Errorf("catch-up must not stack jobs: %d queued", n)
	}
	_ = appPool.QueryRow(ctx, `SELECT count(*) FROM notification_events WHERE event_key = 'schedule.missed' AND subject_id = $1`, id1).Scan(&n)
	if n != 1 {
		t.Errorf("schedule.missed events = %d", n)
	}

	// Run now and delete honour scope.
	if code, _ := call(repoScoped, "POST", "/api/v1/schedules/"+s2["id"].(string)+"/run", nil); code != 403 {
		t.Errorf("run outside scope: %d", code)
	}
	if code, res := call(admin, "POST", "/api/v1/schedules/"+s2["id"].(string)+"/run", nil); code != 200 || res["queued"].(float64) != 1 {
		t.Errorf("run now: %d %v", code, res)
	}
	if code, _ := call(repoScoped, "DELETE", "/api/v1/schedules/"+id1, nil); code != 204 {
		t.Errorf("delete own: %d", code)
	}

	// Lease recovery: a running job whose lease expired returns to the queue.
	_, _ = appPool.Exec(ctx, `UPDATE scan_jobs SET status = 'running', attempts = 1, lease_expires_at = now() - interval '1 minute'
		WHERE repository_id = $1 AND status = 'queued'`, repoB)
	_, _ = schedule.Tick(ctx, appPool, time.Now(), log)
	var status string
	_ = appPool.QueryRow(ctx, `SELECT status FROM scan_jobs WHERE repository_id = $1 ORDER BY queued_at DESC LIMIT 1`, repoB).Scan(&status)
	if status != "queued" {
		t.Errorf("expired lease should requeue, got %s", status)
	}

	// Worker health: one event per outage.
	wid := uuid.Must(uuid.NewV7())
	_, _ = appPool.Exec(ctx, `INSERT INTO workers (id, organization_id, name, family, token_sha256, last_seen_at)
		VALUES ($1, $2, $3, 'core', $4, now() - interval '10 minutes')`, wid, orgID, "w-"+wid.String()[:8], uuid.NewString())
	_, _ = schedule.Tick(ctx, appPool, time.Now(), log)
	_, _ = schedule.Tick(ctx, appPool, time.Now(), log)
	_ = appPool.QueryRow(ctx, `SELECT count(*) FROM notification_events WHERE event_key = 'worker.offline' AND subject_id = $1`, wid).Scan(&n)
	if n != 1 {
		t.Errorf("worker.offline events = %d, want 1", n)
	}

	// Leader election: while one scheduler runs, the lock is taken.
	sctx, cancel := context.WithCancel(ctx)
	done := make(chan struct{})
	go func() {
		_ = (&schedule.Scheduler{Pool: appPool, Log: log, Holder: "it-1", Interval: 50 * time.Millisecond}).Run(sctx)
		close(done)
	}()
	deadline := time.Now().Add(5 * time.Second)
	var holder string
	for time.Now().Before(deadline) {
		_ = appPool.QueryRow(ctx, `SELECT holder FROM scheduler_state WHERE name = 'scheduler' AND heartbeat_at > now() - interval '5 seconds'`).Scan(&holder)
		if holder == "it-1" {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if holder != "it-1" {
		t.Fatal("scheduler never became leader")
	}
	var got bool
	conn, _ := appPool.Acquire(ctx)
	_ = conn.QueryRow(ctx, `SELECT pg_try_advisory_lock($1)`, int64(0x5041_5448_4f53_0001)).Scan(&got)
	if got {
		t.Error("a second replica must not acquire leadership")
		_, _ = conn.Exec(ctx, `SELECT pg_advisory_unlock($1)`, int64(0x5041_5448_4f53_0001))
	}
	conn.Release()
	cancel()
	<-done
	conn, _ = appPool.Acquire(ctx)
	_ = conn.QueryRow(ctx, `SELECT pg_try_advisory_lock($1)`, int64(0x5041_5448_4f53_0001)).Scan(&got)
	if !got {
		t.Error("leadership should be free after the leader stops")
	}
	_, _ = conn.Exec(ctx, `SELECT pg_advisory_unlock($1)`, int64(0x5041_5448_4f53_0001))
	conn.Release()

	if code, stt := call(admin, "GET", "/api/v1/scheduler/status", nil); code != 200 || stt["leader"] != "it-1" {
		t.Errorf("status: %d %v", code, stt)
	}
}

func mustZone(t *testing.T, name string) *time.Location {
	l, err := time.LoadLocation(name)
	if err != nil {
		t.Fatal(err)
	}
	return l
}

func TestNotifications(t *testing.T) {
	ctx := t.Context()
	az := &authz.Authorizer{H: &org.Hierarchy{DB: appPool, OrgID: orgID}}
	kr, _ := crypto.NewKeyring(map[int][]byte{1: testKey})
	store := &secrets.Store{Keys: kr}
	mux := newMux((&notify.Service{DB: appPool, Authz: az, Secrets: store, Log: log, Principal: auth.PrincipalFrom, BaseURL: "https://pathos.test"}).Register)
	call := func(p *authz.Principal, method, path string, body any) (int, map[string]any) {
		t.Helper()
		var rd *bytes.Reader
		if body != nil {
			raw, _ := json.Marshal(body)
			rd = bytes.NewReader(raw)
		} else {
			rd = bytes.NewReader(nil)
		}
		req := httptest.NewRequest(method, path, rd).WithContext(auth.WithPrincipal(ctx, p))
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)
		var out map[string]any
		_ = json.Unmarshal(rec.Body.Bytes(), &out)
		return rec.Code, out
	}
	// Events left by earlier tests (the dispatcher handles 100 per pump)
	// must not be delivered to this test's mailboxes.
	if _, err := appPool.Exec(ctx, `UPDATE notification_events SET processed_at = now() WHERE processed_at IS NULL`); err != nil {
		t.Fatal(err)
	}
	smtpSrv := startFakeSMTP(t)
	disp := &notify.Dispatcher{Pool: appPool, Secrets: store, Sender: notify.SMTPSender{Dial: smtpSrv.dial}, BaseURL: "https://pathos.test", Log: log}
	pump := func() {
		t.Helper()
		if _, err := disp.DispatchEvents(ctx); err != nil {
			t.Fatal(err)
		}
		if _, _, err := disp.SendPending(ctx); err != nil {
			t.Fatal(err)
		}
	}
	orgScope := authz.Scope{Type: authz.ScopeOrganization, ID: orgID}
	admin := realUser(t, "platform_admin", orgScope)
	analyst := realUser(t, "security_analyst", orgScope)

	// Built-in rules were seeded.
	code, rules := call(admin, "GET", "/api/v1/notifications/rules", nil)
	sys := 0
	for _, r := range rules["items"].([]any) {
		if r.(map[string]any)["system"].(bool) {
			sys++
		}
		// The UI relies on lists, never null.
		for _, k := range []string{"roles", "users", "emails", "dynamic"} {
			if _, ok := r.(map[string]any)["recipients"].(map[string]any)[k].([]any); !ok {
				t.Errorf("rule %v: recipients.%s is not a list", r.(map[string]any)["name"], k)
			}
		}
	}
	if code != 200 || sys != 21 { // 19 + gate_failed and architecture_drift (M9)
		t.Fatalf("system rules: %d %d", code, sys)
	}
	if code, _ := call(analyst, "GET", "/api/v1/notifications/rules", nil); code != 403 {
		t.Errorf("analyst must not manage notifications: %d", code)
	}

	// SMTP settings: validation and write-only password.
	for name, body := range map[string]map[string]any{
		"metadata host":  {"enabled": true, "host": "169.254.169.254", "port": 25, "tls_mode": "none", "from_address": "a@b.test"},
		"auth over none": {"enabled": true, "host": "mail.test", "port": 25, "tls_mode": "none", "username": "u", "from_address": "a@b.test"},
		"bad from":       {"enabled": true, "host": "mail.test", "port": 25, "tls_mode": "none", "from_address": "x\r\nBcc: e@x"},
	} {
		if code, _ := call(admin, "PUT", "/api/v1/notifications/smtp", body); code != 400 {
			t.Errorf("%s: want 400, got %d", name, code)
		}
	}
	code, cfg := call(admin, "PUT", "/api/v1/notifications/smtp", map[string]any{
		"enabled": true, "host": "mail.test", "port": 587, "tls_mode": "starttls", "username": "relay", "password": "s3cret-relay-pw",
		"from_address": "pathos@acme.test", "from_name": "PATHOS"})
	if code != 200 || cfg["has_password"] != true || strings.Contains(mustJSON(cfg), "s3cret") {
		t.Fatalf("smtp put: %d %v", code, cfg)
	}

	// Test email under starttls: the fake server offers no STARTTLS, so the
	// sender must refuse (no clear-text fallback) and schedule a retry.
	code, tst := call(admin, "POST", "/api/v1/notifications/smtp/test", nil)
	if code != 202 {
		t.Fatalf("test email: %d %v", code, tst)
	}
	// Repeated test emails are separate deliveries (no event to dedupe on).
	if code, again := call(admin, "POST", "/api/v1/notifications/smtp/test", nil); code != 202 {
		t.Fatalf("second test email: %d %v", code, again)
	} else {
		_, _ = appPool.Exec(ctx, `UPDATE notifications SET status = 'suppressed' WHERE id = $1`, again["id"])
	}
	pump()
	var st, lastErr string
	var attempts int
	_ = appPool.QueryRow(ctx, `SELECT status, attempts, last_error FROM notifications WHERE id = $1`, tst["id"]).Scan(&st, &attempts, &lastErr)
	if st != "pending" || attempts != 1 || !strings.Contains(lastErr, "STARTTLS") || strings.Contains(lastErr, "s3cret") {
		t.Errorf("starttls downgrade: status=%s attempts=%d err=%q", st, attempts, lastErr)
	}
	if len(smtpSrv.to(admin.Email)) != 0 {
		t.Error("no message may be sent without TLS in starttls mode")
	}

	// Plain relay (development): delivered.
	call(admin, "PUT", "/api/v1/notifications/smtp", map[string]any{
		"enabled": true, "host": "mail.test", "port": 25, "tls_mode": "none", "username": "", "password": "", "from_address": "pathos@acme.test"})
	_, _ = appPool.Exec(ctx, `UPDATE notifications SET next_attempt_at = now() WHERE id = $1`, tst["id"])
	pump()
	if msgs := smtpSrv.to(admin.Email); len(msgs) != 1 || !strings.Contains(msgs[0], "Subject: [PATHOS] Test email") || !strings.Contains(msgs[0], "Auto-Submitted: auto-generated") {
		t.Fatalf("test email not delivered: %v", msgs)
	}

	// Scan failure -> built-in "Scan failures" rule (platform admins and
	// security managers covering the repository).
	repo := createRepo(t, "nt-"+uuid.NewString()[:6])
	job := uuid.Must(uuid.NewV7())
	var pv uuid.UUID
	_ = appPool.QueryRow(ctx, `SELECT current_version_id FROM scan_profiles WHERE organization_id = $1 AND is_default`, orgID).Scan(&pv)
	if _, err := appPool.Exec(ctx, `INSERT INTO scan_jobs (id, organization_id, repository_id, profile_version_id, trigger, ref, status, attempts)
		VALUES ($1, $2, $3, $4, 'schedule', 'main', 'running', 3)`, job, orgID, repo, pv); err != nil {
		t.Fatal(err)
	}
	_, _ = appPool.Exec(ctx, `UPDATE scan_jobs SET status = 'failed', error = 'clone failed: repository not found' WHERE id = $1`, job)
	pump()
	msgs := smtpSrv.to(admin.Email)
	if len(msgs) != 2 || !strings.Contains(msgs[1], "Scan failed") || !strings.Contains(msgs[1], "https://pathos.test/scans?job="+job.String()) {
		t.Fatalf("scan failure email: %d %v", len(msgs), msgs)
	}
	var inApp int
	_ = appPool.QueryRow(ctx, `SELECT count(*) FROM notifications WHERE user_id = $1 AND channel = 'in_app' AND event_key = 'scan.failed'`, admin.UserID).Scan(&inApp)
	if inApp != 1 {
		t.Errorf("in-app scan failure notices = %d", inApp)
	}

	// Scoped rule on another repository does not fire; one on this
	// repository with an explicit address does, with the custom template.
	other := createRepo(t, "nt-other-"+uuid.NewString()[:6])
	for _, rr := range []struct {
		scope uuid.UUID
		email string
	}{{other, "other@ext.test"}, {repo, "oncall@ext.test"}} {
		if code, out := call(admin, "POST", "/api/v1/notifications/rules", map[string]any{
			"name": "On-call " + rr.email, "event_key": "scan.failed", "scope_type": "repository", "scope_id": rr.scope,
			"recipients": map[string]any{"emails": []string{rr.email}}, "email": true}); code != 201 {
			t.Fatalf("create rule: %d %v", code, out)
		}
	}
	if code, out := call(admin, "PUT", "/api/v1/notifications/templates/scan.failed", map[string]any{"subject": "{{.Nope}}", "body": "x"}); code != 400 {
		t.Errorf("broken template must be rejected: %d %v", code, out)
	}
	if code, _ := call(admin, "PUT", "/api/v1/notifications/templates/scan.failed", map[string]any{
		"subject": "SCAN DOWN {{.Repository}}", "body": "Error: {{.Scan.Error}}"}); code != 204 {
		t.Errorf("custom template: %d", code)
	}
	job2 := uuid.Must(uuid.NewV7())
	_, _ = appPool.Exec(ctx, `INSERT INTO scan_jobs (id, organization_id, repository_id, profile_version_id, trigger, ref, status, attempts)
		VALUES ($1, $2, $3, $4, 'manual', 'main', 'running', 1)`, job2, orgID, repo, pv)
	// Untrusted text with a header-injection attempt.
	_, _ = appPool.Exec(ctx, `UPDATE scan_jobs SET status = 'failed', error = E'boom\r\nBcc: attacker@evil.test' WHERE id = $1`, job2)
	pump()
	if len(smtpSrv.to("other@ext.test")) != 0 {
		t.Error("rule scoped to another repository must not fire")
	}
	oc := smtpSrv.to("oncall@ext.test")
	if len(oc) != 1 || !strings.Contains(oc[0], "Subject: SCAN DOWN acme/"+"nt-") {
		t.Fatalf("scoped rule / custom template: %v", oc)
	}
	if len(smtpSrv.to("attacker@evil.test")) != 0 || strings.Contains(strings.SplitN(oc[0], "\r\n\r\n", 2)[0], "attacker") {
		t.Error("untrusted text must never reach message headers")
	}
	call(admin, "DELETE", "/api/v1/notifications/templates/scan.failed", nil)

	// Risk acceptance requested: eligible approvers (accept_risk covering
	// the repository) are notified, the requester is not.
	requester := realUser(t, "security_manager", orgScope)
	approver := realUser(t, "security_manager", authz.Scope{Type: authz.ScopeRepository, ID: repo})
	outsider := realUser(t, "security_manager", authz.Scope{Type: authz.ScopeRepository, ID: other})
	f := insertFinding(t, repo, "high", "")
	ra := uuid.Must(uuid.NewV7())
	if _, err := appPool.Exec(ctx, `INSERT INTO risk_acceptances (id, organization_id, finding_id, requested_by, justification, expires_at)
		VALUES ($1, $2, $3, $4, 'Compensating control: WAF rule 12', now() + interval '30 days')`, ra, orgID, f, requester.UserID); err != nil {
		t.Fatal(err)
	}
	pump()
	if len(smtpSrv.to(approver.Email)) != 1 || len(smtpSrv.to(requester.Email)) != 0 || len(smtpSrv.to(outsider.Email)) != 0 {
		t.Errorf("approvers: approver=%d requester=%d outsider=%d",
			len(smtpSrv.to(approver.Email)), len(smtpSrv.to(requester.Email)), len(smtpSrv.to(outsider.Email)))
	}
	_, _ = appPool.Exec(ctx, `UPDATE risk_acceptances SET status = 'approved', decided_by = $2, decided_at = now() WHERE id = $1`, ra, approver.UserID)
	pump()
	if m := smtpSrv.to(requester.Email); len(m) != 1 || !strings.Contains(m[0], "approved") {
		t.Errorf("requester should learn the decision: %v", m)
	}

	// Assignment by someone else notifies; self-assignment does not. Goes
	// through the real API so the actor context is exercised.
	vmux := newMux((&vuln.Service{DB: appPool, Authz: az, Log: log, Principal: auth.PrincipalFrom}).Register)
	assign := func(p *authz.Principal, to uuid.UUID) {
		t.Helper()
		raw, _ := json.Marshal(map[string]any{"assignee_id": to})
		req := httptest.NewRequest("POST", "/api/v1/findings/"+f.String()+"/assign", bytes.NewReader(raw)).WithContext(auth.WithPrincipal(ctx, p))
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()
		vmux.ServeHTTP(rec, req)
		if rec.Code != 204 {
			t.Fatalf("assign: %d %s", rec.Code, rec.Body)
		}
	}
	assign(requester, analyst.UserID)
	assign(approver, approver.UserID)
	pump()
	var assignedA, assignedB int
	_ = appPool.QueryRow(ctx, `SELECT count(*) FROM notifications WHERE event_key = 'finding.assigned' AND user_id = $1`, analyst.UserID).Scan(&assignedA)
	_ = appPool.QueryRow(ctx, `SELECT count(*) FROM notifications WHERE event_key = 'finding.assigned' AND user_id = $1`, approver.UserID).Scan(&assignedB)
	if assignedA != 2 || assignedB != 0 { // in-app + email for the analyst
		t.Errorf("assignment notices: other=%d self=%d", assignedA, assignedB)
	}

	// SLA breach: one event per repository per breach.
	_, _ = appPool.Exec(ctx, `UPDATE findings SET sla_due_at = now() - interval '1 hour' WHERE id = $1`, f)
	n1, err := notify.DetectSLABreaches(ctx, appPool)
	if err != nil || n1 < 1 {
		t.Fatalf("SLA detection: %d %v", n1, err)
	}
	if n2, _ := notify.DetectSLABreaches(ctx, appPool); n2 != 0 {
		t.Errorf("SLA breach must be reported once, got %d more", n2)
	}
	pump()
	if m := smtpSrv.to(approver.Email); len(m) < 2 || !strings.Contains(m[len(m)-1], "SLA breached") {
		t.Errorf("assignee should get the SLA breach: %d", len(m))
	}

	// In-app inbox and read state.
	code, inbox := call(analyst, "GET", "/api/v1/me/notifications", nil)
	if code != 200 || inbox["unread"].(float64) < 1 {
		t.Fatalf("inbox: %d %v", code, inbox)
	}
	if code, _ := call(analyst, "POST", "/api/v1/me/notifications/read", map[string]any{"all": true}); code != 204 {
		t.Errorf("mark read: %d", code)
	}
	if _, inbox = call(analyst, "GET", "/api/v1/me/notifications?unread=1", nil); inbox["unread"].(float64) != 0 || len(inbox["items"].([]any)) != 0 {
		t.Errorf("after read: %v", inbox)
	}

	// Delivery history, retry, and append-only for the app role.
	code, hist := call(admin, "GET", "/api/v1/notifications/deliveries?channel=email&status=sent", nil)
	if code != 200 || len(hist["items"].([]any)) < 3 {
		t.Errorf("history: %d %v", code, hist["email_last_7_days"])
	}
	_, _ = appPool.Exec(ctx, `UPDATE notifications SET status = 'failed' WHERE id = $1`, tst["id"])
	if code, _ := call(admin, "POST", "/api/v1/notifications/deliveries/"+tst["id"].(string)+"/retry", nil); code != 204 {
		t.Errorf("retry: %d", code)
	}
	if _, err := appPool.Exec(ctx, `DELETE FROM notifications WHERE id = $1`, tst["id"]); err == nil {
		t.Error("app role must not delete delivery history")
	}

	// Disabled email: pending messages are suppressed, not lost silently.
	call(admin, "PUT", "/api/v1/notifications/smtp", map[string]any{"enabled": false, "host": "mail.test", "port": 25, "tls_mode": "none", "from_address": "pathos@acme.test"})
	pump()
	_ = appPool.QueryRow(ctx, `SELECT status FROM notifications WHERE id = $1`, tst["id"]).Scan(&st)
	if st != "suppressed" {
		t.Errorf("disabled email should suppress, got %s", st)
	}
}

func mustJSON(v any) string {
	b, _ := json.Marshal(v)
	return string(b)
}

var _ = http.MethodGet
