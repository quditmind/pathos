//go:build integration

package integration

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"pathos/internal/auth"
	"pathos/internal/authz"
	"pathos/internal/org"
	"pathos/internal/platform/db"
	"pathos/internal/review"
	"pathos/internal/vuln"
)

type memBlobs struct {
	mu sync.Mutex
	m  map[string][]byte
}

func (b *memBlobs) Put(_ context.Context, key string, r io.Reader) (int64, error) {
	data, err := io.ReadAll(r)
	b.mu.Lock()
	defer b.mu.Unlock()
	b.m[key] = data
	return int64(len(data)), err
}

func (b *memBlobs) Open(_ context.Context, key string) (io.ReadCloser, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	d, ok := b.m[key]
	if !ok {
		return nil, io.ErrUnexpectedEOF
	}
	return io.NopCloser(bytes.NewReader(d)), nil
}

func (b *memBlobs) Delete(_ context.Context, keys ...string) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	for _, k := range keys {
		delete(b.m, k)
	}
	return nil
}

// reviewUser creates an active user with an organization-wide system role.
func reviewUser(t *testing.T, role string) *authz.Principal {
	t.Helper()
	ctx := t.Context()
	var id uuid.UUID
	email := role + "-" + uuid.NewString()[:8] + "@hr.test"
	if err := appPool.QueryRow(ctx, `INSERT INTO users (id, organization_id, email, display_name, status) VALUES (gen_random_uuid(), $1, $2, $3, 'active') RETURNING id`,
		orgID, email, role+" user").Scan(&id); err != nil {
		t.Fatal(err)
	}
	if _, err := appPool.Exec(ctx, `INSERT INTO role_assignments (id, organization_id, user_id, role_id, scope_type, scope_id)
		SELECT gen_random_uuid(), $1, $2, id, 'organization', $1 FROM roles WHERE key = $3 AND is_system`, orgID, id, role); err != nil {
		t.Fatal(err)
	}
	p := principalWithRole(t, role)
	p.UserID, p.Email, p.DisplayName = id, email, role+" user"
	return p
}

func TestHumanReview(t *testing.T) {
	ctx := t.Context()
	az := &authz.Authorizer{H: &org.Hierarchy{DB: appPool, OrgID: orgID}}
	blobs := &memBlobs{m: map[string][]byte{}}
	svc := &review.Service{DB: appPool, Authz: az, Log: log, Principal: auth.PrincipalFrom, Evidence: blobs}
	vsvc := &vuln.Service{DB: appPool, Authz: az, Log: log, Principal: auth.PrincipalFrom}
	mux := http.NewServeMux()
	svc.Register(mux)
	vsvc.Register(mux)
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
		mux.ServeHTTP(rec, req)
		var out map[string]any
		_ = json.Unmarshal(rec.Body.Bytes(), &out)
		return rec.Code, out
	}
	upload := func(p *authz.Principal, reviewID string, fields map[string]string, fileName string, content []byte) (int, map[string]any) {
		t.Helper()
		var buf bytes.Buffer
		mw := multipart.NewWriter(&buf)
		for k, v := range fields {
			_ = mw.WriteField(k, v)
		}
		if fileName != "" {
			fw, _ := mw.CreateFormFile("file", fileName)
			_, _ = fw.Write(content)
		}
		_ = mw.Close()
		req := httptest.NewRequest("POST", "/api/v1/human-reviews/"+reviewID+"/evidence", &buf)
		req.Header.Set("Content-Type", mw.FormDataContentType())
		req = req.WithContext(auth.WithPrincipal(req.Context(), p))
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)
		var out map[string]any
		_ = json.Unmarshal(rec.Body.Bytes(), &out)
		return rec.Code, out
	}

	analyst, analyst2 := reviewUser(t, "security_analyst"), reviewUser(t, "security_analyst")
	manager := reviewUser(t, "security_manager")
	second := reviewUser(t, "independent_reviewer")
	viewer := reviewUser(t, "viewer")
	repo := createRepo(t, "hr-"+uuid.NewString()[:6])

	// Settings: only needs_review findings are queued automatically.
	code, st := call(manager, "GET", "/api/v1/human-review/settings", nil)
	if code != 200 {
		t.Fatalf("settings: %d %v", code, st)
	}
	st["auto_triggers"] = []string{"needs_review"}
	st["auto_min_severity"] = "low"
	st["required_fields"] = []string{"reachable", "attacker_controlled"}
	if code, out := call(analyst, "PUT", "/api/v1/human-review/settings", st); code != 403 {
		t.Fatalf("analyst cannot configure: %d %v", code, out)
	}
	if code, out := call(manager, "PUT", "/api/v1/human-review/settings", st); code != 200 {
		t.Fatalf("save settings: %d %v", code, out)
	}

	// --- ingestion without duplicates ---------------------------------------
	critical := insertFinding(t, repo, "critical", "eval(request.args['q'])")
	medium := insertFinding(t, repo, "medium", "")
	untriaged := insertFinding(t, repo, "high", "")
	_, _ = appPool.Exec(ctx, `UPDATE findings SET status = 'needs_review' WHERE id = ANY($1)`, []uuid.UUID{critical, medium})
	n, err := svc.Ingest(ctx, orgID)
	if err != nil || n != 2 {
		t.Fatalf("ingest: n=%d err=%v", n, err)
	}
	if n, err := svc.Ingest(ctx, orgID); err != nil || n != 0 {
		t.Fatalf("second ingest must not duplicate: n=%d err=%v", n, err)
	}
	code, out := call(manager, "POST", "/api/v1/human-reviews", map[string]any{"finding_ids": []uuid.UUID{critical, untriaged}, "reason": "pentest scope"})
	if code != 201 || len(out["created"].([]any)) != 1 || len(out["existing"].([]any)) != 1 {
		t.Fatalf("manual add dedupes: %d %v", code, out)
	}
	if code, _ := call(analyst, "POST", "/api/v1/human-reviews", map[string]any{"finding_ids": []uuid.UUID{medium}, "reason": "please"}); code != 403 {
		t.Errorf("analyst cannot add to the queue: %d", code)
	}
	var count int
	_ = appPool.QueryRow(ctx, `SELECT count(*) FROM human_reviews WHERE finding_id = ANY($1)`, []uuid.UUID{critical, medium, untriaged}).Scan(&count)
	if count != 3 {
		t.Fatalf("one review per finding, got %d", count)
	}
	var rid uuid.UUID
	var key, prio string
	var due *time.Time
	_ = appPool.QueryRow(ctx, `SELECT id, review_key, priority, due_at FROM human_reviews WHERE finding_id = $1`, critical).Scan(&rid, &key, &prio, &due)
	if !strings.HasPrefix(key, "QD-HR-") || prio != "p1" || due == nil {
		t.Errorf("review key/priority/due from settings: %s %s %v", key, prio, due)
	}
	id := rid.String()

	// --- queue listing, filters, read-only visibility ------------------------
	code, page := call(analyst, "GET", "/api/v1/human-reviews?repository_id="+repo.String()+"&severity=critical&sort=severity&order=desc", nil)
	if code != 200 || page["total"].(float64) != 1 {
		t.Fatalf("queue filter: %d %v", code, page)
	}
	if code, page := call(viewer, "GET", "/api/v1/human-reviews?repository_id="+repo.String(), nil); code != 200 || page["total"].(float64) != 0 {
		t.Errorf("read-only users see completed reviews only: %d %v", code, page)
	}
	if code, _ := call(viewer, "GET", "/api/v1/human-reviews/"+id, nil); code != 404 {
		t.Errorf("read-only users cannot open an in-progress review: %d", code)
	}
	if code, _ := call(manager, "GET", "/api/v1/human-reviews?sort=bogus", nil); code != 400 {
		t.Errorf("invalid sort: %d", code)
	}

	// --- assignment & access control ----------------------------------------
	if code, _ := call(analyst, "PUT", "/api/v1/human-reviews/"+id+"/assessment", map[string]any{"answers": map[string]string{"reachable": "yes"}}); code != 403 {
		t.Errorf("unassigned analyst cannot assess: %d", code)
	}
	if code, _ := call(analyst, "POST", "/api/v1/human-reviews/"+id+"/assign", map[string]any{"reviewer_id": analyst.UserID}); code != 403 {
		t.Errorf("analyst cannot assign: %d", code)
	}
	if code, _ := call(manager, "POST", "/api/v1/human-reviews/"+id+"/assign", map[string]any{"reviewer_id": viewer.UserID}); code != 400 {
		t.Errorf("assignee needs reviews.assess: %d", code)
	}
	if code, out := call(manager, "POST", "/api/v1/human-reviews/"+id+"/assign", map[string]any{"reviewer_id": analyst.UserID, "note": "please look"}); code != 200 || out["status"] != "assigned" {
		t.Fatalf("assign: %d %v", code, out)
	}
	if code, _ := call(analyst2, "POST", "/api/v1/human-reviews/"+id+"/start", nil); code != 403 {
		t.Errorf("another analyst cannot take an assigned review: %d", code)
	}
	if code, out := call(analyst, "POST", "/api/v1/human-reviews/"+id+"/start", nil); code != 200 || out["status"] != "in_progress" {
		t.Fatalf("start: %d %v", code, out)
	}
	var notified int
	_ = appPool.QueryRow(ctx, `SELECT count(*) FROM notification_events WHERE event_key = 'review.assigned' AND subject_id = $1`, rid).Scan(&notified)
	if notified != 1 {
		t.Errorf("assignment notification: %d", notified)
	}

	// --- assessment, severity -----------------------------------------------
	if code, _ := call(analyst, "PUT", "/api/v1/human-reviews/"+id+"/assessment", map[string]any{"answers": map[string]string{"reachable": "maybe"}}); code != 400 {
		t.Errorf("invalid answer: %d", code)
	}
	if code, _ := call(analyst, "PUT", "/api/v1/human-reviews/"+id+"/assessment", map[string]any{"fields": map[string]string{"bogus": "x"}}); code != 400 {
		t.Errorf("unknown field: %d", code)
	}
	if code, _ := call(analyst, "PUT", "/api/v1/human-reviews/"+id+"/severity", map[string]any{"severity": "low"}); code != 422 {
		t.Errorf("severity override needs a justification: %d", code)
	}
	code, out = call(analyst, "PUT", "/api/v1/human-reviews/"+id+"/severity", map[string]any{"severity": "high",
		"cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N", "justification": "Requires an authenticated session."})
	if code != 200 || out["assessed_severity"] != "high" || out["severity"] != "critical" {
		t.Fatalf("severity: %d %v", code, out)
	}
	var cvss float64
	_ = appPool.QueryRow(ctx, `SELECT assessed_cvss::float8 FROM human_reviews WHERE id = $1`, rid).Scan(&cvss)
	if cvss != 8.1 {
		t.Errorf("CVSS 3.1 score computed from the vector: %v", cvss)
	}
	var findingSeverity string
	_ = appPool.QueryRow(ctx, `SELECT severity FROM findings WHERE id = $1`, critical).Scan(&findingSeverity)
	if findingSeverity != "critical" {
		t.Errorf("the scanner severity must be preserved: %s", findingSeverity)
	}

	// --- decision rules ------------------------------------------------------
	if code, out := call(analyst, "POST", "/api/v1/human-reviews/"+id+"/decision", map[string]any{"disposition": "false_positive", "reason": "nope"}); code != 422 {
		t.Errorf("false positive needs an explanation: %d %v", code, out)
	}
	code, out = call(analyst, "POST", "/api/v1/human-reviews/"+id+"/decision", map[string]any{"disposition": "false_positive",
		"reason": "The argument is a compile-time constant, never user input."})
	if code != 422 || !strings.Contains(out["error"].(map[string]any)["message"].(string), "required assessment fields") {
		t.Fatalf("required fields enforced: %d %v", code, out)
	}
	// "unknown" is an answer, not evidence of non-exploitability.
	if code, _ := call(analyst, "PUT", "/api/v1/human-reviews/"+id+"/assessment", map[string]any{
		"answers": map[string]string{"reachable": "yes", "attacker_controlled": "unknown"},
		"fields":  map[string]string{"attack_scenario": "Attacker sends q=__import__('os')", "network_accessibility": "internet"}}); code != 200 {
		t.Fatalf("save assessment: %d", code)
	}
	code, out = call(analyst, "POST", "/api/v1/human-reviews/"+id+"/decision", map[string]any{"disposition": "false_positive",
		"reason": "The argument is a compile-time constant, never user input."})
	if code != 200 || out["status"] != "awaiting_independent_review" {
		t.Fatalf("critical finding requires independent review: %d %v", code, out)
	}
	if code, _ := call(analyst, "PUT", "/api/v1/human-reviews/"+id+"/assessment", map[string]any{"fields": map[string]string{"investigation_notes": "x"}}); code != 409 {
		t.Errorf("locked while awaiting independent review: %d", code)
	}

	// --- independent review --------------------------------------------------
	if code, _ := call(analyst, "POST", "/api/v1/human-reviews/"+id+"/independent-review", map[string]any{"outcome": "approved", "comments": "ok"}); code != 403 {
		t.Errorf("analyst lacks reviews.approve: %d", code)
	}
	code, out = call(second, "POST", "/api/v1/human-reviews/"+id+"/independent-review", map[string]any{"outcome": "rejected", "comments": "x"})
	if code != 422 {
		t.Errorf("rejection needs comments: %d %v", code, out)
	}
	code, out = call(second, "POST", "/api/v1/human-reviews/"+id+"/independent-review", map[string]any{"outcome": "rejected",
		"comments": "Line 12 passes request data into the constant; please re-check."})
	if code != 200 || out["status"] != "in_progress" {
		t.Fatalf("rejection returns the review to the analyst: %d %v", code, out)
	}
	code, _ = call(analyst, "POST", "/api/v1/human-reviews/"+id+"/decision", map[string]any{"disposition": "false_positive",
		"reason": "Re-checked: the value comes from a hard-coded allow-list, not the request."})
	if code != 200 {
		t.Fatalf("resubmit: %d", code)
	}
	code, out = call(second, "POST", "/api/v1/human-reviews/"+id+"/independent-review", map[string]any{"outcome": "approved", "comments": "Agreed after re-check."})
	if code != 200 || out["status"] != "completed" || out["disposition"] != "false_positive" {
		t.Fatalf("approval completes the review: %d %v", code, out)
	}
	var fStatus string
	var hDisp, hSev *string
	_ = appPool.QueryRow(ctx, `SELECT status, human_disposition, human_severity FROM findings WHERE id = $1`, critical).Scan(&fStatus, &hDisp, &hSev)
	if fStatus != "false_positive" || hDisp == nil || *hDisp != "false_positive" || hSev == nil || *hSev != "high" {
		t.Fatalf("finding reflects the human outcome: %s %v %v", fStatus, hDisp, hSev)
	}
	var decisions, approvals int
	_ = appPool.QueryRow(ctx, `SELECT (SELECT count(*) FROM human_review_decisions WHERE review_id = $1), (SELECT count(*) FROM human_review_approvals WHERE review_id = $1)`, rid).
		Scan(&decisions, &approvals)
	if decisions != 2 || approvals != 2 {
		t.Errorf("decisions and approvals are kept separately: %d %d", decisions, approvals)
	}
	// Now completed: visible to read-only users.
	if code, out := call(viewer, "GET", "/api/v1/human-reviews/"+id, nil); code != 200 || out["can"].(map[string]any)["assess"] != false {
		t.Errorf("read-only user sees the completed assessment: %d", code)
	}

	// --- immutable history ---------------------------------------------------
	code, hist := call(viewer, "GET", "/api/v1/human-reviews/"+id+"/history", nil)
	if code != 200 || len(hist["items"].([]any)) < 10 {
		t.Fatalf("history: %d %v", code, hist)
	}
	for _, stmt := range []string{
		`UPDATE human_review_history SET note = 'tampered'`,
		`DELETE FROM human_review_history`,
		`UPDATE human_review_decisions SET reason = 'tampered'`,
		`DELETE FROM human_review_approvals`,
	} {
		if _, err := appPool.Exec(ctx, stmt); err == nil || !strings.Contains(err.Error(), "permission denied") {
			t.Errorf("%s: expected permission denied, got %v", stmt, err)
		}
	}
	if _, err := appPool.Exec(ctx, `UPDATE human_reviews SET original_severity = 'low' WHERE id = $1`, rid); err == nil {
		t.Error("the original scanner severity must be immutable")
	}

	// --- reopen --------------------------------------------------------------
	if code, _ := call(analyst, "POST", "/api/v1/human-reviews/"+id+"/reopen", map[string]any{"reason": "new info from pentest"}); code != 403 {
		t.Errorf("analyst cannot reopen: %d", code)
	}
	code, out = call(manager, "POST", "/api/v1/human-reviews/"+id+"/reopen", map[string]any{"reason": "Pentest found a bypass of the allow-list."})
	if code != 200 || out["status"] != "reopened" || out["round"].(float64) != 2 {
		t.Fatalf("reopen: %d %v", code, out)
	}
	_ = appPool.QueryRow(ctx, `SELECT status, human_disposition FROM findings WHERE id = $1`, critical).Scan(&fStatus, &hDisp)
	if fStatus != "open" || hDisp != nil {
		t.Errorf("reopen reverts the finding: %s %v", fStatus, hDisp)
	}
	code, det := call(analyst, "GET", "/api/v1/human-reviews/"+id, nil)
	if code != 200 || det["assessment"].(map[string]any)["answers"].(map[string]any)["reachable"] != "yes" {
		t.Errorf("round 2 starts from the previous assessment: %d", code)
	}

	// --- confirmed + remediation sync ---------------------------------------
	mid := reviewIDFor(t, medium)
	if code, _ := call(manager, "POST", "/api/v1/human-reviews/bulk", map[string]any{"review_ids": []uuid.UUID{mid, uuid.New()}, "action": "assign",
		"reviewer_id": analyst2.UserID}); code != 404 {
		t.Errorf("bulk with an unknown review fails atomically: %d", code)
	}
	var reviewer *uuid.UUID
	_ = appPool.QueryRow(ctx, `SELECT reviewer_id FROM human_reviews WHERE id = $1`, mid).Scan(&reviewer)
	if reviewer != nil {
		t.Errorf("bulk must roll back")
	}
	if code, _ := call(manager, "POST", "/api/v1/human-reviews/bulk", map[string]any{"review_ids": []uuid.UUID{mid}, "action": "assign", "reviewer_id": analyst2.UserID}); code != 200 {
		t.Fatalf("bulk assign: %d", code)
	}
	_, _ = call(analyst2, "PUT", "/api/v1/human-reviews/"+mid.String()+"/assessment", map[string]any{"answers": map[string]string{"reachable": "yes", "attacker_controlled": "yes"}})
	code, out = call(analyst2, "POST", "/api/v1/human-reviews/"+mid.String()+"/decision", map[string]any{"disposition": "confirmed",
		"reason": "Reproduced with a crafted request.", "remediation_owner_id": analyst.UserID, "remediation_priority": "p2"})
	if code != 200 || out["status"] != "completed" || out["remediation_status"] != "open" {
		t.Fatalf("confirmed (medium: no independent review): %d %v", code, out)
	}
	var assignee *uuid.UUID
	_ = appPool.QueryRow(ctx, `SELECT status, assignee_id FROM findings WHERE id = $1`, medium).Scan(&fStatus, &assignee)
	if fStatus != "open" || assignee == nil || *assignee != analyst.UserID {
		t.Errorf("confirmed finding goes to remediation: %s %v", fStatus, assignee)
	}
	if code, _ := call(analyst2, "PUT", "/api/v1/human-reviews/"+mid.String()+"/remediation", map[string]any{"status": "verified", "note": "retested"}); code != 409 {
		t.Errorf("cannot verify while the scanner still reports it: %d", code)
	}
	err = db.InTx(ctx, appPool, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `UPDATE findings SET status = 'fixed' WHERE id = $1`, medium)
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	var rem string
	_ = appPool.QueryRow(ctx, `SELECT remediation_status FROM human_reviews WHERE id = $1`, mid).Scan(&rem)
	if rem != "pending_verification" {
		t.Errorf("scan fix moves remediation to pending verification: %s", rem)
	}
	if code, out := call(analyst2, "PUT", "/api/v1/human-reviews/"+mid.String()+"/remediation", map[string]any{"status": "verified", "note": "Retested the endpoint"}); code != 200 || out["remediation_status"] != "verified" {
		t.Errorf("verify: %d %v", code, out)
	}

	// --- accepted risk through the existing approval model ------------------
	ut := reviewIDFor(t, untriaged)
	_, _ = call(manager, "POST", "/api/v1/human-reviews/"+ut.String()+"/assign", map[string]any{"reviewer_id": analyst2.UserID})
	_, _ = call(analyst2, "PUT", "/api/v1/human-reviews/"+ut.String()+"/assessment", map[string]any{"answers": map[string]string{"reachable": "yes", "attacker_controlled": "no"}})
	if code, out := call(analyst2, "POST", "/api/v1/human-reviews/"+ut.String()+"/decision", map[string]any{"disposition": "accepted_risk",
		"reason": "Internal admin tool scheduled for decommissioning in Q1."}); code != 422 || out["error"].(map[string]any)["fields"].(map[string]any)["risk_owner_id"] == nil {
		t.Errorf("accepted risk needs a risk owner: %d %v", code, out)
	}
	code, out = call(analyst2, "POST", "/api/v1/human-reviews/"+ut.String()+"/decision", map[string]any{"disposition": "accepted_risk",
		"reason": "Internal admin tool scheduled for decommissioning in Q1.", "risk_owner_id": manager.UserID, "risk_expires_at": time.Now().Add(60 * 24 * time.Hour)})
	if code != 200 || out["status"] != "awaiting_independent_review" {
		t.Fatalf("accepted risk always needs approval: %d %v", code, out)
	}
	var raID uuid.UUID
	_ = appPool.QueryRow(ctx, `SELECT risk_acceptance_id FROM human_reviews WHERE id = $1`, ut).Scan(&raID)
	if code, _ := call(manager, "POST", "/api/v1/risk-acceptances/"+raID.String()+"/approve", map[string]any{"note": "ok"}); code != 409 {
		t.Errorf("a review's risk acceptance is decided in Human Review: %d", code)
	}
	if code, _ := call(second, "POST", "/api/v1/human-reviews/"+ut.String()+"/independent-review", map[string]any{"outcome": "approved", "comments": "fine"}); code != 403 {
		t.Errorf("approving accepted risk needs findings.accept_risk: %d", code)
	}
	if code, out := call(manager, "POST", "/api/v1/human-reviews/"+ut.String()+"/independent-review", map[string]any{"outcome": "approved", "comments": "Accepted until decommissioning."}); code != 200 || out["status"] != "completed" {
		t.Fatalf("manager approves accepted risk: %d %v", code, out)
	}
	var raStatus string
	_ = appPool.QueryRow(ctx, `SELECT f.status, ra.status FROM findings f JOIN risk_acceptances ra ON ra.finding_id = f.id WHERE f.id = $1`, untriaged).Scan(&fStatus, &raStatus)
	if fStatus != "accepted_risk" || raStatus != "approved" {
		t.Errorf("accepted risk applied: %s %s", fStatus, raStatus)
	}
	// Four eyes in the database as well.
	var did uuid.UUID
	_ = appPool.QueryRow(ctx, `SELECT id FROM human_review_decisions WHERE review_id = $1 ORDER BY created_at DESC LIMIT 1`, ut).Scan(&did)
	if _, err := appPool.Exec(ctx, `INSERT INTO human_review_approvals (id, organization_id, review_id, decision_id, reviewer_id, outcome, comments)
		VALUES (gen_random_uuid(), $1, $2, $3, $4, 'approved', 'self')`, orgID, ut, did, analyst2.UserID); err == nil {
		t.Error("the decision author must not approve it")
	}

	// --- evidence --------------------------------------------------------------
	_, _ = call(manager, "POST", "/api/v1/human-reviews/"+id+"/assign", map[string]any{"reviewer_id": analyst.UserID})
	if code, out := upload(analyst, id, map[string]string{"evidence_type": "screenshot", "description": "x"}, "shot.svg", []byte("<svg onload=alert(1)>")); code != 400 {
		t.Errorf("active content is refused: %d %v", code, out)
	}
	if code, out := upload(analyst, id, map[string]string{"evidence_type": "screenshot", "description": "x"}, "shot.png", []byte("not a png")); code != 400 {
		t.Errorf("content must match the extension: %d %v", code, out)
	}
	png := append([]byte("\x89PNG\r\n\x1a\n"), make([]byte, 64)...)
	code, ev := upload(analyst, id, map[string]string{"evidence_type": "screenshot", "description": "Login bypass", "classification": "restricted"}, "shot.png", png)
	if code != 201 || !strings.HasPrefix(ev["evidence_key"].(string), "QD-EV-") || ev["is_file"] != true {
		t.Fatalf("file evidence: %d %v", code, ev)
	}
	code, tev := upload(analyst, id, map[string]string{"evidence_type": "http_request", "description": "PoC request", "text": "GET /search?q=1' OR '1'='1 HTTP/1.1"}, "", nil)
	if code != 201 || tev["text"] == nil {
		t.Fatalf("text evidence: %d %v", code, tev)
	}
	if code, _ := upload(analyst2, id, map[string]string{"evidence_type": "other", "description": "x", "text": "y"}, "", nil); code != 403 {
		t.Errorf("only the assigned analyst uploads: %d", code)
	}
	req := httptest.NewRequest("GET", "/api/v1/human-reviews/"+id+"/evidence/"+ev["id"].(string)+"/content", nil)
	req = req.WithContext(auth.WithPrincipal(req.Context(), analyst))
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != 200 || !bytes.Equal(rec.Body.Bytes(), png) || !strings.Contains(rec.Header().Get("Content-Security-Policy"), "sandbox") ||
		!strings.HasPrefix(rec.Header().Get("Content-Disposition"), "attachment") {
		t.Errorf("download: %d %v", rec.Code, rec.Header())
	}
	if code, _ := call(analyst, "DELETE", "/api/v1/human-reviews/"+id+"/evidence/"+ev["id"].(string), nil); code != 422 {
		t.Errorf("deletion needs a reason: %d", code)
	}
	if code, _ := call(analyst, "DELETE", "/api/v1/human-reviews/"+id+"/evidence/"+ev["id"].(string)+"?reason=wrong+file", nil); code != 204 {
		t.Errorf("delete evidence: %d", code)
	}
	if len(blobs.m) != 0 {
		t.Errorf("deleted evidence content is removed from the store")
	}

	// --- comments, overview, reports, export -------------------------------
	// The reopened review is hidden from read-only users altogether.
	if code, _ := call(viewer, "POST", "/api/v1/human-reviews/"+id+"/comments", map[string]any{"body": "hi"}); code != 404 {
		t.Errorf("read-only users cannot comment: %d", code)
	}
	if code, _ := call(viewer, "POST", "/api/v1/human-reviews/"+mid.String()+"/comments", map[string]any{"body": "hi"}); code != 403 {
		t.Errorf("read-only users cannot comment on completed reviews: %d", code)
	}
	if code, _ := call(analyst, "POST", "/api/v1/human-reviews/"+id+"/comments", map[string]any{"body": "Checking the allow-list"}); code != 201 {
		t.Errorf("comment: %d", code)
	}
	code, ov := call(manager, "GET", "/api/v1/human-review/overview?repository_id="+repo.String(), nil)
	if code != 200 {
		t.Fatalf("overview: %d %v", code, ov)
	}
	m := ov["metrics"].(map[string]any)
	if m["total"].(float64) != 3 || m["completed"].(float64) != 2 || m["confirmed"].(float64) != 1 || m["accepted_risks"].(float64) != 1 {
		t.Errorf("overview metrics from the database: %v", m)
	}
	code, rep := call(manager, "GET", "/api/v1/human-review/reports?repository_id="+repo.String(), nil)
	if code != 200 || rep["total_reviewed"].(float64) != 2 {
		t.Errorf("reports: %d %v", code, rep)
	}
	req = httptest.NewRequest("GET", "/api/v1/human-review/reports/export?repository_id="+repo.String(), nil)
	req = req.WithContext(auth.WithPrincipal(req.Context(), manager))
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != 200 || strings.Count(rec.Body.String(), "\n") != 4 || !strings.Contains(rec.Body.String(), key) {
		t.Errorf("csv export: %d %q", rec.Code, rec.Body.String())
	}
	code, wl := call(manager, "GET", "/api/v1/human-review/workload?repository_id="+repo.String(), nil)
	if code != 200 || len(wl["items"].([]any)) == 0 {
		t.Errorf("workload: %d %v", code, wl)
	}
	code, rv := call(manager, "GET", "/api/v1/human-review/reviewers?repository_id="+repo.String(), nil)
	if code != 200 || len(rv["items"].([]any)) < 4 {
		t.Errorf("reviewers: %d %v", code, rv)
	}
}

func reviewIDFor(t *testing.T, finding uuid.UUID) uuid.UUID {
	t.Helper()
	var id uuid.UUID
	if err := appPool.QueryRow(t.Context(), `SELECT id FROM human_reviews WHERE finding_id = $1`, finding).Scan(&id); err != nil {
		t.Fatal(err)
	}
	return id
}

// TestHumanReviewAutoAssignment checks least-loaded assignment.
func TestHumanReviewAutoAssignment(t *testing.T) {
	ctx := t.Context()
	az := &authz.Authorizer{H: &org.Hierarchy{DB: appPool, OrgID: orgID}}
	svc := &review.Service{DB: appPool, Authz: az, Log: log, Principal: auth.PrincipalFrom}
	a1, a2 := reviewUser(t, "appsec_engineer"), reviewUser(t, "appsec_engineer")
	if _, err := appPool.Exec(ctx, `UPDATE human_review_settings SET assignment_strategy = 'least_loaded', assignment_pool = $2, auto_triggers = '{needs_review}',
		auto_min_severity = 'info' WHERE organization_id = $1`, orgID, []uuid.UUID{a1.UserID, a2.UserID}); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = appPool.Exec(context.Background(), `UPDATE human_review_settings SET assignment_strategy = 'manual', assignment_pool = '{}' WHERE organization_id = $1`, orgID)
	})
	repo := createRepo(t, "hra-"+uuid.NewString()[:6])
	var ids []uuid.UUID
	for range 4 {
		f := insertFinding(t, repo, "low", "")
		ids = append(ids, f)
	}
	_, _ = appPool.Exec(ctx, `UPDATE findings SET status = 'needs_review' WHERE id = ANY($1)`, ids)
	if _, err := svc.Ingest(ctx, orgID); err != nil {
		t.Fatal(err)
	}
	var n1, n2 int
	_ = appPool.QueryRow(ctx, `SELECT count(*) FILTER (WHERE reviewer_id = $2), count(*) FILTER (WHERE reviewer_id = $3) FROM human_reviews WHERE finding_id = ANY($1)`,
		ids, a1.UserID, a2.UserID).Scan(&n1, &n2)
	if n1 != 2 || n2 != 2 {
		t.Errorf("least-loaded assignment balances work: %d/%d", n1, n2)
	}
}

// TestHumanReviewMigrationRollback runs the Human Review migration down and
// up again.
func TestHumanReviewMigrationRollback(t *testing.T) {
	ctx := context.Background()
	if err := db.MigrateDownTo(ctx, ownerPool, 11, log); err != nil {
		t.Fatalf("down: %v", err)
	}
	var exists bool
	_ = ownerPool.QueryRow(ctx, `SELECT to_regclass('public.human_reviews') IS NOT NULL`).Scan(&exists)
	if exists {
		t.Fatal("down migration must drop human_reviews")
	}
	if err := db.Migrate(ctx, ownerPool, log); err != nil {
		t.Fatalf("up again: %v", err)
	}
	if _, err := ownerPool.Exec(ctx, `SELECT pathos_apply_app_grants()`); err != nil {
		t.Fatal(err)
	}
	// The rollback went below the multi-tenancy migrations: re-enable
	// row-level security as TestMain did.
	if _, err := ownerPool.Exec(ctx, `SELECT pathos_set_multi_tenant(true)`); err != nil {
		t.Fatal(err)
	}
	var settings int
	_ = appPool.QueryRow(ctx, `SELECT count(*) FROM human_review_settings`).Scan(&settings)
	if settings == 0 {
		t.Error("settings are seeded again")
	}
}
