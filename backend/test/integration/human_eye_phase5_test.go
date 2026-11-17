//go:build integration

package integration

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/google/uuid"

	"pathos/internal/auth"
	"pathos/internal/authz"
	"pathos/internal/org"
	"pathos/internal/review"
)

func TestHumanEyeMultiLevelAndPatches(t *testing.T) {
	ctx := t.Context()
	az := &authz.Authorizer{H: &org.Hierarchy{DB: appPool, OrgID: orgID}}
	svc := &review.Service{DB: appPool, Authz: az, Log: log, Principal: auth.PrincipalFrom, Evidence: &memBlobs{m: map[string][]byte{}}}
	mux := http.NewServeMux()
	svc.Register(mux)
	call := func(p *authz.Principal, method, path string, body any) (int, map[string]any, []byte) {
		t.Helper()
		var raw []byte
		if body != nil {
			raw, _ = json.Marshal(body)
		}
		req := httptest.NewRequest(method, path, bytes.NewReader(raw))
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req.WithContext(auth.WithPrincipal(req.Context(), p)))
		var out map[string]any
		_ = json.Unmarshal(rec.Body.Bytes(), &out)
		return rec.Code, out, rec.Body.Bytes()
	}
	analyst := reviewUser(t, "security_analyst")
	manager := reviewUser(t, "security_manager")
	second := reviewUser(t, "independent_reviewer")
	repo := createRepo(t, "p5-"+uuid.NewString()[:6])

	// Critical decisions need an independent review and a final approval.
	_, st, _ := call(manager, "GET", "/api/v1/human-review/settings", nil)
	saved, _ := json.Marshal(st)
	t.Cleanup(func() {
		var orig map[string]any
		_ = json.Unmarshal(saved, &orig)
		call(manager, "PUT", "/api/v1/human-review/settings", orig)
	})
	st["required_fields"] = []string{}
	st["evidence_required_dispositions"] = []string{}
	st["evidence_required_severities"] = []string{}
	st["independent_review_severities"] = []string{"critical"}
	st["final_approval_severities"] = []string{"critical"}
	if code, out, _ := call(manager, "PUT", "/api/v1/human-review/settings", st); code != 200 || len(out["final_approval_severities"].([]any)) != 1 {
		t.Fatalf("settings: %d %v", code, out)
	}
	st["final_approval_severities"] = []string{"severe"}
	if code, _, _ := call(manager, "PUT", "/api/v1/human-review/settings", st); code != 400 {
		t.Errorf("unknown severity rejected: %d", code)
	}

	finding := insertFinding(t, repo, "critical", "")
	code, created, _ := call(manager, "POST", "/api/v1/human-reviews", map[string]any{"finding_ids": []string{finding.String()}, "reason": "phase 5"})
	if code != 201 {
		t.Fatalf("create review: %d %v", code, created)
	}
	var rid uuid.UUID
	_ = appPool.QueryRow(ctx, `SELECT id FROM human_reviews WHERE finding_id = $1`, finding).Scan(&rid)
	id := rid.String()
	if code, out, _ := call(manager, "POST", "/api/v1/human-reviews/"+id+"/assign", map[string]any{"reviewer_id": analyst.UserID}); code != 200 {
		t.Fatalf("assign: %d %v", code, out)
	}
	code, out, _ := call(analyst, "POST", "/api/v1/human-reviews/"+id+"/decision", map[string]any{"disposition": "false_positive",
		"reason": "The evaluated string is a constant defined two lines above."})
	if code != 200 || out["status"] != "awaiting_independent_review" {
		t.Fatalf("decision: %d %v", code, out)
	}
	code, out, _ = call(second, "POST", "/api/v1/human-reviews/"+id+"/independent-review", map[string]any{"outcome": "approved", "comments": "Agreed."})
	if code != 200 || out["status"] != "awaiting_independent_review" {
		t.Fatalf("level 1 approval leaves the review awaiting the final approval: %d %v", code, out)
	}
	_, md, _ := call(manager, "GET", "/api/v1/human-reviews/"+id, nil)
	if c := md["can"].(map[string]any); c["approve"] != true || c["final_approval"] != true {
		t.Errorf("the manager may give the final approval: %v", c)
	}
	_, sd, _ := call(second, "GET", "/api/v1/human-reviews/"+id, nil)
	if c := sd["can"].(map[string]any); c["approve"] != false {
		t.Errorf("the independent reviewer may not approve twice: %v", c)
	}
	if code, _, _ := call(second, "POST", "/api/v1/human-reviews/"+id+"/independent-review", map[string]any{"outcome": "approved", "comments": "Again."}); code != 403 {
		t.Errorf("the independent reviewer cannot also give the final approval: %d", code)
	}
	code, out, _ = call(manager, "POST", "/api/v1/human-reviews/"+id+"/independent-review", map[string]any{"outcome": "approved", "comments": "Final approval."})
	if code != 200 || out["status"] != "completed" || out["disposition"] != "false_positive" {
		t.Fatalf("final approval completes the review: %d %v", code, out)
	}
	var levels []int
	rows, _ := appPool.Query(ctx, `SELECT level FROM human_review_approvals WHERE review_id = $1 ORDER BY level`, rid)
	for rows.Next() {
		var l int
		_ = rows.Scan(&l)
		levels = append(levels, l)
	}
	rows.Close()
	if len(levels) != 2 || levels[0] != 1 || levels[1] != 2 {
		t.Errorf("approval levels recorded: %v", levels)
	}
	var fs string
	_ = appPool.QueryRow(ctx, `SELECT status FROM findings WHERE id = $1`, finding).Scan(&fs)
	if fs != "false_positive" {
		t.Errorf("finding: %s", fs)
	}

	// --- AI patch proposals: decided by a person, never applied ------------------
	patch := "--- a/app/x.py\n+++ b/app/x.py\n@@ -10 +10 @@\n-eval(q)\n+ast.literal_eval(q)\n"
	content, _ := json.Marshal(map[string]any{"summary": "Use literal_eval", "points": []string{}, "references": []string{}, "code": patch})
	recID := uuid.Must(uuid.NewV7())
	if _, err := appPool.Exec(ctx, `INSERT INTO human_review_recommendations (id, organization_id, review_id, kind, content, requested_by, patch_status)
		VALUES ($1, $2, $3, 'patch', $4, $5, 'proposed')`, recID, orgID, rid, content, analyst.UserID); err != nil {
		t.Fatal(err)
	}
	base := "/api/v1/human-reviews/" + id + "/ai/" + recID.String()
	if code, _, _ := call(analyst, "GET", base+"/patch", nil); code != 409 {
		t.Errorf("a proposed patch cannot be downloaded: %d", code)
	}
	if code, _, _ := call(analyst, "POST", base+"/patch-decision", map[string]any{"decision": "rejected"}); code != 422 {
		t.Errorf("rejection needs a note: %d", code)
	}
	if code, out, _ := call(analyst, "POST", base+"/patch-decision", map[string]any{"decision": "approved", "note": "Verified locally"}); code != 204 {
		t.Fatalf("approve patch: %d %v", code, out)
	}
	if code, _, _ := call(analyst, "POST", base+"/patch-decision", map[string]any{"decision": "rejected", "note": "changed my mind"}); code != 409 {
		t.Errorf("decided once: %d", code)
	}
	code, _, body := call(analyst, "GET", base+"/patch", nil)
	if code != 200 || string(body) != patch {
		t.Errorf("download: %d %q", code, body)
	}
	_, list, _ := call(analyst, "GET", "/api/v1/human-reviews/"+id+"/ai", nil)
	item := list["items"].([]any)[0].(map[string]any)
	if item["patch_status"] != "approved" || item["patch_decided_by"] == nil {
		t.Errorf("patch decision listed: %v", item)
	}
	var hist int
	_ = appPool.QueryRow(ctx, `SELECT count(*) FROM human_review_history WHERE review_id = $1 AND action = 'ai.patch_approved'`, rid).Scan(&hist)
	if hist != 1 {
		t.Errorf("patch decision in history: %d", hist)
	}
	// The AI kinds are offered.
	_, cat, _ := call(analyst, "GET", "/api/v1/human-review/catalog", nil)
	if b, _ := json.Marshal(cat); !strings.Contains(string(b), "duplicate_candidates") {
		t.Errorf("catalog lists the new AI kinds")
	}
}
