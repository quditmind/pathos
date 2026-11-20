//go:build integration

package integration

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"pathos/internal/ai"
	"pathos/internal/auth"
	"pathos/internal/authz"
	"pathos/internal/correlation"
	"pathos/internal/platform/crypto"
	"pathos/internal/secrets"
	"pathos/internal/threatmodel"
)

// aiEvidenceCallPaths names every AI call path of the backend; the unit
// test internal/ai/evidence_test.go fails when a path calling a model is
// missing here. Each one is exercised below with a stub provider and its
// evidence record is checked for completeness.
var aiEvidenceCallPaths = []string{
	"Service.review",             // automated / requested AI review
	"Service.SubmitInteractive",  // MCP review by a person's own assistant
	"Service.Assist",             // Human Eye assistance
	"Service.ProposeFix",         // verified AI fixes
	"Service.Troubleshoot",       // diagnostics
	"Service.Generate",           // analyst answers and report narratives
	"Service.SuggestThreats",     // threat-model suggestions
	"Service.ExplainCorrelation", // cross-phase correlation
	"Service.replayEvidence",     // Reproduce
}

// stubAI is a fake provider (never a real call). Answers follow the
// requested schema; a cloud stub varies its answer on each call (as a
// hosted model may), a self-hosted one is deterministic.
type stubAI struct {
	mu       sync.Mutex
	kind     string
	calls    []ai.Request
	n        int
	verdict  string
	exploit  string
	failNext error
}

type stubPool struct {
	mu    sync.Mutex
	kinds map[string]*stubAI
}

func (p *stubPool) get(kind string) *stubAI {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.kinds[kind] == nil {
		p.kinds[kind] = &stubAI{kind: kind, verdict: ai.FalsePositive, exploit: ai.NotExploitable}
	}
	return p.kinds[kind]
}

func (s *stubAI) Kind() string                           { return s.kind }
func (s *stubAI) Validate(context.Context, string) error { return nil }

func (s *stubAI) count() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.calls)
}

func evidenceJSON(user string) map[string]any {
	i := strings.Index(user, "<untrusted_evidence")
	j := strings.Index(user, "</untrusted_evidence")
	if i < 0 || j < 0 {
		return nil
	}
	body := user[i:j]
	body = body[strings.Index(body, "\n")+1:]
	var out map[string]any
	_ = json.Unmarshal([]byte(body), &out)
	return out
}

func (s *stubAI) Review(_ context.Context, req ai.Request) (ai.Response, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.calls = append(s.calls, req)
	s.n++
	if err := s.failNext; err != nil {
		s.failNext = nil
		return ai.Response{}, err
	}
	vary := ""
	if s.kind != ai.SelfHosted {
		vary = " (sample " + string(rune('A'+s.n%26)) + ")"
	}
	// The schema is a Go map on a first call and decoded JSON on a replay.
	var req0 []string
	switch v := req.Schema["required"].(type) {
	case []string:
		req0 = v
	case []any:
		for _, x := range v {
			req0 = append(req0, x.(string))
		}
	}
	has := func(k string) bool {
		for _, x := range req0 {
			if x == k {
				return true
			}
		}
		return false
	}
	var out any
	switch {
	case has("verdict"):
		out = map[string]any{"verdict": s.verdict, "confidence": 0.82, "suggested_severity": "low", "rationale": "The input is a constant" + vary + ".",
			"remediation": "", "evidence_cited": []string{"line 10: eval(x)", "x is assigned a literal"}}
	case has("diff"):
		out = map[string]any{"summary": "Use ast.literal_eval" + vary, "diff": "--- a/app/x.py\n+++ b/app/x.py\n@@ -10 +10 @@\n-eval(x)\n+ast.literal_eval(x)\n"}
	case has("points"):
		out = map[string]any{"summary": "Explanation" + vary, "points": []string{"Input reaches eval", "No validation"}, "references": []string{"CWE-95"}, "code": ""}
	case has("likely_cause"):
		out = map[string]any{"likely_cause": "The provider key was rotated" + vary, "probable_causes": []string{"rotation"}, "actions": []string{"Replace the key"}, "verify": []string{"Test"}}
	case has("answer"):
		out = map[string]any{"answer": "Two findings are critical" + vary, "cited_findings": []string{}, "follow_up_questions": []string{"Which repository?"}}
	case has("priority"):
		out = map[string]any{"priority": "low", "exploitability": s.exploit, "confidence": 0.7, "explanation": "No route reaches the code" + vary,
			"reasoning": []string{"No CodeGraph route calls the function", "Not exposed at runtime"}}
	case has("threats"):
		ev := evidenceJSON(req.User)
		var keys []string
		if els, ok := ev["elements"].([]any); ok {
			for _, e := range els {
				if k, ok := e.(map[string]any)["key"].(string); ok && len(keys) < 2 {
					keys = append(keys, k)
				}
			}
		}
		out = map[string]any{"threats": []map[string]any{
			{"title": "Session token replay against the API" + vary, "description": "Tokens are not bound to the client.", "category": "spoofing",
				"severity": "high", "confidence": 0.6, "element_keys": keys[:1], "mitigation": "Bind tokens to the client and expire them quickly.",
				"reasoning": []string{"The route " + keys[0] + " accepts bearer tokens"}},
			{"title": "Bulk export exhausts the database" + vary, "description": "Unbounded queries.", "category": "denial_of_service",
				"severity": "medium", "confidence": 0.4, "element_keys": keys, "mitigation": "Paginate and rate-limit the export.",
				"reasoning": []string{"The handler reads all rows"}},
			// Not on the diagram: dropped.
			{"title": "Invented element", "description": "x", "category": "tampering", "severity": "low", "confidence": 0.3,
				"element_keys": []string{"fn:does-not-exist"}, "mitigation": "m", "reasoning": []string{"r"}},
		}}
	default:
		return ai.Response{}, errors.New("stub: unknown schema")
	}
	b, _ := json.Marshal(out)
	return ai.Response{JSON: b, Model: map[bool]string{true: "qwen3-coder:30b", false: "claude-opus-5-5"}[s.kind == ai.SelfHosted],
		InputTokens: 500, OutputTokens: 80}, nil
}

// TestAIEvidence: record completeness for every AI call path, reproduce,
// retention, model per task (code never sent to a cloud model without
// permission), no silent suppression, and the threat suggestion flow.
func TestAIEvidence(t *testing.T) {
	quietNotifications(t)
	ctx := t.Context()
	kr, _ := crypto.NewKeyring(map[int][]byte{1: testKey})
	pool := &stubPool{kinds: map[string]*stubAI{}}
	gh := newGraphHarness(t)
	aiSvc := &ai.Service{DB: appPool, Authz: gh.svc.Authz, Secrets: &secrets.Store{Keys: kr}, Log: log, Principal: auth.PrincipalFrom,
		NewProvider: func(c ai.Config) (ai.Provider, error) { return pool.get(c.Kind), nil }}
	tm := &threatmodel.Service{DB: appPool, Authz: gh.svc.Authz, Log: log, Principal: auth.PrincipalFrom, AI: aiSvc}
	aiSvc.SubjectAccess = map[string]ai.SubjectAccess{"threat_model": tm.EvidenceAccess, "threat": tm.EvidenceAccess}
	aiSvc.SubjectReviewers = map[string]ai.SubjectReviewer{"threat_suggestion_item": tm.ReviewSuggestion}
	aiSvc.Register(gh.api)
	tm.Register(gh.api)
	gh.graph.OnSnapshotReady = tm.OnSnapshotReady
	(&correlation.Service{DB: appPool, Authz: gh.svc.Authz, Log: log, Principal: auth.PrincipalFrom, AI: aiSvc, ThreatAccess: tm.EvidenceAccess}).Register(gh.api)

	admin := principalWithRole(t, authz.RoleSuperAdmin)
	analyst, analyst2 := tmUser(t, "security_analyst"), tmUser(t, "security_analyst")
	manager := tmUser(t, "security_manager")
	viewer := tmUser(t, "viewer")

	// Existing default configuration (left by other tests): restored at
	// the end; this test's providers and configurations are archived.
	var prevDefault *uuid.UUID
	_ = appPool.QueryRow(ctx, `SELECT id FROM ai_configurations WHERE organization_id = $1 AND is_default AND archived_at IS NULL`, orgID).Scan(&prevDefault)
	var mine []uuid.UUID
	t.Cleanup(func() {
		c := context.Background()
		_, _ = appPool.Exec(c, `DELETE FROM ai_task_assignments WHERE organization_id = $1`, orgID)
		_, _ = appPool.Exec(c, `DELETE FROM ai_evidence_settings WHERE organization_id = $1`, orgID)
		_, _ = appPool.Exec(c, `UPDATE ai_configurations SET archived_at = now(), is_default = false WHERE id = ANY($1)`, mine)
		_, _ = appPool.Exec(c, `UPDATE ai_providers SET archived_at = now() WHERE organization_id = $1 AND name LIKE 'ev-%'`, orgID)
		if prevDefault != nil {
			_, _ = appPool.Exec(c, `UPDATE ai_configurations SET is_default = true WHERE id = $1`, *prevDefault)
		}
		setFlag(t, "ai_intelligence", false)
	})

	// Providers: a cloud model and a self-hosted (local) model.
	cloudProv, localProv := uuid.Must(uuid.NewV7()), uuid.Must(uuid.NewV7())
	sec, err := (&secrets.Store{Keys: kr}).Create(ctx, appPool, orgID, secrets.KindAI, "ev-cloud", []byte("sk-ant-test"), nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := appPool.Exec(ctx, `INSERT INTO ai_providers (id, organization_id, name, kind, secret_id, status) VALUES ($1, $2, 'ev-cloud', 'anthropic', $3, 'ok'),
		($4, $2, 'ev-local', 'self_hosted', NULL, 'ok')`, cloudProv, orgID, sec, localProv); err != nil {
		t.Fatal(err)
	}
	if _, err := appPool.Exec(ctx, `UPDATE ai_providers SET base_url = 'http://ollama.internal:11434/v1' WHERE id = $1`, localProv); err != nil {
		t.Fatal(err)
	}
	mkConfig := func(name string, prov uuid.UUID, model string, sendCode bool, policy string) uuid.UUID {
		code, b := gh.user(admin, "POST", "/api/v1/ai/configurations", map[string]any{"name": name, "provider_id": prov, "model": model, "effort": "low",
			"send_code_context": sendCode, "approval_policy": policy, "categories": []string{"sast", "sca"}, "min_severity": "low", "is_default": false})
		if code != 201 {
			t.Fatalf("configuration %s: %d %v", name, code, b)
		}
		id := uuid.MustParse(b["id"].(string))
		mine = append(mine, id)
		return id
	}
	// The cloud configuration is the default and may NOT receive code; the
	// AI review policy "never" would auto-apply verdicts.
	cloudCfg := mkConfig("ev-cloud-nocode", cloudProv, "claude-opus-5-5", false, "never")
	localCfg := mkConfig("ev-local", localProv, "qwen3-coder:30b", true, "never")
	if _, err := appPool.Exec(ctx, `UPDATE ai_configurations SET is_default = (id = $2) WHERE organization_id = $1 AND archived_at IS NULL`, orgID, cloudCfg); err != nil {
		t.Fatal(err)
	}
	cloud, local := pool.get(ai.Anthropic), pool.get(ai.SelfHosted)

	repo := createRepo(t, "aiev-"+uuid.NewString()[:6])
	appID := uuid.Must(uuid.NewV7())
	if _, err := appPool.Exec(ctx, `INSERT INTO applications (id, organization_id, name, criticality) VALUES ($1, $2, $3, 'high')`,
		appID, orgID, "AI evidence app "+uuid.NewString()[:6]); err != nil {
		t.Fatal(err)
	}
	if _, err := appPool.Exec(ctx, `UPDATE repositories SET application_id = $2 WHERE id = $1`, repo, appID); err != nil {
		t.Fatal(err)
	}
	newFinding := func(sev string) uuid.UUID {
		id := uuid.Must(uuid.NewV7())
		if _, err := appPool.Exec(ctx, `INSERT INTO findings (id, organization_id, repository_id, fingerprint, category, scanner_keys, rule_id,
			title, description, severity, file_path, start_line, snippet, snippet_start_line, package_name)
			VALUES ($1, $2, $3, $4, 'sast', '{opengrep}', 'pathos.python.eval-injection', 'eval() on input', 'eval of user data', $5,
			'internal/store/store.go', 38, 'x = request.args[\"q\"]\neval(x)\n', 37, '')`, id, orgID, repo, uuid.NewString(), sev); err != nil {
			t.Fatal(err)
		}
		return id
	}

	// record loads a record through the API (with its prompt and
	// response) and checks it is complete.
	record := func(p *authz.Principal, id uuid.UUID, task, op string) map[string]any {
		t.Helper()
		code, b := gh.user(p, "GET", "/api/v1/ai/evidence/"+id.String()+"?include=prompt,response", nil)
		if code != 200 {
			t.Fatalf("record %s: %d %v", op, code, b)
		}
		r := b["record"].(map[string]any)
		missing := []string{}
		for _, k := range []string{"task", "operation", "subject_kind", "provider", "provider_location", "model", "model_reported", "prompt_template",
			"input_sha256", "response_sha256", "conclusion", "verdict", "created_at", "config_version_id"} {
			if v, ok := r[k]; !ok || v == nil || v == "" {
				missing = append(missing, k)
			}
		}
		if len(missing) > 0 || r["task"] != task || r["operation"] != op || r["status"] != "succeeded" || r["label"] != "ai_inferred" {
			t.Errorf("record %s incomplete (missing %v): %v", op, missing, r)
		}
		if steps, _ := r["steps"].([]any); len(steps) == 0 {
			t.Errorf("record %s has no reasoning steps", op)
		}
		params, _ := r["parameters"].(map[string]any)
		if params["temperature"] == nil || params["effort"] == nil {
			t.Errorf("record %s parameters: %v", op, params)
		}
		pr, _ := b["prompt"].(map[string]any)
		if pr == nil || !strings.Contains(pr["user"].(string), "untrusted_evidence") || pr["system"] == "" || b["response"] == "" {
			t.Errorf("record %s: prompt and response must be stored (redacted): %v", op, b)
		}
		return r
	}
	lastRecord := func(op string) uuid.UUID {
		t.Helper()
		var id uuid.UUID
		if err := appPool.QueryRow(ctx, `SELECT id FROM ai_evidence_records WHERE organization_id = $1 AND operation = $2 ORDER BY created_at DESC LIMIT 1`,
			orgID, op).Scan(&id); err != nil {
			t.Fatalf("no record for %s: %v", op, err)
		}
		return id
	}

	// --- flag off: the API is absent, but records are still written ------------
	setFlag(t, "ai_intelligence", false)
	if code, b := gh.user(admin, "GET", "/api/v1/ai/evidence", nil); code != 404 || errCode(b) != "PTH-PLAT-1007" {
		t.Fatalf("flag off: %d %v", code, b)
	}
	f0 := newFinding("high")
	if err := ai.Enqueue(ctx, appPool, orgID, f0, &analyst.UserID); err != nil {
		t.Fatal(err)
	}
	if n, err := aiSvc.ProcessOne(ctx); n != 1 || err != nil {
		t.Fatalf("process: %d %v", n, err)
	}
	var loc string
	if err := appPool.QueryRow(ctx, `SELECT provider_location FROM ai_evidence_records WHERE finding_id = $1`, f0).Scan(&loc); err != nil || loc != ai.LocationCloud {
		t.Fatalf("flag off: the default configuration answers and the call is recorded: %q %v", loc, err)
	}
	setFlag(t, "ai_intelligence", true)

	// --- model per task: code-bearing tasks default to the local model -----------
	code, b := gh.user(admin, "GET", "/api/v1/ai/task-assignments", nil)
	if code != 200 {
		t.Fatalf("task assignments: %d %v", code, b)
	}
	eff := map[string]map[string]any{}
	for _, it := range tmItems(t, b) {
		e, _ := it["effective"].(map[string]any)
		eff[it["task"].(string)] = e
	}
	if eff["finding_validation"]["location"] != "local" || eff["fix_proposal"]["source"] != "local_default" || eff["analyst"]["location"] != "cloud" {
		t.Fatalf("defaults: code-bearing tasks on the local model, analyst on the default: %v", eff)
	}
	if code, _ := gh.user(analyst, "GET", "/api/v1/ai/task-assignments", nil); code != 403 {
		t.Errorf("analyst lacks ai.configure: %d", code)
	}

	// 1. Service.review: automated review on the local model (code allowed).
	f1 := newFinding("high")
	if err := ai.Enqueue(ctx, appPool, orgID, f1, &analyst.UserID); err != nil {
		t.Fatal(err)
	}
	if n, err := aiSvc.ProcessOne(ctx); n != 1 || err != nil {
		t.Fatalf("process: %d %v", n, err)
	}
	if last := local.calls[len(local.calls)-1]; !strings.Contains(last.User, "eval(x)") || last.Temperature == nil || *last.Temperature != 0 || last.Seed == nil {
		t.Errorf("local review: code allowed and deterministic parameters: %+v", last)
	}
	revRec := lastRecord("ai_review")
	r := record(analyst, revRec, "finding_validation", "ai_review")
	if r["provider_location"] != "local" || r["deterministic"] != true || r["sent_code"] != true || r["review_decision"] != "pending" ||
		r["verdict"] != "false_positive" || r["proposes_suppression"] != true {
		t.Errorf("review record: %v", r)
	}
	if rel, _ := r["related"].(map[string]any); rel["findings"] == nil {
		t.Errorf("review record must reference its finding: %v", r["related"])
	}
	// No silent suppression: policy "never", a false positive on a High
	// finding is only proposed.
	var st, aiSt string
	_ = appPool.QueryRow(ctx, `SELECT f.status, ar.status FROM findings f JOIN ai_reviews ar ON ar.finding_id = f.id WHERE f.id = $1`, f1).Scan(&st, &aiSt)
	if st != "open" || aiSt != "pending_approval" {
		t.Fatalf("AI false positive must not close the finding: finding %s, review %s", st, aiSt)
	}
	// A person decides through the evidence record (four-eyes as for the
	// review: the analyst who did not submit it).
	if code, b := gh.user(viewer, "POST", "/api/v1/ai/evidence/"+revRec.String()+"/review", map[string]any{"decision": "accepted"}); code != 404 && code != 403 {
		t.Errorf("viewer cannot decide: %d %v", code, b)
	}
	if code, b := gh.user(analyst2, "POST", "/api/v1/ai/evidence/"+revRec.String()+"/review", map[string]any{"decision": "accepted", "note": "checked: constant"}); code != 200 ||
		b["review_decision"] != "accepted" || b["confirmed"] != true || b["reviewer_name"] == nil {
		t.Fatalf("accept: %d %v", code, b)
	}
	_ = appPool.QueryRow(ctx, `SELECT f.status, ar.status FROM findings f JOIN ai_reviews ar ON ar.finding_id = f.id WHERE f.id = $1`, f1).Scan(&st, &aiSt)
	if st != "false_positive" || aiSt != "applied" {
		t.Errorf("after the person's acceptance: finding %s, review %s", st, aiSt)
	}
	if code, b := gh.user(analyst2, "POST", "/api/v1/ai/evidence/"+revRec.String()+"/review", map[string]any{"decision": "rejected"}); code != 409 || errCode(b) != "PTH-AI-1103" {
		t.Errorf("second decision: %d %v", code, b)
	}
	// Records are immutable except the review.
	if _, err := appPool.Exec(ctx, `UPDATE ai_evidence_records SET conclusion = 'tampered' WHERE id = $1`, revRec); err == nil {
		t.Error("a record's conclusion must not change")
	}

	// 2. Service.SubmitInteractive (MCP): recorded, not replayable.
	f2 := newFinding("medium")
	if _, err := aiSvc.SubmitInteractive(ctx, analyst, f2, ai.Output{Verdict: ai.TruePositive, Confidence: 0.9, SuggestedSeverity: "medium",
		Rationale: "Reachable from the route.", Evidence: []string{"line 38"}}); err != nil {
		t.Fatal(err)
	}
	mcpRec := lastRecord("interactive_mcp")
	code, b = gh.user(analyst, "GET", "/api/v1/ai/evidence/"+mcpRec.String(), nil)
	if rr := b["record"].(map[string]any); code != 200 || rr["provider_location"] != "user" || rr["replayable"] != false || rr["verdict"] != "true_positive" {
		t.Errorf("MCP record: %d %v", code, b)
	}
	if code, b := gh.user(analyst, "POST", "/api/v1/ai/evidence/"+mcpRec.String()+"/replay", nil); code != 409 || errCode(b) != "PTH-AI-1204" {
		t.Errorf("MCP replay: %d %v", code, b)
	}

	// 3. Service.Assist (Human Eye), local model.
	fid3 := newFinding("high")
	actx := ai.WithSubject(ctx, ai.Subject{Kind: "finding", ID: &fid3, RequestedBy: &analyst.UserID})
	ev, _, _ := ai.LoadEvidence(ctx, appPool, orgID, fid3, true)
	if res, err := aiSvc.Assist(actx, orgID, "explanation", ai.AssistInput{Evidence: ev}, true); err != nil || res.EvidenceID == uuid.Nil {
		t.Fatalf("assist: %v", err)
	}
	record(analyst, lastRecord("assist:explanation"), "finding_validation", "assist:explanation")

	// 4. Service.ProposeFix, local model.
	fctx := ai.WithSubject(ctx, ai.Subject{Kind: "finding", ID: &fid3, RequestedBy: &analyst.UserID})
	fixIn := ai.FixInput{Finding: ai.FixFinding{Scanner: "opengrep", Category: "sast", Title: "eval", FilePath: "app/x.py", StartLine: 10},
		File: ai.FixRegion{Path: "app/x.py", FirstLine: 1, LastLine: 12, TotalLines: 12, Code: strings.Repeat("pass\n", 9) + "eval(x)\n"}}
	if res, err := aiSvc.ProposeFix(fctx, orgID, fixIn); err != nil || res.EvidenceID == uuid.Nil {
		t.Fatalf("fix: %v", err)
	}
	record(analyst, lastRecord("fix_proposal"), "fix_proposal", "fix_proposal")

	// 5. Service.Troubleshoot (troubleshooting task: local model).
	tctx := ai.WithSubject(ctx, ai.Subject{Kind: "error", RequestedBy: &analyst.UserID})
	if res, err := aiSvc.Troubleshoot(tctx, orgID, ai.TroubleshootInput{Code: "PTH-AI-1003", Title: "key", Description: "d", Actions: []string{"a"}}); err != nil ||
		res.EvidenceID == uuid.Nil {
		t.Fatalf("troubleshoot: %v", err)
	}
	tr := record(analyst, lastRecord("troubleshoot"), "troubleshooting", "troubleshoot")
	// Other people see a troubleshooting record only as AI administrators.
	if code, _ := gh.user(analyst2, "GET", "/api/v1/ai/evidence/"+tr["id"].(string), nil); code != 404 {
		t.Errorf("another person's troubleshooting record: %d", code)
	}

	// 6. Service.Generate (analyst task: the default, cloud, model; no code).
	gctx := ai.WithSubject(ctx, ai.Subject{Kind: "conversation", RequestedBy: &analyst.UserID})
	if res, err := aiSvc.Generate(gctx, orgID, ai.TaskAnalyst, "system", "Answer.", map[string]any{"question": "q"}, map[string]any{"type": "object",
		"required": []string{"answer", "cited_findings", "follow_up_questions"}}, 500); err != nil || res.EvidenceID == uuid.Nil {
		t.Fatalf("generate: %v", err)
	}
	ga := record(analyst, lastRecord("analyst_answer"), "analyst", "analyst_answer")
	if ga["provider_location"] != "cloud" || ga["deterministic"] != false || !strings.Contains(ga["determinism_note"].(string), "replay") {
		t.Errorf("analyst record on the cloud model: %v", ga)
	}

	// --- code never goes to a cloud model without permission ----------------------
	code, b = gh.user(admin, "PUT", "/api/v1/ai/task-assignments", map[string]any{"assignments": map[string]any{"fix_proposal": cloudCfg, "finding_validation": cloudCfg}})
	if code != 200 {
		t.Fatalf("assign: %d %v", code, b)
	}
	for _, it := range tmItems(t, b) {
		if it["task"] == "fix_proposal" && !strings.Contains(it["warning"].(string), "Cloud model without permission") {
			t.Errorf("assignment warning: %v", it)
		}
	}
	before := cloud.count()
	if _, err := aiSvc.ProposeFix(fctx, orgID, fixIn); !errors.Is(err, ai.ErrCodeNotAllowed) {
		t.Fatalf("a fix on a cloud model without code permission must be refused: %v", err)
	}
	if cloud.count() != before {
		t.Fatal("the cloud model must not have been called")
	}
	var refusedStatus, refusedCode string
	_ = appPool.QueryRow(ctx, `SELECT status, error_code FROM ai_evidence_records WHERE operation = 'fix_proposal' ORDER BY created_at DESC LIMIT 1`).Scan(&refusedStatus, &refusedCode)
	if refusedStatus != "disabled" || refusedCode != "PTH-AI-1101" {
		t.Errorf("the refusal is recorded: %s %s", refusedStatus, refusedCode)
	}
	// Triage on the cloud model: the code is left out.
	f7 := newFinding("medium")
	if err := ai.Enqueue(ctx, appPool, orgID, f7, &analyst.UserID); err != nil {
		t.Fatal(err)
	}
	if n, err := aiSvc.ProcessOne(ctx); n != 1 || err != nil {
		t.Fatalf("process: %d %v", n, err)
	}
	if last := cloud.calls[len(cloud.calls)-1]; strings.Contains(last.User, "eval(x)") || strings.Contains(last.User, "request.args") {
		t.Fatalf("code sent to a cloud model without permission: %s", last.User)
	}
	var sentCode bool
	_ = appPool.QueryRow(ctx, `SELECT sent_code FROM ai_evidence_records WHERE finding_id = $1`, f7).Scan(&sentCode)
	if sentCode {
		t.Error("record must say no code was sent")
	}
	if code, b := gh.user(admin, "PUT", "/api/v1/ai/task-assignments", map[string]any{"assignments": map[string]any{"fix_proposal": nil, "finding_validation": localCfg,
		"nonsense": localCfg}}); code != 422 || errCode(b) != "PTH-AI-1102" {
		t.Errorf("unknown task: %d %v", code, b)
	}
	if code, _ := gh.user(admin, "PUT", "/api/v1/ai/task-assignments", map[string]any{"assignments": map[string]any{"fix_proposal": nil, "finding_validation": nil}}); code != 200 {
		t.Errorf("clear assignments: %d", code)
	}

	// --- 7. Service.ExplainCorrelation: deterministic join, then a proposal -----
	setFlag(t, "codegraph", true)
	setFlag(t, "threat_models", true)
	t.Cleanup(func() { setFlag(t, "codegraph", false); setFlag(t, "threat_models", false) })
	_, reg := gh.worker(bootstrap, "POST", "/internal/worker/v1/register", map[string]any{"name": "graph-aiev-" + uuid.NewString()[:6], "family": "graph",
		"scanners": map[string]string{"pathos-graph": "test"}})
	gh.runGraphBuild(admin, appID, repo, reg["token"].(string), strings.Repeat("e", 40), graphFixture(t, "fixture-graph.json"))
	fc := newFinding("high")
	code, b = gh.user(analyst, "GET", "/api/v1/findings/"+fc.String()+"/correlation", nil)
	if code != 200 || b["deterministic"] != true {
		t.Fatalf("correlation: %d %v", code, b)
	}
	cg, _ := b["codegraph"].(map[string]any)
	if nodes, _ := cg["nodes"].([]any); len(nodes) == 0 || nodes[0].(map[string]any)["evidence"] != "verified" {
		t.Errorf("the finding at internal/store/store.go:38 joins CodeGraph nodes: %v", cg)
	}
	before = local.count()
	code, b = gh.user(analyst, "POST", "/api/v1/findings/"+fc.String()+"/correlation/explain", nil)
	if code != 200 || b["label"] != "ai_inferred" || b["proposes_suppression"] != true || b["review_decision"] != "pending" {
		t.Fatalf("explain: %d %v", code, b)
	}
	if local.count() != before+1 {
		t.Error("correlation is code-bearing: the local model answers")
	}
	corrRec := uuid.MustParse(b["evidence_record_id"].(string))
	cr := record(analyst, corrRec, "correlation", "correlation_explain")
	if rel, _ := cr["related"].(map[string]any); rel["codegraph_nodes"] == nil {
		t.Errorf("correlation record must reference its CodeGraph nodes: %v", cr["related"])
	}
	// "Not exploitable" never changes the finding, even once a person
	// accepts the explanation: the status is changed in triage.
	if code, _ := gh.user(analyst2, "POST", "/api/v1/ai/evidence/"+corrRec.String()+"/review", map[string]any{"decision": "accepted"}); code != 200 {
		t.Errorf("accept explanation: %d", code)
	}
	_ = appPool.QueryRow(ctx, `SELECT status FROM findings WHERE id = $1`, fc).Scan(&st)
	if st != "open" {
		t.Errorf("an AI not-exploitable conclusion must not close the finding: %s", st)
	}

	// --- 8. Service.SuggestThreats: AI-inferred threats in the draft -------------
	code, b = gh.user(manager, "POST", "/api/v1/threat-models", map[string]any{"application_id": appID, "title": "AI evidence model", "generate": true})
	if code != 201 {
		t.Fatalf("threat model: %d %v", code, b)
	}
	modelID := b["model"].(map[string]any)["id"].(string)
	if code, _ := gh.user(viewer, "POST", "/api/v1/threat-models/"+modelID+"/suggest", map[string]any{}); code != 403 && code != 404 {
		t.Errorf("viewer suggest: %d", code)
	}
	code, b = gh.user(analyst, "POST", "/api/v1/threat-models/"+modelID+"/suggest", map[string]any{"max_threats": 5})
	if code != 200 {
		t.Fatalf("suggest: %d %v", code, b)
	}
	sugg := tmItems(t, b)
	if len(sugg) != 2 || b["dropped"].(float64) != 1 {
		t.Fatalf("two suggestions on the diagram, one dropped: %d %v", len(sugg), b)
	}
	for _, th := range sugg {
		if th["method"] != "ai" || th["evidence_type"] != "ai_inferred" || th["label"] != "AI-inferred" || th["ai_evidence_id"] == nil ||
			th["ai_review"] != "pending" || len(th["elements"].([]any)) == 0 {
			t.Errorf("suggested threat: %v", th)
		}
	}
	callRec := uuid.MustParse(b["evidence_record_id"].(string))
	record(analyst, callRec, "threat_suggestion", "threat_suggestion")
	item := uuid.MustParse(sugg[0]["ai_evidence_id"].(string))
	code, b = gh.user(analyst, "GET", "/api/v1/ai/evidence/"+item.String()+"?include=prompt", nil)
	if ir := b["record"].(map[string]any); code != 200 || ir["parent_id"] != callRec.String() || ir["confidence"] == nil || len(ir["steps"].([]any)) == 0 ||
		b["prompt"] == nil {
		t.Errorf("suggestion item record: %d %v", code, b)
	}
	code, b = gh.user(analyst, "GET", "/api/v1/ai/evidence?threat_id="+sugg[0]["id"].(string), nil)
	if code != 200 || len(tmItems(t, b)) != 2 {
		t.Errorf("a threat lists its item and call records: %d %v", code, b)
	}
	// Submission waits for a person's decision on every suggestion.
	code, b = gh.user(manager, "POST", "/api/v1/threat-models/"+modelID+"/submit", map[string]any{})
	if code != 422 || errCode(b) != "PTH-AI-1302" {
		t.Errorf("submit with pending suggestions: %d %v", code, b)
	}
	if code, b := gh.user(analyst, "POST", "/api/v1/ai/evidence/"+item.String()+"/review", map[string]any{"decision": "accepted", "note": "real risk"}); code != 200 ||
		b["review_decision"] != "accepted" {
		t.Fatalf("accept suggestion: %d %v", code, b)
	}
	reject := uuid.MustParse(sugg[1]["ai_evidence_id"].(string))
	if code, b := gh.user(analyst, "POST", "/api/v1/ai/evidence/"+reject.String()+"/review", map[string]any{"decision": "rejected", "note": "not applicable"}); code != 200 {
		t.Fatalf("reject suggestion: %d %v", code, b)
	}
	var left int
	_ = appPool.QueryRow(ctx, `SELECT count(*) FROM threats WHERE threat_model_id = $1 AND method = 'ai'`, modelID).Scan(&left)
	if left != 1 {
		t.Errorf("the rejected suggestion is removed, the accepted one stays: %d", left)
	}
	code, b = gh.user(manager, "GET", "/api/v1/threat-models/"+modelID, nil)
	if counts := b["model"].(map[string]any)["counts"].(map[string]any); code != 200 || counts["ai_pending"].(float64) != 0 {
		t.Errorf("no pending suggestion left: %v", b)
	}
	// The AI path still needs its record (M5 constraint).
	if _, err := appPool.Exec(ctx, `INSERT INTO threats (id, organization_id, threat_model_id, title, category, method, evidence_type, severity, confidence)
		VALUES ($1, $2, $3, 'x', 'spoofing', 'ai', 'ai_inferred', 'low', 0.5)`, uuid.Must(uuid.NewV7()), orgID, modelID); err == nil {
		t.Error("an AI-inferred threat without an evidence record must be refused")
	}

	// --- 9. Reproduce ----------------------------------------------------------------
	// A local, deterministic record: same answer.
	code, b = gh.user(analyst, "POST", "/api/v1/ai/evidence/"+corrRec.String()+"/replay", nil)
	if code != 201 || b["comparison"] == nil {
		t.Fatalf("replay local: %d %v", code, b)
	}
	cmp := b["comparison"].(map[string]any)
	if cmp["same_conclusion"] != true || cmp["identical_response"] != true || cmp["deterministic"] != true {
		t.Errorf("local replay: %v", cmp)
	}
	rep := b["record"].(map[string]any)
	if rep["replay_of"] != corrRec.String() || rep["operation"] != "replay" || rep["review_decision"] != "not_required" {
		t.Errorf("replay record: %v", rep)
	}
	record(analyst, uuid.MustParse(rep["id"].(string)), "correlation", "replay")
	_ = appPool.QueryRow(ctx, `SELECT status FROM findings WHERE id = $1`, fc).Scan(&st)
	if st != "open" {
		t.Error("a replay never changes the subject")
	}
	// A hosted model: the answer differs and the record says why.
	code, b = gh.user(analyst, "POST", "/api/v1/ai/evidence/"+ga["id"].(string)+"/replay", nil)
	if code != 201 || b["comparison"] == nil {
		t.Fatalf("replay cloud: %d %v", code, b)
	}
	cmp = b["comparison"].(map[string]any)
	if cmp["same_conclusion"] != false || cmp["identical_response"] != false || cmp["deterministic"] != false ||
		!strings.Contains(cmp["determinism_note"].(string), "Hosted model") {
		t.Errorf("cloud replay: %v", cmp)
	}

	// --- list, filters, access -----------------------------------------------------
	code, b = gh.user(viewer, "GET", "/api/v1/ai/evidence?finding_id="+f1.String(), nil)
	if code != 200 || len(tmItems(t, b)) != 1 || tmItems(t, b)[0]["can_review"] != false {
		t.Errorf("viewer reads a finding's records but cannot review: %d %v", code, b)
	}
	if code, b := gh.user(viewer, "GET", "/api/v1/ai/evidence/"+revRec.String()+"/replay", nil); code != 405 && code != 404 {
		t.Errorf("replay is POST: %d %v", code, b)
	}
	if code, _ := gh.user(viewer, "POST", "/api/v1/ai/evidence/"+revRec.String()+"/replay", nil); code != 404 && code != 403 {
		t.Errorf("viewer cannot replay: %d", code)
	}
	code, b = gh.user(admin, "GET", "/api/v1/ai/evidence?task=troubleshooting&limit=1", nil)
	if code != 200 || len(tmItems(t, b)) != 1 {
		t.Errorf("admin sees troubleshooting records: %d %v", code, b)
	}
	if code, _ := gh.user(admin, "GET", "/api/v1/ai/evidence?task=nope", nil); code != 400 {
		t.Errorf("bad filter: %d", code)
	}

	// --- 10. Retention ---------------------------------------------------------------
	if code, b := gh.user(admin, "PUT", "/api/v1/ai/evidence-settings", map[string]any{"retention_days": 0}); code != 422 || errCode(b) != "PTH-AI-1102" {
		t.Errorf("retention 0: %d %v", code, b)
	}
	if code, b := gh.user(admin, "PUT", "/api/v1/ai/evidence-settings", map[string]any{"retention_days": 30}); code != 200 || b["retention_days"].(float64) != 30 {
		t.Fatalf("retention: %d %v", code, b)
	}
	// Age the correlation record past 30 days (the trigger forbids it to
	// the application; the owner bypasses it for the test).
	if err := pgx.BeginFunc(ctx, ownerPool, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `ALTER TABLE ai_evidence_records DISABLE TRIGGER ai_evidence_immutable`); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `UPDATE ai_evidence_records SET created_at = now() - interval '31 days' WHERE id = $1`, corrRec); err != nil {
			return err
		}
		_, err := tx.Exec(ctx, `ALTER TABLE ai_evidence_records ENABLE TRIGGER ai_evidence_immutable`)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if n, err := ai.Retain(ctx, appPool); err != nil || n < 1 {
		t.Fatalf("retention purged %d: %v", n, err)
	}
	code, b = gh.user(analyst, "GET", "/api/v1/ai/evidence/"+corrRec.String()+"?include=prompt,response", nil)
	if rr := b["record"].(map[string]any); code != 200 || rr["payload_purged_at"] == nil || rr["replayable"] != false || b["prompt"] != nil ||
		rr["conclusion"] == "" || rr["input_sha256"] == "" {
		t.Errorf("purged record keeps its hashes and conclusion, not its prompt: %v", b)
	}
	if code, b := gh.user(analyst, "POST", "/api/v1/ai/evidence/"+corrRec.String()+"/replay", nil); code != 409 || errCode(b) != "PTH-AI-1202" {
		t.Errorf("replay after retention: %d %v", code, b)
	}
	// Prompt storage off: new records keep hashes only.
	if code, _ := gh.user(admin, "PUT", "/api/v1/ai/evidence-settings", map[string]any{"retention_days": 30, "store_payloads": false}); code != 200 {
		t.Fatal("store_payloads off")
	}
	if _, err := aiSvc.Troubleshoot(tctx, orgID, ai.TroubleshootInput{Code: "PTH-AI-1004", Actions: []string{"a"}}); err != nil {
		t.Fatal(err)
	}
	var hasPayload bool
	_ = appPool.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM ai_evidence_payloads WHERE record_id = $1)`, lastRecord("troubleshoot")).Scan(&hasPayload)
	if hasPayload {
		t.Error("prompt storage off: no payload")
	}
	// Deleted with the finding.
	if _, err := ownerPool.Exec(ctx, `DELETE FROM findings WHERE id = $1`, f2); err != nil {
		t.Fatal(err)
	}
	var gone bool
	_ = appPool.QueryRow(ctx, `SELECT NOT EXISTS (SELECT 1 FROM ai_evidence_records WHERE id = $1)`, mcpRec).Scan(&gone)
	if !gone {
		t.Error("a finding's records are deleted with it")
	}

	// --- a failed call is recorded too -------------------------------------------------
	cloud.failNext = ai.ErrRateLimited
	if _, err := aiSvc.Generate(gctx, orgID, ai.TaskAnalyst, "system", "Answer.", map[string]any{"q": 1}, map[string]any{"required": []string{"answer"}}, 100); !errors.Is(err, ai.ErrRateLimited) {
		t.Fatalf("failure: %v", err)
	}
	var fStatus, fCode string
	_ = appPool.QueryRow(ctx, `SELECT status, error_code FROM ai_evidence_records WHERE operation = 'analyst_answer' ORDER BY created_at DESC LIMIT 1`).Scan(&fStatus, &fCode)
	if fStatus != "failed" || fCode != "PTH-AI-1004" {
		t.Errorf("failed call record: %s %s", fStatus, fCode)
	}
	// Master key rotation rewraps the payloads too.
	kr2, _ := crypto.NewKeyring(map[int][]byte{1: testKey, 2: []byte(strings.Repeat("k", 32))})
	var rewrapped int
	if err := pgx.BeginFunc(ctx, appPool, func(tx pgx.Tx) error {
		var err error
		rewrapped, err = ai.RewrapPayloads(ctx, tx, kr2)
		return err
	}); err != nil || rewrapped == 0 {
		t.Fatalf("rewrap: %d %v", rewrapped, err)
	}
	aiSvc.Secrets = &secrets.Store{Keys: kr2}
	code, b = gh.user(analyst, "GET", "/api/v1/ai/evidence/"+revRec.String()+"?include=prompt", nil)
	if code != 200 || b["prompt"] == nil {
		t.Errorf("payload readable after rotation: %d %v", code, b)
	}
	t.Logf("AI evidence call paths exercised: %v", aiEvidenceCallPaths)
}
