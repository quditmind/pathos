//go:build integration

package integration

import (
	"encoding/json"
	"fmt"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/google/uuid"

	"pathos/internal/auth"
	"pathos/internal/authz"
	"pathos/internal/identity"
	"pathos/internal/threatmodel"
)

// tmUser creates a real user (threat models reference users) with a
// system role organization-wide.
func tmUser(t *testing.T, role string) *authz.Principal {
	t.Helper()
	u, err := identity.CreateUser(t.Context(), appPool, identity.User{OrganizationID: orgID, Email: "tm-" + role + "-" + uuid.NewString()[:6] + "@tm.test",
		Status: identity.StatusActive})
	if err != nil {
		t.Fatal(err)
	}
	p := principalWithRole(t, role)
	p.UserID, p.Email = u.ID, u.Email
	return p
}

// rawBody calls the user API and returns the status, headers and raw body.
func (h *graphHarness) rawBody(p *authz.Principal, method, path string) (int, string, []byte) {
	h.t.Helper()
	req := httptest.NewRequest(method, path, nil)
	req = req.WithContext(auth.WithPrincipal(req.Context(), p))
	rec := httptest.NewRecorder()
	h.api.ServeHTTP(rec, req)
	return rec.Code, rec.Header().Get("Content-Disposition"), rec.Body.Bytes()
}

func tmItems(t *testing.T, b map[string]any) []map[string]any {
	t.Helper()
	raw, _ := b["items"].([]any)
	out := make([]map[string]any, 0, len(raw))
	for _, x := range raw {
		out = append(out, x.(map[string]any))
	}
	return out
}

// TestThreatModels builds a threat model from a fixture CodeGraph snapshot
// (the real worker-graph output on the fixture repository) and checks the
// M5 done-when on every threat, editing with reasons, the approval rules,
// regeneration keeping human edits, the architecture feedback loop, and
// import and export (Threat Dragon round trip).
func TestThreatModels(t *testing.T) {
	quietNotifications(t)
	h := newGraphHarness(t)
	ctx := t.Context()
	tm := &threatmodel.Service{DB: appPool, Authz: h.svc.Authz, Log: log, Principal: auth.PrincipalFrom}
	tm.Register(h.api)
	h.graph.OnSnapshotReady = tm.OnSnapshotReady

	author := tmUser(t, "appsec_engineer")
	approver := tmUser(t, "security_manager")
	viewer := tmUser(t, "viewer")
	admin := principalWithRole(t, authz.RoleSuperAdmin)
	repo := createRepo(t, "tm-"+uuid.NewString()[:6])
	appID := uuid.Must(uuid.NewV7())
	if _, err := appPool.Exec(ctx, `INSERT INTO applications (id, organization_id, name, criticality) VALUES ($1, $2, $3, 'high')`,
		appID, orgID, "Threat model app "+uuid.NewString()[:6]); err != nil {
		t.Fatal(err)
	}
	if _, err := appPool.Exec(ctx, `UPDATE repositories SET application_id = $2, public_exposure = 'yes' WHERE id = $1`, repo, appID); err != nil {
		t.Fatal(err)
	}
	// An open finding inside AddProduct (fixture file internal/store/store.go:38),
	// an open, internet-facing finding with a CVE for the attack path.
	findingID := uuid.Must(uuid.NewV7())
	if _, err := appPool.Exec(ctx, `INSERT INTO findings (id, organization_id, repository_id, fingerprint, scanner_keys, category, rule_id, title,
		severity, file_path, start_line, status, cwe, risk_score) VALUES ($1, $2, $3, $4, '{opengrep}', 'sast', 'test.sqli', 'SQL injection (fixture)', 'high',
		'internal/store/store.go', 38, 'open', '{CWE-89}', 80)`, findingID, orgID, repo, "fp-tm-"+uuid.NewString()); err != nil {
		t.Fatal(err)
	}

	// Behind the flag.
	setFlag(t, "codegraph", true)
	t.Cleanup(func() { setFlag(t, "codegraph", false) })
	setFlag(t, "threat_models", false)
	if code, b := h.user(author, "GET", "/api/v1/threat-models", nil); code != 404 || errCode(b) != "PTH-PLAT-1007" {
		t.Fatalf("flag off: %d %v", code, b)
	}
	setFlag(t, "threat_models", true)
	t.Cleanup(func() { setFlag(t, "threat_models", false) })

	// No snapshot yet: PTH-TM-1002.
	if code, b := h.user(author, "POST", "/api/v1/threat-models", map[string]any{"application_id": appID, "title": "Shop", "generate": true}); code != 409 || errCode(b) != "PTH-TM-1002" {
		t.Fatalf("no snapshot: %d %v", code, b)
	}
	_, reg := h.worker(bootstrap, "POST", "/internal/worker/v1/register", map[string]any{"name": "graph-tm-" + uuid.NewString()[:6], "family": "graph",
		"scanners": map[string]string{"pathos-graph": "test"}})
	token := reg["token"].(string)
	sid1 := h.runGraphBuild(admin, appID, repo, token, strings.Repeat("c", 40), graphFixture(t, "fixture-graph.json"))

	// Viewers cannot create.
	if code, _ := h.user(viewer, "POST", "/api/v1/threat-models", map[string]any{"application_id": appID, "title": "Shop"}); code != 403 {
		t.Errorf("viewer create: %d", code)
	}
	code, b := h.user(author, "POST", "/api/v1/threat-models", map[string]any{"application_id": appID, "title": "Shop threat model", "generate": true})
	if code != 201 {
		t.Fatalf("create: %d %v", code, b)
	}
	model := b["model"].(map[string]any)
	modelID := model["id"].(string)
	if model["status"] != "draft" || model["version"].(float64) != 1 || model["method"] != "stride" {
		t.Fatalf("model: %v", model)
	}
	if ids := model["codegraph_snapshot_ids"].([]any); len(ids) != 1 || ids[0] != sid1 {
		t.Errorf("snapshots %v", ids)
	}
	if code, b := h.user(author, "POST", "/api/v1/threat-models", map[string]any{"application_id": appID, "title": "Again"}); code != 409 || errCode(b) != "PTH-TM-1008" {
		t.Errorf("duplicate: %d %v", code, b)
	}

	// Done when: every threat has evidence, method, severity, confidence and mitigation.
	_, b = h.user(viewer, "GET", "/api/v1/threat-models/"+modelID+"/threats", nil)
	threats := tmItems(t, b)
	if len(threats) < 8 {
		t.Fatalf("only %d threats generated", len(threats))
	}
	rules := map[string]int{}
	var sqlThreat, routeThreat, apThreat map[string]any
	for _, th := range threats {
		ev := th["evidence"].(map[string]any)
		nodes, _ := ev["nodes"].([]any)
		edges, _ := ev["edges"].([]any)
		switch {
		case th["rule_id"] == "" || th["rule_version"] == "" || (th["method"] != "rule" && th["method"] != "attack_path"):
			t.Errorf("%s: method %v rule %v", th["title"], th["method"], th["rule_id"])
		case th["severity"] == "" || th["severity_reason"] == "":
			t.Errorf("%s: severity", th["title"])
		case th["confidence"].(float64) <= 0 || th["confidence"].(float64) > 1 || th["confidence_reason"] == "":
			t.Errorf("%s: confidence", th["title"])
		case strings.TrimSpace(th["mitigation"].(string)) == "":
			t.Errorf("%s: no mitigation", th["title"])
		case len(nodes) == 0 && len(edges) == 0:
			t.Errorf("%s: no evidence", th["title"])
		case th["evidence_type"] != "verified" && th["evidence_type"] != "observed":
			t.Errorf("%s: evidence type %v", th["title"], th["evidence_type"])
		case len(th["elements"].([]any)) == 0:
			t.Errorf("%s: no element", th["title"])
		}
		for _, e := range edges {
			em := e.(map[string]any)
			if refs, _ := em["refs"].([]any); len(refs) == 0 || em["id"] == "" {
				t.Errorf("%s: evidence edge %v without references", th["title"], em["key"])
			}
		}
		for _, n := range nodes {
			if _, err := uuid.Parse(n.(map[string]any)["id"].(string)); err != nil && th["method"] == "rule" {
				t.Errorf("%s: evidence node without CodeGraph id", th["title"])
			}
		}
		rules[th["rule_id"].(string)]++
		if th["rule_id"] == "TM-T-001" && strings.Contains(th["title"].(string), "PostgreSQL") {
			sqlThreat = th
		}
		if th["rule_id"] == "TM-S-001" && routeThreat == nil {
			routeThreat = th
		}
		if th["method"] == "attack_path" {
			apThreat = th
		}
	}
	t.Logf("generated %d threats: %v", len(threats), rules)
	if sqlThreat == nil || routeThreat == nil {
		t.Fatalf("expected TM-T-001 on PostgreSQL and TM-S-001: %v", rules)
	}
	// The finding inside AddProduct is linked, with its CWE.
	linked := false
	for _, f := range sqlThreat["findings"].([]any) {
		if f.(map[string]any)["id"] == findingID.String() {
			linked = true
		}
	}
	if !linked {
		t.Errorf("finding in AddProduct not linked to %s: %v", sqlThreat["title"], sqlThreat["findings"])
	}
	maps := fmt.Sprint(sqlThreat["mappings"])
	for _, want := range []string{"CAPEC-66", "CWE-89", "T1565.001", "D3-DQSA", "Stored Data Manipulation"} {
		if !strings.Contains(maps, want) {
			t.Errorf("mappings of %s lack %s: %s", sqlThreat["title"], want, maps)
		}
	}
	// The attack path of the internet-facing finding.
	if apThreat == nil || !strings.Contains(fmt.Sprint(apThreat["evidence"]), findingID.String()) {
		t.Errorf("attack path threat missing: %v", apThreat)
	}

	// Diagram: every drawn flow has evidence references.
	_, d := h.user(viewer, "GET", "/api/v1/threat-models/"+modelID+"/diagram", nil)
	if len(d["nodes"].([]any)) == 0 || len(d["edges"].([]any)) == 0 {
		t.Fatalf("diagram: %d nodes %d edges", len(d["nodes"].([]any)), len(d["edges"].([]any)))
	}
	for _, e := range d["edges"].([]any) {
		if refs, _ := e.(map[string]any)["evidence_refs"].([]any); len(refs) == 0 {
			t.Errorf("diagram edge without evidence: %v", e)
		}
	}

	// Edits: a reason is required for severity and status.
	tid := routeThreat["id"].(string)
	if code, b := h.user(author, "PATCH", "/api/v1/threats/"+tid, map[string]any{"severity": "low"}); code != 422 || errCode(b) != "PTH-TM-1007" {
		t.Errorf("no reason: %d %v", code, b)
	}
	if code, _ := h.user(viewer, "PATCH", "/api/v1/threats/"+tid, map[string]any{"mitigation": "x"}); code != 403 && code != 404 {
		t.Errorf("viewer edit: %d", code)
	}
	code, b = h.user(author, "PATCH", "/api/v1/threats/"+tid, map[string]any{"severity": "low", "reason": "internal network only",
		"mitigation": "Gateway authentication (team decision)", "mappings_add": []map[string]string{{"framework": "capec", "id": "CAPEC-115"}}})
	if code != 200 || b["severity"] != "low" || b["severity_overridden"] != true || b["mitigation_edited"] != true {
		t.Fatalf("edit: %d %v", code, b)
	}
	sqlID := sqlThreat["id"].(string)
	if code, b := h.user(author, "PATCH", "/api/v1/threats/"+sqlID, map[string]any{"status": "accepted", "reason": "risk accepted until Q3"}); code != 200 || b["status"] != "accepted" {
		t.Errorf("status: %d %v", code, b)
	}
	if code, b := h.user(author, "DELETE", "/api/v1/threats/"+sqlID, nil); code != 409 || errCode(b) != "PTH-TM-1009" {
		t.Errorf("delete generated: %d %v", code, b)
	}
	if code, b := h.user(author, "PATCH", "/api/v1/threats/"+sqlID, map[string]any{"mappings_add": []map[string]string{{"framework": "attack", "id": "T0000"}}}); code != 422 {
		t.Errorf("unknown mapping: %d %v", code, b)
	}

	// A manual threat without evidence is "manual, unverified" and blocks submit.
	code, b = h.user(author, "POST", "/api/v1/threat-models/"+modelID+"/threats", map[string]any{"title": "Customer data linkable across orders",
		"category": "linking", "severity": "medium"})
	if code != 201 || b["evidence_type"] != "unverified" || b["label"] != "manual, unverified" || b["method"] != "manual" {
		t.Fatalf("manual threat: %d %v", code, b)
	}
	manualID := b["id"].(string)
	if code, b := h.user(author, "POST", "/api/v1/threat-models/"+modelID+"/submit", map[string]any{}); code != 422 || errCode(b) != "PTH-TM-1004" {
		t.Errorf("submit without mitigation: %d %v", code, b)
	}
	if code, _ := h.user(author, "PATCH", "/api/v1/threats/"+manualID, map[string]any{"mitigation": "Pseudonymise customer ids per order"}); code != 200 {
		t.Fatal("mitigation")
	}
	if code, b := h.user(author, "POST", "/api/v1/threat-models/"+modelID+"/submit", map[string]any{}); code != 422 || errCode(b) != "PTH-TM-1006" {
		t.Errorf("submit unverified: %d %v", code, b)
	}
	if code, b := h.user(author, "PATCH", "/api/v1/threats/"+manualID, map[string]any{"link": map[string]any{"element_keys": []map[string]string{{"key": "no-such-key"}}}}); code != 422 || errCode(b) != "PTH-TM-1003" {
		t.Errorf("bad link: %d %v", code, b)
	}
	code, b = h.user(author, "PATCH", "/api/v1/threats/"+manualID, map[string]any{"link": map[string]any{"element_keys": []map[string]string{{"key": "ds:postgresql"}},
		"finding_ids": []string{findingID.String()}}})
	if code != 200 || b["evidence_type"] != "verified" || len(b["findings"].([]any)) != 1 {
		t.Fatalf("link: %d %v", code, b)
	}

	// Approval: draft → in review → approved; the approver is not the author.
	if code, b := h.user(author, "POST", "/api/v1/threat-models/"+modelID+"/submit", map[string]any{"note": "ready"}); code != 200 || b["status"] != "in_review" {
		t.Fatalf("submit: %d %v", code, b)
	}
	if code, b := h.user(author, "PATCH", "/api/v1/threats/"+manualID, map[string]any{"mitigation": "x"}); code != 409 || errCode(b) != "PTH-TM-1001" {
		t.Errorf("edit in review: %d %v", code, b)
	}
	if code, _ := h.user(author, "POST", "/api/v1/threat-models/"+modelID+"/approve", map[string]any{}); code != 403 {
		t.Errorf("author without threats.approve: %d", code)
	}
	selfApprover := tmUser(t, "security_manager")
	_, _ = appPool.Exec(ctx, `UPDATE threat_models SET submitted_by = $2 WHERE id = $1`, modelID, selfApprover.UserID)
	if code, b := h.user(selfApprover, "POST", "/api/v1/threat-models/"+modelID+"/approve", map[string]any{}); code != 409 || errCode(b) != "PTH-TM-1005" {
		t.Errorf("self approval: %d %v", code, b)
	}
	if _, err := appPool.Exec(ctx, `UPDATE threat_models SET approved_by = created_by, status = 'approved' WHERE id = $1`, modelID); err == nil {
		t.Error("the database accepted an approval by the author")
	}
	if code, b := h.user(approver, "POST", "/api/v1/threat-models/"+modelID+"/reject", map[string]any{"note": ""}); code != 422 {
		t.Errorf("reject without note: %d %v", code, b)
	}
	code, b = h.user(approver, "POST", "/api/v1/threat-models/"+modelID+"/approve", map[string]any{"note": "looks right"})
	if code != 200 || b["status"] != "approved" || b["approved_by"].(map[string]any)["id"] != approver.UserID.String() {
		t.Fatalf("approve: %d %v", code, b)
	}
	if _, err := appPool.Exec(ctx, `UPDATE threat_model_approvals SET note = 'changed' WHERE threat_model_id = $1`, modelID); err == nil {
		t.Error("approvals are not append-only")
	}

	// Architecture change: a new snapshot regenerates into a new draft
	// version (feedback loop), keeping every human edit.
	sid2 := h.runGraphBuild(admin, appID, repo, token, strings.Repeat("d", 40), graphFixture(t, "fixture-graph-v2.json"))
	_, b = h.user(viewer, "GET", "/api/v1/threat-models/"+modelID+"/versions", nil)
	vs := tmItems(t, b)
	if len(vs) != 2 || vs[0]["status"] != "draft" || vs[0]["version"].(float64) != 2 || vs[1]["status"] != "approved" {
		t.Fatalf("feedback loop: versions %v", vs)
	}
	if appr := b["approvals"].([]any); len(appr) != 2 {
		t.Errorf("approvals: %v", appr)
	}
	v2 := vs[0]["id"].(string)
	if ids := vs[0]["codegraph_snapshot_ids"].([]any); len(ids) != 1 || ids[0] != sid2 {
		t.Errorf("v2 snapshots: %v", ids)
	}
	var audits int
	_ = appPool.QueryRow(ctx, `SELECT count(*) FROM audit_logs WHERE action = 'threat_model.auto_update' AND target_id = $1`, v2).Scan(&audits)
	if audits != 1 {
		t.Errorf("auto_update audit entries: %d", audits)
	}
	_, b = h.user(viewer, "GET", "/api/v1/threat-models/"+v2+"/threats", nil)
	v2threats := tmItems(t, b)
	states := map[string]int{}
	for _, th := range v2threats {
		states[th["change_state"].(string)]++
		switch th["fingerprint"] {
		case routeThreat["fingerprint"]:
			if th["severity"] != "low" || th["mitigation"] != "Gateway authentication (team decision)" || !strings.Contains(fmt.Sprint(th["mappings"]), "CAPEC-115") {
				t.Errorf("regeneration lost the human edits: %v", th)
			}
		case sqlThreat["fingerprint"]:
			if th["status"] != "accepted" {
				t.Errorf("regeneration lost the status: %v", th["status"])
			}
		}
		if th["title"] == "Customer data linkable across orders" && th["evidence_type"] != "verified" {
			t.Errorf("manual threat changed: %v", th)
		}
	}
	t.Logf("regeneration on the second snapshot: %v", states)
	if len(v2threats) != len(threats)+1+states["new"] {
		t.Errorf("v2 has %d threats, v1 %d (+1 manual, +%d new)", len(v2threats), len(threats), states["new"])
	}
	if states["unchanged"] == 0 {
		t.Errorf("no threat kept its evidence across snapshots: %v", states)
	}
	if states["new"]+states["changed"]+states["resolved"] == 0 {
		t.Errorf("the second snapshot changed nothing: %v", states)
	}
	// History follows the threat across versions.
	for _, th := range v2threats {
		if th["fingerprint"] == routeThreat["fingerprint"] {
			_, d := h.user(viewer, "GET", "/api/v1/threats/"+th["id"].(string), nil)
			if !strings.Contains(fmt.Sprint(d["events"]), "internal network only") {
				t.Errorf("history lost: %v", d["events"])
			}
		}
	}
	// Generating an approved, superseded version is refused; the draft regenerates in place.
	if code, b := h.user(author, "POST", "/api/v1/threat-models/"+modelID+"/generate", map[string]any{}); code != 409 || errCode(b) != "PTH-TM-1001" {
		t.Errorf("generate old version: %d %v", code, b)
	}
	code, b = h.user(author, "POST", "/api/v1/threat-models/"+v2+"/generate", map[string]any{"engines": []string{"stride"}})
	if code != 200 || b["result"].(map[string]any)["created_version"] != false || b["result"].(map[string]any)["new"].(float64) != 0 {
		t.Errorf("regenerate draft: %d %v", code, b)
	}

	// Export: four formats, version-stamped.
	for _, f := range []string{"pathos", "threat_dragon", "pytm", "markdown"} {
		code, disp, body := h.rawBody(viewer, "GET", "/api/v1/threat-models/"+modelID+"/export?format="+f)
		if code != 200 || !strings.Contains(disp, "-v1.") || len(body) < 100 {
			t.Errorf("export %s: %d %q %d bytes", f, code, disp, len(body))
		}
	}
	_, _, tdBody := h.rawBody(viewer, "GET", "/api/v1/threat-models/"+modelID+"/export?format=threat_dragon")
	_, _, pathosBody := h.rawBody(viewer, "GET", "/api/v1/threat-models/"+modelID+"/export?format=pathos")
	if !strings.Contains(string(pathosBody), "The MITRE Corporation") || !strings.Contains(string(pathosBody), "PATHOS v") {
		t.Error("PATHOS export lacks the MITRE notice or the version stamp")
	}

	// Import the Threat Dragon export into another application: imported, unverified.
	app2 := uuid.Must(uuid.NewV7())
	if _, err := appPool.Exec(ctx, `INSERT INTO applications (id, organization_id, name, criticality) VALUES ($1, $2, $3, 'low')`, app2, orgID,
		"Imported app "+uuid.NewString()[:6]); err != nil {
		t.Fatal(err)
	}
	if code, b := h.user(author, "POST", "/api/v1/threat-models/import", map[string]any{"application_id": app2, "format": "pytm", "document": map[string]any{}}); code != 415 || errCode(b) != "PTH-TM-1102" {
		t.Errorf("pytm import: %d %v", code, b)
	}
	if code, b := h.user(author, "POST", "/api/v1/threat-models/import", map[string]any{"application_id": app2, "format": "threat_dragon", "document": map[string]any{"detail": map[string]any{}}}); code != 422 || errCode(b) != "PTH-TM-1101" {
		t.Errorf("bad import: %d %v", code, b)
	}
	code, b = h.user(author, "POST", "/api/v1/threat-models/import", map[string]any{"application_id": app2, "format": "threat_dragon", "document": json.RawMessage(tdBody)})
	if code != 201 {
		t.Fatalf("import: %d %v", code, b)
	}
	imp := b["model"].(map[string]any)
	if imp["method"] != "imported" || imp["imported_format"] != "threat_dragon" {
		t.Errorf("imported model: %v", imp)
	}
	_, b = h.user(author, "GET", "/api/v1/threat-models/"+imp["id"].(string)+"/threats", nil)
	impThreats := tmItems(t, b)
	if len(impThreats) != len(threats)+1 {
		t.Errorf("imported %d threats, exported %d", len(impThreats), len(threats)+1)
	}
	for _, th := range impThreats {
		if th["label"] != "imported, unverified" || th["method"] != "imported" {
			t.Errorf("imported threat label %v", th["label"])
			break
		}
	}
	if code, b := h.user(author, "POST", "/api/v1/threat-models/"+imp["id"].(string)+"/submit", map[string]any{}); code != 422 || errCode(b) != "PTH-TM-1006" {
		t.Errorf("submit imported unverified: %d %v", code, b)
	}
	// A PATHOS export imported for the same application (repository scope)
	// links threats whose CodeGraph elements exist.
	code, b = h.user(author, "POST", "/api/v1/threat-models/import", map[string]any{"application_id": appID, "repository_id": repo, "format": "pathos",
		"document": json.RawMessage(pathosBody)})
	if code != 201 || b["result"].(map[string]any)["linked"].(float64) == 0 {
		t.Errorf("pathos import: %d %v", code, b)
	}

	// Framework catalogue.
	_, b = h.user(viewer, "GET", "/api/v1/threat-frameworks", nil)
	if len(b["frameworks"].([]any)) != 5 || len(b["rules"].([]any)) < 10 || len(b["notices"].([]any)) != 5 {
		t.Errorf("frameworks: %v", b["frameworks"])
	}
	_, b = h.user(viewer, "GET", "/api/v1/threat-frameworks/attack/entries?q=T1190", nil)
	if it := tmItems(t, b); len(it) == 0 || it[0]["id"] != "T1190" || b["release"] != "20.1" {
		t.Errorf("entries: %v", b)
	}
	if code, _ := h.user(viewer, "GET", "/api/v1/threat-frameworks/linddun-cards/entries", nil); code != 404 {
		t.Errorf("unknown framework: %d", code)
	}
	// List with counts.
	_, b = h.user(viewer, "GET", "/api/v1/threat-models?application_id="+appID.String(), nil)
	if ls := tmItems(t, b); len(ls) != 2 || ls[0]["counts"].(map[string]any)["total"].(float64) == 0 {
		t.Errorf("list: %v", ls)
	}
}
