//go:build integration

package integration

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"os"
	"pathos/internal/vuln"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"pathos/internal/auth"
	"pathos/internal/authz"
	"pathos/internal/org"
	"pathos/internal/platform/crypto"
	"pathos/internal/scans"
	"pathos/internal/secrets"
)

// PATHOS 2.0 worker-mobile and worker-ai targets: mobile app targets
// (uploaded APK, AAB or IPA), LLM endpoint targets (credential stored
// encrypted, authorization and intrusive testing flag, model name), manifest
// results on them, and the AI-BOM in the component inventory.
func TestMobileAndLLMTargets(t *testing.T) {
	ctx := t.Context()
	var start time.Time
	_ = appPool.QueryRow(ctx, `SELECT now()`).Scan(&start)
	t.Cleanup(func() {
		_, _ = appPool.Exec(context.Background(), `UPDATE notification_events SET processed_at = now() WHERE processed_at IS NULL AND created_at >= $1`, start)
	})
	kr, _ := crypto.NewKeyring(map[int][]byte{1: testKey})
	svc := &scans.Service{DB: appPool, Authz: &authz.Authorizer{H: &org.Hierarchy{DB: appPool, OrgID: orgID}}, Log: log,
		Principal: auth.PrincipalFrom, BootstrapToken: bootstrap, OrgID: orgID, Secrets: &secrets.Store{Keys: kr}}
	vsvc := &vuln.Service{DB: appPool, Authz: svc.Authz, Log: log, Principal: auth.PrincipalFrom}
	h := &scanHarness{t: t, api: newMux(func(m *http.ServeMux) { svc.Register(m); vsvc.Register(m) }), internal: svc.InternalHandler()}
	admin := reviewUser(t, "platform_admin")
	repo := createRepo(t, "mob-"+uuid.NewString()[:6])
	tag := uuid.NewString()[:6]

	// A worker of the ai and mobile families advertises their manifests.
	tools := map[string]any{
		"garak": map[string]any{"name": "garak", "category": "ai", "scan_types": []string{"ai"}, "license_spdx": "Apache-2.0", "family": "ai",
			"targets": []string{"llm-endpoint"}, "network": "target", "intrusive": true, "parser": "import:garak", "first_party": true},
		"promptfoo": map[string]any{"name": "promptfoo", "category": "ai", "scan_types": []string{"ai"}, "license_spdx": "MIT", "family": "ai",
			"targets": []string{"llm-endpoint"}, "network": "target", "intrusive": true, "parser": "import:promptfoo", "first_party": true},
		"mobile-app-checks": map[string]any{"name": "Mobile app configuration checks", "category": "mobile", "scan_types": []string{"mobile"},
			"license_spdx": "Apache-2.0", "family": "mobile", "targets": []string{"mobile-app"}, "network": "none", "parser": "jsonmap",
			"first_party": true},
	}
	code, reg := h.worker(bootstrap, "POST", "/internal/worker/v1/register", map[string]any{"name": "ai-mobile-" + tag, "family": "ai",
		"scanners": map[string]string{"gitleaks": "8.30.1", "garak": "0.17.1", "promptfoo": "0.126.0", "mobile-app-checks": "1"}, "tools": tools})
	if code != 200 {
		t.Fatalf("register: %d %v", code, reg)
	}
	token := reg["token"].(string)
	var adv []byte
	_ = appPool.QueryRow(ctx, `SELECT tools FROM workers WHERE name = $1`, "ai-mobile-"+tag).Scan(&adv)
	if !strings.Contains(string(adv), "llm-endpoint") {
		t.Errorf("llm-endpoint targets advertised: %s", adv)
	}

	// --- LLM endpoint target -------------------------------------------------
	llm := map[string]any{"repository_id": repo, "kind": "llm-endpoint", "name": "Support bot", "reference": "https://llm.example.test/v1/chat/completions",
		"auth_type": "header", "auth_header_name": "Authorization", "auth_secret": "Bearer llm-secret-4711",
		"config": map[string]any{"tools": []string{"garak", "promptfoo"}}}
	if code, out := h.user(admin, "POST", "/api/v1/scan-targets", llm); code != 400 || !strings.Contains(errMsg(out), "model") {
		t.Errorf("LLM endpoint without a model: %d %v", code, out)
	}
	llm["config"] = map[string]any{"tools": []string{"garak", "promptfoo"}, "model": "support-bot-v2"}
	if code, out := h.user(admin, "POST", "/api/v1/scan-targets", llm); code != 400 || !strings.Contains(errMsg(out), "authorized") {
		t.Errorf("LLM endpoint without authorization: %d %v", code, out)
	}
	llm["authorized"] = true
	code, lt := h.user(admin, "POST", "/api/v1/scan-targets", llm)
	if code != 201 || lt["kind"] != "llm-endpoint" || lt["has_secret"] != true || lt["egress_host"] != "llm.example.test" || lt["authorized_at"] == nil {
		t.Fatalf("create LLM endpoint: %d %v", code, lt)
	}
	if raw, _ := json.Marshal(lt); strings.Contains(string(raw), "llm-secret-4711") {
		t.Fatal("the credential is returned by the API")
	}
	var stored []byte
	_ = appPool.QueryRow(ctx, `SELECT s.ciphertext FROM secrets s JOIN scan_targets t ON t.secret_id = s.id WHERE t.id = $1`, lt["id"]).Scan(&stored)
	if len(stored) == 0 || bytes.Contains(stored, []byte("llm-secret-4711")) {
		t.Error("the credential is stored encrypted")
	}
	llmID := lt["id"].(string)
	// garak and promptfoo are intrusive: the scan needs the intrusive flag.
	if code, out := h.user(admin, "POST", "/api/v1/scan-targets/"+llmID+"/scan", nil); code != 409 || !strings.Contains(errMsg(out), "intrusive") {
		t.Errorf("intrusive tools without the flag: %d %v", code, out)
	}
	if code, out := h.user(admin, "PUT", "/api/v1/scan-targets/"+llmID, map[string]any{"intrusive_authorized": true,
		"intrusive_authorization_note": "Red-team test window approved"}); code != 200 || out["intrusive_authorized_at"] == nil {
		t.Fatalf("intrusive testing authorization: %d %v", code, out)
	}
	_, q := h.user(admin, "POST", "/api/v1/scan-targets/"+llmID+"/scan", nil)
	if q["job_id"] == nil {
		t.Fatalf("queue: %v", q)
	}
	job := h.leaseJob(token, q["job_id"].(string))
	tg, _ := job["target"].(map[string]any)
	if tg == nil || tg["kind"] != "llm-endpoint" || tg["model"] != "support-bot-v2" || tg["header_value"] != "Bearer llm-secret-4711" ||
		tg["intrusive_authorized"] != true {
		t.Fatalf("leased LLM target: %v", tg)
	}
	var keys []string
	for _, sc := range job["scanners"].([]any) {
		keys = append(keys, sc.(map[string]any)["key"].(string))
	}
	if strings.Join(keys, ",") != "garak,promptfoo" {
		t.Errorf("LLM target scanners: %v", keys)
	}
	jid := q["job_id"].(string)
	for _, r := range []map[string]any{
		{"scanner": "garak", "status": "succeeded", "output_gzip": workerFixture(t, "ai-garak.jsonl"), "parser": map[string]any{"kind": "import", "format": "garak"}},
		{"scanner": "promptfoo", "status": "succeeded", "output_gzip": workerFixture(t, "ai-promptfoo.json"),
			"parser": map[string]any{"kind": "import", "format": "promptfoo"}},
	} {
		if code, out := h.worker(token, "POST", "/internal/worker/v1/jobs/"+jid+"/results", r); code != 200 && code != 201 {
			t.Fatalf("upload %s: %d %v", r["scanner"], code, out)
		}
	}
	h.worker(token, "POST", "/internal/worker/v1/jobs/"+jid+"/complete", map[string]any{"status": "succeeded"})
	var aiFindings int
	_ = appPool.QueryRow(ctx, `SELECT count(*) FROM findings WHERE scan_target_id = $1 AND category = 'ai' AND status = 'open'`, llmID).Scan(&aiFindings)
	if aiFindings < 7 {
		t.Errorf("AI findings on the LLM target: %d", aiFindings)
	}
	_, lst := h.user(admin, "GET", "/api/v1/findings?target_kind=llm-endpoint&repository_id="+repo.String(), nil)
	if items, _ := lst["items"].([]any); len(items) != aiFindings {
		t.Errorf("findings by target kind: %d", len(items))
	}

	// --- mobile app target ---------------------------------------------------
	upload := func(fileName string, data []byte) (int, map[string]any) {
		var buf bytes.Buffer
		mw := multipart.NewWriter(&buf)
		_ = mw.WriteField("repository_id", repo.String())
		fw, _ := mw.CreateFormFile("file", fileName)
		_, _ = fw.Write(data)
		_ = mw.Close()
		req := httptest.NewRequest("POST", "/api/v1/scan-targets/mobile-app", &buf)
		req.Header.Set("Content-Type", mw.FormDataContentType())
		rec := httptest.NewRecorder()
		h.api.ServeHTTP(rec, req.WithContext(auth.WithPrincipal(req.Context(), admin)))
		var out map[string]any
		_ = json.Unmarshal(rec.Body.Bytes(), &out)
		return rec.Code, out
	}
	apk, err := os.ReadFile("../../../workers/mobile/test/apk/pathos-test.apk")
	if err != nil {
		t.Fatal(err)
	}
	if code, _ := upload("app.apk", []byte("not a zip archive")); code != 400 {
		t.Errorf("a non-ZIP package: %d", code)
	}
	if code, _ := upload("app.zip", apk); code != 400 {
		t.Errorf("a ZIP that is not named .apk, .aab or .ipa: %d", code)
	}
	if code, out := h.user(admin, "POST", "/api/v1/scan-targets", map[string]any{"repository_id": repo, "kind": "mobile-app", "name": "x"}); code != 400 ||
		!strings.Contains(errMsg(out), "upload") {
		t.Errorf("mobile apps are uploaded: %d %v", code, out)
	}
	code, mt := upload("pathos-test.apk", apk)
	if code != 201 || mt["kind"] != "mobile-app" || !strings.HasPrefix(mt["reference"].(string), "pathos-test.apk (") {
		t.Fatalf("mobile app target: %d %v", code, mt)
	}
	mobID := mt["id"].(string)
	if code, out := h.user(admin, "PUT", "/api/v1/scan-targets/"+mobID, map[string]any{"config": map[string]any{"tools": []string{"mobile-app-checks"}}}); code != 200 {
		t.Fatalf("select mobile tools: %d %v", code, out)
	}
	if code, out := h.user(admin, "PUT", "/api/v1/scan-targets/"+mobID, map[string]any{"config": map[string]any{"tools": []string{"garak"}}}); code != 400 {
		t.Errorf("an LLM tool on a mobile app: %d %v", code, out)
	}
	_, mq := h.user(admin, "POST", "/api/v1/scan-targets/"+mobID+"/scan", nil)
	mjob := h.leaseJob(token, mq["job_id"].(string))
	mtg := mjob["target"].(map[string]any)
	if mtg["kind"] != "mobile-app" || mtg["file_name"] != "pathos-test.apk" {
		t.Errorf("leased mobile target: %v", mtg)
	}
	keys = nil
	for _, sc := range mjob["scanners"].([]any) {
		keys = append(keys, sc.(map[string]any)["key"].(string))
	}
	if strings.Join(keys, ",") != "binary-hardening,mobile-app-checks" {
		t.Errorf("mobile target scanners: %v", keys)
	}
	mjid := mq["job_id"].(string)
	req := httptest.NewRequest("GET", "/internal/worker/v1/jobs/"+mjid+"/target-file", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	h.internal.ServeHTTP(rec, req)
	if rec.Code != 200 || !bytes.Equal(rec.Body.Bytes(), apk) {
		t.Errorf("target file download: %d (%d bytes)", rec.Code, rec.Body.Len())
	}
	jm := map[string]any{"records": "findings", "rule_id": "id", "title": "title", "message": "description", "severity": "severity",
		"file": "file", "cwe": "cwe", "identity": "{id} {component}"}
	if code, out := h.worker(token, "POST", "/internal/worker/v1/jobs/"+mjid+"/results", map[string]any{"scanner": "mobile-app-checks",
		"status": "succeeded", "output_gzip": workerFixture(t, "mobile-checks-apk.json"), "parser": map[string]any{"kind": "jsonmap", "jsonmap": jm}}); code != 200 && code != 201 {
		t.Fatalf("upload: %d %v", code, out)
	}
	h.worker(token, "POST", "/internal/worker/v1/jobs/"+mjid+"/complete", map[string]any{"status": "succeeded"})
	var mobile int
	_ = appPool.QueryRow(ctx, `SELECT count(*) FROM findings WHERE scan_target_id = $1 AND category = 'mobile'`, mobID).Scan(&mobile)
	if mobile != 8 {
		t.Errorf("mobile findings: %d", mobile)
	}

	// --- AI-BOM in the component inventory -----------------------------------
	_, rq := h.user(admin, "POST", "/api/v1/repositories/"+repo.String()+"/scan", nil)
	rjid := rq["job_id"].(string)
	h.leaseJob(token, rjid)
	aibom := `{"bomFormat": "CycloneDX", "specVersion": "1.6", "components": [
	  {"type": "framework", "bom-ref": "aibom:pypi:torch", "name": "torch", "version": "2.5.1", "purl": "pkg:pypi/torch@2.5.1"},
	  {"type": "machine-learning-model", "bom-ref": "aibom:file:models/m.onnx", "name": "models/m.onnx"}],
	  "services": [{"bom-ref": "aibom:service:openai-api", "name": "OpenAI API", "provider": {"name": "OpenAI"}}]}`
	for _, r := range []map[string]any{
		{"scanner": "syft", "status": "succeeded", "output_gzip": fixture(t, "syft.cdx.json")},
		{"scanner": "ai-bom", "status": "succeeded", "output_gzip": gzB64([]byte(aibom))},
	} {
		if code, out := h.worker(token, "POST", "/internal/worker/v1/jobs/"+rjid+"/results", r); code != 200 && code != 201 {
			t.Fatalf("upload %s: %d %v", r["scanner"], code, out)
		}
	}
	h.worker(token, "POST", "/internal/worker/v1/jobs/"+rjid+"/complete", map[string]any{"status": "succeeded"})
	counts := func() (scan, ai int, types string) {
		_ = appPool.QueryRow(ctx, `SELECT count(*) FILTER (WHERE source = 'scan'), count(*) FILTER (WHERE source = 'aibom'),
			COALESCE(string_agg(type, ',' ORDER BY type) FILTER (WHERE source = 'aibom'), '') FROM sbom_components WHERE repository_id = $1`, repo).
			Scan(&scan, &ai, &types)
		return
	}
	if s, a, ty := counts(); s == 0 || a != 3 || ty != "framework,machine-learning-model,service" {
		t.Fatalf("inventory after Syft and AI-BOM: %d %d %s", s, a, ty)
	}
	// The SBOM download is Syft's SBOM, not the AI-BOM uploaded after it
	// (which was returned before: a CycloneDX file without the packages).
	if code, sbom := h.user(admin, "GET", "/api/v1/repositories/"+repo.String()+"/sbom", nil); code != 200 {
		t.Fatalf("SBOM download: %d", code)
	} else if comps, _ := sbom["components"].([]any); len(comps) == 0 || strings.Contains(fmt.Sprint(comps), "aibom:") {
		t.Errorf("SBOM download returned the AI-BOM instead of Syft's SBOM: %v", comps)
	}
	var aiFindingsRepo int
	_ = appPool.QueryRow(ctx, `SELECT count(*) FROM scan_results WHERE scan_job_id = $1 AND scanner_key = 'ai-bom' AND findings_count = 0 AND status = 'succeeded'`,
		rjid).Scan(&aiFindingsRepo)
	if aiFindingsRepo != 1 {
		t.Error("the AI-BOM result has no findings")
	}
	// The next SBOM scan keeps the AI-BOM entries (and the next AI-BOM
	// would replace them).
	_, rq2 := h.user(admin, "POST", "/api/v1/repositories/"+repo.String()+"/scan", nil)
	rjid2 := rq2["job_id"].(string)
	h.leaseJob(token, rjid2)
	h.worker(token, "POST", "/internal/worker/v1/jobs/"+rjid2+"/results", map[string]any{"scanner": "syft", "status": "succeeded",
		"output_gzip": fixture(t, "syft.cdx.json")})
	h.worker(token, "POST", "/internal/worker/v1/jobs/"+rjid2+"/complete", map[string]any{"status": "succeeded"})
	if s, a, _ := counts(); s == 0 || a != 3 {
		t.Errorf("inventory after another Syft scan: %d %d", s, a)
	}
}

// workerFixture reads a manifest fixture of the worker tests, gzipped and
// base64-encoded like a result upload.
func workerFixture(t *testing.T, name string) string {
	t.Helper()
	raw, err := os.ReadFile("../../internal/worker/testdata/manifests/" + name)
	if err != nil {
		t.Fatal(err)
	}
	return gzB64(raw)
}
