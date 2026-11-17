//go:build integration

package integration

import (
	"bytes"
	"encoding/json"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/google/uuid"

	"pathos/internal/auth"
	"pathos/internal/authz"
	"pathos/internal/intel"
	"pathos/internal/org"
	"pathos/internal/repos"
	"pathos/internal/risk"
	"pathos/internal/scans"
)

const testEPSS = "#model_version:v2025.03.14,score_date:2026-11-16T00:00:00Z\ncve,epss,percentile\nCVE-2021-44228,0.94358,0.99962\nCVE-2020-0001,0.00100,0.05000\n"
const testKEV = `{"catalogVersion":"2026.11.16","vulnerabilities":[{"cveID":"CVE-2021-44228","vendorProject":"Apache","product":"Log4j2","dueDate":"2021-12-24"}]}`

func TestIntelligenceAndRisk(t *testing.T) {
	ctx := t.Context()
	az := &authz.Authorizer{H: &org.Hierarchy{DB: appPool, OrgID: orgID}}
	feedSrv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "kev.json") {
			_, _ = w.Write([]byte(testKEV))
			return
		}
		http.NotFound(w, r)
	}))
	defer feedSrv.Close()
	intelSvc := &intel.Service{DB: appPool, Log: log, Principal: auth.PrincipalFrom, HTTP: feedSrv.Client()}
	riskSvc := &risk.Service{DB: appPool, Authz: az, Log: log, Principal: auth.PrincipalFrom}
	scanSvc := &scans.Service{DB: appPool, Authz: az, Log: log, Principal: auth.PrincipalFrom}
	repoSvc := &repos.Service{DB: appPool, Authz: az, Log: log, Principal: auth.PrincipalFrom}
	mux := http.NewServeMux()
	intelSvc.Register(mux)
	riskSvc.Register(mux)
	scanSvc.Register(mux)
	repoSvc.Register(mux)
	do := func(p *authz.Principal, req *http.Request) (int, map[string]any) {
		t.Helper()
		req = req.WithContext(auth.WithPrincipal(req.Context(), p))
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)
		var out map[string]any
		_ = json.Unmarshal(rec.Body.Bytes(), &out)
		return rec.Code, out
	}
	call := func(p *authz.Principal, method, path string, body any) (int, map[string]any) {
		var raw []byte
		if body != nil {
			raw, _ = json.Marshal(body)
		}
		req := httptest.NewRequest(method, path, bytes.NewReader(raw))
		req.Header.Set("Content-Type", "application/json")
		return do(p, req)
	}
	upload := func(p *authz.Principal, feed, content string) (int, map[string]any) {
		var buf bytes.Buffer
		mw := multipart.NewWriter(&buf)
		fw, _ := mw.CreateFormFile("file", feed+".dat")
		_, _ = fw.Write([]byte(content))
		_ = mw.Close()
		req := httptest.NewRequest("POST", "/api/v1/intel/feeds/"+feed+"/import", &buf)
		req.Header.Set("Content-Type", mw.FormDataContentType())
		return do(p, req)
	}
	admin := reviewUser(t, "platform_admin")
	analyst := reviewUser(t, "security_analyst")

	repo := createRepo(t, "intel-"+uuid.NewString()[:6])
	log4j := insertFinding(t, repo, "critical", "")
	low := insertFinding(t, repo, "low", "")
	_, _ = appPool.Exec(ctx, `UPDATE findings SET cve = 'CVE-2021-44228', category = 'sca' WHERE id = $1`, log4j)
	_, _ = appPool.Exec(ctx, `UPDATE findings SET cve = 'CVE-2020-0001' WHERE id = $1`, low)

	// --- feeds: offline import (admin only), online fetch -----------------
	if code, _ := upload(analyst, "epss", testEPSS); code != 403 {
		t.Errorf("only administrators import feeds: %d", code)
	}
	if code, out := upload(admin, "epss", "not,a,feed\n"); code != 422 {
		t.Errorf("invalid feed: %d %v", code, out)
	}
	code, run := upload(admin, "epss", testEPSS)
	if code != 200 || run["records"].(float64) != 2 || run["mode"] != "file" {
		t.Fatalf("epss import: %d %v", code, run)
	}
	if code, out := call(admin, "PUT", "/api/v1/intel/feeds/kev", map[string]any{"url": "http://insecure.example/kev.json"}); code != 400 {
		t.Errorf("feed URLs must be https: %d %v", code, out)
	}
	if code, _ := call(admin, "PUT", "/api/v1/intel/feeds/kev", map[string]any{"url": feedSrv.URL + "/kev.json"}); code != 200 {
		t.Fatalf("set kev url: %d", code)
	}
	code, run = call(admin, "POST", "/api/v1/intel/feeds/kev/run", nil)
	if code != 200 || run["records"].(float64) != 1 || run["status"] != "succeeded" {
		t.Fatalf("kev online: %d %v", code, run)
	}
	code, feeds := call(analyst, "GET", "/api/v1/intel/feeds", nil)
	if code != 200 || len(feeds["items"].([]any)) != 2 {
		t.Errorf("feeds: %d %v", code, feeds)
	}
	code, cve := call(analyst, "GET", "/api/v1/intel/cves/cve-2021-44228", nil)
	if code != 200 || cve["kev"] == nil || cve["epss_percentile"].(float64) < 0.99 {
		t.Errorf("cve: %d %v", code, cve)
	}

	// --- risk scoring --------------------------------------------------------
	for {
		n, err := risk.Recompute(ctx, appPool, orgID, 500)
		if err != nil {
			t.Fatal(err)
		}
		if n == 0 {
			break
		}
	}
	var scoreLog4j, scoreLow float64
	var kev bool
	var pct float64
	_ = appPool.QueryRow(ctx, `SELECT risk_score::float8, kev, epss_percentile::float8 FROM findings WHERE id = $1`, log4j).Scan(&scoreLog4j, &kev, &pct)
	_ = appPool.QueryRow(ctx, `SELECT risk_score::float8 FROM findings WHERE id = $1`, low).Scan(&scoreLow)
	if !kev || pct < 0.99 || scoreLog4j < 80 || scoreLow >= scoreLog4j || scoreLow <= 0 {
		t.Fatalf("scores: log4j=%v (kev %v, epss %v) low=%v", scoreLog4j, kev, pct, scoreLow)
	}
	code, expl := call(analyst, "GET", "/api/v1/findings/"+log4j.String()+"/risk", nil)
	if code != 200 || expl["band"] != "critical" || !strings.Contains(mustJSON(expl["explanation"]), "CISA KEV") {
		t.Errorf("explanation: %d %v", code, expl)
	}

	// Context changes re-score: exposure up, score up.
	_, _ = appPool.Exec(ctx, `UPDATE repositories SET public_exposure = 'no' WHERE id = $1`, repo)
	var dirty bool
	_ = appPool.QueryRow(ctx, `SELECT risk_dirty FROM findings WHERE id = $1`, low).Scan(&dirty)
	if !dirty {
		t.Error("a repository context change marks its findings for re-scoring")
	}
	_, _ = risk.Recompute(ctx, appPool, orgID, 500)
	var lowAfter float64
	_ = appPool.QueryRow(ctx, `SELECT risk_score::float8 FROM findings WHERE id = $1`, low).Scan(&lowAfter)
	if lowAfter >= scoreLow {
		t.Errorf("not exposed lowers risk: %v -> %v", scoreLow, lowAfter)
	}

	// Risk model: versioned, validated, settings.manage only.
	if code, _ := call(analyst, "PUT", "/api/v1/risk-model", map[string]any{"weights": risk.Default()}); code != 403 {
		t.Errorf("analyst cannot change the model: %d", code)
	}
	bad := risk.Default()
	bad.LikelihoodUnknown = 0
	if code, _ := call(admin, "PUT", "/api/v1/risk-model", map[string]any{"weights": bad}); code != 400 {
		t.Errorf("invalid model: %d", code)
	}
	w := risk.Default()
	w.Exposure["no"] = 0.5
	code, m := call(admin, "PUT", "/api/v1/risk-model", map[string]any{"weights": w, "change_note": "internal assets matter less"})
	if code != 200 || m["model"].(map[string]any)["version"].(float64) < 1 || m["pending_recompute"].(float64) == 0 {
		t.Fatalf("model update: %d %v", code, m)
	}

	// --- findings API: lifecycle, intel fields, filters, risk sort ----------
	_, _ = risk.Recompute(ctx, appPool, orgID, 5000)
	code, list := call(analyst, "GET", "/api/v1/findings?repository_id="+repo.String()+"&sort=risk", nil)
	items := list["items"].([]any)
	if code != 200 || len(items) != 2 || items[0].(map[string]any)["id"] != log4j.String() {
		t.Fatalf("risk sort: %d %v", code, list)
	}
	first := items[0].(map[string]any)
	if first["lifecycle_status"] != "new" || first["kev"] != true || first["confidence"] == nil || first["risk_score"] == nil {
		t.Errorf("finding fields: %v", first)
	}
	if code, l := call(analyst, "GET", "/api/v1/findings?repository_id="+repo.String()+"&kev=true", nil); code != 200 || len(l["items"].([]any)) != 1 {
		t.Errorf("kev filter: %d %v", code, l)
	}
	// The model now weighs internal-only assets at 0.5: the KEV finding
	// drops to about 37, the other to about 4.
	if code, l := call(analyst, "GET", "/api/v1/findings?repository_id="+repo.String()+"&risk_min=30", nil); code != 200 || len(l["items"].([]any)) != 1 {
		t.Errorf("risk filter: %d %v", code, l)
	}
	_, _ = appPool.Exec(ctx, `UPDATE findings SET status = 'fixed' WHERE id = $1`, low)
	if code, l := call(analyst, "GET", "/api/v1/findings?repository_id="+repo.String()+"&lifecycle=resolved", nil); code != 200 || len(l["items"].([]any)) != 1 {
		t.Errorf("lifecycle filter spans stored statuses: %d %v", code, l)
	}
	_, _ = appPool.Exec(ctx, `UPDATE findings SET status = 'open' WHERE id = $1`, low)
	if code, l := call(analyst, "GET", "/api/v1/findings?repository_id="+repo.String()+"&lifecycle=reopened", nil); code != 200 || len(l["items"].([]any)) != 1 {
		t.Errorf("reopened after recurrence: %d %v", code, l)
	}
	if code, _ := call(analyst, "GET", "/api/v1/findings?lifecycle=bogus", nil); code != 400 {
		t.Errorf("invalid lifecycle: %d", code)
	}

	// --- applications: permanent ID and new fields --------------------------
	manager := reviewUser(t, "security_manager")
	code, app := call(admin, "POST", "/api/v1/applications", map[string]any{"name": "Payments " + uuid.NewString()[:6], "lifecycle": "maintenance",
		"technical_owner_user_id": manager.UserID})
	if code != 201 || !strings.HasPrefix(app["application_key"].(string), "QD-APP-") || app["lifecycle"] != "maintenance" ||
		app["technical_owner"] == nil {
		t.Fatalf("application: %d %v", code, app)
	}
	if code, _ := call(admin, "PATCH", "/api/v1/applications/"+app["id"].(string), map[string]any{"lifecycle": "bogus"}); code != 400 {
		t.Errorf("invalid lifecycle: %d", code)
	}
	if _, err := appPool.Exec(ctx, `UPDATE applications SET application_key = 'QD-APP-999999' WHERE id = $1`, app["id"]); err == nil {
		t.Error("application keys are permanent")
	}
}
