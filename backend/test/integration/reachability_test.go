//go:build integration

package integration

import (
	"bytes"
	"compress/gzip"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"pathos/internal/auth"
	"pathos/internal/authz"
	"pathos/internal/intel"
	"pathos/internal/org"
	"pathos/internal/platform/db"
	"pathos/internal/reach"
	"pathos/internal/risk"
	"pathos/internal/scanners"
	"pathos/internal/scans"
)

func gzipBytes(b []byte) []byte {
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	_, _ = zw.Write(b)
	_ = zw.Close()
	return buf.Bytes()
}

// Function-level reachability end to end: a pathos-reach report and a
// govulncheck run stored with the repository, OSV records naming the
// vulnerable functions imported offline, the findings' answers with their
// evidence, the findings filters and the risk factor.
func TestFunctionLevelReachability(t *testing.T) {
	ctx := t.Context()
	az := &authz.Authorizer{H: &org.Hierarchy{DB: appPool, OrgID: orgID}}
	scanSvc := &scans.Service{DB: appPool, Authz: az, Log: log, Principal: auth.PrincipalFrom, BootstrapToken: bootstrap, OrgID: orgID}
	h := &scanHarness{t: t, api: newMux(func(m *http.ServeMux) { scanSvc.Register(m) }), internal: scanSvc.InternalHandler()}
	admin := reviewUser(t, "platform_admin")
	suffix := uuid.NewString()[:6]
	repo := createRepo(t, "reach-"+suffix)
	_, q := h.user(admin, "POST", "/api/v1/repositories/"+repo.String()+"/scan", nil)
	job := uuid.MustParse(q["job_id"].(string))

	n := time.Now().UnixNano() % 90000000
	cveTpl, cveZip, cveU := fmt.Sprintf("CVE-2097-%d", 10000+n), fmt.Sprintf("CVE-2097-%d", 10001+n), fmt.Sprintf("CVE-2097-%d", 10002+n)
	tpl := insertRiskFinding(t, repo, "sca", "high", 0, false, "lodash", "4.17.15", cveTpl)
	zip := insertRiskFinding(t, repo, "sca", "high", 0, false, "lodash", "4.17.15", cveZip)
	und := insertRiskFinding(t, repo, "sca", "high", 0, false, "underscore", "1.12.0", cveU)
	noSymbols := insertRiskFinding(t, repo, "sca", "high", 0, false, "minimist", "1.2.5", "")
	goVuln := insertRiskFinding(t, repo, "sca", "medium", 0, false, "golang.org/x/text", "v0.3.7", "CVE-2022-32149")

	// The worker's reports: pathos-reach (real output on the benchmark
	// samples) and govulncheck (real output on go/app).
	reachRaw, err := os.ReadFile("../../internal/worker/testdata/manifests/sca/pathos-reach.json")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := scanSvc.Ingest(ctx, orgID, job, scans.ResultUpload{Scanner: scanners.PathosReach, Version: "pathos-reach 1.0.0", Status: "succeeded"},
		gzipBytes(reachRaw)); err != nil {
		t.Fatal(err)
	}
	gvRaw, err := os.ReadFile("../../internal/reachscan/testdata/bench/go/govulncheck-app.json")
	if err != nil {
		t.Fatal(err)
	}
	parser := scanners.ToolParser{Kind: "import", Format: "govulncheck"}
	if _, err := scanSvc.Ingest(ctx, orgID, job, scans.ResultUpload{Scanner: "govulncheck", Version: "v1.10.0", Status: "succeeded", Parser: &parser},
		gzipBytes(gvRaw)); err != nil {
		t.Fatal(err)
	}
	var tools []string
	rows, _ := appPool.Query(ctx, `SELECT tool FROM repository_reach_reports WHERE repository_id = $1 ORDER BY tool`, repo)
	tools, _ = pgx.CollectRows(rows, pgx.RowTo[string])
	if strings.Join(tools, ",") != "govulncheck,pathos-reach" {
		t.Fatalf("reports stored: %v", tools)
	}
	// No raw finding comes from pathos-reach.
	var reachFindings int
	_ = appPool.QueryRow(ctx, `SELECT count(*) FROM findings WHERE repository_id = $1 AND 'pathos-reach' = ANY(scanner_keys)`, repo).Scan(&reachFindings)
	if reachFindings != 0 {
		t.Errorf("pathos-reach produced %d findings", reachFindings)
	}
	if err := db.InTx(ctx, appPool, func(tx pgx.Tx) error { _, err := reach.Update(ctx, tx, repo); return err }); err != nil {
		t.Fatal(err)
	}
	type state struct {
		reach, basis, method string
		ev                   *reach.Evidence
	}
	get := func(id uuid.UUID) state {
		var s state
		var raw []byte
		if err := appPool.QueryRow(ctx, `SELECT reachability, reachability_basis, reachability_method, reachability_evidence FROM findings WHERE id = $1`, id).
			Scan(&s.reach, &s.basis, &s.method, &raw); err != nil {
			t.Fatal(err)
		}
		if raw != nil {
			s.ev = &reach.Evidence{}
			_ = json.Unmarshal(raw, s.ev)
		}
		return s
	}
	// Go: govulncheck's call path, mapped to the finding by module and alias.
	if s := get(goVuln); s.reach != "reachable" || s.method != "call_graph" || s.ev == nil || len(s.ev.Paths) == 0 ||
		s.ev.Paths[0][len(s.ev.Paths[0])-1].Function != "golang.org/x/text/language.ParseAcceptLanguage" {
		t.Errorf("go: %+v", s)
	}
	// Without OSV symbols the package-level answer stands.
	if s := get(tpl); s.method == "symbol_calls" {
		t.Errorf("no symbols yet: %+v", s)
	}

	// OSV records naming the vulnerable functions, imported offline: the
	// findings of repositories with a report are decided again.
	osv := fmt.Sprintf(`[{"id":"GHSA-r1%[1]s-aaaa","aliases":["%[2]s"],"affected":[{"package":{"ecosystem":"npm","name":"lodash"},
	    "database_specific":{"vulnerable_functions":["lodash.template"]}}]},
	  {"id":"GHSA-r2%[1]s-aaaa","aliases":["%[3]s"],"affected":[{"package":{"ecosystem":"npm","name":"lodash"},
	    "database_specific":{"vulnerable_functions":["lodash.zipObjectDeep"]}}]},
	  {"id":"GHSA-r3%[1]s-aaaa","aliases":["%[4]s"],"affected":[{"package":{"ecosystem":"npm","name":"underscore"},
	    "database_specific":{"vulnerable_functions":["underscore.template"]}}]}]`, suffix[:4], cveTpl, cveZip, cveU)
	if run, err := intel.Load(ctx, appPool, intel.OSV, "file", nil, []byte(osv)); err != nil || run.Records != 3 {
		t.Fatalf("OSV import: %v %+v", err, run)
	}
	s := get(tpl)
	if s.reach != "reachable" || s.method != "symbol_calls" || s.ev == nil || s.ev.Tool != "pathos-reach" || len(s.ev.Paths) == 0 ||
		s.ev.ScanJobID == nil || *s.ev.ScanJobID != job || len(s.ev.Symbols) != 1 {
		t.Fatalf("lodash.template: %+v", s)
	}
	last := s.ev.Paths[0][len(s.ev.Paths[0])-1]
	if last.File != "js/app/src/views.js" || last.Line != 5 || !strings.Contains(s.basis, "lodash.template") {
		t.Errorf("call site: %+v %s", last, s.basis)
	}
	if s := get(zip); s.reach != "not_reachable" || s.method != "symbol_calls" || !strings.Contains(s.basis, "lodash.zipObjectDeep") {
		t.Errorf("lodash.zipObjectDeep: %+v", s)
	}
	if s := get(und); s.reach != "unknown" || s.method != "symbol_calls" || s.ev == nil || len(s.ev.Dynamic) == 0 {
		t.Errorf("underscore (dynamic): %+v", s)
	}
	if s := get(noSymbols); s.method != "" && s.method != "import" {
		t.Errorf("no advisory: %+v", s)
	}

	// Filters and the finding drawer's evidence.
	list := func(query string) []string {
		_, out := h.user(admin, "GET", "/api/v1/findings?status=all&repository_id="+repo.String()+"&"+query, nil)
		var ids []string
		for _, it := range out["items"].([]any) {
			ids = append(ids, it.(map[string]any)["id"].(string))
		}
		return ids
	}
	if ids := list("reachability=not_reachable"); !contains(ids, zip.String()) || contains(ids, tpl.String()) {
		t.Errorf("reachability filter: %v", ids)
	}
	// govulncheck's own findings (GO-2022-1059, GO-2026-5970, GO-2026-6629)
	// get the same call-graph answers as the finding of another scanner.
	if ids := list("reachability_method=call_graph"); len(ids) != 4 || !contains(ids, goVuln.String()) {
		t.Errorf("method filter: %v", ids)
	}
	var notCalled string
	_ = appPool.QueryRow(ctx, `SELECT reachability FROM findings WHERE repository_id = $1 AND rule_id = 'GO-2026-5970'`, repo).Scan(&notCalled)
	// govulncheck found no call, but the pathos-reach report (of the whole
	// benchmark directory) has go/dynamic calling norm.Form methods through
	// reflection: unknown, not "not reachable".
	if notCalled != "unknown" {
		t.Errorf("GO-2026-5970 (reflection on unicode/norm): %q", notCalled)
	}
	if code, _ := h.user(admin, "GET", "/api/v1/findings?reachability_method=guess", nil); code != 400 {
		t.Errorf("invalid method filter: %d", code)
	}
	_, detail := h.user(admin, "GET", "/api/v1/findings/"+tpl.String(), nil)
	ev, _ := detail["reachability_evidence"].(map[string]any)
	if detail["reachability_method"] != "symbol_calls" || ev == nil || len(ev["paths"].([]any)) == 0 || ev["limits"] == "" {
		t.Errorf("detail evidence: %v %v", detail["reachability_method"], ev)
	}
	_, lst := h.user(admin, "GET", "/api/v1/findings?status=all&repository_id="+repo.String(), nil)
	for _, it := range lst["items"].([]any) {
		if _, ok := it.(map[string]any)["reachability_evidence"]; ok {
			t.Error("the list carries no evidence")
		}
	}

	// The risk factor says it is function level.
	if _, err := risk.Recompute(ctx, appPool, orgID, 10000); err != nil {
		t.Fatal(err)
	}
	var factors []byte
	_ = appPool.QueryRow(ctx, `SELECT risk_factors FROM findings WHERE id = $1`, zip).Scan(&factors)
	if !bytes.Contains(factors, []byte(`"Reachability (vulnerable function, calls in the code)"`)) || !bytes.Contains(factors, []byte(`"not called"`)) {
		t.Errorf("risk factors: %s", factors)
	}
}
