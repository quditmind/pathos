package main

import (
	"bytes"
	"encoding/json"
	"encoding/pem"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

const (
	testToken = "pat_secrettokenvalue1234567890"
	repoUUID  = "0193a1c2-0000-7000-8000-000000000101"
	jobUUID   = "0193a1c2-5b6e-7c3d-9e10-1f2a3b4c5d6e"
)

// fakeAPI is a minimal PATHOS API.
type fakeAPI struct {
	t        *testing.T
	mu       sync.Mutex
	polls    int
	final    string // final scan status
	gate     map[string]any
	lastForm map[string]string
	lastFile string
	lastPath string
	scanBody map[string]any
	queries  []string
	// stage gate: outcome to answer and the last request body.
	outcome  string
	evalBody map[string]any
}

func (f *fakeAPI) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if r.Header.Get("Authorization") != "Bearer "+testToken {
		w.WriteHeader(401)
		_, _ = io.WriteString(w, `{"error":{"code":"invalid_token","message":"invalid API token"}}`)
		return
	}
	if !strings.HasPrefix(r.Header.Get("User-Agent"), "pathos-cli/") {
		f.t.Errorf("user agent %q", r.Header.Get("User-Agent"))
	}
	f.queries = append(f.queries, r.URL.Path+"?"+r.URL.RawQuery)
	w.Header().Set("Content-Type", "application/json")
	switch {
	case r.Method == "GET" && r.URL.Path == "/api/v1/repositories":
		q := r.URL.Query()
		switch {
		case q.Get("repository_key") == "QD-REPO-000042", q.Get("q") == "acme/payments":
			_, _ = io.WriteString(w, `{"items":[{"id":"`+repoUUID+`","full_name":"acme/payments","repository_key":"QD-REPO-000042"},
				{"id":"0193a1c2-0000-7000-8000-000000000999","full_name":"acme/payments-old","repository_key":"QD-REPO-000043"}]}`)
		case q.Get("q") == "acme/dup":
			_, _ = io.WriteString(w, `{"items":[{"id":"a","full_name":"acme/dup"},{"id":"b","full_name":"ACME/dup"}]}`)
		default:
			_, _ = io.WriteString(w, `{"items":[]}`)
		}
	case r.Method == "POST" && (r.URL.Path == "/api/v1/imports/results" || r.URL.Path == "/api/v1/imports/sbom"):
		f.lastPath = r.URL.Path
		if err := r.ParseMultipartForm(1 << 20); err != nil {
			f.t.Errorf("multipart: %v", err)
		}
		f.lastForm = map[string]string{}
		for k, v := range r.MultipartForm.Value {
			f.lastForm[k] = v[0]
		}
		file, _, err := r.FormFile("file")
		if err == nil {
			b, _ := io.ReadAll(file)
			f.lastFile = string(b)
		}
		if strings.Contains(f.lastFile, "broken") {
			w.WriteHeader(422)
			_, _ = io.WriteString(w, `{"error":{"code":"invalid_report","message":"unrecognised report"},"import":{"status":"failed"}}`)
			return
		}
		w.WriteHeader(201)
		_, _ = io.WriteString(w, `{"id":"i1","status":"succeeded","records":3,"format":"semgrep","scan_job_id":"`+jobUUID+`","scan_key":"QD-SCAN-000007"}`)
	case r.Method == "POST" && r.URL.Path == "/api/v1/scans":
		_ = json.NewDecoder(r.Body).Decode(&f.scanBody)
		w.WriteHeader(202)
		_, _ = io.WriteString(w, `{"items":[{"repository_id":"`+repoUUID+`","job_id":"`+jobUUID+`","coalesced":false}]}`)
	case r.Method == "GET" && r.URL.Path == "/api/v1/scans":
		_, _ = io.WriteString(w, `{"items":[{"id":"running-one","status":"running"},{"id":"`+jobUUID+`","status":"succeeded"}]}`)
	case r.Method == "GET" && r.URL.Path == "/api/v1/scans/"+jobUUID:
		f.polls++
		status, stage := "running", "scanning:gitleaks"
		if f.polls >= 3 {
			status, stage = f.final, "finished"
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"id": jobUUID, "scan_key": "QD-SCAN-000007", "status": status, "stage": stage,
			"progress": f.polls * 30, "findings_new": 2, "error": map[bool]string{true: "scanners failed: x"}[status == "failed"]})
	case r.Method == "GET" && r.URL.Path == "/api/v1/scans/"+jobUUID+"/gate":
		g := map[string]any{"scan_id": jobUUID, "scan_key": "QD-SCAN-000007", "repository_name": "acme/payments", "status": "succeeded",
			"fail_on": r.URL.Query().Get("fail_on"), "scope": r.URL.Query().Get("scope"),
			"by_severity": map[string]int{"critical": 1}, "passed": true, "reasons": []string{}}
		for k, v := range f.gate {
			g[k] = v
		}
		_ = json.NewEncoder(w).Encode(g)
	case r.Method == "POST" && r.URL.Path == "/api/v1/gates/evaluate":
		f.evalBody = map[string]any{}
		_ = json.NewDecoder(r.Body).Decode(&f.evalBody)
		out := f.outcome
		if out == "" {
			out = "pass"
		}
		d := map[string]any{"id": "d1", "stage": f.evalBody["stage"], "outcome": out, "repository_name": "acme/payments",
			"gates": []map[string]any{}, "reasons": []map[string]any{{"code": "no_policy", "message": "no security gate applies"}}}
		if out != "pass" {
			d["gates"] = []map[string]any{{"name": "No criticals", "mode": "block", "effect": out, "count": 2, "policy": map[string]any{"name": "Critical", "version": 2}}}
			d["reasons"] = []map[string]any{}
		}
		_ = json.NewEncoder(w).Encode(d)
	case r.Method == "GET" && r.URL.Path == "/api/v1/findings":
		if r.URL.Query().Get("cursor") == "" {
			_, _ = io.WriteString(w, `{"items":[{"id":"f1","severity":"critical","status":"open","title":"SQL injection","file_path":"a.go","start_line":3,"scanner_keys":["opengrep"]}],"next_cursor":"c2"}`)
		} else {
			_, _ = io.WriteString(w, `{"items":[{"id":"f2","severity":"high","status":"open","title":"Weak\thash","file_path":"b.go","scanner_keys":["import-sast-x"]}],"next_cursor":null}`)
		}
	case r.Method == "GET" && r.URL.Path == "/api/v1/repositories/"+repoUUID+"/sbom":
		_, _ = io.WriteString(w, `{"bomFormat":"CycloneDX","format":"`+r.URL.Query().Get("format")+`"}`)
	default:
		w.WriteHeader(404)
		_, _ = io.WriteString(w, `{"error":{"code":"not_found","message":"not found"}}`)
	}
}

// setup starts a TLS fake API and returns it, its URL and a CA file.
func setup(t *testing.T) (*fakeAPI, string, string) {
	t.Helper()
	api := &fakeAPI{t: t, final: "succeeded"}
	srv := httptest.NewTLSServer(api)
	t.Cleanup(srv.Close)
	ca := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(ca, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw}), 0o600); err != nil {
		t.Fatal(err)
	}
	return api, srv.URL, ca
}

type result struct {
	code           int
	stdout, stderr string
}

func runCLI(t *testing.T, env map[string]string, args ...string) result {
	t.Helper()
	var out, errb bytes.Buffer
	a := &app{stdout: &out, stderr: &errb, getenv: func(k string) string { return env[k] }, pollInterval: time.Millisecond}
	a.cfg = config{URL: env["PATHOS_URL"], Token: env["PATHOS_TOKEN"], TokenFile: env["PATHOS_TOKEN_FILE"], CACert: env["PATHOS_CA_CERT"], Timeout: 10 * time.Second}
	code := a.run(args)
	r := result{code, out.String(), errb.String()}
	if strings.Contains(r.stdout, testToken) || strings.Contains(r.stderr, testToken) {
		t.Errorf("the token leaked into the output: %+v", r)
	}
	return r
}

func envFor(url, ca string) map[string]string {
	return map[string]string{"PATHOS_URL": url, "PATHOS_TOKEN": testToken, "PATHOS_CA_CERT": ca}
}

func TestTLSVerificationAndCACert(t *testing.T) {
	_, url, ca := setup(t)
	env := envFor(url, ca)
	delete(env, "PATHOS_CA_CERT")
	if r := runCLI(t, env, "findings", "--limit", "1"); r.code != exitError || !strings.Contains(r.stderr, "certificate") {
		t.Errorf("an untrusted certificate must fail: %+v", r)
	}
	if r := runCLI(t, env, "--ca-cert", ca, "findings", "--limit", "1"); r.code != exitOK {
		t.Errorf("--ca-cert trusts the server: %+v", r)
	}
	bad := filepath.Join(t.TempDir(), "bad.pem")
	_ = os.WriteFile(bad, []byte("nope"), 0o600)
	if r := runCLI(t, env, "findings", "--ca-cert", bad); r.code != exitError || !strings.Contains(r.stderr, "no PEM") {
		t.Errorf("bad CA file: %+v", r)
	}
}

func TestConfigurationErrors(t *testing.T) {
	_, url, ca := setup(t)
	if r := runCLI(t, map[string]string{"PATHOS_TOKEN": testToken}, "findings"); r.code != exitError || !strings.Contains(r.stderr, "PATHOS_URL") {
		t.Errorf("missing URL: %+v", r)
	}
	if r := runCLI(t, map[string]string{"PATHOS_URL": url, "PATHOS_CA_CERT": ca}, "findings"); r.code != exitError || !strings.Contains(r.stderr, "no API token") {
		t.Errorf("missing token: %+v", r)
	}
	env := envFor("http://pathos.example.com", "")
	if r := runCLI(t, env, "findings"); r.code != exitError || !strings.Contains(r.stderr, "plain http") {
		t.Errorf("http must be refused: %+v", r)
	}
	wrong := envFor(url, ca)
	wrong["PATHOS_TOKEN"] = "pat_wrongtoken"
	if r := runCLI(t, wrong, "findings"); r.code != exitError || !strings.Contains(r.stderr, "invalid_token") || strings.Contains(r.stderr, "pat_wrongtoken") {
		t.Errorf("invalid token: %+v", r)
	}
	tf := filepath.Join(t.TempDir(), "token")
	_ = os.WriteFile(tf, []byte(testToken+"\n"), 0o600)
	if r := runCLI(t, map[string]string{"PATHOS_URL": url, "PATHOS_CA_CERT": ca}, "findings", "--token-file", tf, "--limit", "1"); r.code != exitOK {
		t.Errorf("token file: %+v", r)
	}
	if r := runCLI(t, nil, "bogus"); r.code != exitUsage {
		t.Errorf("unknown command: %+v", r)
	}
	if r := runCLI(t, nil, "--version"); r.code != exitOK || !strings.Contains(r.stdout, "Quditmind PATHOS vdev (build unknown, unknown)") {
		t.Errorf("version: %+v", r)
	}
	if r := runCLI(t, nil); r.code != exitUsage || !strings.Contains(r.stderr, "Commands:") {
		t.Errorf("no command: %+v", r)
	}
	if r := runCLI(t, nil, "gate", "--help"); r.code != exitOK || !strings.Contains(r.stderr, "--fail-on") && !strings.Contains(r.stderr, "-fail-on") {
		t.Errorf("command help: %+v", r)
	}
}

func TestHTTPToLocalhostAllowed(t *testing.T) {
	api := &fakeAPI{t: t, final: "succeeded"}
	srv := httptest.NewServer(api)
	defer srv.Close()
	if r := runCLI(t, envFor(srv.URL, ""), "findings", "--limit", "1"); r.code != exitOK {
		t.Errorf("http to 127.0.0.1 is allowed: %+v", r)
	}
}

func TestRepositoryResolution(t *testing.T) {
	api, url, ca := setup(t)
	env := envFor(url, ca)
	for _, ref := range []string{"QD-REPO-000042", "acme/payments", repoUUID} {
		if r := runCLI(t, env, "sbom", "export", "--repo", ref); r.code != exitOK || !strings.Contains(r.stdout, "CycloneDX") {
			t.Errorf("%s: %+v", ref, r)
		}
	}
	if r := runCLI(t, env, "sbom", "export", "--repo", "acme/none"); r.code != exitError || !strings.Contains(r.stderr, "not found") {
		t.Errorf("unknown repository: %+v", r)
	}
	if r := runCLI(t, env, "sbom", "export", "--repo", "acme/dup"); r.code != exitError || !strings.Contains(r.stderr, "matches 2") {
		t.Errorf("ambiguous repository: %+v", r)
	}
	_ = api
}

func TestImport(t *testing.T) {
	api, url, ca := setup(t)
	env := envFor(url, ca)
	env["GITHUB_SHA"] = "0123456789abcdef0123456789abcdef01234567"
	env["GITHUB_REF_NAME"] = "main"
	file := filepath.Join(t.TempDir(), "semgrep.json")
	_ = os.WriteFile(file, []byte(`{"results":[]}`), 0o600)
	r := runCLI(t, env, "import", "--repo", "acme/payments", "--file", file, "--format", "semgrep", "--complete")
	if r.code != exitOK || !strings.Contains(r.stdout, "Imported 3 findings") || !strings.Contains(r.stdout, "QD-SCAN-000007: succeeded") {
		t.Fatalf("import: %+v", r)
	}
	want := map[string]string{"repository_id": repoUUID, "format": "semgrep", "commit_sha": env["GITHUB_SHA"], "branch": "main", "resolve_missing": "true"}
	for k, v := range want {
		if api.lastForm[k] != v {
			t.Errorf("field %s = %q, want %q", k, api.lastForm[k], v)
		}
	}
	if _, ok := api.lastForm["tool"]; ok {
		t.Error("tool is only sent when given")
	}
	if api.lastFile != `{"results":[]}` || api.lastPath != "/api/v1/imports/results" {
		t.Errorf("file %q path %s", api.lastFile, api.lastPath)
	}
	// JSON output.
	api.polls = 0
	r = runCLI(t, env, "--json", "import", "--repo", repoUUID, "--file", file, "--tool", "Semgrep CI", "--category", "sast")
	var out map[string]map[string]any
	if r.code != exitOK || json.Unmarshal([]byte(r.stdout), &out) != nil || out["import"]["records"].(float64) != 3 || out["scan"]["status"] != "succeeded" {
		t.Errorf("json import: %+v", r)
	}
	if api.lastForm["tool"] != "Semgrep CI" || api.lastForm["category"] != "sast" {
		t.Errorf("tool/category: %v", api.lastForm)
	}
	// SBOM.
	r = runCLI(t, env, "import", "--repo", repoUUID, "--file", file, "--sbom", "--no-wait")
	if r.code != exitOK || api.lastPath != "/api/v1/imports/sbom" || api.lastForm["commit_sha"] != "" {
		t.Errorf("sbom import: %+v %v", r, api.lastForm)
	}
	// Rejected file.
	bad := filepath.Join(t.TempDir(), "bad.json")
	_ = os.WriteFile(bad, []byte("broken"), 0o600)
	if r := runCLI(t, env, "import", "--repo", repoUUID, "--file", bad); r.code != exitError || !strings.Contains(r.stderr, "unrecognised report") {
		t.Errorf("rejected file: %+v", r)
	}
	if r := runCLI(t, env, "import", "--repo", repoUUID); r.code != exitUsage {
		t.Errorf("missing file: %+v", r)
	}
	if r := runCLI(t, env, "import", "--repo", repoUUID, "--file", file, "--commit", "xyz"); r.code != exitUsage {
		t.Errorf("bad commit: %+v", r)
	}
}

func TestScanFollowsProgress(t *testing.T) {
	api, url, ca := setup(t)
	env := envFor(url, ca)
	r := runCLI(t, env, "scan", "--repo", "QD-REPO-000042", "--profile", repoUUID)
	if r.code != exitOK || !strings.Contains(r.stdout, "succeeded") || !strings.Contains(r.stderr, "scanning:gitleaks") || api.polls < 3 {
		t.Fatalf("scan: %+v (polls %d)", r, api.polls)
	}
	if ids := api.scanBody["repository_ids"].([]any); ids[0] != repoUUID || api.scanBody["profile_id"] != repoUUID {
		t.Errorf("scan request: %v", api.scanBody)
	}
	api.polls, api.final = 0, "failed"
	if r := runCLI(t, env, "scan", "--repo", repoUUID, "--quiet"); r.code != exitScanFailed || r.stderr == "" || strings.Contains(r.stderr, "scanning:") {
		t.Errorf("failed scan: %+v", r)
	}
	api.polls = -1000
	if r := runCLI(t, env, "scan", "--repo", repoUUID, "--wait-timeout", "5ms"); r.code != exitScanFailed || !strings.Contains(r.stderr, "timed out") {
		t.Errorf("timeout: %+v", r)
	}
}

func TestGateExitCodes(t *testing.T) {
	api, url, ca := setup(t)
	env := envFor(url, ca)
	r := runCLI(t, env, "gate", "--scan", jobUUID, "--fail-on", "high")
	if r.code != exitOK || !strings.Contains(r.stdout, "PASSED") {
		t.Errorf("passed: %+v", r)
	}
	api.gate = map[string]any{"passed": false, "threshold_count": 1, "reasons": []string{"1 new finding(s) at or above high"}}
	r = runCLI(t, env, "gate", "--repo", "acme/payments", "--fail-on", "high", "--scope", "all")
	if r.code != exitGateFailed || !strings.Contains(r.stdout, "FAILED") || !strings.Contains(r.stdout, "at or above high") {
		t.Errorf("failed: %+v", r)
	}
	last := api.queries[len(api.queries)-1]
	if !strings.Contains(last, "/api/v1/scans/"+jobUUID+"/gate") || !strings.Contains(last, "scope=all") || !strings.Contains(last, "fail_on=high") {
		t.Errorf("gate request picks the latest finished execution: %s", last)
	}
	r = runCLI(t, env, "gate", "--scan", jobUUID, "--json")
	var g map[string]any
	if r.code != exitGateFailed || json.Unmarshal([]byte(r.stdout), &g) != nil || g["passed"] != false {
		t.Errorf("json gate: %+v", r)
	}
	for _, args := range [][]string{{"gate"}, {"gate", "--scan", jobUUID, "--repo", "x"}, {"gate", "--scan", jobUUID, "--fail-on", "urgent"}, {"gate", "--scan", "nope"}} {
		if r := runCLI(t, env, args...); r.code != exitUsage {
			t.Errorf("%v: %+v", args, r)
		}
	}
}

// pathos gate --stage asks the organization's gates (no client threshold):
// block and approval_required exit 1, everything else 0.
func TestGateStage(t *testing.T) {
	api, url, ca := setup(t)
	env := envFor(url, ca)
	r := runCLI(t, env, "gate", "--stage", "pre-commit", "--repo", "acme/payments", "--commit", "0123abcd")
	if r.code != exitOK || !strings.Contains(r.stdout, "PASS") || !strings.Contains(r.stdout, "no security gate applies") {
		t.Errorf("pass: %+v", r)
	}
	if api.evalBody["stage"] != "pre_commit" || api.evalBody["repository_id"] != repoUUID || api.evalBody["commit_sha"] != "0123abcd" {
		t.Errorf("request: %v", api.evalBody)
	}
	for outcome, code := range map[string]int{"warn": exitOK, "exception_applied": exitOK, "block": exitGateFailed, "approval_required": exitGateFailed} {
		api.outcome = outcome
		if r := runCLI(t, env, "gate", "--stage", "deploy", "--repo", repoUUID); r.code != code {
			t.Errorf("%s: %+v", outcome, r)
		}
	}
	api.outcome = "block"
	if r := runCLI(t, env, "gate", "--stage", "ci", "--repo", repoUUID, "--scan", jobUUID, "--json"); r.code != exitGateFailed || !strings.Contains(r.stdout, `"outcome":"block"`) {
		t.Errorf("json: %+v", r)
	}
	if api.evalBody["scan_id"] != jobUUID {
		t.Errorf("scan id: %v", api.evalBody)
	}
	for _, args := range [][]string{
		{"gate", "--stage", "prod", "--repo", repoUUID},
		{"gate", "--stage", "ci"},
		{"gate", "--stage", "ci", "--repo", repoUUID, "--fail-on", "high"},
		{"gate", "--stage", "ci", "--repo", repoUUID, "--application", repoUUID},
		{"gate", "--stage", "ci", "--repo", repoUUID, "--pull-request", "3"},
		{"gate", "--scan", jobUUID, "--commit", "abcdef1"},
	} {
		if r := runCLI(t, env, args...); r.code != exitUsage {
			t.Errorf("%v: %+v", args, r)
		}
	}
}

func TestFindingsOutput(t *testing.T) {
	_, url, ca := setup(t)
	env := envFor(url, ca)
	r := runCLI(t, env, "findings", "--repo", repoUUID, "--severity", "critical,high")
	if r.code != exitOK || !strings.Contains(r.stdout, "SEVERITY") || !strings.Contains(r.stdout, "a.go:3") || !strings.Contains(r.stdout, "Weak hash") {
		t.Errorf("table: %+v", r)
	}
	r = runCLI(t, env, "findings", "--output", "json", "--limit", "1")
	var out struct {
		Items []map[string]any `json:"items"`
	}
	if r.code != exitOK || json.Unmarshal([]byte(r.stdout), &out) != nil || len(out.Items) != 1 {
		t.Errorf("json: %+v", r)
	}
	if r := runCLI(t, env, "findings", "--limit", "0"); r.code != exitUsage {
		t.Errorf("limit: %+v", r)
	}
}

func TestSBOMExportToFile(t *testing.T) {
	_, url, ca := setup(t)
	out := filepath.Join(t.TempDir(), "sbom.spdx.json")
	r := runCLI(t, envFor(url, ca), "sbom", "export", "--repo", repoUUID, "--format", "spdx", "--output", out)
	b, _ := os.ReadFile(out)
	if r.code != exitOK || !strings.Contains(string(b), `"format":"spdx"`) {
		t.Errorf("sbom: %+v %s", r, b)
	}
	if r := runCLI(t, envFor(url, ca), "sbom", "export", "--repo", repoUUID, "--format", "xml"); r.code != exitUsage {
		t.Errorf("bad format: %+v", r)
	}
	if r := runCLI(t, envFor(url, ca), "sbom"); r.code != exitUsage {
		t.Errorf("sbom without export: %+v", r)
	}
}

func TestCIEnvironmentDefaults(t *testing.T) {
	a := &app{getenv: func(k string) string {
		return map[string]string{"GIT_COMMIT": "abcdef1", "GIT_BRANCH": "origin/feature/x", "CI_COMMIT_SHA": "not-a-sha"}[k]
	}}
	if a.ciCommit() != "abcdef1" || a.ciBranch() != "feature/x" {
		t.Errorf("jenkins: %q %q", a.ciCommit(), a.ciBranch())
	}
	b := &app{getenv: func(k string) string {
		return map[string]string{"BITBUCKET_COMMIT": "0123456789abcdef0123456789abcdef01234567", "BITBUCKET_BRANCH": "feature/y"}[k]
	}}
	if b.ciCommit() != "0123456789abcdef0123456789abcdef01234567" || b.ciBranch() != "feature/y" {
		t.Errorf("bitbucket pipelines: %q %q", b.ciCommit(), b.ciBranch())
	}
}
