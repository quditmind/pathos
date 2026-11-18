//go:build integration

package integration

import (
	"bytes"
	"compress/gzip"
	"encoding/json"
	"io"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/google/uuid"

	"pathos/internal/auth"
	"pathos/internal/authz"
	"pathos/internal/org"
	"pathos/internal/scans"
)

// Native import formats: detection, explicit formats, default tool and
// category, secret removal before storage, the format recorded for
// evidence capture, and complete imports of empty reports.
func TestImportNativeFormats(t *testing.T) {
	ctx := t.Context()
	az := &authz.Authorizer{H: &org.Hierarchy{DB: appPool, OrgID: orgID}}
	svc := &scans.Service{DB: appPool, Authz: az, Log: log, Principal: auth.PrincipalFrom}
	mux := http.NewServeMux()
	svc.Register(mux)
	upload := func(p *authz.Principal, fields map[string]string, content []byte) (int, map[string]any) {
		t.Helper()
		var buf bytes.Buffer
		mw := multipart.NewWriter(&buf)
		for k, v := range fields {
			_ = mw.WriteField(k, v)
		}
		fw, _ := mw.CreateFormFile("file", "report")
		_, _ = fw.Write(content)
		_ = mw.Close()
		req := httptest.NewRequest("POST", "/api/v1/imports/results", &buf)
		req.Header.Set("Content-Type", mw.FormDataContentType())
		req = req.WithContext(auth.WithPrincipal(req.Context(), p))
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)
		var out map[string]any
		_ = json.Unmarshal(rec.Body.Bytes(), &out)
		return rec.Code, out
	}
	analyst := reviewUser(t, "security_analyst")
	repo := createRepo(t, "fmt-"+uuid.NewString()[:6])
	fixture := func(name string) []byte {
		b, err := os.ReadFile("../../internal/scanners/testdata/imports/" + name)
		if err != nil {
			t.Fatal(err)
		}
		return b
	}

	// The format list.
	req := httptest.NewRequest("GET", "/api/v1/imports/formats", nil)
	req = req.WithContext(auth.WithPrincipal(req.Context(), analyst))
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	var formats struct {
		Results []struct{ ID, Label, Tool, Category string } `json:"results"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &formats)
	if rec.Code != 200 || len(formats.Results) < 20 {
		t.Fatalf("formats: %d %s", rec.Code, rec.Body.String())
	}

	// Trivy, detected; tool and category default from the format.
	code, out := upload(analyst, map[string]string{"repository_id": repo.String()}, fixture("trivy.json"))
	if code != 201 || out["format"] != "trivy" || out["tool"] != "Trivy" || out["scanner_key"] != "import-other-trivy" || out["records"].(float64) != 4 {
		t.Fatalf("trivy import: %d %v", code, out)
	}
	var cats []string
	rows, _ := appPool.Query(ctx, `SELECT category FROM findings WHERE repository_id = $1 AND 'import-other-trivy' = ANY(scanner_keys) ORDER BY category`, repo)
	for rows.Next() {
		var c string
		_ = rows.Scan(&c)
		cats = append(cats, c)
	}
	rows.Close()
	if strings.Join(cats, ",") != "iac,sca,sca,secrets" {
		t.Errorf("per-record categories: %v", cats)
	}
	var ct string
	var gz []byte
	if err := appPool.QueryRow(ctx, `SELECT a.content_type, a.data_gzip FROM scan_artifacts a JOIN scan_results r ON r.id = a.scan_result_id
		WHERE r.scan_job_id = $1`, out["scan_job_id"]).Scan(&ct, &gz); err != nil {
		t.Fatal(err)
	}
	zr, _ := gzip.NewReader(bytes.NewReader(gz))
	stored, _ := io.ReadAll(zr)
	if !strings.Contains(ct, "pathos-format=trivy") || strings.Contains(string(stored), "AKIAEXAMPLEEXAMPLE12") || !strings.Contains(string(stored), "CVE-2021-23337") {
		t.Errorf("stored report: %s secret kept=%v", ct, strings.Contains(string(stored), "AKIA"))
	}

	// A named format must match the content.
	code, out = upload(analyst, map[string]string{"repository_id": repo.String(), "format": "gitleaks"}, fixture("semgrep.json"))
	if code != 422 || !strings.Contains(out["error"].(map[string]any)["message"].(string), "Semgrep") {
		t.Errorf("format mismatch: %d %v", code, out)
	}
	if code, _ := upload(analyst, map[string]string{"repository_id": repo.String(), "format": "nope"}, fixture("semgrep.json")); code != 400 {
		t.Errorf("unknown format: %d", code)
	}
	// Generic formats need a tool name.
	if code, _ := upload(analyst, map[string]string{"repository_id": repo.String()}, fixture("csv.csv")); code != 400 {
		t.Errorf("csv without tool: %d", code)
	}
	if code, out := upload(analyst, map[string]string{"repository_id": repo.String(), "tool": "Pentest 2026"}, fixture("csv.csv")); code != 201 || out["format"] != "csv" {
		t.Errorf("csv: %d %v", code, out)
	}
	// Unrecognised content is recorded as a failed import.
	code, out = upload(analyst, map[string]string{"repository_id": repo.String(), "tool": "x"}, []byte("[]"))
	if code != 422 || out["import"].(map[string]any)["format"] != "unknown" {
		t.Errorf("ambiguous: %d %v", code, out)
	}

	// Gitleaks: secrets never stored; an empty complete report resolves.
	gl := map[string]string{"repository_id": repo.String(), "format": "gitleaks"}
	if code, out := upload(analyst, gl, fixture("gitleaks.json")); code != 201 || out["records"].(float64) != 2 || out["category"] != "secrets" {
		t.Fatalf("gitleaks: %d %v", code, out)
	}
	var leaked bool
	_ = appPool.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM findings WHERE repository_id = $1 AND (title || description) LIKE '%ghp_EXAMPLE%')`, repo).Scan(&leaked)
	if leaked {
		t.Error("secret value stored in a finding")
	}
	gl["resolve_missing"] = "true"
	if code, out := upload(analyst, gl, []byte("[]")); code != 201 || out["records"].(float64) != 0 {
		t.Fatalf("empty complete gitleaks: %d %v", code, out)
	}
	var open int
	_ = appPool.QueryRow(ctx, `SELECT count(*) FROM findings WHERE repository_id = $1 AND 'import-secrets-gitleaks' = ANY(scanner_keys) AND status = 'open'`, repo).Scan(&open)
	if open != 0 {
		t.Errorf("complete empty import resolves: %d open", open)
	}
}
