package worker

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

func TestNucleiArgs(t *testing.T) {
	t.Setenv("HTTPS_PROXY", "http://egress:3128")
	url := nucleiArgs(&JobTarget{Kind: "url", Reference: "https://app.example", AuthType: "header", HeaderName: "Authorization", HeaderValue: "Bearer s3cr3t",
		MinSeverity: "high"}, "/out/n.jsonl", "")
	joined := strings.Join(url, " ")
	for _, want := range []string{"-u https://app.example", "-etags dos,intrusive,bruteforce,fuzz", "-rl 20", "-proxy http://egress:3128",
		"-H Authorization: Bearer s3cr3t", "-s high,critical", "-ni", "-duc", "-or"} {
		if !strings.Contains(joined, want) {
			t.Errorf("url args missing %q: %s", want, joined)
		}
	}
	if slices.Contains(url, "-dast") {
		t.Error("URL scans must not fuzz")
	}
	api := nucleiArgs(&JobTarget{Kind: "api", Reference: "https://api.example", RateLimit: 500, AuthType: "basic", Username: "u", Password: "p"}, "/o", "/w/openapi.yaml")
	joined = strings.Join(api, " ")
	for _, want := range []string{"-l /w/openapi.yaml", "-im openapi", "-dast", "-rl 20", "-H Authorization: Basic dTpw"} {
		if !strings.Contains(joined, want) {
			t.Errorf("api args missing %q: %s", want, joined)
		}
	}
	if !strings.Contains(joined, "-etags dos,intrusive,bruteforce") {
		t.Error("API scans must exclude intrusive templates")
	}
}

func TestHasWorkflows(t *testing.T) {
	dir := t.TempDir()
	if hasWorkflows(dir) || hasWorkflows("") {
		t.Error("empty repository has no workflows")
	}
	if err := os.MkdirAll(filepath.Join(dir, ".github", "workflows"), 0o700); err != nil {
		t.Fatal(err)
	}
	if hasWorkflows(dir) {
		t.Error("an empty workflows directory has no workflows")
	}
	if err := os.WriteFile(filepath.Join(dir, ".github", "workflows", "ci.yml"), []byte("on: push"), 0o600); err != nil {
		t.Fatal(err)
	}
	if !hasWorkflows(dir) {
		t.Error("workflow not detected")
	}
	action := t.TempDir()
	_ = os.WriteFile(filepath.Join(action, "action.yml"), []byte("runs: {}"), 0o600)
	if !hasWorkflows(action) {
		t.Error("composite action not detected")
	}
}

func TestTargetSecretsRedacted(t *testing.T) {
	api := &eventsAPI{fakeAPI: &fakeAPI{t: t}}
	a := newEventsAgent(t, api)
	r := a.newReporter(Job{JobID: "j1", Target: &JobTarget{Kind: "url", AuthType: "basic", Username: "scanner", Password: "hunter2-pw"}})
	r.log("info", "nuclei", "request with password hunter2-pw and header Basic "+basicAuth("scanner", "hunter2-pw"))
	r.close()
	api.mu.Lock()
	defer api.mu.Unlock()
	if len(api.bodies) == 0 {
		t.Fatal("nothing reported")
	}
	for _, b := range api.bodies {
		if strings.Contains(b, "hunter2-pw") || strings.Contains(b, basicAuth("scanner", "hunter2-pw")) {
			t.Fatalf("target credential leaked: %s", b)
		}
	}
	if (*JobTarget)(nil).secrets() != nil {
		t.Error("nil target has no secrets")
	}
}

func TestCheckReachable(t *testing.T) {
	app := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte("ok")) }))
	defer app.Close()
	for _, k := range []string{"HTTPS_PROXY", "https_proxy", "HTTP_PROXY", "http_proxy"} {
		t.Setenv(k, "")
	}
	if err := checkReachable(t.Context(), app.URL); err != nil {
		t.Fatalf("reachable target: %v", err)
	}
	// A proxy that denies the destination, as Squid does.
	deny := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Squid-Error", "ERR_ACCESS_DENIED 0")
		w.WriteHeader(http.StatusForbidden)
	}))
	defer deny.Close()
	t.Setenv("HTTP_PROXY", deny.URL)
	err := checkReachable(t.Context(), "http://staging.example.test/")
	if err == nil || !strings.Contains(err.Error(), "egress proxy denied access to staging.example.test") || !strings.Contains(err.Error(), "allowlist.txt") {
		t.Fatalf("denied target: %v", err)
	}
	dns := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Squid-Error", "ERR_DNS_FAIL 0")
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer dns.Close()
	t.Setenv("HTTP_PROXY", dns.URL)
	if err := checkReachable(t.Context(), "http://nowhere.example.test/"); err == nil || !strings.Contains(err.Error(), "does not resolve") {
		t.Fatalf("DNS failure: %v", err)
	}
}

func TestWorkflowFiles(t *testing.T) {
	dir := t.TempDir()
	_ = os.MkdirAll(filepath.Join(dir, ".github", "workflows"), 0o700)
	for _, n := range []string{"ci.yml", "release.yaml", "README.md"} {
		_ = os.WriteFile(filepath.Join(dir, ".github", "workflows", n), []byte("on: push"), 0o600)
	}
	got := workflowFiles(dir)
	if !slices.Equal(got, []string{".github/workflows/ci.yml", ".github/workflows/release.yaml"}) {
		t.Errorf("workflow files: %v", got)
	}
	if workflowFiles("") != nil {
		t.Error("no source, no files")
	}
}
