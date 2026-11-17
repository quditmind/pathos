package scanners

import (
	"os"
	"slices"
	"testing"
)

func TestNucleiJSONL(t *testing.T) {
	raw, err := os.ReadFile("testdata/nuclei.jsonl")
	if err != nil {
		t.Fatal(err)
	}
	fs, err := Parse(Nuclei, raw)
	if err != nil {
		t.Fatal(err)
	}
	if len(fs) != 2 {
		t.Fatalf("want 2 findings, got %d", len(fs))
	}
	h, sq := fs[0], fs[1]
	if h.Category != "dast" || h.Severity != "info" || h.Confidence != "low" || h.FilePath != "https://app.example.test" {
		t.Errorf("headers finding: %+v", h)
	}
	if h.Title != "HTTP Missing Security Headers (content-security-policy)" || !slices.Equal(h.CWE, []string{"CWE-693"}) {
		t.Errorf("headers title/cwe: %q %v", h.Title, h.CWE)
	}
	if sq.Severity != "critical" || sq.CVSS == nil || *sq.CVSS != 10 || sq.CVSSVersion != "3.1" || sq.Confidence != "medium" {
		t.Errorf("sqli finding: %+v", sq)
	}
	if sq.Title != `Error based SQL Injection in query parameter "id"` || sq.FilePath != "https://app.example.test/api/orders?id=1%27" {
		t.Errorf("sqli title/location: %q %q", sq.Title, sq.FilePath)
	}
	if sq.Fingerprint == "" || sq.Fingerprint == h.Fingerprint {
		t.Error("fingerprints must be set and distinct")
	}
	// Identity is stable across runs.
	again, _ := Parse(Nuclei, raw)
	if again[1].Fingerprint != sq.Fingerprint {
		t.Error("fingerprint is not stable")
	}
	// An empty report is valid (nothing found).
	if fs, err := Parse(Nuclei, nil); err != nil || len(fs) != 0 {
		t.Errorf("empty report: %v %d", err, len(fs))
	}
	if _, err := Parse(Nuclei, []byte("{not json}\n")); err == nil {
		t.Error("malformed line must fail")
	}
	if _, err := Parse(Nuclei, []byte(`{"info":{}}`)); err == nil {
		t.Error("a result without template-id must fail")
	}
}

func TestZizmorSARIF(t *testing.T) {
	fs := load(t, Zizmor)
	if len(fs) != 5 {
		t.Fatalf("want 5 findings, got %d", len(fs))
	}
	by := map[string]Finding{}
	for _, f := range fs {
		by[f.RuleID] = f
		if f.Category != "iac" || f.FilePath != ".github/workflows/ci.yml" || f.StartLine == nil {
			t.Errorf("finding %+v", f)
		}
	}
	ti := by["zizmor/template-injection"]
	if ti.Severity != "high" || ti.Confidence != "high" || ti.Title != "code injection via template expansion" {
		t.Errorf("template injection: severity %s confidence %s title %q", ti.Severity, ti.Confidence, ti.Title)
	}
	// zizmor's own severity wins over the SARIF level ("warning" = medium,
	// "error" = high): artipacked is Medium / Low confidence.
	ap := by["zizmor/artipacked"]
	if ap.Severity != "medium" || ap.Confidence != "low" {
		t.Errorf("artipacked: %s %s", ap.Severity, ap.Confidence)
	}
}

func TestTrivyImageParsesPackages(t *testing.T) {
	raw, err := os.ReadFile("testdata/trivy-fs.sarif")
	if err != nil {
		t.Fatal(err)
	}
	img, err := Parse(TrivyImage, raw)
	if err != nil {
		t.Fatal(err)
	}
	fsys, _ := Parse(TrivyFS, raw)
	if len(img) == 0 || len(img) != len(fsys) {
		t.Fatalf("image %d, fs %d", len(img), len(fsys))
	}
	for i, f := range img {
		if f.Category != "container" || f.PackageName == "" || f.PackageVersion == "" || f.CVE == "" {
			t.Errorf("image finding without package data: %+v", f)
		}
		if f.Fingerprint == fsys[i].Fingerprint {
			t.Error("image and repository findings must not share a fingerprint")
		}
	}
}

func TestTargetScanners(t *testing.T) {
	for kind, keys := range TargetScanners {
		for _, k := range keys {
			sc, ok := Lookup(k)
			if !ok || !sc.AdapterAvailable {
				t.Errorf("%s target scanner %s is not runnable", kind, k)
			}
		}
	}
	if !IsTargetOnly(Nuclei) || !IsTargetOnly(TrivyImage) || IsTargetOnly(Grype) || IsTargetOnly(Zizmor) {
		t.Error("target-only flags")
	}
	if sc, _ := Lookup(Zizmor); !sc.DefaultEnabled || sc.TargetOnly {
		t.Error("zizmor runs in repository scans by default")
	}
}
