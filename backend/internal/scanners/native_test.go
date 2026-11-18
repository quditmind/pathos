package scanners

import (
	"os"
	"slices"
	"strings"
	"testing"
)

func TestMisconfigurationCategory(t *testing.T) {
	raw, err := os.ReadFile("testdata/opengrep-misconfig.sarif")
	if err != nil {
		t.Fatal(err)
	}
	fs, err := Parse(Opengrep, raw)
	if err != nil {
		t.Fatal(err)
	}
	by := map[string]Finding{}
	for _, f := range fs {
		by[f.RuleID] = f
	}
	dbg := by["pathos.misconfig.django.debug-true"]
	if dbg.Category != "misconfiguration" || dbg.FilePath != "django/settings.py" || dbg.Severity != "high" ||
		!slices.Contains(dbg.CWE, "CWE-489") || dbg.Confidence != "high" {
		t.Errorf("Django DEBUG finding: %+v", dbg)
	}
	if f := by["pathos.misconfig.django.csrf-exempt"]; f.Category != "misconfiguration" || f.Severity != "medium" {
		t.Errorf("csrf_exempt: %+v", f)
	}
	if f := by["pathos.misconfig.django.transport-security-disabled"]; f.Severity != "low" {
		t.Errorf("INFO rules are low: %+v", f)
	}
	// A hard-coded secret key never ends up in the finding's code context.
	if f := by["pathos.misconfig.django.insecure-secret-key"]; f.Category != "misconfiguration" || strings.Contains(f.Snippet, "django-insecure") {
		t.Errorf("secret key finding: %+v", f)
	}
	// The baseline security rules stay SAST.
	for _, f := range load(t, Opengrep) {
		if f.Category != "sast" {
			t.Errorf("%s: %s", f.RuleID, f.Category)
		}
	}
	if !misconfigurationRule("x.rules.custom.rule", map[string]any{"tags": []any{"CWE-16", "misconfiguration"}}) {
		t.Error("administrator rules opt in with metadata category misconfiguration")
	}
}

func TestNativeReport(t *testing.T) {
	raw := []byte(`{"tool":"binary-hardening","version":"1.1.0","findings":[
	  {"rule_id":"binary/elf-no-pie","title":"Executable is not position independent (no PIE)","description":"d","severity":"medium",
	   "confidence":"high","cwe":["CWE-693","bogus"],"file_path":"/work/j1/src/bin/app","key":"binary/elf-no-pie","evidence":"format: ELF64"},
	  {"rule_id":"binary/elf-no-pie","title":"t","severity":"weird","file_path":"bin/other","key":"binary/elf-no-pie"}]}`)
	fs, err := Parse(BinaryHardening, raw)
	if err != nil || len(fs) != 2 {
		t.Fatalf("%v %d", err, len(fs))
	}
	f := fs[0]
	if f.Category != "binary" || f.FilePath != "bin/app" || f.Severity != "medium" || f.Confidence != "high" ||
		len(f.CWE) != 1 || f.Snippet != "format: ELF64" {
		t.Errorf("%+v", f)
	}
	if fs[1].Severity != "medium" || fs[0].Fingerprint == fs[1].Fingerprint {
		t.Errorf("unknown severities default to medium; files have their own fingerprint: %+v", fs[1])
	}
	// The fingerprint is stable across scanner versions.
	again, _ := Parse(BinaryHardening, []byte(strings.Replace(string(raw), `"version":"1.1.0"`, `"version":"1.2.0"`, 1)))
	if again[0].Fingerprint != f.Fingerprint {
		t.Error("fingerprint changed with the scanner version")
	}
	if _, err := Parse(ClamAV, []byte(`{"findings":[{"rule_id":"bad id with spaces"}]}`)); err == nil {
		t.Error("invalid rule IDs are rejected")
	}
	if _, err := Parse(ClamAV, []byte(`not json`)); err == nil {
		t.Error("invalid report")
	}
	if sc, _ := Lookup(ClamAV); sc.FindingCategory() != "malware" || !sc.AdapterAvailable || sc.DefaultEnabled || sc.TargetOnly {
		t.Errorf("clamav catalog entry: %+v", sc)
	}
	if sc, _ := Lookup(LicenseCheck); sc.FindingCategory() != "license" || !sc.DefaultEnabled {
		t.Errorf("licensecheck catalog entry: %+v", sc)
	}
	if !slices.Contains(TargetScanners["artifact"], BinaryHardening) {
		t.Error("binary hardening runs for build artifacts")
	}
}

func TestParseFileLicenses(t *testing.T) {
	ls, err := ParseFileLicenses([]byte(`{"licenses":[
	  {"path":"/work/j1/src/a.c","spdx":"GPL-3.0-only","method":"spdx-tag","line":1,"alternatives":["MIT","bad id!","GPL-3.0-only"]},
	  {"path":"a.c","spdx":"GPL-3.0-only","method":"spdx-tag"},
	  {"path":"b.c","spdx":"not valid!"},
	  {"path":"","spdx":"MIT"},
	  {"path":"LICENSE","spdx":"MIT","method":"other","percent":98.5}]}`))
	if err != nil || len(ls) != 2 {
		t.Fatalf("%v %+v", err, ls)
	}
	if ls[0].Path != "a.c" || len(ls[0].Alternatives) != 1 || ls[0].Alternatives[0] != "MIT" || ls[1].Method != "license-text" {
		t.Errorf("%+v", ls)
	}
}
