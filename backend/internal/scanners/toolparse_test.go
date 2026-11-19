package scanners

import (
	"encoding/json"
	"slices"
	"strings"
	"testing"
)

func TestToolParserSpec(t *testing.T) {
	m := &JSONMap{RuleID: "id", Title: "msg"}
	for _, c := range []struct {
		spec string
		m    *JSONMap
		kind string
		ok   bool
	}{
		{"", nil, "sarif", true},
		{"sarif", nil, "sarif", true},
		{"import:bandit", nil, "import", true},
		{"import:no-such-format", nil, "", false},
		{"import:Bad Format", nil, "", false},
		{"jsonmap", m, "jsonmap", true},
		{"jsonmap", nil, "", false},
		{"sarif", m, "", false},
		{"xml", nil, "", false},
	} {
		p, err := ParseToolParserSpec(c.spec, c.m)
		if (err == nil) != c.ok || (c.ok && p.Kind != c.kind) {
			t.Errorf("%q: %+v %v", c.spec, p, err)
		}
	}
	for _, bad := range []JSONMap{
		{},                             // no rule id
		{RuleID: "a b"},                // not a path
		{RuleID: "x", Records: "a..b"}, // bad records path
		{RuleID: "{x"},                 // unbalanced template
		{RuleID: "x", SeverityMap: map[string]string{"e": "urgent"}}, // not a PATHOS severity
		{RuleID: "x", DefaultSeverity: "severe"},
		{RuleID: "x", Category: "eol"},
		{RuleID: "x", Category: "nope"},
	} {
		if err := (ToolParser{Kind: "jsonmap", Map: &bad}).Validate(); err == nil {
			t.Errorf("invalid mapping accepted: %+v", bad)
		}
	}
	// Uploaded parsers are validated the same way.
	if (ToolParser{Kind: "import", Format: "bandit", Map: m}).Validate() == nil || (ToolParser{Kind: "shell"}).Validate() == nil {
		t.Error("invalid parser accepted")
	}
}

func TestJSONMap(t *testing.T) {
	report := `{"vulns": [
	  {"id": 7, "pkg": {"name": "lodash", "version": "4.17.20", "fix": "4.17.21"}, "sev": "HIGH", "aliases": ["GHSA-x", "CVE-2021-23337"],
	   "cwes": [94, "CWE-77"], "score": 7.2, "where": {"path": "/work/j1/src/package-lock.json", "line": 12}, "text": "Command injection\nin template"},
	  {"id": 8, "sev": "weird", "where": {"path": "app/x.js"}, "text": "second"},
	  {"id": 8, "sev": "weird", "where": {"path": "app/x.js"}, "text": "second"}
	]}`
	m := &JSONMap{Records: "vulns", RuleID: "R{id}", Message: "text", Severity: "sev", SeverityMap: map[string]string{"HIGH": "high"},
		DefaultSeverity: "low", File: "where.path", Line: "where.line", Package: "pkg.name", Version: "pkg.version",
		FixedVersion: "pkg.fix", CVE: "aliases", CWE: "cwes", CVSS: "score"}
	p := ToolParser{Kind: "jsonmap", Map: m}
	fs, err := ParseToolOutput("plugin-sca-demo", p, []byte(report))
	if err != nil || len(fs) != 3 {
		t.Fatalf("parse: %v %d", err, len(fs))
	}
	f := fs[0]
	if f.RuleID != "R7" || f.Title != "Command injection" || f.Severity != "high" || f.CVE != "CVE-2021-23337" ||
		f.PackageName != "lodash" || f.PackageVersion != "4.17.20" || f.FixedVersion != "4.17.21" || f.FilePath != "package-lock.json" ||
		f.StartLine == nil || *f.StartLine != 12 || f.CVSS == nil || *f.CVSS != 7.2 || !slices.Equal(f.CWE, []string{"CWE-94", "CWE-77"}) ||
		f.Category != "sca" || f.ScannerKey != "plugin-sca-demo" {
		t.Errorf("mapped finding: %+v", f)
	}
	if fs[1].Severity != "low" || fs[1].StartLine != nil {
		t.Errorf("default severity, no line: %+v", fs[1])
	}
	// Identical records stay two findings (outside SCA, whose identity is
	// package, version and vulnerability).
	if code, _ := ParseToolOutput("plugin-sast-demo", p, []byte(report)); len(code) != 3 || code[1].Fingerprint == code[2].Fingerprint {
		t.Error("identical records are told apart")
	}
	for _, f := range fs {
		loc, err := LocateToolOutput("plugin-sca-demo", p, []byte(report), f.Fingerprint)
		if err != nil || !strings.Contains(string(loc.Raw), `"sev"`) {
			t.Errorf("locate: %v %s", err, loc.Raw)
		}
	}
	// The stored parser locates the same records.
	stored, _ := json.Marshal(p)
	if loc, err := LocateStored("plugin-sca-demo", "application/json", stored, []byte(report), fs[0].Fingerprint); err != nil || loc == nil {
		t.Errorf("locate stored: %v", err)
	}

	// JSON Lines, with and without a records path.
	lines := "{\"r\":[{\"c\":1,\"m\":\"a\"}]}\n\n{\"r\":[{\"c\":2,\"m\":\"b\"},{\"c\":3,\"m\":\"c\"}]}\n"
	fs, err = ParseToolOutput("plugin-code-quality-lint", ToolParser{Kind: "jsonmap", Map: &JSONMap{Lines: true, Records: "r", RuleID: "L{c}", Title: "m"}}, []byte(lines))
	if err != nil || len(fs) != 3 || fs[2].RuleID != "L3" || fs[0].Category != "code-quality" || fs[0].Severity != "info" {
		t.Errorf("json lines: %v %+v", err, fs)
	}
	fs, err = ParseToolOutput("plugin-sast-x", ToolParser{Kind: "jsonmap", Map: &JSONMap{Lines: true, RuleID: "rule|id", Title: "m"}}, []byte("{\"id\":\"A\",\"m\":\"x\"}\n{\"rule\":\"B\",\"m\":\"y\"}\n"))
	if err != nil || len(fs) != 2 || fs[0].RuleID != "A" || fs[1].RuleID != "B" {
		t.Errorf("alternatives: %v %+v", err, fs)
	}
	// A top-level array; an empty report has no findings.
	if fs, err := ParseToolOutput("plugin-sast-x", ToolParser{Kind: "jsonmap", Map: &JSONMap{RuleID: "id"}}, []byte(`[{"id":"Z"}]`)); err != nil || len(fs) != 1 {
		t.Errorf("array: %v %d", err, len(fs))
	}
	if fs, err := ParseToolOutput("plugin-sast-x", ToolParser{Kind: "jsonmap", Map: &JSONMap{RuleID: "id"}}, nil); err != nil || len(fs) != 0 {
		t.Errorf("empty: %v %d", err, len(fs))
	}
	// Records without a rule id are an error, not silently dropped.
	if _, err := ParseToolOutput("plugin-sast-x", ToolParser{Kind: "jsonmap", Map: &JSONMap{RuleID: "id"}}, []byte(`[{"x":1}]`)); err == nil {
		t.Error("missing rule id")
	}
	// Secrets in messages are redacted like every import.
	fs, _ = ParseToolOutput("plugin-secrets-x", ToolParser{Kind: "jsonmap", Map: &JSONMap{RuleID: "id", Message: "m"}},
		[]byte(`[{"id":"k","m":"token ghp_abcdefghijklmnopqrstuvwxyz0123456789"}]`))
	if len(fs) != 1 || strings.Contains(fs[0].Description, "ghp_abcdefghijklmnopqrstuvwxyz0123456789") {
		t.Errorf("redaction: %+v", fs)
	}
}

func TestToolOutputImportAndSARIF(t *testing.T) {
	bandit := `{"results":[{"code":"1 import os\n","filename":"/work/j/src/a.py","issue_confidence":"HIGH","issue_severity":"LOW",
	  "issue_cwe":{"id":78},"issue_text":"Consider possible security implications","line_number":1,"line_range":[1],"test_id":"B404","test_name":"blacklist"}]}`
	fs, err := ParseToolOutput("bandit", ToolParser{Kind: "import", Format: "bandit"}, []byte(bandit))
	if err != nil || len(fs) != 1 || fs[0].ScannerKey != "bandit" || fs[0].Category != "sast" || fs[0].FilePath != "a.py" || fs[0].RuleID != "B404" {
		t.Fatalf("import parser: %v %+v", err, fs)
	}
	if loc, err := LocateToolOutput("bandit", ToolParser{Kind: "import", Format: "bandit"}, []byte(bandit), fs[0].Fingerprint); err != nil || loc == nil {
		t.Errorf("locate import: %v", err)
	}
	sarif := `{"version":"2.1.0","runs":[{"tool":{"driver":{"name":"x"}},"results":[{"ruleId":"R","level":"error","message":{"text":"m"},
	  "locations":[{"physicalLocation":{"artifactLocation":{"uri":"b.js"},"region":{"startLine":2}}}]}]}]}`
	fs, err = ParseToolOutput("njsscan", ToolParser{Kind: "sarif"}, []byte(sarif))
	if err != nil || len(fs) != 1 || fs[0].Severity != "high" {
		t.Errorf("sarif: %v %+v", err, fs)
	}
	if ToolContentType(ToolParser{Kind: "import", Format: "bandit"}) != ImportContentType("bandit") ||
		ToolContentType(ToolParser{Kind: "jsonmap", Map: &JSONMap{Lines: true}}) != "application/x-ndjson" {
		t.Error("content types")
	}
}

func TestCategoriesAndKeys(t *testing.T) {
	for _, c := range []string{"api", "iast", "mobile", "fuzz", "crypto", "cicd", "ai", "runtime", "compliance", "database", "code-quality"} {
		if !IsFindingCategory(c) || !slices.Contains(ToolCategories, c) {
			t.Errorf("category %s", c)
		}
		if (Scanner{Category: c}).FindingCategory() != c {
			t.Errorf("finding category of %s", c)
		}
		key := PluginKey(c, "tool-x")
		sc, ok := ResolvePlugin(key)
		if !ok || sc.Category != c || !IsPluginKey(key) || !ManifestRouted(key) {
			t.Errorf("plugin key %s: %+v %v", key, sc, ok)
		}
		ik, err := ImportKey(c, "Tool X")
		if err != nil || !IsImportKey(ik) {
			t.Errorf("import key %s: %v", ik, err)
		}
		if r, ok := Resolve(ik); !ok || r.Category != c {
			t.Errorf("resolve %s: %+v", ik, r)
		}
	}
	if IsPluginKey("plugin-eol-x") || slices.Contains(ToolCategories, "eol") {
		t.Error("eol is not a tool category")
	}
	if (Scanner{Category: "sbom"}).FindingCategory() != "other" {
		t.Error("non-finding categories map to other")
	}
	// Built-in core tools are not routed; family tools and plugins are.
	if ManifestRouted(Gitleaks) || ManifestRouted(TrivyFS) || ManifestRouted(EndOfLife) || !ManifestRouted("bandit") || ManifestRouted("nope") {
		t.Error("ManifestRouted")
	}
	if !slices.Contains(RoutedCatalogKeys(), "shellcheck") || slices.Contains(RoutedCatalogKeys(), Opengrep) {
		t.Error("RoutedCatalogKeys")
	}
}
