package bench

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"pathos/internal/scanners"
)

// sarif builds a minimal SARIF log with results (file, rule, CWE).
func sarif(tool string, results ...[3]string) string {
	type res struct {
		RuleID     string         `json:"ruleId"`
		Message    map[string]any `json:"message"`
		Locations  []any          `json:"locations"`
		Properties map[string]any `json:"properties"`
	}
	var rs []res
	for _, r := range results {
		rs = append(rs, res{RuleID: r[1], Message: map[string]any{"text": "m"},
			Locations: []any{map[string]any{"physicalLocation": map[string]any{
				"artifactLocation": map[string]any{"uri": r[0]}, "region": map[string]any{"startLine": 3}}}},
			Properties: map[string]any{"cwe": []string{r[2]}}})
	}
	raw, _ := json.Marshal(map[string]any{"version": "2.1.0", "runs": []any{map[string]any{
		"tool": map[string]any{"driver": map[string]any{"name": tool}}, "results": rs}}})
	return string(raw)
}

func writeRun(t *testing.T, dir string, results []localResult, outputs map[string]string) {
	t.Helper()
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	for k, v := range outputs {
		if err := os.WriteFile(filepath.Join(dir, k), []byte(v), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	raw, _ := json.Marshal(results)
	if err := os.WriteFile(filepath.Join(dir, "results.json"), raw, 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestOWASPScoring(t *testing.T) {
	dir := t.TempDir()
	csv := "# test name, category, real vulnerability, cwe\n" +
		"BenchmarkTest00001,sqli,true,89\nBenchmarkTest00002,sqli,false,89\n" +
		"BenchmarkTest00003,xss,true,79\nBenchmarkTest00004,xss,false,79\n"
	if err := os.WriteFile(filepath.Join(dir, "expected.csv"), []byte(csv), 0o644); err != nil {
		t.Fatal(err)
	}
	l, err := OWASPLabels(filepath.Join(dir, "expected.csv"), "t", "s", "GPL-2.0")
	if err != nil || len(l.Cases) != 4 || l.Cases[0].CWE != "CWE-89" || !l.Cases[0].Vulnerable || l.Cases[1].Vulnerable {
		t.Fatalf("labels %+v %v", l, err)
	}
	// Tool a: finds 00001 (TP) and 00002 (FP) with CWE-89, and 00003
	// with the wrong CWE (counts only for the file-only comparison).
	// Tool b: finds 00004 (FP) with CWE-79 in a workspace path, and a
	// finding in a helper file (unrelated).
	writeRun(t, filepath.Join(dir, "a"), []localResult{{Scanner: "opengrep", Version: "1", Status: "succeeded", Output: "opengrep.out"}},
		map[string]string{"opengrep.out": sarif("opengrep",
			[3]string{"src/main/java/BenchmarkTest00001.java", "r1", "CWE-89"},
			[3]string{"src/main/java/BenchmarkTest00002.java", "r1", "CWE-89"},
			[3]string{"src/main/java/BenchmarkTest00003.java", "r2", "CWE-22"})})
	writeRun(t, filepath.Join(dir, "b"), []localResult{
		{Scanner: "semgrep-ce", Version: "2", Status: "succeeded", Output: "semgrep-ce.out"},
		{Scanner: "bearer", Status: "failed", Error: "boom"},
	}, map[string]string{"semgrep-ce.out": sarif("semgrep-ce",
		[3]string{"/work/x/src/testcode/BenchmarkTest00004.py", "r3", "CWE-79"},
		[3]string{"helpers/utils.py", "r4", "CWE-79"})})
	runs, err := LoadRuns(filepath.Join(dir, "a"), filepath.Join(dir, "b"))
	if err != nil {
		t.Fatal(err)
	}
	r := Score(l, runs)
	og, sg, br, all := r.Tools[0], r.Tools[1], r.Tools[2], r.Combined
	if og.Overall.Counts != (Counts{TP: 1, FP: 1, FN: 1, TN: 1}) || og.Findings != 3 || og.Unrelated != 0 {
		t.Errorf("opengrep %+v", og)
	}
	if *og.Overall.Recall != 0.5 || *og.Overall.FPR != 0.5 || *og.Overall.Score != 0 || *og.Overall.Precision != 0.5 {
		t.Errorf("opengrep rates %+v", og.Overall)
	}
	if og.FileOnly == nil || og.FileOnly.TP != 2 || og.FileOnly.FP != 1 {
		t.Errorf("opengrep file-only %+v", og.FileOnly)
	}
	if sg.Overall.Counts != (Counts{TP: 0, FP: 1, FN: 2, TN: 1}) || sg.Unrelated != 1 {
		t.Errorf("semgrep %+v", sg)
	}
	if br.Status != "failed" || br.Overall.Recall != nil {
		t.Errorf("a failed tool has no score: %+v", br)
	}
	// Combined: the union of the detections.
	if all.Overall.Counts != (Counts{TP: 1, FP: 2, FN: 1, TN: 0}) || all.Findings != 5 {
		t.Errorf("combined %+v", all)
	}
	if c := all.ByCategory["xss"]; c.Counts != (Counts{FP: 1, FN: 1}) {
		t.Errorf("combined xss %+v", c)
	}
	md := Markdown([]Result{r})
	for _, want := range []string{"| opengrep | 1 | succeeded |", "| bearer |  | failed: boom |", "PATHOS combined", "| sqli | 1 | 1 |"} {
		if !strings.Contains(md, want) {
			t.Errorf("markdown lacks %q:\n%s", want, md)
		}
	}
}

func TestMergeLikeFindingsTable(t *testing.T) {
	f := func(key, pkg, ver, cve, rule string) scanners.Finding {
		x := scanners.Finding{ScannerKey: key, Category: "sca", PackageName: pkg, PackageVersion: ver, CVE: cve, RuleID: rule, FilePath: "a/package-lock.json"}
		x.Fingerprint = scanners.Fingerprint(x, "")
		return x
	}
	runs := []ToolRun{
		{Scanner: "trivy-fs", Status: "succeeded", Findings: []scanners.Finding{f("trivy-fs", "lodash", "4.17.15", "CVE-2020-8203", "CVE-2020-8203")}},
		{Scanner: "grype", Status: "succeeded", Findings: []scanners.Finding{f("grype", "lodash", "4.17.15", "CVE-2020-8203", "GHSA-p6mc-m468-83gw"),
			f("grype", "lodash", "4.17.15", "CVE-2021-23337", "GHSA-35jh-r3h4-6jhm")}},
	}
	m := Merge(runs)
	if len(m) != 2 || len(m[0].Scanners) != 2 || m[0].Scanners[0] != "grype" {
		t.Fatalf("merged %+v", m)
	}
	l := Labels{Match: MatchSCA, Cases: []Case{
		{ID: "1", Category: "npm", Vulnerable: true, File: "a", Packages: []string{"lodash"}, Vulns: []string{"CVE-2021-23337", "GHSA-35jh-r3h4-6jhm"}},
		{ID: "2", Category: "npm", Vulnerable: true, File: "a", Packages: []string{"lodash"}, Vulns: []string{"CVE-2020-28500"}},
		{ID: "3", Category: "npm", Vulnerable: false, File: "b", Packages: []string{"lodash"}, Vulns: []string{"CVE-2020-8203"}},
	}}
	r := Score(l, runs)
	if r.Tools[0].Overall.Counts != (Counts{FN: 2, TN: 1}) || r.Tools[1].Overall.Counts != (Counts{TP: 1, FN: 1, TN: 1}) {
		t.Errorf("per tool %+v %+v", r.Tools[0].Overall, r.Tools[1].Overall)
	}
	if r.Combined.Findings != 2 || r.Combined.Overall.Counts != (Counts{TP: 1, FN: 1, TN: 1}) {
		t.Errorf("combined %+v", r.Combined)
	}
}

func TestGenerateSecretsDeterministic(t *testing.T) {
	a, b := t.TempDir(), t.TempDir()
	la, err := GenerateSecrets(a, 7)
	if err != nil {
		t.Fatal(err)
	}
	lb, _ := GenerateSecrets(b, 7)
	if len(la.Cases) != len(lb.Cases) || len(la.Cases) < 100 {
		t.Fatalf("cases %d %d", len(la.Cases), len(lb.Cases))
	}
	pos := 0
	for i, c := range la.Cases {
		if c.ID != lb.Cases[i].ID || c.Category != lb.Cases[i].Category || c.Vulnerable != lb.Cases[i].Vulnerable {
			t.Fatalf("case %d differs: %+v %+v", i, c, lb.Cases[i])
		}
		x, err := os.ReadFile(filepath.Join(a, "src", c.File))
		if err != nil {
			t.Fatal(err)
		}
		y, _ := os.ReadFile(filepath.Join(b, "src", c.File))
		if string(x) != string(y) {
			t.Fatalf("%s differs between runs with the same seed", c.File)
		}
		if strings.Contains(string(x), "%!") {
			t.Errorf("%s: formatting error: %s", c.File, x)
		}
		if c.Vulnerable {
			pos++
		}
	}
	if pos == 0 || pos == len(la.Cases) {
		t.Errorf("positives %d of %d", pos, len(la.Cases))
	}
}
