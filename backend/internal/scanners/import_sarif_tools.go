package scanners

import (
	"encoding/json"
	"strings"
)

// Named SARIF formats: SARIF 2.1 logs of a known tool. They are parsed by
// the SARIF importer like any SARIF log; the format names the tool (so an
// import needs no "tool" field and gets its own scanner key) and its
// default category. A SARIF log is detected as a named format when the
// driver of every run (runs[].tool.driver.name) is a name of that format's
// tool; a log of several tools, or of an unknown one, stays "sarif".

type sarifTool struct {
	id, label, tool, category string
	order                     int
	// drivers are the tool.driver.name values the tool writes (compared
	// without case).
	drivers []string
}

// sarifSanitizers remove secret values from the logs of secret scanners
// before they are stored.
var sarifSanitizers = map[string]func([]byte) []byte{"sarif-gitleaks": sanitizeSARIFSnippets}

var sarifTools = []sarifTool{
	// SAST and code quality.
	{"codeql", "CodeQL (SARIF)", "CodeQL", "sast", 500, []string{"CodeQL"}},
	{"sarif-semgrep", "Semgrep (SARIF)", "Semgrep", "sast", 501, []string{"Semgrep OSS", "Semgrep PRO", "Semgrep", "Semgrep Code"}},
	{"devskim", "Microsoft DevSkim (SARIF)", "DevSkim", "sast", 502, []string{"DevSkim"}},
	{"psscriptanalyzer", "PSScriptAnalyzer (SARIF, ConvertToSARIF)", "PSScriptAnalyzer", "code-quality", 503, []string{"PSScriptAnalyzer"}},
	{"msvc-analyze", "Microsoft C/C++ code analysis, MSVC /analyze (SARIF)", "MSVC Code Analysis", "sast", 504, []string{"PREfast", "MSVC", "Microsoft (R) C/C++ Optimizing Compiler"}},
	{"roslyn", "Roslyn analyzers, .NET compiler error log (SARIF)", "Roslyn Analyzers", "code-quality", 505,
		[]string{"Microsoft (R) Visual C# Compiler", "Microsoft (R) Visual Basic Compiler", "Microsoft.CodeAnalysis.NetAnalyzers"}},
	{"sonarlint", "SonarLint / SonarQube for IDE (SARIF)", "SonarLint", "code-quality", 506, []string{"SonarLint", "SonarQube for IDE"}},
	{"infer", "Infer (SARIF, --sarif)", "Infer", "sast", 507, []string{"Infer"}},
	{"pysa", "Pysa (SARIF, SAPP export)", "Pysa", "sast", 508, []string{"Pysa"}},
	{"mariana-trench", "Mariana Trench (SARIF, SAPP export)", "Mariana Trench", "mobile", 509, []string{"Mariana Trench"}},
	{"clang-analyzer", "Clang Static Analyzer (SARIF)", "Clang Static Analyzer", "sast", 510, []string{"clang"}},
	{"sarif-eslint", "ESLint (SARIF, @microsoft/eslint-formatter-sarif)", "ESLint", "sast", 511, []string{"ESLint"}},
	{"sarif-brakeman", "Brakeman (SARIF)", "Brakeman", "sast", 512, []string{"Brakeman"}},
	{"sarif-fortify", "Fortify (SARIF)", "Fortify SCA", "sast", 513,
		[]string{"Fortify", "Fortify SCA", "Fortify Static Code Analyzer", "OpenText Fortify", "Fortify on Demand", "Fortify SSC"}},
	{"sarif-veracode", "Veracode Pipeline Scan (SARIF)", "Veracode", "sast", 514,
		[]string{"Veracode", "Veracode Static Analysis Pipeline Scan", "Veracode Pipeline Scan", "Veracode Static Analysis"}},
	{"sarif-mend-sast", "Mend SAST (SARIF)", "Mend", "sast", 515, []string{"Mend SAST", "Mend.io SAST", "Mend"}},
	{"datadog-sast", "Datadog Static Analyzer (SARIF)", "Datadog SAST", "sast", 516, []string{"datadog-static-analyzer"}},
	{"detekt", "detekt (SARIF)", "detekt", "code-quality", 517, []string{"detekt"}},
	{"pvs-studio", "PVS-Studio (SARIF)", "PVS-Studio", "sast", 518, []string{"PVS-Studio"}},
	{"binskim", "BinSkim (SARIF)", "BinSkim", "binary", 519, []string{"BinSkim"}},
	// IaC, CI/CD and API definitions.
	{"sarif-snyk-iac", "Snyk IaC (SARIF)", "Snyk IaC", "iac", 530, []string{"Snyk IaC"}},
	{"sarif-kics", "KICS (SARIF)", "KICS", "iac", 531, []string{"KICS"}},
	{"sarif-tfsec", "tfsec (SARIF)", "tfsec", "iac", 532, []string{"tfsec", "defsec"}},
	{"sarif-checkov", "Checkov (SARIF)", "Checkov", "iac", 533, []string{"Checkov"}},
	{"ansible-lint", "ansible-lint (SARIF)", "ansible-lint", "iac", 534, []string{"ansible-lint"}},
	{"sarif-zizmor", "zizmor (SARIF)", "zizmor", "cicd", 535, []string{"zizmor"}},
	{"spectral", "Spectral (SARIF)", "Spectral", "api", 536, []string{"spectral"}},
	// Dependencies, images and secrets.
	{"sarif-grype", "Grype (SARIF)", "Grype", "sca", 540, []string{"Grype"}},
	{"sarif-trivy", "Trivy (SARIF)", "Trivy", "", 541, []string{"Trivy"}},
	{"sarif-osv-scanner", "OSV-Scanner (SARIF)", "OSV-Scanner", "sca", 542, []string{"osv-scanner"}},
	{"sarif-gitleaks", "Gitleaks (SARIF)", "Gitleaks", "secrets", 543, []string{"gitleaks"}},
}

// sarifDrivers maps a lower-case driver name to its named SARIF format,
// including the SARIF formats registered elsewhere.
var sarifDrivers = map[string]string{
	"snykcode": "snyk-code", "docker scout": "docker-scout", "nowsecure": "nowsecure", "clusterfuzzlite/cifuzz": "clusterfuzzlite",
}

func init() {
	for _, t := range sarifTools {
		registerImportFormat(ImportFormat{ID: t.id, Label: t.label, Tool: t.tool, Category: t.category, Media: "sarif", Parser: "sarif", Order: t.order,
			sanitize: sarifSanitizers[t.id]})
		for _, d := range t.drivers {
			d = strings.ToLower(d)
			if _, dup := sarifDrivers[d]; dup {
				panic("duplicate SARIF driver " + d)
			}
			sarifDrivers[d] = t.id
		}
	}
}

// sarifFormatOf returns the named SARIF format of a SARIF log ("sarif"
// when its tool is unknown or it has runs of several tools).
func sarifFormatOf(p *importProbe) string {
	var runs []struct {
		Tool struct {
			Driver struct {
				Name string `json:"name"`
			} `json:"driver"`
		} `json:"tool"`
	}
	if json.Unmarshal(p.keys["runs"], &runs) != nil || len(runs) == 0 {
		return "sarif"
	}
	found := ""
	for _, r := range runs {
		id, ok := sarifDrivers[strings.ToLower(strings.TrimSpace(r.Tool.Driver.Name))]
		if !ok || (found != "" && id != found) {
			return "sarif"
		}
		found = id
	}
	if _, ok := importFormats[found]; !ok {
		return "sarif"
	}
	return found
}

// sanitizeSARIFSnippets replaces the text of every region snippet of a
// SARIF log (secret scanners put the secret there) with [REDACTED]. Finding
// identity does not depend on snippets of secrets.
func sanitizeSARIFSnippets(raw []byte) []byte {
	var x any
	if json.Unmarshal(raw, &x) != nil {
		return raw
	}
	var walk func(any)
	walk = func(v any) {
		switch t := v.(type) {
		case []any:
			for _, e := range t {
				walk(e)
			}
		case map[string]any:
			for k, e := range t {
				if s, ok := e.(map[string]any); ok && k == "snippet" {
					if txt, ok := s["text"].(string); ok && txt != "" {
						s["text"] = "[REDACTED]"
					}
					continue
				}
				walk(e)
			}
		}
	}
	walk(x)
	b, err := json.Marshal(x)
	if err != nil {
		return raw
	}
	return b
}
