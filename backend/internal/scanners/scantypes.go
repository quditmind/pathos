package scanners

import "slices"

// ScanType is one kind of security testing PATHOS reports on. Each type
// names the finding categories its findings are recorded under and the
// catalog tools that cover it; the API adds what is runnable in a
// deployment (GET /api/v1/scan-types) from the workers that are online.
type ScanType struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Description string `json:"description"`
	// Categories are the findings.category values of this type's findings.
	Categories []string `json:"categories"`
	// Tools are catalog keys (Catalog, Builtins or Syft) that cover the
	// type. Declarative adapters add themselves through their manifest's
	// scan_types.
	Tools []string `json:"tools"`
	// ImportFormats are import formats that carry this type's results in
	// addition to those whose default category is the type's first
	// category: formats whose findings keep their own categories (Trivy,
	// GitLab, linters with security and code-quality rules), and formats
	// recorded under another category (Nuclei and ZAP for API security).
	ImportFormats []string `json:"-"`
	// Note explains a mapping that is not obvious (empty for most types).
	Note string `json:"note,omitempty"`
}

// ScanTypes are the 25 scan types, in display order.
var ScanTypes = []ScanType{
	{ID: "sast", Name: "SAST", Description: "Static analysis of source code for security weaknesses",
		Categories: []string{"sast"},
		Tools: []string{Opengrep, "semgrep-ce", "codeql", "bandit", "gosec", "brakeman", "spotbugs", "pmd", "flawfinder", "cppcheck", "infer",
			"pysa", "psalm", "phpstan", "ruff", "eslint-security", "njsscan", "sobelow"},
		ImportFormats: []string{"veracode", "coverity", "klocwork", "horusec", "bearer", "spotbugs", "pmd", "cppcheck", "psalm", "ruff", "pylint",
			"golangci-lint", "codacy", "gitlab"}},
	{ID: "dast", Name: "DAST", Description: "Dynamic testing of running web applications",
		Categories:    []string{"dast"},
		Tools:         []string{Nuclei, "zap", EndpointCheck},
		ImportFormats: []string{"gitlab"}},
	{ID: "sca", Name: "SCA", Description: "Known vulnerabilities in open-source dependencies",
		Categories: []string{"sca", "eol"},
		Tools: []string{TrivyFS, Grype, OSVScanner, "dependency-check", "retirejs", "govulncheck", "pip-audit", "cargo-audit", "bundler-audit",
			"dep-scan", EndOfLife},
		ImportFormats: []string{"trivy", "veracode", "gitlab"}},
	{ID: "secrets", Name: "Secrets", Description: "Credentials and keys committed to repositories",
		Categories:    []string{"secrets"},
		Tools:         []string{Gitleaks, "trufflehog", "detect-secrets", "kingfisher"},
		ImportFormats: []string{"trivy", "trivy-k8s", "bearer", "horusec", "gitlab"}},
	{ID: "iac", Name: "Infrastructure as code", Description: "Misconfigurations in Terraform, Kubernetes, CloudFormation and similar files",
		Categories:    []string{"iac"},
		Tools:         []string{Checkov, "kics", "kube-linter", "kubescape", "tflint", "conftest", "hadolint"},
		ImportFormats: []string{"trivy", "trivy-k8s", "polaris"}},
	{ID: "container", Name: "Container", Description: "Vulnerabilities and misconfigurations of container images",
		Categories:    []string{"container"},
		Tools:         []string{TrivyImage, "dockle"},
		ImportFormats: []string{"trivy", "trivy-k8s", "gitlab"}},
	{ID: "api", Name: "API security", Description: "Testing of APIs described by an OpenAPI document",
		Categories:    []string{"api", "dast"},
		Tools:         []string{Nuclei, "schemathesis"},
		ImportFormats: []string{"nuclei", "zap", "burp", "burp-enterprise", "stackhawk", "gitlab"},
		Note:          "Nuclei runs its DAST templates against API targets; those findings, and imports of DAST tools, are recorded as dast"},
	{ID: "iast", Name: "IAST", Description: "Interactive testing by agents inside the running application",
		Categories: []string{"iast"}},
	{ID: "mobile", Name: "Mobile (MAST)", Description: "Security testing of Android and iOS applications",
		Categories:    []string{"mobile"},
		Tools:         []string{"mobsfscan"},
		ImportFormats: []string{"mobsfscan"}},
	{ID: "fuzzing", Name: "Fuzzing", Description: "Generated inputs that look for crashes and unexpected behaviour",
		Categories:    []string{"fuzz"},
		ImportFormats: []string{"gitlab"}},
	{ID: "license", Name: "Licence", Description: "Licences of dependencies and source files",
		Categories: []string{"license"},
		Tools:      []string{LicenseCheck, "scancode", "trivy-license"}},
	{ID: "sbom", Name: "SBOM", Description: "Software bill of materials (inventory; vulnerabilities are reported by SCA)",
		Categories: []string{},
		Tools:      []string{Syft},
		Note:       "SBOM generation produces an inventory, not findings"},
	{ID: "malware", Name: "Malware", Description: "Malicious files in repositories and build artifacts",
		Categories:    []string{"malware"},
		Tools:         []string{ClamAV},
		ImportFormats: []string{"modelscan"},
		Note:          "ModelScan imports (unsafe operators in model files) are recorded under ai unless imported with category other"},
	{ID: "code-quality", Name: "Code-quality security", Description: "Code-quality defects with security impact (unsafe shell, error handling, resource use)",
		Categories: []string{"code-quality"},
		Tools:      []string{"shellcheck", "pmd", "ruff"},
		ImportFormats: []string{"coverity", "klocwork", "spotbugs", "pmd", "cppcheck", "psalm", "ruff", "pylint", "golangci-lint", "codacy",
			"polaris"}},
	{ID: "supply-chain", Name: "Supply chain", Description: "Provenance, signatures and project health of components",
		Categories: []string{"supply-chain"},
		Tools:      []string{Cosign, "scorecard"}},
	{ID: "crypto", Name: "Cryptography", Description: "Weak algorithms, keys and certificates",
		Categories:    []string{"crypto"},
		ImportFormats: []string{"testssl", "sslyze", "sslscan"},
		Note:          "TLS scanner imports (testssl.sh, SSLyze, sslscan) are recorded as misconfiguration"},
	{ID: "configuration", Name: "Configuration", Description: "Insecure framework and application configuration",
		Categories: []string{"misconfiguration"},
		Tools:      []string{Opengrep},
		Note:       "Opengrep rules tagged misconfiguration (Django, Express, Spring)"},
	{ID: "cicd", Name: "CI/CD pipeline", Description: "Security of build pipelines and workflow definitions",
		Categories: []string{"cicd", "iac"},
		Tools:      []string{Zizmor, Actionlint},
		Note:       "zizmor and actionlint findings are recorded as iac"},
	{ID: "binary", Name: "Binary", Description: "Hardening of compiled executables and libraries",
		Categories: []string{"binary"},
		Tools:      []string{BinaryHardening}},
	{ID: "ai", Name: "AI / LLM", Description: "Security of AI models and LLM applications",
		Categories: []string{"ai"}},
	{ID: "runtime", Name: "Runtime", Description: "Detections from running workloads",
		Categories:    []string{"runtime"},
		ImportFormats: []string{"asff", "gcp-scc"}},
	{ID: "compliance", Name: "Compliance", Description: "Benchmark and compliance checks",
		Categories:    []string{"compliance"},
		Tools:         []string{"kube-bench"},
		ImportFormats: []string{"asff", "gcp-scc"}},
	{ID: "license-policy", Name: "Licence policy", Description: "The organization's licence policy applied to the SBOM inventory",
		Categories: []string{"license"},
		Tools:      []string{LicensePolicy},
		Note:       "Evaluated by the PATHOS server, not by a worker"},
	{ID: "database", Name: "Database security", Description: "Configuration and access of database systems",
		Categories: []string{"database"}},
	{ID: "manual", Name: "Manual review", Description: "Findings from manual testing and code review",
		Categories:    []string{},
		ImportFormats: []string{"hackerone", "hackerone-csv", "bugcrowd", "intigriti"},
		Note:          "Recorded through result imports (PATHOS findings JSON, CSV, SARIF, bug-bounty and pentest platform exports) and Human Eye reviews"},
}

// LookupScanType returns a scan type by id.
func LookupScanType(id string) (ScanType, bool) {
	for _, t := range ScanTypes {
		if t.ID == id {
			return t, true
		}
	}
	return ScanType{}, false
}

// ScanTypesOf returns the scan types whose tool list names key.
func ScanTypesOf(key string) []string {
	out := []string{}
	for _, t := range ScanTypes {
		if slices.Contains(t.Tools, key) {
			out = append(out, t.ID)
		}
	}
	return out
}

// ScanTypeImportFormats returns the import formats of a scan type: the
// formats whose default category is the type's first category, plus its
// explicit ones. The other categories of a type (dast for API security,
// iac for CI/CD) are where some of its tools record findings, not formats
// of the type. Generic formats (no default category) are not included.
func ScanTypeImportFormats(t ScanType) []ImportFormat {
	var out []ImportFormat
	for _, f := range ImportFormats() {
		if (f.Category != "" && f.Category != "other" && len(t.Categories) > 0 && f.Category == t.Categories[0]) || slices.Contains(t.ImportFormats, f.ID) {
			out = append(out, f)
		}
	}
	return out
}

// GenericImportFormats are the formats that carry any category.
func GenericImportFormats() []ImportFormat {
	var out []ImportFormat
	for _, f := range ImportFormats() {
		if f.Category == "" && !slices.ContainsFunc(ScanTypes, func(t ScanType) bool { return slices.Contains(t.ImportFormats, f.ID) }) {
			out = append(out, f)
		}
	}
	return out
}

// WithScanTypes returns sc with ScanTypes filled from the registry.
func WithScanTypes(sc Scanner) Scanner {
	sc.ScanTypes = ScanTypesOf(sc.Key)
	return sc
}
