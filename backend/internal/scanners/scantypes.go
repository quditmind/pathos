package scanners

import (
	"fmt"
	"maps"
	"slices"
	"strings"
)

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
			"golangci-lint", "codacy", "gitlab", "kiuwan", "checkmarx-one", "fod", "appscan-cloud"}},
	{ID: "dast", Name: "DAST", Description: "Dynamic testing of running web applications",
		Categories:    []string{"dast"},
		Tools:         []string{Nuclei, "zap", EndpointCheck},
		ImportFormats: []string{"gitlab", "fod", "appscan-cloud"}},
	{ID: "sca", Name: "SCA", Description: "Known vulnerabilities in open-source dependencies",
		Categories: []string{"sca", "eol"},
		Tools: []string{TrivyFS, Grype, OSVScanner, "dependency-check", "retirejs", "govulncheck", "pip-audit", "cargo-audit", "bundler-audit",
			"dep-scan", EndOfLife},
		ImportFormats: []string{"trivy", "veracode", "gitlab", "sarif-trivy", "wiz", "lacework", "insightvm", "xeol", "kiuwan", "checkmarx-one", "fod", "appscan-cloud"}},
	{ID: "secrets", Name: "Secrets", Description: "Credentials and keys committed to repositories",
		Categories:    []string{"secrets"},
		Tools:         []string{Gitleaks, "trufflehog", "detect-secrets", "kingfisher"},
		ImportFormats: []string{"trivy", "trivy-k8s", "bearer", "horusec", "gitlab"}},
	{ID: "iac", Name: "Infrastructure as code", Description: "Misconfigurations in Terraform, Kubernetes, CloudFormation and similar files",
		Categories:    []string{"iac"},
		Tools:         []string{Checkov, "kics", "kube-linter", "kubescape", "tflint", "conftest", "hadolint"},
		ImportFormats: []string{"trivy", "trivy-k8s", "polaris", "kube-score", "sarif-trivy", "checkmarx-one", "trivy-operator"}},
	{ID: "container", Name: "Container", Description: "Vulnerabilities and misconfigurations of container images",
		Categories:    []string{"container"},
		Tools:         []string{TrivyImage, "dockle"},
		ImportFormats: []string{"trivy", "trivy-k8s", "gitlab", "sarif-trivy", "wiz", "lacework", "trivy-operator"}},
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
			"polaris", "kube-score"}},
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
		ImportFormats: []string{"asff", "gcp-scc", "wiz", "lacework", "trivy-operator"}},
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

// --- Kinds of check (PATHOS 3.0 M6) -----------------------------------------
//
// The build prompt (§7) groups security testing into 20 kinds of check of
// about 10 tools each. PATHOS keeps its 25 scan types (decision C8): a kind
// of check is a display grouping of scan types, and the UI shows the kind
// of check and "confirmed by N engines" instead of tool names everywhere
// except Configurations › Scan profiles, Configurations › Scanners &
// workers and Import results (rule 3, decision C5). docs/SCANNER_CATALOG.md
// lists, for every kind, the catalogued tools and the gap list.

// ToolsPerKind is the number of tools the build prompt targets per kind of
// check ("N of 10 tools").
const ToolsPerKind = 10

// KindTool is one tool of the prompt's §7 table for a kind of check.
type KindTool struct {
	// Name is the tool as the §7 table names it.
	Name string `json:"name"`
	// Key is the catalog key when PATHOS catalogues the tool ("" when it
	// is on the gap list, an intelligence feed or a PATHOS engine).
	Key string `json:"key,omitempty"`
	// Source: catalog (a catalogued integration), feed (a vulnerability
	// intelligence feed of the server), pathos (a PATHOS engine or view)
	// or gap (not in PATHOS yet; docs/SCANNER_CATALOG.md has its licence
	// and maintenance status).
	Source string `json:"source"`
	// Mode names the part of a catalogued tool the kind needs when PATHOS
	// runs the tool for another purpose (for example Trivy's SBOM mode);
	// such entries are on the gap list until the mode is wired.
	Mode string `json:"mode,omitempty"`
	// AfterV2: the prompt schedules the tool after PATHOS 2.0.
	AfterV2 bool `json:"after_v2,omitempty"`
}

// CheckKind is one of the prompt's 20 kinds of check.
type CheckKind struct {
	ID   string `json:"id"`
	Name string `json:"name"`
	// Phase is the lifecycle phase of the §7 table.
	Phase int `json:"phase"`
	// ScanTypes are the scan types the kind groups (each scan type belongs
	// to exactly one kind; ai and manual stay outside the 20 kinds).
	ScanTypes []string `json:"scan_types"`
	// Tools are the §7 tools of the kind, in the table's order.
	Tools []KindTool `json:"tools"`
	// Extra are catalogued tools of the kind's scan types that the §7 table
	// does not list (they count for profiles but not for "N of 10").
	Extra []string `json:"extra_tools"`
	// AfterV2: the whole kind is scheduled after PATHOS 2.0.
	AfterV2 bool `json:"after_v2,omitempty"`
}

func ct(name, key string) KindTool { return KindTool{Name: name, Key: key, Source: "catalog"} }
func gap(name string) KindTool     { return KindTool{Name: name, Source: "gap"} }
func feed(name string) KindTool    { return KindTool{Name: name, Source: "feed"} }
func pathosEngine(name string) KindTool {
	return KindTool{Name: name, Source: "pathos"}
}
func modeGap(name, key, mode string) KindTool {
	return KindTool{Name: name, Key: key, Source: "gap", Mode: mode}
}
func later(t KindTool) KindTool { t.AfterV2 = true; return t }

// KindOutside groups the scan types outside the 20 kinds (AI / LLM and
// manual review) and findings of category other.
const KindOutside = "other"

// CheckKinds are the 20 kinds of check of the build prompt (§7), in its
// order. Extra is filled from the scan-type registry at init.
var CheckKinds = []CheckKind{
	// PATHOS 3.0 M4: pathos-graph (CodeGraph discovery, worker-graph) is the
	// kind's PATHOS engine; it runs no scan type, so it is named here.
	{ID: "discovery", Name: "Discovery & CodeGraph", Phase: 3, ScanTypes: []string{}, Extra: []string{PathosGraph},
		Tools: []KindTool{gap("tree-sitter"), gap("Joern"), ct("Syft", Syft), modeGap("Opengrep (route & DB rules)", Opengrep, "route and database rules"),
			gap("go-enry"), gap("scc"), gap("Microsoft Application Inspector"), gap("Universal Ctags"), gap("dependency-cruiser"), gap("kin-openapi")}},
	{ID: "sbom", Name: "SBOM", Phase: 3, ScanTypes: []string{"sbom"},
		Tools: []KindTool{ct("Syft", Syft), modeGap("Trivy (SBOM)", TrivyFS, "SBOM output"), ct("cdxgen", CDXGen), gap("Microsoft sbom-tool"),
			gap("cyclonedx-gomod"), gap("cyclonedx-py"), gap("cyclonedx-npm"), gap("CycloneDX Maven plugin"), gap("CycloneDX CLI"), gap("sbomqs")}},
	{ID: "threat-modelling", Name: "Threat modelling", Phase: 4, ScanTypes: []string{},
		Tools: []KindTool{pathosEngine("PATHOS STRIDE engine"), pathosEngine("PATHOS attack paths & blast radius"), gap("OWASP pytm"),
			gap("OWASP Threat Dragon (format)"), gap("Threagile"), gap("MITRE ATT&CK"), gap("MITRE CAPEC"), gap("MITRE CWE"), gap("MITRE D3FEND"), gap("LINDDUN")}},
	// PATHOS 3.0 M10: pathos-rea (worker-rea, static tier) runs radare2,
	// binwalk and ILSpy (Ghidra and Jadx when built in) on build artifacts;
	// it runs no scan type (its own queue lane), so it is named here.
	{ID: "reverse-engineering", Name: "Reverse engineering", Phase: 5, ScanTypes: []string{}, Extra: []string{PathosREA},
		Tools: []KindTool{gap("radare2"), gap("Joern"), gap("Ghidra (headless)"), gap("angr"), gap("Jadx"), gap("ILSpy (ilspycmd)"), gap("binwalk"),
			later(gap("Frida")), later(gap("Tracee")), later(gap("Qiling"))}},
	{ID: "sast-deep", Name: "SAST: deep engines", Phase: 6, ScanTypes: []string{"sast", "configuration", "crypto"},
		Tools: []KindTool{ct("Opengrep", Opengrep), gap("Joern (taint)"), ct("Semgrep CE", SemgrepCE), ct("CodeQL", "codeql"), ct("Infer", "infer"),
			ct("Pysa", "pysa"), ct("SpotBugs + FindSecBugs", "spotbugs"), ct("PMD", "pmd"), ct("cppcheck", "cppcheck"), ct("Flawfinder", "flawfinder")}},
	{ID: "sast-language", Name: "SAST: language checks", Phase: 6, ScanTypes: []string{"code-quality"},
		Tools: []KindTool{ct("Bandit", "bandit"), ct("Gosec", "gosec"), ct("Brakeman", "brakeman"), ct("Psalm", "psalm"), ct("PHPStan", "phpstan"),
			ct("Ruff (S rules)", "ruff"), ct("ESLint + security plugin", "eslint-security"), ct("njsscan", "njsscan"), ct("Sobelow", "sobelow"), ct("ShellCheck", "shellcheck")}},
	{ID: "secrets", Name: "Secrets", Phase: 6, ScanTypes: []string{"secrets"},
		Tools: []KindTool{ct("Gitleaks", Gitleaks), ct("TruffleHog", "trufflehog"), ct("detect-secrets", "detect-secrets"), ct("Kingfisher", "kingfisher"),
			modeGap("Trivy (secret)", TrivyFS, "secret scanner"), ct("Talisman", "talisman"), gap("git-secrets"), gap("secretlint"), gap("ripsecrets"),
			modeGap("Opengrep (secret rules)", Opengrep, "secret rule pack")}},
	{ID: "dependencies", Name: "Dependency check", Phase: 6, ScanTypes: []string{"sca"},
		Tools: []KindTool{ct("Trivy (filesystem)", TrivyFS), ct("OSV-Scanner", OSVScanner), ct("Grype", Grype), ct("OWASP Dependency-Check", "dependency-check"),
			ct("govulncheck", "govulncheck"), ct("pip-audit", "pip-audit"), ct("Retire.js", "retirejs"), ct("cargo-audit", "cargo-audit"),
			ct("bundler-audit", "bundler-audit"), ct("OWASP dep-scan", "dep-scan")}},
	{ID: "vulnerability-intelligence", Name: "CVE & vulnerability intelligence", Phase: 7, ScanTypes: []string{},
		Tools: []KindTool{feed("OSV.dev"), gap("GitHub Advisory Database"), feed("CISA KEV"), feed("FIRST EPSS"), ct("endoflife.date", EndOfLife), gap("NVD"),
			gap("CVE List"), gap("CISA Vulnrichment"), gap("OpenSSF malicious-packages"), gap("Go vulnerability database")}},
	{ID: "iac", Name: "Infrastructure as code", Phase: 6, ScanTypes: []string{"iac"},
		Tools: []KindTool{ct("Checkov", Checkov), ct("KICS", "kics"), ct("Trivy (config)", "trivy-config"), ct("TFLint", "tflint"), ct("Conftest", "conftest"),
			ct("Hadolint", "hadolint"), ct("KubeLinter", "kube-linter"), ct("kube-score", "kube-score"), ct("cfn-lint", "cfn-lint"), ct("cfn-nag", "cfn-nag")}},
	{ID: "cloud-kubernetes", Name: "Cloud & Kubernetes posture", Phase: 6, ScanTypes: []string{"compliance", "runtime"},
		Tools: []KindTool{gap("Prowler"), ct("Kubescape", "kubescape"), ct("kube-bench", "kube-bench"), modeGap("Trivy (Kubernetes)", TrivyFS, "Kubernetes cluster scan"),
			ct("Polaris", "polaris"), gap("Popeye"), gap("ScoutSuite"), gap("CloudSploit"), gap("Steampipe"), later(gap("Falco"))}},
	{ID: "cicd", Name: "CI/CD pipelines", Phase: 6, ScanTypes: []string{"cicd"},
		Tools: []KindTool{ct("actionlint", Actionlint), ct("zizmor", Zizmor), gap("poutine"), modeGap("Checkov (CI policies)", Checkov, "CI pipeline policies"),
			ct("OpenSSF Scorecard (CI checks)", "scorecard"), gap("Legitify"), gap("octoscan"), gap("Raven"), gap("ratchet"), gap("frizbee")}},
	{ID: "container", Name: "Container images", Phase: 6, ScanTypes: []string{"container"},
		Tools: []KindTool{ct("Trivy (image)", TrivyImage), ct("Grype", Grype), ct("Syft", Syft), ct("cosign", Cosign), ct("Dockle", "dockle"), ct("Hadolint", "hadolint"),
			gap("Clair"), gap("Docker Bench for Security"), gap("container-structure-test"), gap("dive")}},
	{ID: "license", Name: "Licence compliance", Phase: 6, ScanTypes: []string{"license", "license-policy"},
		Tools: []KindTool{ct("licensecheck (built in)", LicenseCheck), ct("ScanCode Toolkit", "scancode"), ct("Trivy (licence)", "trivy-license"),
			gap("OSS Review Toolkit"), gap("FOSSology"), gap("licensee"), gap("askalono"), gap("go-licenses"), gap("pip-licenses"), gap("license-checker")}},
	{ID: "supply-chain", Name: "Supply chain & integrity", Phase: 6, ScanTypes: []string{"supply-chain"},
		Tools: []KindTool{ct("cosign", Cosign), gap("Rekor"), gap("slsa-verifier"), gap("in-toto"), gap("witness"), ct("OpenSSF Scorecard", "scorecard"), gap("GUAC"),
			feed("deps.dev"), ct("GuardDog", "guarddog"), gap("OpenSSF Package Analysis")}},
	{ID: "malware", Name: "Malware", Phase: 6, ScanTypes: []string{"malware"},
		Tools: []KindTool{ct("ClamAV", ClamAV), ct("YARA-X", "yara-x"), ct("capa", "capa"), gap("Malcontent"), gap("Detect-It-Easy"), gap("LOKI"), gap("Manalyze"),
			gap("TLSH"), ct("GuardDog", "guarddog"), later(gap("Tracee"))}},
	{ID: "binary", Name: "Binary security", Phase: 6, ScanTypes: []string{"binary"},
		Tools: []KindTool{ct("checksec-style checks (built in)", BinaryHardening), gap("cwe_checker"), gap("BinAbsInspector"), gap("LIEF"), gap("binwalk"),
			later(gap("EMBA")), modeGap("Trivy (binary)", TrivyFS, "binary scan"), modeGap("Syft (binary)", Syft, "binary cataloguing"), ct("Grype", Grype), ct("capa", "capa")}},
	{ID: "mobile", Name: "Mobile apps", Phase: 6, ScanTypes: []string{"mobile"},
		Tools: []KindTool{ct("mobsfscan", "mobsfscan"), later(gap("MobSF")), later(gap("Jadx")), later(gap("apktool")), later(gap("Androguard")), ct("APKLeaks", "apkleaks"),
			ct("Quark-Engine", "quark-engine"), later(gap("FlowDroid")), later(gap("Frida")), later(gap("objection"))}},
	{ID: "web-api", Name: "Web app & API testing", Phase: 6, ScanTypes: []string{"dast", "api", "iast", "database"},
		Tools: []KindTool{ct("Nuclei", Nuclei), ct("OWASP ZAP", "zap"), ct("Schemathesis", "schemathesis"), ct("testssl.sh", "testssl"), gap("RESTler"),
			ct("Wapiti", "wapiti"), ct("Nikto", "nikto"), gap("Katana"), ct("ffuf", "ffuf"), gap("GraphQL Cop")}},
	{ID: "fuzzing", Name: "Fuzz testing", Phase: 6, ScanTypes: []string{"fuzzing"}, AfterV2: true,
		Tools: []KindTool{ct("Go native fuzzing", "go-fuzz"), gap("ClusterFuzzLite"), gap("AFL++"), gap("libFuzzer"), ct("Atheris", "atheris"), ct("Jazzer", "jazzer"),
			gap("Jazzer.js"), gap("cargo-fuzz"), gap("boofuzz"), gap("Radamsa")}},
}

// OutsideKinds are the display groups of the scan types that none of the
// 20 kinds covers (AI / LLM security and manual review), and of findings of
// category other. They are not counted among the 20 kinds.
var OutsideKinds = []CheckKind{
	{ID: "ai", Name: "AI / LLM", ScanTypes: []string{"ai"}},
	{ID: "manual", Name: "Manual review", ScanTypes: []string{"manual"}},
	{ID: KindOutside, Name: "Other", ScanTypes: []string{}},
}

func init() {
	for i := range CheckKinds {
		// Never nil (the API returns extra_tools as a list).
		CheckKinds[i].Extra = append(append([]string{}, CheckKinds[i].Extra...), kindExtraTools(CheckKinds[i])...)
	}
	for i := range OutsideKinds {
		OutsideKinds[i].Extra = kindExtraTools(OutsideKinds[i])
	}
}

// kindExtraTools are the catalogued tools of k's scan types that k's §7
// list does not name, in scan-type order.
func kindExtraTools(k CheckKind) []string {
	out := []string{}
	for _, id := range k.ScanTypes {
		st, _ := LookupScanType(id)
		for _, key := range st.Tools {
			if key == LicensePolicy || slices.Contains(out, key) || slices.ContainsFunc(k.Tools, func(t KindTool) bool { return t.Key == key && t.Source == "catalog" }) {
				continue
			}
			out = append(out, key)
		}
	}
	return out
}

// LookupKind returns a kind of check (one of the 20, or an outside group).
func LookupKind(id string) (CheckKind, bool) {
	for _, k := range append(append([]CheckKind{}, CheckKinds...), OutsideKinds...) {
		if k.ID == id {
			return k, true
		}
	}
	return CheckKind{}, false
}

// KindName is the display name of a kind id ("" for unknown ids).
func KindName(id string) string {
	k, _ := LookupKind(id)
	return k.Name
}

// KindOfScanType returns the kind a scan type belongs to.
func KindOfScanType(typeID string) string {
	for _, k := range append(append([]CheckKind{}, CheckKinds...), OutsideKinds...) {
		if slices.Contains(k.ScanTypes, typeID) {
			return k.ID
		}
	}
	return KindOutside
}

// CatalogKeys are the catalogued tools of the kind (§7 tools PATHOS has,
// then the extra tools of its scan types).
func (k CheckKind) CatalogKeys() []string {
	out := []string{}
	for _, t := range k.Tools {
		if t.Source == "catalog" && !slices.Contains(out, t.Key) {
			out = append(out, t.Key)
		}
	}
	for _, key := range k.Extra {
		if !slices.Contains(out, key) {
			out = append(out, key)
		}
	}
	return out
}

// ListedKeys are the catalogued tools among the kind's §7 tools: the "N"
// of "N of 10 tools" counts these.
func (k CheckKind) ListedKeys() []string {
	out := []string{}
	for _, t := range k.Tools {
		if t.Source == "catalog" && !slices.Contains(out, t.Key) {
			out = append(out, t.Key)
		}
	}
	return out
}

// KindsOfTool returns the kinds whose catalogued tools include key.
func KindsOfTool(key string) []string {
	out := []string{}
	for _, k := range append(append([]CheckKind{}, CheckKinds...), OutsideKinds...) {
		if slices.Contains(k.CatalogKeys(), key) {
			out = append(out, k.ID)
		}
	}
	return out
}

// PrimaryKindOfTool is the kind a tool's own results belong to: among the
// kinds whose §7 tools list it (else whose scan types cover it), the kind of
// its catalog category, else the first.
func PrimaryKindOfTool(key string) string {
	cat := ""
	if sc, ok := Resolve(key); ok {
		cat = sc.Category
	}
	pick := func(kinds []string) string {
		if len(kinds) == 0 {
			return ""
		}
		if k := KindOfCategory(cat); slices.Contains(kinds, k) {
			return k
		}
		return kinds[0]
	}
	var listed []string
	for _, k := range CheckKinds {
		if slices.Contains(k.ListedKeys(), key) {
			listed = append(listed, k.ID)
		}
	}
	if k := pick(listed); k != "" {
		return k
	}
	if k := pick(KindsOfTool(key)); k != "" {
		return k
	}
	return KindOfCategory(cat)
}

// --- kind of a finding --------------------------------------------------------

// categoryKinds maps findings.category to its kind of check. The language
// checks of SAST (Bandit, Gosec, …) and the TLS and web scanners that
// record misconfiguration or crypto findings are told apart by their
// tools (kindOverrides).
var categoryKinds = map[string]string{
	"secrets": "secrets", "sast": "sast-deep", "code-quality": "sast-language", "misconfiguration": "sast-deep", "crypto": "sast-deep",
	"sca": "dependencies", "eol": "dependencies", "iac": "iac", "cicd": "cicd", "container": "container", "license": "license",
	"supply-chain": "supply-chain", "malware": "malware", "binary": "binary", "mobile": "mobile", "dast": "web-api", "api": "web-api",
	"iast": "web-api", "database": "web-api", "fuzz": "fuzzing", "compliance": "cloud-kubernetes", "runtime": "cloud-kubernetes",
	"ai": "ai", "other": KindOutside,
	// sbom is a tool category (Syft, cdxgen), not a finding category.
	"sbom": "sbom",
}

// kindOverride: a finding of one of Categories whose engines are all in
// Tools belongs to Kind instead of the category's kind.
type kindOverride struct {
	Kind       string   `json:"kind"`
	Categories []string `json:"categories"`
	Tools      []string `json:"tools"`
}

var kindOverrides = []kindOverride{
	{Kind: "sast-language", Categories: []string{"sast"}, Tools: nil}, // filled at init: the language-check tools
	{Kind: "web-api", Categories: []string{"misconfiguration", "crypto"}, Tools: []string{"testssl", "sslyze", "nikto", "import-misconfiguration-testssl",
		"import-misconfiguration-sslyze", "import-misconfiguration-sslscan", "import-crypto-testssl", "import-crypto-sslyze", "import-crypto-sslscan"}},
}

func init() {
	lang, _ := LookupKind("sast-language")
	var keys []string
	for _, key := range lang.CatalogKeys() {
		keys = append(keys, key, "import-sast-"+key, "import-code-quality-"+key)
	}
	kindOverrides[0].Tools = keys
}

// KindOfCategory is the kind of check of a finding category.
func KindOfCategory(category string) string {
	if k, ok := categoryKinds[category]; ok {
		return k
	}
	return KindOutside
}

// KindOfFinding is the kind of check of a finding: its category's kind,
// unless every engine that reported it belongs to a more specific kind
// (kindOverrides). KindSQL computes the same in SQL.
func KindOfFinding(category string, scannerKeys []string) string {
	for _, o := range kindOverrides {
		if slices.Contains(o.Categories, category) && len(scannerKeys) > 0 &&
			!slices.ContainsFunc(scannerKeys, func(k string) bool { return !slices.Contains(o.Tools, k) }) {
			return o.Kind
		}
	}
	return KindOfCategory(category)
}

// KindSQL is KindOfFinding as a SQL expression over the category and
// scanner_keys columns of alias (for example "f"). It contains only
// constants of this package, never user input.
func KindSQL(alias string) string {
	var b strings.Builder
	b.WriteString("CASE")
	for _, o := range kindOverrides {
		fmt.Fprintf(&b, " WHEN %s.category IN (%s) AND cardinality(%s.scanner_keys) > 0 AND %s.scanner_keys <@ ARRAY[%s]::text[] THEN '%s'",
			alias, sqlList(o.Categories), alias, alias, sqlList(o.Tools), o.Kind)
	}
	cats := slices.Sorted(maps.Keys(categoryKinds))
	for _, c := range cats {
		fmt.Fprintf(&b, " WHEN %s.category = '%s' THEN '%s'", alias, c, categoryKinds[c])
	}
	fmt.Fprintf(&b, " ELSE '%s' END", KindOutside)
	return b.String()
}

func sqlList(vs []string) string {
	q := make([]string, len(vs))
	for i, v := range vs {
		q[i] = "'" + strings.ReplaceAll(v, "'", "''") + "'"
	}
	return strings.Join(q, ", ")
}

// --- engines ------------------------------------------------------------------

// Engine is the engine identity of a scanner key, so that the same tool run
// by a worker and imported from a report, or run in several modes (Trivy
// filesystem, image, config, licence; ZAP baseline, full and API scans),
// counts once: imports lose their "import-<category>-" prefix and SARIF
// variants their "sarif-" prefix, and tool families share one identity.
func Engine(key string) string {
	if m := importKeyRe.FindStringSubmatch(key); m != nil {
		key = m[2]
	}
	key = strings.TrimPrefix(key, "sarif-")
	for _, fam := range engineFamilies {
		if key == fam || strings.HasPrefix(key, fam+"-") {
			return fam
		}
	}
	if a, ok := engineAliases[key]; ok {
		return a
	}
	return key
}

// engineAliases are catalog keys spelled differently from their import
// format ("retirejs" runs the tool whose reports import as "retire-js").
var engineAliases = map[string]string{"retirejs": "retire"}

// engineFamilies are tools whose keys share a prefix across modes.
var engineFamilies = []string{"trivy", "zap", "trufflehog", "nuclei", "prowler", "hackerone", "twistlock", "sysdig", "kiuwan", "retire"}

// EnginesCount is the number of distinct engines among scanner keys: the
// "confirmed by N engines" of a de-duplicated finding.
func EnginesCount(keys []string) int {
	seen := map[string]bool{}
	for _, k := range keys {
		if k != "" {
			seen[Engine(k)] = true
		}
	}
	return len(seen)
}

// KindNameSQL is the display name of KindSQL(alias).
func KindNameSQL(alias string) string {
	var b strings.Builder
	b.WriteString("CASE " + KindSQL(alias))
	for _, k := range append(append([]CheckKind{}, CheckKinds...), OutsideKinds...) {
		fmt.Fprintf(&b, " WHEN '%s' THEN '%s'", k.ID, strings.ReplaceAll(k.Name, "'", "''"))
	}
	b.WriteString(" ELSE 'Other' END")
	return b.String()
}

// EnginesSQL is EnginesCount over the scanner_keys column of alias.
func EnginesSQL(alias string) string {
	norm := fmt.Sprintf(`regexp_replace(regexp_replace(regexp_replace(k, '^import-(%s)-', ''), '^sarif-', ''), '^(%s)(-.*)?$', '\1')`,
		strings.Join(ImportCategories, "|"), strings.Join(engineFamilies, "|"))
	var b strings.Builder
	b.WriteString("CASE " + norm)
	for _, k := range slices.Sorted(maps.Keys(engineAliases)) {
		fmt.Fprintf(&b, " WHEN '%s' THEN '%s'", k, engineAliases[k])
	}
	b.WriteString(" ELSE " + norm + " END")
	return fmt.Sprintf(`(SELECT count(DISTINCT %s) FROM unnest(%s.scanner_keys) k WHERE k <> '')`, b.String(), alias)
}

// ToolKeysOfKind are the catalogued tools whose results belong to kind
// (PrimaryKindOfTool), and ImportPrefixesOfKind the scanner-key prefixes of
// imports recorded under the kind's categories: together they select the
// scan results of a kind.
func ToolKeysOfKind(kind string) []string {
	out := []string{}
	for _, sc := range append(append(append([]Scanner{}, Catalog...), Builtins...), SyftUtility) {
		if PrimaryKindOfTool(sc.Key) == kind {
			out = append(out, sc.Key)
		}
	}
	return out
}

// ImportPrefixesOfKind: see ToolKeysOfKind.
func ImportPrefixesOfKind(kind string) []string {
	out := []string{}
	for _, c := range ImportCategories {
		if KindOfCategory(c) == kind {
			out = append(out, "import-"+c+"-")
		}
	}
	return out
}
