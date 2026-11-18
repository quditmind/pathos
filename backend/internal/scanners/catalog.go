// Package scanners holds the scanner catalog and turns raw tool output into
// normalized, fingerprinted findings.
//
// The catalog mirrors docs/SCANNER_CATALOG.md. `pathosctl migrate` syncs it
// into scanner_catalog. AdapterAvailable marks tools that a shipped worker
// image runs today; the rest are catalogued but not yet executable.
package scanners

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"pathos/internal/platform/db"
)

// Scanner is one catalog entry.
type Scanner struct {
	Key              string `json:"key"`
	Name             string `json:"name"`
	Category         string `json:"category"` // secrets | sast | sca | iac | container | license | dast | supply-chain
	License          string `json:"license_spdx"`
	Decision         string `json:"decision"` // use | optional | restricted
	Family           string `json:"worker_family"`
	RequiresBuild    bool   `json:"requires_build"`
	Mandatory        bool   `json:"mandatory"`
	AdapterAvailable bool   `json:"adapter_available"`
	DefaultEnabled   bool   `json:"default_enabled"`
	// TargetOnly scanners run for scan targets (images, URLs, APIs), not
	// as part of a repository scan profile.
	TargetOnly   bool   `json:"target_only"`
	OutputFormat string `json:"output_format"`
	Homepage     string `json:"homepage"`
	Notes        string `json:"notes"`
}

// FindingCategory maps a scanner category to the findings.category column.
func (s Scanner) FindingCategory() string {
	switch s.Category {
	case "secrets", "sast", "sca", "iac", "container", "license", "dast", "eol", "supply-chain":
		return s.Category
	}
	return "other"
}

// Core scanners shipped in the worker-core image.
const (
	Gitleaks   = "gitleaks"
	Opengrep   = "opengrep"
	TrivyFS    = "trivy-fs"
	Syft       = "syft"
	Grype      = "grype"
	OSVScanner = "osv-scanner"
	Checkov    = "checkov"
	TrivyImage = "trivy-image"
	Nuclei     = "nuclei"
	Zizmor     = "zizmor"
)

func s(key, name, cat, lic, decision, family string, opts ...func(*Scanner)) Scanner {
	sc := Scanner{Key: key, Name: name, Category: cat, License: lic, Decision: decision, Family: family, OutputFormat: "sarif"}
	for _, o := range opts {
		o(&sc)
	}
	return sc
}

var (
	core = func(sc *Scanner) { sc.AdapterAvailable, sc.DefaultEnabled = true, true }
	// target scanners run for scan targets (images, URLs, APIs), never as
	// part of a repository profile.
	target    = func(sc *Scanner) { sc.AdapterAvailable, sc.TargetOnly = true, true }
	mandatory = func(sc *Scanner) { sc.Mandatory = true }
	build     = func(sc *Scanner) { sc.RequiresBuild = true }
	format    = func(f string) func(*Scanner) { return func(sc *Scanner) { sc.OutputFormat = f } }
	note      = func(n string) func(*Scanner) { return func(sc *Scanner) { sc.Notes = n } }
	home      = func(u string) func(*Scanner) { return func(sc *Scanner) { sc.Homepage = u } }
)

// Catalog lists every scanner integration (52), in display order.
var Catalog = []Scanner{
	s(Gitleaks, "Gitleaks", "secrets", "MIT", "use", "core", core, mandatory, home("https://github.com/gitleaks/gitleaks"), note("Always on; secrets are redacted in reports")),
	s("trufflehog", "TruffleHog", "secrets", "AGPL-3.0", "use", "secrets", note("Verification mode off by default")),
	s("detect-secrets", "detect-secrets", "secrets", "Apache-2.0", "use", "secrets", format("json")),
	s("kingfisher", "Kingfisher", "secrets", "Apache-2.0", "use", "secrets"),
	s(Opengrep, "Opengrep", "sast", "LGPL-2.1", "use", "core", core, home("https://github.com/opengrep/opengrep"), note("Runs the PATHOS baseline rules plus administrator rule sets")),
	s("semgrep-ce", "Semgrep CE", "sast", "LGPL-2.1", "optional", "lang", note("Registry rules are license-restricted")),
	s("codeql", "CodeQL", "sast", "LicenseRef-GitHub-CodeQL-Terms", "restricted", "build", build, note("Free only for OSS/research")),
	s("bandit", "Bandit", "sast", "Apache-2.0", "use", "lang"),
	s("gosec", "Gosec", "sast", "Apache-2.0", "use", "lang"),
	s("brakeman", "Brakeman", "sast", "LicenseRef-Brakeman", "optional", "lang", note("Verify license before enabling")),
	s("spotbugs", "SpotBugs + FindSecBugs", "sast", "LGPL-2.1", "optional", "build", build),
	s("pmd", "PMD", "sast", "BSD-4-Clause", "use", "jvm"),
	s("flawfinder", "Flawfinder", "sast", "GPL-2.0", "use", "lang"),
	s("cppcheck", "cppcheck", "sast", "GPL-3.0", "use", "lang"),
	s("infer", "Infer", "sast", "MIT", "optional", "build", build),
	s("pysa", "Pysa (Pyre)", "sast", "MIT", "optional", "lang"),
	s("psalm", "Psalm", "sast", "MIT", "use", "lang"),
	s("phpstan", "PHPStan", "sast", "MIT", "use", "lang"),
	s("ruff", "Ruff (S rules)", "sast", "MIT", "use", "lang"),
	s("eslint-security", "ESLint + eslint-plugin-security", "sast", "MIT", "use", "lang"),
	s("njsscan", "njsscan", "sast", "LGPL-3.0", "use", "lang"),
	s("mobsfscan", "mobsfscan", "sast", "LGPL-3.0", "use", "lang"),
	s("sobelow", "Sobelow", "sast", "Apache-2.0", "use", "lang"),
	s("shellcheck", "ShellCheck", "sast", "GPL-3.0", "use", "lang"),
	s(TrivyFS, "Trivy (filesystem)", "sca", "Apache-2.0", "use", "core", core, home("https://github.com/aquasecurity/trivy")),
	s(Grype, "Grype", "sca", "Apache-2.0", "use", "core", core, format("json"), home("https://github.com/anchore/grype"), note("Scans the Syft SBOM")),
	s(OSVScanner, "OSV-Scanner", "sca", "Apache-2.0", "use", "core", core, home("https://github.com/google/osv-scanner")),
	s("dependency-check", "OWASP Dependency-Check", "sca", "Apache-2.0", "use", "jvm", note("Needs an NVD API key")),
	s("retirejs", "Retire.js", "sca", "Apache-2.0", "use", "lang"),
	s("govulncheck", "govulncheck", "sca", "BSD-3-Clause", "use", "lang"),
	s("pip-audit", "pip-audit", "sca", "Apache-2.0", "use", "lang"),
	s("cargo-audit", "cargo-audit", "sca", "Apache-2.0", "use", "lang"),
	s("bundler-audit", "bundler-audit", "sca", "GPL-3.0", "use", "lang"),
	s("dep-scan", "OWASP dep-scan", "sca", "MIT", "use", "lang"),
	s(Checkov, "Checkov", "iac", "Apache-2.0", "use", "core", core, home("https://github.com/bridgecrewio/checkov")),
	s("kics", "KICS", "iac", "Apache-2.0", "use", "iac"),
	s("kube-linter", "KubeLinter", "iac", "Apache-2.0", "use", "iac"),
	s("kubescape", "Kubescape", "iac", "Apache-2.0", "use", "iac"),
	s("tflint", "TFLint", "iac", "MPL-2.0", "use", "iac"),
	s("conftest", "Conftest", "iac", "Apache-2.0", "use", "iac"),
	s("hadolint", "Hadolint", "iac", "GPL-3.0", "use", "iac"),
	s("dockle", "Dockle", "container", "Apache-2.0", "use", "container"),
	s(TrivyImage, "Trivy (image)", "container", "Apache-2.0", "use", "core", target, home("https://github.com/aquasecurity/trivy"), note("Runs for container image targets")),
	s(Actionlint, "actionlint", "iac", "MIT", "use", "core", core, format("json"), home("https://github.com/rhysd/actionlint"), note("GitHub Actions workflow checks (script injection, syntax, types); runs only when the repository has workflows")),
	s(Zizmor, "zizmor", "iac", "MIT", "use", "core", core, home("https://github.com/zizmorcore/zizmor"), note("GitHub Actions workflow security; runs offline and only when the repository has workflows")),
	s("scorecard", "OpenSSF Scorecard", "supply-chain", "Apache-2.0", "use", "supply-chain"),
	s("scancode", "ScanCode Toolkit", "license", "Apache-2.0", "use", "license"),
	s("trivy-license", "Trivy (license)", "license", "Apache-2.0", "use", "license"),
	s("zap", "OWASP ZAP", "dast", "Apache-2.0", "use", "dast", note("Targets a URL, not a repository")),
	s(Nuclei, "Nuclei", "dast", "MIT", "use", "core", target, format("jsonl"), home("https://github.com/projectdiscovery/nuclei"), note("Runs for authorized web application and API targets; non-intrusive templates only")),
	s("schemathesis", "Schemathesis", "dast", "MIT", "use", "dast"),
	s("kube-bench", "kube-bench", "iac", "Apache-2.0", "optional", "cluster", note("Cluster target")),
}

// Syft is an SBOM utility run alongside Grype; it is not a finding source.
var SyftUtility = Scanner{Key: Syft, Name: "Syft", Category: "sbom", License: "Apache-2.0", Decision: "use", Family: "core",
	AdapterAvailable: true, OutputFormat: "cyclonedx-json", Homepage: "https://github.com/anchore/syft", Notes: "SBOM generation (CycloneDX)"}

// Lookup returns a catalog entry.
// TargetScanners maps a scan target kind to the scanners that run for it.
// Cosign runs only when signature verification is configured on the
// target, and Nuclei for declared endpoints only when enabled.
var TargetScanners = map[string][]string{
	"image": {TrivyImage, Cosign},
	"url":   {Nuclei},
	"api":   {Nuclei},
	"sbom":  {Grype},
	// Build artifacts: archives are extracted; Java archives and binaries
	// are read as they are.
	"artifact": {TrivyFS, Cosign},
	// A repository's declared public endpoints.
	"endpoints": {EndpointCheck, Nuclei},
}

// IsTargetOnly reports whether a scanner runs only for scan targets.
func IsTargetOnly(key string) bool {
	sc, ok := Lookup(key)
	return ok && sc.TargetOnly
}

func Lookup(key string) (Scanner, bool) {
	for _, sc := range Catalog {
		if sc.Key == key {
			return sc, true
		}
	}
	if key == Syft {
		return SyftUtility, true
	}
	for _, sc := range Builtins {
		if sc.Key == key {
			return sc, true
		}
	}
	return Scanner{}, false
}

// Sync upserts the catalog into the database.
func Sync(ctx context.Context, pool *pgxpool.Pool) error {
	return db.InTx(ctx, pool, func(tx pgx.Tx) error {
		all := append(append(append([]Scanner{}, Catalog...), SyftUtility), Builtins...)
		for i, sc := range all {
			if _, err := tx.Exec(ctx, `
				INSERT INTO scanner_catalog (key, name, category, license_spdx, decision, worker_family, requires_build,
				  mandatory, adapter_available, default_enabled, output_format, homepage, notes, sort_order)
				VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14)
				ON CONFLICT (key) DO UPDATE SET name = EXCLUDED.name, category = EXCLUDED.category,
				  license_spdx = EXCLUDED.license_spdx, decision = EXCLUDED.decision, worker_family = EXCLUDED.worker_family,
				  requires_build = EXCLUDED.requires_build, mandatory = EXCLUDED.mandatory,
				  adapter_available = EXCLUDED.adapter_available, default_enabled = EXCLUDED.default_enabled,
				  output_format = EXCLUDED.output_format, homepage = EXCLUDED.homepage, notes = EXCLUDED.notes,
				  sort_order = EXCLUDED.sort_order`,
				sc.Key, sc.Name, sc.Category, sc.License, sc.Decision, sc.Family, sc.RequiresBuild, sc.Mandatory,
				sc.AdapterAvailable, sc.DefaultEnabled, sc.OutputFormat, sc.Homepage, sc.Notes, i); err != nil {
				return fmt.Errorf("sync scanner %s: %w", sc.Key, err)
			}
		}
		return nil
	})
}
