package scanners

import (
	"slices"
	"strings"
)

// The worker-sast family image (workers/sast, PATHOS 2.0 SAST pack): the
// tools its manifests run (workers/sast/tools.d), the tools that were
// evaluated for it and are not bundled, and the scan types they cover.
// Entries of catalog.go are replaced in place (same key and position),
// new tools are appended.

// SemgrepCE is Semgrep Community Edition, which the worker-sast image runs
// with the PATHOS rules; its rule ids and categories are read like
// Opengrep's.
const SemgrepCE = "semgrep-ce"

// sastPackNote is the note of a tool shipped in the worker-sast image.
func sastPackNote(n string) func(*Scanner) {
	return note("worker-sast image (tool manifest; " + n + ")")
}

var sastPack = []Scanner{
	// SAST
	s("gosec", "gosec", "sast", "Apache-2.0", "use", "sast", available, format("json"), home("https://github.com/securego/gosec"),
		sastPackNote("JSON parsed with the gosec import parser; packages are type-checked offline with the image's Go toolchain")),
	s("flawfinder", "Flawfinder", "sast", "GPL-2.0-or-later", "use", "sast", available, format("csv"), home("https://github.com/david-a-wheeler/flawfinder"),
		sastPackNote("CSV parsed with the Flawfinder import parser")),
	s("cppcheck", "cppcheck", "sast", "GPL-3.0-or-later", "use", "sast", available, format("xml"), home("https://github.com/danmar/cppcheck"),
		sastPackNote("XML version 2 parsed with the cppcheck import parser")),
	s("psalm", "Psalm (taint analysis)", "sast", "MIT", "use", "sast", available, format("json"), home("https://github.com/vimeo/psalm"),
		sastPackNote("taint analysis; JSON parsed with the Psalm import parser")),
	s("phpstan", "PHPStan", "code-quality", "MIT", "use", "sast", available, format("json"), home("https://github.com/phpstan/phpstan"),
		sastPackNote("type checks without security rules, so its findings are code-quality findings; JSON parsed with the PHPStan import parser")),
	s("ruff", "Ruff (S rules)", "sast", "MIT", "use", "sast", available, format("json"), home("https://github.com/astral-sh/ruff"),
		sastPackNote("flake8-bandit rules (S) only; JSON parsed with the Ruff import parser")),
	s("eslint-security", "ESLint + eslint-plugin-security", "sast", "MIT AND Apache-2.0", "use", "sast", available, format("json"),
		home("https://github.com/eslint-community/eslint-plugin-security"),
		sastPackNote("ESLint (MIT) with eslint-plugin-security (Apache-2.0) and the image's configuration; JSON parsed with the ESLint import parser")),
	s(SemgrepCE, "Semgrep CE", "sast", "LGPL-2.1-or-later", "optional", "sast", available, home("https://github.com/semgrep/semgrep"),
		sastPackNote("PATHOS rules only, no Semgrep Registry rules (their licence restricts use in a product); metrics and version check off; SARIF")),
	s("bearer", "Bearer CLI", "sast", "Elastic-2.0", "optional", "sast", available, format("json"), home("https://github.com/Bearer/bearer"),
		sastPackNote("Elastic License 2.0 (source-available); bundled rules (Bearer/bearer-rules, Elastic-2.0), rule download and version check off; JSON parsed with the Bearer import parser")),
	s("brakeman", "Brakeman", "sast", "LicenseRef-Brakeman-Public-Use", "restricted", "sast", format("json"), home("https://github.com/presidentbeef/brakeman"),
		note("Not bundled: the Brakeman Public Use License forbids distribution as part of a product and commercial use without a licence. Import its JSON report (brakeman format)")),
	s("sobelow", "Sobelow", "sast", "Apache-2.0", "use", "lang", format("json"), home("https://github.com/nccgroup/sobelow"),
		note("Not bundled in worker-sast: it needs an Erlang/Elixir runtime for one Phoenix-only tool. Import its JSON report (sobelow format)")),
	s("pmd", "PMD", "code-quality", "BSD-4-Clause", "use", "jvm", format("xml"), home("https://github.com/pmd/pmd"),
		note("Not bundled in worker-sast: it needs a Java runtime; belongs to a JVM family image. Import its XML report (pmd format)")),
	// Secrets
	s("trufflehog", "TruffleHog", "secrets", "AGPL-3.0-only", "use", "sast", available, format("jsonl"), home("https://github.com/trufflesecurity/trufflehog"),
		sastPackNote("filesystem mode; verification off (--no-verification), no update check; JSON Lines parsed with the TruffleHog import parser")),
	s("detect-secrets", "detect-secrets", "secrets", "Apache-2.0", "use", "sast", available, format("json"), home("https://github.com/Yelp/detect-secrets"),
		sastPackNote("all files; no online verification; JSON parsed with the detect-secrets import parser")),
	s("kingfisher", "Kingfisher", "secrets", "Apache-2.0", "use", "sast", available, format("json"), home("https://github.com/mongodb/kingfisher"),
		sastPackNote("validation off (--no-validate), no update check, current files only; JSON parsed with the Kingfisher import parser")),
	s("talisman", "Talisman", "secrets", "MIT", "use", "sast", available, format("json"), home("https://github.com/thoughtworks/talisman"),
		sastPackNote("current files, committed to a throwaway Git repository; no line numbers; JSON parsed with the Talisman import parser. "+
			"High noise: it flagged 33 of 39 look-alike files (84.6% false positive rate) in the PATHOS secrets benchmark (docs/BENCHMARKS.md); "+
			"not in the default profile, enable it only where its file-level checks are wanted")),
	s("noseyparker", "Nosey Parker", "secrets", "Apache-2.0", "use", "import", format("json"), home("https://github.com/praetorian-inc/noseyparker"),
		note("Not bundled: the repository is archived (last release v0.24.0, May 2025). Import its JSON report (noseyparker format)")),
	s("whispers", "Whispers", "secrets", "Apache-2.0", "use", "import", format("json"), home("https://github.com/Skyscanner/whispers"),
		note("Not bundled: the repository is archived (last release 2021). Import its JSON report (whispers format)")),
	// Code-quality security
	s("pylint", "Pylint (security-relevant checks)", "code-quality", "GPL-2.0-or-later", "use", "sast", available, format("json"),
		home("https://github.com/pylint-dev/pylint"),
		sastPackNote("security-relevant checks only (eval/exec, bare except, missing timeouts, unclosed resources, subprocess misuse); JSON parsed with the Pylint import parser")),
	s("golangci-lint", "golangci-lint (security linters)", "code-quality", "GPL-3.0-only", "use", "sast", available, format("json"),
		home("https://github.com/golangci/golangci-lint"),
		sastPackNote("gosec, errcheck, bodyclose, noctx, rowserrcheck, sqlclosecheck, govet, staticcheck, errorlint and nilerr; JSON parsed with the golangci-lint import parser")),
	// Evaluated, not bundled
	s("horusec", "Horusec", "sast", "Apache-2.0", "use", "import", format("json"), home("https://github.com/ZupIT/horusec"),
		note("Not bundled: no release since v2.8.0 (June 2022), and it runs its analysers as Docker containers. Import its JSON report (horusec format)")),
	s("devskim", "DevSkim", "sast", "MIT", "use", "lang", home("https://github.com/microsoft/DevSkim"),
		note("Not bundled in worker-sast: it needs the .NET runtime, which no PATHOS image has yet. Import its SARIF report")),
}

// sastScanTypeTools are the scan-type tool lists the SAST pack adds to.
var sastScanTypeTools = map[string][]string{
	"sast":         {"bearer", "horusec", "devskim"},
	"secrets":      {"talisman", "noseyparker", "whispers"},
	"code-quality": {"pylint", "golangci-lint", "phpstan"},
	// The PATHOS Opengrep rule packs (workers/rules/pathos-{crypto,database,ai,cicd}.yml).
	"crypto":   {Opengrep},
	"database": {Opengrep},
	"ai":       {Opengrep},
	"cicd":     {Opengrep},
}

// sastScanTypeNotes explain the Opengrep entries above.
var sastScanTypeNotes = map[string]string{
	"crypto":   "Opengrep runs the PATHOS cryptography rules (pathos.crypto.*)",
	"database": "Opengrep runs the PATHOS database rules (pathos.database.*)",
	"ai":       "Opengrep runs the PATHOS AI/LLM rules (pathos.ai.*)",
	"cicd":     "Opengrep runs the PATHOS GitLab CI, Azure Pipelines, Bitbucket Pipelines and Jenkins rules (pathos.cicd.*)",
}

func init() {
	for _, sc := range sastPack {
		upsertCatalog(sc)
	}
	for id, tools := range sastScanTypeTools {
		addScanTypeTools(id, tools...)
	}
	for id, n := range sastScanTypeNotes {
		addScanTypeNote(id, n)
	}
}

// upsertCatalog replaces the catalog entry with sc's key in place, or
// appends sc.
func upsertCatalog(sc Scanner) {
	if i := slices.IndexFunc(Catalog, func(c Scanner) bool { return c.Key == sc.Key }); i >= 0 {
		Catalog[i] = sc
		return
	}
	Catalog = append(Catalog, sc)
}

// addScanTypeTools adds catalog keys to a scan type's tool list.
func addScanTypeTools(id string, keys ...string) {
	for i := range ScanTypes {
		if ScanTypes[i].ID != id {
			continue
		}
		for _, k := range keys {
			if !slices.Contains(ScanTypes[i].Tools, k) {
				ScanTypes[i].Tools = append(ScanTypes[i].Tools, k)
			}
		}
	}
}

// addScanTypeNote adds a sentence to a scan type's note.
func addScanTypeNote(id, n string) {
	for i := range ScanTypes {
		if ScanTypes[i].ID != id {
			continue
		}
		if ScanTypes[i].Note == "" {
			ScanTypes[i].Note = n
		} else if !strings.Contains(ScanTypes[i].Note, n) {
			ScanTypes[i].Note += "; " + n
		}
	}
}
