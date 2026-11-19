package scanners

// SCA, malware and SBOM tools of the worker-sca family image (workers/sca,
// Compose profile sca). Each is defined by a tool manifest in
// workers/sca/tools.d and run by the image's pathos-sca helper; the catalog
// entries below make them runnable (AdapterAvailable) and record their
// licences and what they contact.

// CDXGen is the cdxgen SBOM generator; like Syft its output is an
// inventory, not findings.
const CDXGen = "cdxgen"

func init() {
	reg := contacts("registry")
	iacscaUpsert(
		s("dependency-check", "OWASP Dependency-Check", "sca", "Apache-2.0", "use", "sca", available, reg, format("json"),
			home("https://github.com/dependency-check/DependencyCheck"),
			note("worker-sca image (tool manifest; Dependency-Check JSON, dependency-check import parser): NVD data downloaded into the worker's cache; NVD API key optional and off by default (NVD_API_KEY in /etc/pathos/sca.env on the worker)")),
		s("retirejs", "Retire.js", "sca", "Apache-2.0", "use", "sca", available, format("json"), home("https://github.com/RetireJS/retire.js"),
			note("worker-sca image (tool manifest; Retire.js JSON, retire-js import parser): JavaScript files of the repository, Retire.js repository bundled in the image (offline)")),
		s("govulncheck", "govulncheck", "sca", "BSD-3-Clause", "use", "sca", available, reg, format("json"), home("https://pkg.go.dev/golang.org/x/vuln/cmd/govulncheck"),
			note("worker-sca image (tool manifest; govulncheck JSON, govulncheck import parser): call-graph reachability; Go modules from the Go module proxy, vulnerability data from vuln.go.dev")),
		s("pip-audit", "pip-audit", "sca", "Apache-2.0", "use", "sca", available, reg, format("json"), home("https://github.com/pypa/pip-audit"),
			note("worker-sca image (tool manifest; pip-audit JSON, pip-audit import parser): pinned requirements of every requirements*.txt; vulnerability data from PyPI")),
		s("cargo-audit", "cargo-audit", "sca", "Apache-2.0 OR MIT", "use", "sca", available, format("json"), home("https://github.com/rustsec/rustsec"),
			note("worker-sca image (tool manifest; cargo-audit JSON, cargo-audit import parser): every Cargo.lock, RustSec advisory database bundled in the image (offline)")),
		s("bundler-audit", "bundler-audit", "sca", "GPL-3.0-or-later", "use", "sca", available, format("json"), home("https://github.com/rubysec/bundler-audit"),
			note("worker-sca image (tool manifest; bundler-audit JSON, bundler-audit import parser): every Gemfile.lock, Ruby advisory database bundled in the image (offline)")),
		s("npm-audit", "npm audit", "sca", "Artistic-2.0", "use", "sca", available, reg, format("json"), home("https://docs.npmjs.com/cli/commands/npm-audit"),
			note("worker-sca image (tool manifest; npm audit JSON, npm-audit import parser): the root package-lock.json, sent to the npm registry's audit endpoint")),
		s("yarn-audit", "yarn audit", "sca", "BSD-2-Clause", "use", "sca", available, reg, format("jsonl"), home("https://classic.yarnpkg.com/en/docs/cli/audit"),
			note("worker-sca image (tool manifest; yarn audit JSON Lines, yarn-audit import parser): the root yarn.lock (Yarn 1 lockfiles), sent to the npm registry's audit endpoint")),
		s("pnpm-audit", "pnpm audit", "sca", "MIT", "use", "sca", available, reg, format("json"), home("https://pnpm.io/cli/audit"),
			note("worker-sca image (tool manifest; pnpm audit JSON, pnpm-audit import parser): the root pnpm-lock.yaml, sent to the npm registry's audit endpoint")),
		s("composer-audit", "Composer audit", "sca", "MIT", "use", "sca", available, reg, format("json"), home("https://getcomposer.org/doc/03-cli.md#audit"),
			note("worker-sca image (tool manifest; Composer audit JSON, composer-audit import parser): the root composer.lock, plugins and scripts disabled; advisories from Packagist")),
		s("guarddog", "GuardDog", "malware", "Apache-2.0", "use", "sca", available, reg, home("https://github.com/DataDog/guarddog"),
			note("worker-sca image (tool manifest; SARIF): malware heuristics on the PyPI and npm dependencies declared in requirements*.txt and package.json; each package is downloaded and analysed statically")),
		s("pathos-depcheck", "PATHOS dependency confusion and typosquatting check", "supply-chain", "Apache-2.0", "use", "sca", available, format("json"),
			home("https://github.com/quditmind/pathos"),
			note("worker-sca image (tool manifest; JSON mapped with jsonmap): dependencies one edit away from popular npm and PyPI packages, pip --extra-index-url, npm scopes not mapped to the private registry; offline")),
		s(CDXGen, "cdxgen", "sbom", "Apache-2.0", "use", "sca", available, format("cyclonedx-json"), home("https://github.com/CycloneDX/cdxgen"),
			note("worker-sca image (tool manifest): CycloneDX SBOM with cryptographic assets, from lockfiles and manifests only (no package manager runs); replaces the component inventory like Syft; no findings")),
	)
	iacscaScanTypeTools("sca", "npm-audit", "yarn-audit", "pnpm-audit", "composer-audit")
	iacscaScanTypeTools("malware", "guarddog")
	iacscaScanTypeTools("supply-chain", "guarddog", "pathos-depcheck")
	iacscaScanTypeTools("sbom", CDXGen)
}

// IsSBOMTool reports whether a scanner's output is an SBOM (Syft, cdxgen):
// it becomes the repository's component inventory, not findings.
func IsSBOMTool(key string) bool {
	sc, ok := Lookup(key)
	return ok && sc.Category == "sbom"
}
