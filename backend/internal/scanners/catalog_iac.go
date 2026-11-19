package scanners

import "slices"

// IaC and CI/CD pipeline tools of the worker-iac family image
// (workers/iac, Compose profile iac). Each is defined by a tool manifest in
// workers/iac/tools.d; the catalog entries below make them runnable
// (AdapterAvailable) and record their licences.

func init() {
	iacscaUpsert(
		s("kics", "KICS", "iac", "Apache-2.0", "use", "iac", available, format("json"), home("https://github.com/Checkmarx/kics"),
			note("worker-iac image (tool manifest; KICS JSON, kics import parser): the queries bundled with the release; no descriptions download")),
		s("kube-linter", "KubeLinter", "iac", "Apache-2.0", "use", "iac", available, format("json"), home("https://github.com/stackrox/kube-linter"),
			note("worker-iac image (tool manifest; KubeLinter JSON, kube-linter import parser)")),
		s("kubescape", "Kubescape", "iac", "Apache-2.0", "use", "iac", available, format("json"), home("https://github.com/kubescape/kubescape"),
			note("worker-iac image (tool manifest; Kubescape JSON, kubescape import parser): offline scan of Kubernetes manifests with the frameworks bundled in the image; nothing is uploaded")),
		s("tflint", "TFLint", "iac", "MPL-2.0", "use", "iac", available, format("json"), home("https://github.com/terraform-linters/tflint"),
			note("worker-iac image (tool manifest; TFLint JSON, tflint import parser): the bundled Terraform ruleset; plugins and remote modules are not downloaded")),
		s("conftest", "Conftest", "iac", "Apache-2.0", "use", "iac", available, format("json"), home("https://github.com/open-policy-agent/conftest"),
			note("worker-iac image (tool manifest; Conftest JSON, conftest import parser): the PATHOS policy bundle for Kubernetes, Dockerfiles and Terraform")),
		s("hadolint", "Hadolint", "iac", "GPL-3.0-only", "use", "iac", available, format("json"), home("https://github.com/hadolint/hadolint"),
			note("worker-iac image (tool manifest; Hadolint JSON, hadolint import parser): Dockerfiles and Containerfiles")),
		s("cfn-lint", "cfn-lint", "iac", "MIT-0", "use", "iac", available, format("json"), home("https://github.com/aws-cloudformation/cfn-lint"),
			note("worker-iac image (tool manifest; cfn-lint JSON, cfn-lint import parser): CloudFormation templates")),
		s("cfn-nag", "cfn_nag", "iac", "MIT", "use", "iac", available, format("json"), home("https://github.com/stelligent/cfn_nag"),
			note("worker-iac image (tool manifest; cfn_nag JSON, cfn-nag import parser): CloudFormation templates")),
		s("polaris", "Polaris", "iac", "Apache-2.0", "use", "iac", available, format("json"), home("https://github.com/FairwindsOps/polaris"),
			note("worker-iac image (tool manifest; Polaris audit JSON, polaris import parser): offline audit of Kubernetes manifests with Polaris' security checks only")),
		s("kube-score", "kube-score", "iac", "MIT", "use", "iac", available, format("json"), home("https://github.com/zegl/kube-score"),
			note("worker-iac image (tool manifest; kube-score JSON, kube-score import parser)")),
		s("trivy-config", "Trivy (config)", "iac", "Apache-2.0", "use", "iac", available, home("https://github.com/aquasecurity/trivy"),
			note("worker-iac image (tool manifest; SARIF): Trivy misconfiguration scanning with the checks embedded in the binary; no check bundle download")),
		s("scorecard", "OpenSSF Scorecard", "supply-chain", "Apache-2.0", "use", "iac", available, format("json"), home("https://github.com/ossf/scorecard"),
			note("worker-iac image (tool manifest; Scorecard JSON, scorecard import parser): --local mode on the checkout with the checks that need no API token; nothing is contacted")),
	)
	iacscaScanTypeTools("iac", "cfn-lint", "cfn-nag", "polaris", "kube-score", "trivy-config")
	iacscaScanTypeTools("cicd", "scorecard")
}

// iacscaUpsert replaces the catalog entries with the same keys, or appends
// new ones, keeping the order of catalog.go for the existing keys.
func iacscaUpsert(entries ...Scanner) {
	for _, sc := range entries {
		if i := slices.IndexFunc(Catalog, func(c Scanner) bool { return c.Key == sc.Key }); i >= 0 {
			Catalog[i] = sc
			continue
		}
		Catalog = append(Catalog, sc)
	}
}

// iacscaScanTypeTools adds tools to a scan type's tool list (once each).
func iacscaScanTypeTools(typeID string, keys ...string) {
	for i := range ScanTypes {
		if ScanTypes[i].ID != typeID {
			continue
		}
		for _, k := range keys {
			if !slices.Contains(ScanTypes[i].Tools, k) {
				ScanTypes[i].Tools = append(ScanTypes[i].Tools, k)
			}
		}
		return
	}
	panic("unknown scan type " + typeID)
}
