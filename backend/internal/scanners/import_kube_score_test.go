package scanners

import "testing"

// testdata/imports/kube-score.json: kube-score 1.20.0 (`kube-score score
// --output-format json`, all default checks) on the worker-iac manifest
// sample (a privileged Deployment with host networking and a hostPath
// volume, a NodePort Service and a Pod without a security context), run in
// the pathos-worker-iac image offline. The output is unchanged.

func TestImportKubeScore(t *testing.T) {
	runImportCases(t, []importCase{
		{file: "kube-score.json", format: "kube-score", count: 25, checks: map[int]want{
			0:  {sev: "high", file: "k8s/deployment.yaml", line: 1, rule: "container-resources"},
			7:  {sev: "high", rule: "container-security-context-privileged"},
			13: {sev: "medium", rule: "deployment-replicas"},
			14: {sev: "medium", rule: "service-type", line: 30},
			23: {sev: "high", file: "k8s/pod.yaml", line: 1, rule: "container-image-tag"},
		}, cats: map[int]string{0: "iac", 6: "other", 7: "iac", 13: "other", 14: "iac"}},
	})
}

func TestNormalizePathRelativeWorkspace(t *testing.T) {
	for in, want := range map[string]string{
		"../../work/j1/src/terraform/main.tf": "terraform/main.tf",
		"/work/j1/src/a.tf":                   "a.tf",
		"work/j1/src/a.tf":                    "a.tf",
		"../a.tf":                             "a.tf",
		"src/work/x/src/a.tf":                 "src/work/x/src/a.tf",
	} {
		if got := NormalizePath(in); got != want {
			t.Errorf("NormalizePath(%q) = %q, want %q", in, got, want)
		}
	}
}
