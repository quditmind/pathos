package worker

import (
	"slices"
	"testing"
)

// A scanned repository must not be able to configure checkov: a bare
// "-d"/"--directory" argument makes checkov load the repository's
// .checkov.yaml (external-checks-dir → code execution in the worker).
func TestCheckovArgsDoNotLoadRepositoryConfig(t *testing.T) {
	args := checkovArgs("/work/job/src", "/work/job/out/checkov")
	for i, a := range args {
		if a == "-d" || a == "--directory" {
			t.Fatalf("bare %q at %d: checkov would read the repository's .checkov.yaml", a, i)
		}
		if a == "--config-file" || a == "--external-checks-dir" || a == "--external-checks-git" {
			t.Fatalf("unexpected %q", a)
		}
	}
	if !slices.Contains(args, "--directory=/work/job/src") {
		t.Fatalf("source directory missing: %v", args)
	}
}
