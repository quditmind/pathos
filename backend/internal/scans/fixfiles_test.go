package scans

import (
	"testing"

	"pathos/internal/depfix"
	"pathos/internal/scm"
)

// A dependency fix may only change manifests and lockfiles of its
// ecosystem: the API pushes the worker's files as a branch.
func TestManifestsOnly(t *testing.T) {
	ok := []struct {
		eco   string
		paths []string
	}{
		{depfix.NPM, []string{"package.json", "web/package.json"}},
		{depfix.Go, []string{"go.mod", "go.sum"}},
		{depfix.PyPI, []string{"requirements.txt", "constraints/prod-constraints.txt"}},
		{depfix.Maven, []string{"pom.xml", "gradle/libs.versions.toml", "app/build.gradle.kts"}},
		{depfix.NuGet, []string{"src/App.csproj", "Directory.Packages.props"}},
	}
	for _, c := range ok {
		var files []scm.FileChange
		for _, p := range c.paths {
			files = append(files, scm.FileChange{Path: p})
		}
		if err := manifestsOnly(files, c.eco); err != nil {
			t.Errorf("%s %v: %v", c.eco, c.paths, err)
		}
	}
	bad := []struct {
		eco, path string
	}{
		{depfix.NPM, ".github/workflows/release.yml"},
		{depfix.NPM, "src/index.js"},
		{depfix.Go, "package.json"}, // another ecosystem's manifest
		{depfix.PyPI, "Makefile"},
		{"", "go.mod"},
	}
	for _, c := range bad {
		if err := manifestsOnly([]scm.FileChange{{Path: "package.json"}, {Path: c.path}}, c.eco); err == nil {
			t.Errorf("%q accepted for ecosystem %q", c.path, c.eco)
		}
	}
}
