package aifix

import (
	"errors"
	"fmt"
	"path"
	"strings"
)

// Policy confines a fix. The finding's file may always be changed (even
// when it is a CI file, build script or manifest: that is where the
// finding is). Other files must be in the same directory, must not be
// protected (Protected) and the whole fix changes at most MaxFiles files.
type Policy struct {
	FindingFile string
}

// Check validates a parsed diff against the policy.
func (p Policy) Check(d Diff) error {
	if len(d.Files) > MaxFiles {
		return fmt.Errorf("the fix changes %d files; at most %d are allowed", len(d.Files), MaxFiles)
	}
	dir := path.Dir(p.FindingFile)
	touchesFinding := false
	for _, f := range d.Files {
		if f.Path == p.FindingFile {
			touchesFinding = true
			continue
		}
		if path.Dir(f.Path) != dir {
			return fmt.Errorf("the fix changes %s, outside the finding's directory; only %s and files next to it may change", f.Path, p.FindingFile)
		}
		if why := Protected(f.Path); why != "" {
			return fmt.Errorf("the fix changes %s (%s); only the finding's own file may be such a file", f.Path, why)
		}
	}
	if !touchesFinding {
		return fmt.Errorf("the fix does not change the finding's file %s", p.FindingFile)
	}
	removed, added := map[string]int{}, map[string]int{}
	for _, f := range d.Files {
		for _, h := range f.Hunks {
			for _, l := range h.Lines {
				norm := strings.Join(strings.Fields(l[1:]), " ")
				switch l[0] {
				case '+':
					if strings.Contains(l, Placeholder) {
						return errors.New("the fix writes the redaction placeholder " + Placeholder + " into the code")
					}
					added[norm]++
				case '-':
					removed[norm]++
				}
			}
		}
	}
	same := len(removed) == len(added)
	for k, n := range removed {
		if added[k] != n {
			same = false
		}
	}
	if same {
		return errors.New("the fix makes no change beyond whitespace")
	}
	return nil
}

// Protected files are CI definitions, build scripts, dependency manifests
// and lockfiles, and repository control files. A fix may change one only
// when the finding is in it. Protected returns why a path is protected
// ("" when it is not).
func Protected(p string) string {
	lp := strings.ToLower(p)
	base := path.Base(lp)
	for _, dir := range protectedDirs {
		if strings.HasPrefix(lp, dir.prefix) || strings.Contains(lp, "/"+dir.prefix) {
			return dir.why
		}
	}
	if why, ok := protectedNames[base]; ok {
		return why
	}
	for _, s := range protectedSuffixes {
		if strings.HasSuffix(base, s.suffix) {
			return s.why
		}
	}
	switch {
	case strings.HasPrefix(base, "requirements") && strings.HasSuffix(base, ".txt"),
		strings.HasPrefix(base, "constraints") && strings.HasSuffix(base, ".txt"):
		return manifest
	case strings.HasPrefix(base, "dockerfile"), strings.HasSuffix(base, ".dockerfile"), strings.HasPrefix(base, "containerfile"):
		return build
	case strings.HasPrefix(base, ".pathos"):
		return control
	}
	return ""
}

const (
	ci       = "a CI/CD pipeline definition"
	build    = "a build script"
	manifest = "a dependency manifest or lockfile"
	control  = "a repository control file"
)

var protectedDirs = []struct{ prefix, why string }{
	{".github/workflows/", ci}, {".github/actions/", ci}, {".gitlab/", ci}, {".circleci/", ci}, {".buildkite/", ci},
	{".tekton/", ci}, {".azure-pipelines/", ci}, {".drone/", ci}, {".woodpecker/", ci}, {".forgejo/workflows/", ci},
	{".gitea/workflows/", ci}, {"gradle/wrapper/", build}, {".mvn/", build},
	{".git/", control}, {".husky/", control}, {".githooks/", control}, {".devcontainer/", control}, {".vscode/", control},
}

var protectedNames = map[string]string{
	".gitlab-ci.yml": ci, "azure-pipelines.yml": ci, "azure-pipelines.yaml": ci, "bitbucket-pipelines.yml": ci, ".travis.yml": ci,
	".drone.yml": ci, ".woodpecker.yml": ci, "jenkinsfile": ci, "appveyor.yml": ci, ".appveyor.yml": ci, "cloudbuild.yaml": ci,
	"cloudbuild.yml": ci, "buildspec.yml": ci, "buildspec.yaml": ci, "codemagic.yaml": ci, ".pre-commit-config.yaml": ci,
	"dependabot.yml": ci, "renovate.json": ci, ".gitlab-ci.yaml": ci, "action.yml": ci, "action.yaml": ci,

	"makefile": build, "gnumakefile": build, "cmakelists.txt": build, "build.gradle": build, "build.gradle.kts": build,
	"settings.gradle": build, "settings.gradle.kts": build, "gradle.properties": build, "gradlew": build, "gradlew.bat": build,
	"mvnw": build, "mvnw.cmd": build, "build.xml": build, "build.sh": build, "configure": build, "configure.ac": build,
	"setup.py": build, "setup.cfg": build, "noxfile.py": build, "tox.ini": build, "rakefile": build, "taskfile.yml": build,
	"taskfile.yaml": build, "justfile": build, "magefile.go": build, "build.rs": build, "meson.build": build, "build": build,
	"build.bazel": build, "workspace": build, "workspace.bazel": build, "module.bazel": build, "conftest.py": build,

	"package.json": manifest, "package-lock.json": manifest, "npm-shrinkwrap.json": manifest, "yarn.lock": manifest,
	"pnpm-lock.yaml": manifest, "pnpm-workspace.yaml": manifest, ".npmrc": manifest, ".yarnrc": manifest, ".yarnrc.yml": manifest,
	"bun.lockb": manifest, "bun.lock": manifest, "go.mod": manifest, "go.sum": manifest, "go.work": manifest, "go.work.sum": manifest,
	"pipfile": manifest, "pipfile.lock": manifest, "pyproject.toml": manifest, "poetry.lock": manifest, "uv.lock": manifest,
	"pdm.lock": manifest, "gemfile": manifest, "gemfile.lock": manifest, "cargo.toml": manifest, "cargo.lock": manifest,
	"composer.json": manifest, "composer.lock": manifest, "pom.xml": manifest, "packages.config": manifest,
	"packages.lock.json": manifest, "directory.packages.props": manifest, "directory.build.props": manifest,
	"directory.build.targets": manifest, "nuget.config": manifest, "build.sbt": manifest, "mix.exs": manifest, "mix.lock": manifest,
	"package.swift": manifest, "package.resolved": manifest, "podfile": manifest, "podfile.lock": manifest, "pubspec.yaml": manifest,
	"pubspec.lock": manifest, "gradle.lockfile": manifest, "libs.versions.toml": manifest, "vcpkg.json": manifest,
	"conanfile.txt": manifest, "conanfile.py": manifest, "deno.json": manifest, "deno.jsonc": manifest, "deno.lock": manifest,

	".gitmodules": control, ".gitattributes": control, ".gitignore": control, "codeowners": control, ".envrc": control,
}

var protectedSuffixes = []struct{ suffix, why string }{
	{".mk", build}, {".cmake", build}, {".bzl", build}, {".gemspec", manifest}, {".csproj", manifest}, {".vbproj", manifest},
	{".fsproj", manifest}, {".sln", build}, {".nuspec", manifest},
}
