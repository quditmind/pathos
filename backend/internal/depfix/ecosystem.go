package depfix

import (
	"net/url"
	"strings"
)

// FromPURL returns the ecosystem of a package URL and the package name in
// the form depfix expects (Maven "group:artifact", npm "@scope/name").
func FromPURL(purl string) (ecosystem, name, version string) {
	rest, ok := strings.CutPrefix(purl, "pkg:")
	if !ok {
		return "", "", ""
	}
	rest, _, _ = strings.Cut(rest, "#")
	rest, _, _ = strings.Cut(rest, "?")
	typ, path, ok := strings.Cut(rest, "/")
	if !ok {
		return "", "", ""
	}
	if i := strings.LastIndex(path, "@"); i > 0 {
		version, _ = url.PathUnescape(path[i+1:])
		path = path[:i]
	}
	segs := strings.Split(path, "/")
	for i, s := range segs {
		segs[i], _ = url.PathUnescape(s)
	}
	n := segs[len(segs)-1]
	ns := strings.Join(segs[:len(segs)-1], "/")
	typ = strings.ToLower(typ)
	switch typ {
	case Maven:
		if ns == "" {
			return typ, n, version
		}
		return typ, ns + ":" + n, version
	case NPM:
		if ns != "" {
			return typ, ns + "/" + n, version
		}
		return typ, n, version
	case Go:
		if ns != "" {
			return typ, ns + "/" + n, version
		}
		return typ, n, version
	case PyPI, NuGet, Cargo, Composer, RubyGems:
		if ns != "" && typ == Composer {
			return typ, ns + "/" + n, version
		}
		return typ, n, version
	}
	return typ, n, version
}

// FromPath guesses the ecosystem from the manifest or lockfile a scanner
// reported.
func FromPath(p string) string {
	b := strings.ToLower(base(p))
	switch {
	case b == "package.json" || b == "package-lock.json" || b == "npm-shrinkwrap.json" || b == "yarn.lock" || b == "pnpm-lock.yaml" || b == "bun.lock":
		return NPM
	case pyRequirementsFile(p) || b == "pipfile" || b == "pipfile.lock" || b == "poetry.lock" || b == "uv.lock" || b == "pyproject.toml" || b == "setup.py":
		return PyPI
	case b == "pom.xml" || strings.HasSuffix(b, ".gradle") || strings.HasSuffix(b, ".gradle.kts") || b == "gradle.lockfile" ||
		strings.HasSuffix(b, ".versions.toml") || strings.HasSuffix(b, ".jar"):
		return Maven
	case strings.HasSuffix(b, ".csproj") || strings.HasSuffix(b, ".fsproj") || strings.HasSuffix(b, ".vbproj") || b == "packages.lock.json" ||
		b == "packages.config" || b == "directory.packages.props":
		return NuGet
	case b == "go.mod" || b == "go.sum":
		return Go
	case b == "cargo.lock" || b == "cargo.toml":
		return Cargo
	case b == "composer.lock" || b == "composer.json":
		return Composer
	case b == "gemfile.lock" || b == "gemfile" || strings.HasSuffix(b, ".gemspec"):
		return RubyGems
	}
	return ""
}
