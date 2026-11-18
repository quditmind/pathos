package worker

import (
	"encoding/json"
	"encoding/xml"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// RuntimeInventory lists the runtimes and base images a repository declares
// (version files, build files, Dockerfiles), for end-of-life matching. It
// is computed by reading files only; nothing is executed.
type RuntimeInventory struct {
	Version  int            `json:"version"`
	Runtimes []RuntimeEntry `json:"runtimes"`
}

// RuntimeEntry is one declaration.
type RuntimeEntry struct {
	Kind    string `json:"kind"` // runtime | image
	Name    string `json:"name"` // node, python, ruby, go, java, dotnet, php; image: the reference
	Version string `json:"version"`
	Path    string `json:"path"`
}

const (
	maxRuntimeFiles   = 20000
	maxRuntimeEntries = 500
	maxRuntimeFileLen = 512 << 10
)

var (
	// An exact or "major[.minor]" version, optionally with ^, ~, = or v
	// (ranges such as ">=16" say nothing about what actually runs).
	exactVersionRe = regexp.MustCompile(`^[\^~=v]?\s*(\d+(?:\.\d+){0,3})(?:\.x|\.\*)?(?:[-+][\w.]+)?$`)
	fromRe         = regexp.MustCompile(`(?im)^\s*FROM\s+(?:--platform=\S+\s+)?(\S+)`)
	gemRubyRe      = regexp.MustCompile(`(?m)^\s*ruby\s+['"]([^'"]+)['"]`)
	toolchainRe    = regexp.MustCompile(`(?m)^toolchain\s+go(\d+\.\d+(?:\.\d+)?)\s*$`)
	gradleJavaRe   = regexp.MustCompile(`(?:JavaLanguageVersion\.of\(\s*(\d+)\s*\)|(?:source|target)Compatibility\s*=\s*['"]?(?:JavaVersion\.VERSION_)?(\d+(?:[._]\d+)?)['"]?)`)
	runtimeTxtRe   = regexp.MustCompile(`^(python|ruby|php|node)-(\d+(?:\.\d+){0,2})$`)
	targetFwRe     = regexp.MustCompile(`(?i)<TargetFrameworks?>([^<]+)</TargetFrameworks?>`)
	netFwRe        = regexp.MustCompile(`(?i)^net(?:coreapp)?(\d+\.\d+)`)
)

// exactVersion returns the version of an exact or major[.minor] spec.
func exactVersion(spec string) string {
	spec = strings.TrimSpace(spec)
	if m := exactVersionRe.FindStringSubmatch(spec); m != nil {
		return m[1]
	}
	return ""
}

// toolVersionNames maps asdf/mise tool names to runtime names.
var toolVersionNames = map[string]string{"nodejs": "node", "node": "node", "python": "python", "ruby": "ruby", "golang": "go",
	"go": "go", "java": "java", "php": "php", "dotnet": "dotnet", "dotnet-core": "dotnet"}

// runtimesOf parses one file (by base name) and returns its declarations.
func runtimesOf(rel, name string, data []byte) []RuntimeEntry {
	text := string(data)
	var out []RuntimeEntry
	add := func(kind, n, v string) {
		if n != "" && (v != "" || kind == "image") && len(n) <= 300 && len(v) <= 100 {
			out = append(out, RuntimeEntry{Kind: kind, Name: n, Version: v, Path: rel})
		}
	}
	first := strings.TrimSpace(strings.SplitN(text, "\n", 2)[0])
	lower := strings.ToLower(name)
	switch {
	case lower == ".nvmrc" || lower == ".node-version":
		add("runtime", "node", exactVersion(first))
	case lower == ".python-version":
		add("runtime", "python", exactVersion(first))
	case lower == ".ruby-version":
		add("runtime", "ruby", exactVersion(strings.TrimPrefix(first, "ruby-")))
	case lower == ".java-version":
		add("runtime", "java", exactVersion(first))
	case lower == ".go-version":
		add("runtime", "go", exactVersion(first))
	case lower == "runtime.txt":
		if m := runtimeTxtRe.FindStringSubmatch(first); m != nil {
			add("runtime", m[1], m[2])
		}
	case lower == ".tool-versions":
		for _, line := range strings.Split(text, "\n") {
			f := strings.Fields(line)
			if len(f) >= 2 && !strings.HasPrefix(f[0], "#") {
				if n, ok := toolVersionNames[f[0]]; ok {
					v := f[1]
					if n == "java" {
						// e.g. temurin-17.0.8+7 or openjdk-21
						if i := strings.LastIndex(v, "-"); i >= 0 {
							v = v[i+1:]
						}
					}
					add("runtime", n, exactVersion(v))
				}
			}
		}
	case lower == "go.mod":
		// Only the toolchain line names the Go release that builds the
		// module; the go line is a minimum language version.
		if m := toolchainRe.FindStringSubmatch(text); m != nil {
			add("runtime", "go", m[1])
		}
	case lower == "global.json":
		var g struct {
			SDK struct {
				Version string `json:"version"`
			} `json:"sdk"`
		}
		if json.Unmarshal(data, &g) == nil {
			add("runtime", "dotnet", exactVersion(g.SDK.Version))
		}
	case strings.HasSuffix(lower, ".csproj") || strings.HasSuffix(lower, ".fsproj") || strings.HasSuffix(lower, ".vbproj"):
		for _, m := range targetFwRe.FindAllStringSubmatch(text, 5) {
			for _, fw := range strings.Split(m[1], ";") {
				if n := netFwRe.FindStringSubmatch(strings.TrimSpace(fw)); n != nil {
					add("runtime", "dotnet", n[1])
				}
			}
		}
	case lower == "gemfile":
		if m := gemRubyRe.FindStringSubmatch(text); m != nil {
			add("runtime", "ruby", exactVersion(m[1]))
		}
	case lower == "package.json":
		var p struct {
			Engines map[string]string `json:"engines"`
		}
		if json.Unmarshal(data, &p) == nil {
			add("runtime", "node", exactVersion(p.Engines["node"]))
		}
	case lower == "composer.json":
		var c struct {
			Require map[string]string `json:"require"`
		}
		if json.Unmarshal(data, &c) == nil {
			add("runtime", "php", exactVersion(c.Require["php"]))
		}
	case lower == "pom.xml":
		var pom struct {
			Properties struct {
				Java    string `xml:"java.version"`
				Release string `xml:"maven.compiler.release"`
				Source  string `xml:"maven.compiler.source"`
			} `xml:"properties"`
		}
		if xml.Unmarshal(data, &pom) == nil {
			v := firstNonEmptyStr(pom.Properties.Release, pom.Properties.Java, pom.Properties.Source)
			if !strings.Contains(v, "${") {
				add("runtime", "java", javaVersion(v))
			}
		}
	case lower == "build.gradle" || lower == "build.gradle.kts":
		if m := gradleJavaRe.FindStringSubmatch(text); m != nil {
			add("runtime", "java", javaVersion(firstNonEmptyStr(m[1], m[2])))
		}
	case lower == "dockerfile" || strings.HasPrefix(lower, "dockerfile.") || strings.HasSuffix(lower, ".dockerfile") || lower == "containerfile":
		stages := map[string]bool{}
		for _, line := range strings.Split(text, "\n") {
			m := fromRe.FindStringSubmatch(line)
			if m == nil {
				continue
			}
			ref := m[1]
			f := strings.Fields(strings.TrimSpace(line))
			if len(f) >= 4 && strings.EqualFold(f[len(f)-2], "as") {
				stages[strings.ToLower(f[len(f)-1])] = true
			}
			if strings.EqualFold(ref, "scratch") || strings.Contains(ref, "$") || stages[strings.ToLower(ref)] {
				continue
			}
			add("image", ref, "")
		}
	}
	return out
}

// javaVersion normalizes "1.8" to "8" and "17" stays "17".
func javaVersion(v string) string {
	v = strings.ReplaceAll(strings.TrimSpace(v), "_", ".")
	if strings.HasPrefix(v, "1.") {
		v = strings.TrimPrefix(v, "1.")
	}
	return exactVersion(v)
}

// runtimeFile reports whether a file name may declare a runtime.
func runtimeFile(name string) bool {
	l := strings.ToLower(name)
	switch l {
	case ".nvmrc", ".node-version", ".python-version", ".ruby-version", ".java-version", ".go-version", ".tool-versions",
		"runtime.txt", "go.mod", "global.json", "gemfile", "package.json", "composer.json", "pom.xml", "build.gradle",
		"build.gradle.kts", "dockerfile", "containerfile":
		return true
	}
	return strings.HasPrefix(l, "dockerfile.") || strings.HasSuffix(l, ".dockerfile") || strings.HasSuffix(l, ".csproj") ||
		strings.HasSuffix(l, ".fsproj") || strings.HasSuffix(l, ".vbproj")
}

// collectRuntimes walks src and builds the runtime inventory.
func collectRuntimes(src string) RuntimeInventory {
	inv := RuntimeInventory{Version: 1, Runtimes: []RuntimeEntry{}}
	root, err := os.OpenRoot(src)
	if err != nil {
		return inv
	}
	defer root.Close()
	files := 0
	seen := map[RuntimeEntry]bool{}
	_ = filepath.WalkDir(src, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if d.IsDir() {
			if path != src && (skipDirs[d.Name()] || (strings.HasPrefix(d.Name(), ".") && d.Name() != ".github")) {
				return filepath.SkipDir
			}
			return nil
		}
		if !d.Type().IsRegular() || !runtimeFile(d.Name()) {
			return nil
		}
		if files++; files > maxRuntimeFiles || len(inv.Runtimes) >= maxRuntimeEntries {
			return filepath.SkipAll
		}
		rel, err := filepath.Rel(src, path)
		if err != nil {
			return nil
		}
		f, err := root.Open(rel)
		if err != nil {
			return nil
		}
		data, err := io.ReadAll(io.LimitReader(f, maxRuntimeFileLen))
		_ = f.Close()
		if err != nil {
			return nil
		}
		for _, e := range runtimesOf(filepath.ToSlash(rel), d.Name(), data) {
			if !seen[e] && len(inv.Runtimes) < maxRuntimeEntries {
				seen[e] = true
				inv.Runtimes = append(inv.Runtimes, e)
			}
		}
		return nil
	})
	return inv
}
