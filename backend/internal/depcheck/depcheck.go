// Package depcheck finds dependency-confusion and typosquatting risks in a
// repository's dependency declarations, offline. It reads package.json,
// .npmrc, requirements*.txt and pyproject.toml files; it never contacts a
// registry and never runs repository code.
//
// Checks:
//
//	DEPCHECK-TYPOSQUAT-NPM / -PYPI   a dependency whose name is one edit
//	    (insertion, deletion, substitution or transposition of adjacent
//	    characters) or one separator away from a popular package of the
//	    same ecosystem, and is not itself a popular package
//	DEPCHECK-PIP-EXTRA-INDEX         a requirements file adds an index with
//	    --extra-index-url: pip takes the highest version from all indexes,
//	    so a public package can replace a private one of the same name
//	DEPCHECK-NPM-UNMAPPED-SCOPE      .npmrc maps some scopes to a private
//	    registry, but a scoped dependency's scope is not mapped, so npm
//	    fetches it from the default (public) registry
//
// The popular package lists (data/) are the top PyPI and npm package names
// shipped with Datadog GuardDog (Apache-2.0), see data/README.
package depcheck

import (
	"bufio"
	_ "embed"
	"encoding/json"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strings"
)

//go:embed data/top-npm.txt
var topNPM string

//go:embed data/top-pypi.txt
var topPyPI string

// Finding is one risk.
type Finding struct {
	RuleID    string `json:"rule_id"`
	Severity  string `json:"severity"`
	Title     string `json:"title"`
	Message   string `json:"message"`
	File      string `json:"file"`
	Line      int    `json:"line,omitempty"`
	Ecosystem string `json:"ecosystem"`
	Package   string `json:"package,omitempty"`
	Version   string `json:"version,omitempty"`
	// SimilarTo is the popular package a typosquatting candidate resembles.
	SimilarTo string `json:"similar_to,omitempty"`
	CWE       string `json:"cwe"`
}

// Report is the tool's output.
type Report struct {
	Tool     string    `json:"tool"`
	Version  string    `json:"version"`
	Findings []Finding `json:"findings"`
}

// Popular is a set of popular package names of one ecosystem.
type Popular struct {
	names map[string]bool
	byLen map[int][]string
	norm  map[string]string // separator-free name -> popular name
}

// NewPopular builds a set from names (one per line, most popular first;
// # comments). Every name counts as popular; only the first top names are
// targets of typosquatting comparisons, because less popular names are
// often one edit away from each other legitimately.
func NewPopular(list string, top int) *Popular {
	p := &Popular{names: map[string]bool{}, byLen: map[int][]string{}, norm: map[string]string{}}
	for _, l := range strings.Split(list, "\n") {
		n := strings.ToLower(strings.TrimSpace(l))
		if n == "" || strings.HasPrefix(n, "#") || p.names[n] {
			continue
		}
		p.names[n] = true
		if top > 0 && len(p.names) > top {
			continue
		}
		p.byLen[len(n)] = append(p.byLen[len(n)], n)
		if _, ok := p.norm[stripSep(n)]; !ok {
			p.norm[stripSep(n)] = n
		}
	}
	for _, v := range p.byLen {
		sort.Strings(v)
	}
	return p
}

// Len is the number of names.
func (p *Popular) Len() int { return len(p.names) }

func stripSep(n string) string {
	return strings.NewReplacer("-", "", "_", "", ".", "").Replace(n)
}

// compareTop is how many of the most popular names of each ecosystem are
// compared with dependencies.
const compareTop = 1000

// minPopularLen: names shorter than this are not compared (one edit away
// from almost anything).
const minPopularLen = 5

// Similar returns the popular package name resembles, or "".
func (p *Popular) Similar(name string) string {
	n := strings.ToLower(name)
	if p.names[n] {
		return ""
	}
	if m, ok := p.norm[stripSep(n)]; ok && m != n {
		return m
	}
	for l := len(n) - 1; l <= len(n)+1; l++ {
		if l < minPopularLen {
			continue
		}
		for _, c := range p.byLen[l] {
			if oneEdit(n, c) {
				return c
			}
		}
	}
	return ""
}

// oneEdit reports whether a and b differ by exactly one insertion,
// deletion, substitution or adjacent transposition.
func oneEdit(a, b string) bool {
	if a == b {
		return false
	}
	la, lb := len(a), len(b)
	switch {
	case la == lb:
		i := 0
		for i < la && a[i] == b[i] {
			i++
		}
		if a[i+1:] == b[i+1:] {
			return true // substitution
		}
		return i+1 < la && a[i] == b[i+1] && a[i+1] == b[i] && a[i+2:] == b[i+2:]
	case la+1 == lb:
		a, b = b, a
		fallthrough
	case la == lb+1:
		i := 0
		for i < len(b) && a[i] == b[i] {
			i++
		}
		return a[i+1:] == b[i:]
	}
	return false
}

// Checker runs the checks.
type Checker struct {
	NPM, PyPI *Popular
}

// Default uses the embedded popular package lists.
func Default() *Checker {
	return &Checker{NPM: NewPopular(topNPM, compareTop), PyPI: NewPopular(topPyPI, compareTop)}
}

var skipDirs = map[string]bool{".git": true, "node_modules": true, "vendor": true, ".venv": true, "venv": true, "site-packages": true,
	"bower_components": true, ".tox": true}

const maxFileSize = 4 << 20

// Scan checks the repository at root. Paths in findings are relative to it.
func (c *Checker) Scan(root string) ([]Finding, error) {
	var out []Finding
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil // unreadable entries are skipped
		}
		if d.IsDir() {
			if path != root && skipDirs[d.Name()] {
				return filepath.SkipDir
			}
			return nil
		}
		if !d.Type().IsRegular() {
			return nil
		}
		name := d.Name()
		rel, _ := filepath.Rel(root, path)
		rel = filepath.ToSlash(rel)
		switch {
		case name == "package.json":
			out = append(out, c.packageJSON(path, rel)...)
		case name == "pyproject.toml":
			out = append(out, c.pyproject(path, rel)...)
		case strings.HasPrefix(name, "requirements") && strings.HasSuffix(name, ".txt"):
			out = append(out, c.requirements(path, rel)...)
		}
		return nil
	})
	return out, err
}

func readSmall(path string) ([]byte, bool) {
	st, err := os.Stat(path)
	if err != nil || st.Size() > maxFileSize {
		return nil, false
	}
	// #nosec G304 -- a file of the repository being scanned
	b, err := os.ReadFile(path)
	return b, err == nil
}

// lineOf returns the first line (1-based) of text that contains needle.
func lineOf(text, needle string) int {
	for i, l := range strings.Split(text, "\n") {
		if strings.Contains(l, needle) {
			return i + 1
		}
	}
	return 0
}

func (c *Checker) typo(eco string, p *Popular, name, version, rel string, line int) []Finding {
	m := p.Similar(name)
	if m == "" {
		return nil
	}
	reg := map[string]string{"npm": "npm", "pypi": "PyPI"}[eco]
	return []Finding{{RuleID: "DEPCHECK-TYPOSQUAT-" + strings.ToUpper(eco), Severity: "high", Ecosystem: eco, Package: name, Version: version,
		SimilarTo: m, File: rel, Line: line, CWE: "CWE-1357",
		Title: "Possible typosquatting: " + name + " resembles the popular " + reg + " package " + m,
		Message: "The dependency " + name + " differs from the popular " + reg + " package " + m + " by one character or separator. " +
			"Typosquatting packages imitate popular names to be installed by mistake. Check that " + name + " is the intended package."}}
}

// packageJSON checks npm dependencies, and scoped dependencies against the
// .npmrc next to package.json.
func (c *Checker) packageJSON(path, rel string) []Finding {
	raw, ok := readSmall(path)
	if !ok {
		return nil
	}
	var pkg map[string]json.RawMessage
	if json.Unmarshal(raw, &pkg) != nil {
		return nil
	}
	deps := map[string]string{}
	for _, k := range []string{"dependencies", "devDependencies", "optionalDependencies", "peerDependencies"} {
		var m map[string]string
		if json.Unmarshal(pkg[k], &m) == nil {
			for n, v := range m {
				deps[n] = v
			}
		}
	}
	names := make([]string, 0, len(deps))
	for n := range deps {
		names = append(names, n)
	}
	sort.Strings(names)
	text := string(raw)
	scopes, private := npmrcScopes(filepath.Join(filepath.Dir(path), ".npmrc"))
	var out []Finding
	for _, n := range names {
		v := deps[n]
		if strings.Contains(v, ":") && !strings.HasPrefix(v, "npm:") {
			continue // file:, git:, http:, workspace: and similar are not registry packages
		}
		line := lineOf(text, `"`+n+`"`)
		if strings.HasPrefix(n, "@") {
			scope := strings.SplitN(n, "/", 2)[0]
			if private && !scopes[scope] {
				out = append(out, Finding{RuleID: "DEPCHECK-NPM-UNMAPPED-SCOPE", Severity: "medium", Ecosystem: "npm", Package: n, Version: v,
					File: rel, Line: line, CWE: "CWE-427",
					Title: "Scope " + scope + " is not mapped to the private registry",
					Message: ".npmrc maps other scopes to a private registry, but not " + scope + ": npm fetches " + n +
						" from the default registry. If " + scope + " is an internal scope, anyone who registers it on the public registry can supply this package."})
			}
			continue
		}
		out = append(out, c.typo("npm", c.NPM, n, v, rel, line)...)
	}
	return out
}

var npmrcScopeRe = regexp.MustCompile(`^\s*(@[a-z0-9][a-z0-9._~-]*)\s*:\s*registry\s*=\s*(\S+)`)

// npmrcScopes returns the scopes an .npmrc maps to a registry, and whether
// it maps any scope to a registry other than the public one.
func npmrcScopes(path string) (map[string]bool, bool) {
	raw, ok := readSmall(path)
	scopes := map[string]bool{}
	if !ok {
		return scopes, false
	}
	private := false
	for _, l := range strings.Split(string(raw), "\n") {
		if m := npmrcScopeRe.FindStringSubmatch(strings.ToLower(l)); m != nil {
			scopes[m[1]] = true
			if !strings.Contains(m[2], "registry.npmjs.org") && !strings.Contains(m[2], "registry.yarnpkg.com") {
				private = true
			}
		}
	}
	return scopes, private
}

var reqNameRe = regexp.MustCompile(`^([A-Za-z0-9][A-Za-z0-9._-]*)\s*(\[[^\]]*\])?\s*(?:(===|==|~=|>=|<=|!=|>|<)\s*([^\s;,#]+))?`)

// requirements checks a pip requirements file.
func (c *Checker) requirements(path, rel string) []Finding {
	raw, ok := readSmall(path)
	if !ok {
		return nil
	}
	var out []Finding
	sc := bufio.NewScanner(strings.NewReader(string(raw)))
	sc.Buffer(make([]byte, 64<<10), 1<<20)
	ln := 0
	for sc.Scan() {
		ln++
		l := strings.TrimSpace(sc.Text())
		if i := strings.Index(l, " #"); i >= 0 {
			l = strings.TrimSpace(l[:i])
		}
		if l == "" || strings.HasPrefix(l, "#") {
			continue
		}
		if strings.HasPrefix(l, "--extra-index-url") {
			out = append(out, Finding{RuleID: "DEPCHECK-PIP-EXTRA-INDEX", Severity: "medium", Ecosystem: "pypi", File: rel, Line: ln, CWE: "CWE-427",
				Title: "pip --extra-index-url allows dependency confusion",
				Message: "This requirements file adds a package index with --extra-index-url. pip installs the highest version found in any index, " +
					"so a package published on PyPI under the name of a private package can replace it. Use a single index that proxies PyPI, " +
					"or pin every requirement with --hash."})
			continue
		}
		if strings.HasPrefix(l, "-") || strings.Contains(l, "://") || strings.Contains(l, "@ ") {
			continue
		}
		if m := reqNameRe.FindStringSubmatch(l); m != nil {
			out = append(out, c.typo("pypi", c.PyPI, m[1], m[4], rel, ln)...)
		}
	}
	return out
}

var (
	tomlSectionRe = regexp.MustCompile(`^\s*\[([^\]]+)\]\s*$`)
	tomlKeyRe     = regexp.MustCompile(`^\s*"?([A-Za-z0-9][A-Za-z0-9._-]*)"?\s*=`)
	quotedRe      = regexp.MustCompile(`"([^"]+)"|'([^']+)'`)
)

// pyproject checks [project] dependencies, optional dependencies and
// Poetry dependency tables of a pyproject.toml (line-based reading of the
// common layouts).
func (c *Checker) pyproject(path, rel string) []Finding {
	raw, ok := readSmall(path)
	if !ok {
		return nil
	}
	var out []Finding
	section, inArray := "", false
	seen := map[string]bool{}
	add := func(spec string, ln int) {
		m := reqNameRe.FindStringSubmatch(strings.TrimSpace(spec))
		if m == nil || seen[strings.ToLower(m[1])] || strings.EqualFold(m[1], "python") {
			return
		}
		seen[strings.ToLower(m[1])] = true
		out = append(out, c.typo("pypi", c.PyPI, m[1], m[4], rel, ln)...)
	}
	for i, l := range strings.Split(string(raw), "\n") {
		ln := i + 1
		if m := tomlSectionRe.FindStringSubmatch(l); m != nil {
			section, inArray = strings.TrimSpace(m[1]), false
			continue
		}
		t := strings.TrimSpace(l)
		if strings.HasPrefix(t, "#") {
			continue
		}
		poetry := strings.HasPrefix(section, "tool.poetry") && strings.HasSuffix(section, "dependencies")
		switch {
		case poetry:
			if m := tomlKeyRe.FindStringSubmatch(l); m != nil {
				add(m[1], ln)
			}
		case section == "project" || section == "project.optional-dependencies" || section == "dependency-groups":
			if !inArray {
				k := tomlKeyRe.FindStringSubmatch(l)
				if k == nil || (section == "project" && k[1] != "dependencies") {
					continue
				}
				inArray = true
				t = t[strings.Index(t, "=")+1:]
			}
			for _, q := range quotedRe.FindAllStringSubmatch(t, -1) {
				add(q[1]+q[2], ln)
			}
			if strings.Contains(t, "]") {
				inArray = false
			}
		}
	}
	return out
}

// Sorted orders findings by file, line and rule.
func Sorted(fs []Finding) []Finding {
	slices.SortStableFunc(fs, func(a, b Finding) int {
		if a.File != b.File {
			return strings.Compare(a.File, b.File)
		}
		if a.Line != b.Line {
			return a.Line - b.Line
		}
		return strings.Compare(a.RuleID, b.RuleID)
	})
	return fs
}
