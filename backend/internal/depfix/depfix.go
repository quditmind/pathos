// Package depfix updates a vulnerable dependency to a fixed version in a
// checked-out repository, for automatic fix pull requests.
//
// It only edits text: it never runs a package manager, build tool or any
// code from the repository. An ecosystem is supported only where a text
// edit of the manifest is the complete, correct change. Where a lockfile
// would need regenerating (it records resolved versions and integrity
// hashes the edit cannot compute without the ecosystem's tool), the
// request is reported as not supported instead of producing a lockfile
// that disagrees with its manifest.
package depfix

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

// Ecosystems (package URL types).
const (
	NPM      = "npm"
	PyPI     = "pypi"
	Maven    = "maven"
	NuGet    = "nuget"
	Go       = "golang"
	Cargo    = "cargo"
	Composer = "composer"
	RubyGems = "gem"
)

// NotSupportedError explains why a fix cannot be produced automatically.
type NotSupportedError struct{ Reason string }

func (e *NotSupportedError) Error() string { return "not supported: " + e.Reason }

func notSupported(format string, a ...any) error {
	return &NotSupportedError{Reason: fmt.Sprintf(format, a...)}
}

// IsNotSupported reports whether err is a NotSupportedError.
func IsNotSupported(err error) bool {
	var ns *NotSupportedError
	return errors.As(err, &ns)
}

// Support describes whether an ecosystem can be fixed automatically.
type Support struct {
	Supported bool   `json:"supported"`
	Reason    string `json:"reason,omitempty"`
	Edits     string `json:"edits,omitempty"`
}

// Supported reports what depfix can do for an ecosystem.
func Supported(ecosystem string) Support {
	switch ecosystem {
	case PyPI:
		return Support{Supported: true, Edits: "pins the package in requirements/constraints files (files with --hash entries are not edited)"}
	case Maven:
		return Support{Supported: true, Edits: "updates the version in pom.xml (literal or ${property}) or in Gradle build files and version catalogs (not when a gradle.lockfile pins it)"}
	case NuGet:
		return Support{Supported: true, Edits: "updates PackageReference/PackageVersion in project files and Directory.Packages.props (not when packages.lock.json is used)"}
	case NPM:
		return Support{Supported: true, Edits: "updates package.json only when the project has no lockfile; projects with package-lock.json, yarn.lock or pnpm-lock.yaml are not supported because the lockfile must be regenerated with npm, yarn or pnpm"}
	case Go:
		return Support{Reason: "go.sum must be updated with checksums from the Go toolchain, which is not in the worker image"}
	case Cargo:
		return Support{Reason: "Cargo.lock must be regenerated with cargo, which is not in the worker image"}
	case Composer:
		return Support{Reason: "composer.lock must be regenerated with Composer, which is not in the worker image"}
	case RubyGems:
		return Support{Reason: "Gemfile.lock must be regenerated with Bundler, which is not in the worker image"}
	case "":
		return Support{Reason: "the package ecosystem is unknown (no package URL in the SBOM and no recognised manifest)"}
	}
	return Support{Reason: "automatic fixes are not available for " + ecosystem + " packages"}
}

// Request is one dependency to update.
type Request struct {
	Ecosystem string
	Package   string
	Current   string
	Target    string
	// ManifestHint is the file the scanner reported (may be a lockfile).
	ManifestHint string
}

// Change is the new content of one file (path relative to the root).
type Change struct {
	Path    string
	Content []byte
}

// Result is the set of edited files.
type Result struct {
	Changes []Change
	Notes   []string
}

var (
	versionRe = regexp.MustCompile(`^[0-9A-Za-z][0-9A-Za-z.+_-]{0,99}$`)
	packageRe = regexp.MustCompile(`^[A-Za-z0-9@][A-Za-z0-9@/._:+-]{0,299}$`)
)

// ValidVersion reports whether v is a plain version string safe to write.
func ValidVersion(v string) bool { return versionRe.MatchString(v) }

// Limits on the repository walk.
const (
	maxFiles     = 100000
	maxFileBytes = 4 << 20
	maxDepth     = 14
)

// Apply edits the repository at root.
func Apply(root string, req Request) (Result, error) {
	if !ValidVersion(req.Target) {
		return Result{}, errors.New("invalid target version")
	}
	if !packageRe.MatchString(req.Package) {
		return Result{}, errors.New("invalid package name")
	}
	if s := Supported(req.Ecosystem); !s.Supported {
		return Result{}, notSupported("%s", s.Reason)
	}
	files, err := walk(root)
	if err != nil {
		return Result{}, err
	}
	var r Result
	switch req.Ecosystem {
	case PyPI:
		err = fixPyPI(root, files, req, &r)
	case Maven:
		err = fixMaven(root, files, req, &r)
	case NuGet:
		err = fixNuGet(root, files, req, &r)
	case NPM:
		err = fixNPM(root, files, req, &r)
	}
	if err != nil {
		return Result{}, err
	}
	if len(r.Changes) == 0 {
		return Result{}, notSupported("%s %s is not declared directly in a manifest PATHOS can edit (it is probably a transitive dependency; upgrade the package that depends on it, or add an override/constraint)", req.Package, req.Current)
	}
	sort.Slice(r.Changes, func(i, j int) bool { return r.Changes[i].Path < r.Changes[j].Path })
	return r, nil
}

// walk lists regular files (relative, slash-separated), skipping VCS and
// dependency directories and symbolic links.
func walk(root string) ([]string, error) {
	var out []string
	err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		rel, _ := filepath.Rel(root, p)
		rel = filepath.ToSlash(rel)
		if d.IsDir() {
			switch d.Name() {
			case ".git", "node_modules", "vendor", ".venv", "venv", "__pycache__", "target", "build", "dist", "bin", "obj", ".gradle":
				if rel != "." {
					return filepath.SkipDir
				}
			}
			if strings.Count(rel, "/") >= maxDepth {
				return filepath.SkipDir
			}
			return nil
		}
		if !d.Type().IsRegular() {
			return nil
		}
		if len(out) >= maxFiles {
			return filepath.SkipAll
		}
		out = append(out, rel)
		return nil
	})
	return out, err
}

func read(root, rel string) ([]byte, bool) {
	p := filepath.Join(root, filepath.FromSlash(rel))
	info, err := os.Lstat(p)
	if err != nil || !info.Mode().IsRegular() || info.Size() > maxFileBytes {
		return nil, false
	}
	b, err := os.ReadFile(p) // #nosec G304 -- path comes from walking the job's own checkout; symlinks are skipped
	return b, err == nil
}

func base(rel string) string { return rel[strings.LastIndex(rel, "/")+1:] }

// --- PyPI --------------------------------------------------------------------

var (
	pyNormRe = regexp.MustCompile(`[-_.]+`)
	pyLineRe = regexp.MustCompile(`^(\s*)([A-Za-z0-9][A-Za-z0-9._-]*)(\s*\[[^\]]*\])?\s*((?:===|==|~=|!=|<=|>=|<|>)[^;#]*)?(\s*;[^#]*)?(\s*#.*)?$`)
)

func pyNorm(s string) string { return strings.ToLower(pyNormRe.ReplaceAllString(s, "-")) }

func pyRequirementsFile(rel string) bool {
	b := strings.ToLower(base(rel))
	return strings.HasSuffix(b, ".txt") && (strings.Contains(b, "requirements") || strings.Contains(b, "constraints"))
}

func fixPyPI(root string, files []string, req Request, r *Result) error {
	want := pyNorm(req.Package)
	for _, rel := range files {
		if !pyRequirementsFile(rel) && rel != req.ManifestHint {
			continue
		}
		if !strings.HasSuffix(strings.ToLower(rel), ".txt") {
			continue
		}
		data, ok := read(root, rel)
		if !ok {
			continue
		}
		lines := strings.SplitAfter(string(data), "\n")
		changed, hashed := false, false
		for i, raw := range lines {
			body := strings.TrimRight(raw, "\r\n")
			eol := raw[len(body):]
			t := strings.TrimSpace(body)
			if t == "" || strings.HasPrefix(t, "#") || strings.HasPrefix(t, "-") {
				continue
			}
			m := pyLineRe.FindStringSubmatch(body)
			if m == nil || pyNorm(m[2]) != want {
				continue
			}
			if strings.Contains(string(data), "--hash") || strings.HasSuffix(strings.TrimSpace(body), `\`) {
				hashed = true
				break
			}
			spec := strings.TrimSpace(m[4])
			if spec == "=="+req.Target || spec == "==="+req.Target {
				continue
			}
			pad := m[4][len(strings.TrimRight(m[4], " \t")):]
			lines[i] = m[1] + m[2] + strings.TrimSpace(m[3]) + "==" + req.Target + pad + m[5] + m[6] + eol
			changed = true
		}
		if hashed {
			return notSupported("%s pins packages with --hash; the hashes of %s %s must be added with pip-compile or pip hash", rel, req.Package, req.Target)
		}
		if changed {
			r.Changes = append(r.Changes, Change{Path: rel, Content: []byte(strings.Join(lines, ""))})
		}
	}
	return nil
}

// --- Maven and Gradle ------------------------------------------------------------

var (
	mvnDepRe      = regexp.MustCompile(`(?s)<dependency>(.*?)</dependency>`)
	mvnGroupRe    = regexp.MustCompile(`<groupId>\s*([^<\s]+)\s*</groupId>`)
	mvnArtifactRe = regexp.MustCompile(`<artifactId>\s*([^<\s]+)\s*</artifactId>`)
	mvnVersionRe  = regexp.MustCompile(`<version>(\s*)([^<]*?)(\s*)</version>`)
	mvnPropRe     = regexp.MustCompile(`^\$\{([A-Za-z0-9._-]+)\}$`)
	propsRe       = regexp.MustCompile(`(?s)<properties>(.*?)</properties>`)
)

// edit is a byte-range replacement.
type edit struct {
	start, end int
	text       string
}

func applyEdits(data []byte, edits []edit) []byte {
	sort.Slice(edits, func(i, j int) bool { return edits[i].start > edits[j].start })
	out := append([]byte(nil), data...)
	last := len(out) + 1
	for _, e := range edits {
		if e.end > last { // overlapping; keep the later one only
			continue
		}
		out = append(out[:e.start], append([]byte(e.text), out[e.end:]...)...)
		last = e.start
	}
	return out
}

func splitGA(pkg string) (string, string, bool) {
	g, a, ok := strings.Cut(pkg, ":")
	if !ok || g == "" || a == "" || strings.Contains(a, ":") {
		// Some scanners report "group/artifact".
		g, a, ok = strings.Cut(pkg, "/")
		if !ok || g == "" || a == "" {
			return "", "", false
		}
	}
	return g, a, true
}

func fixMaven(root string, files []string, req Request, r *Result) error {
	g, a, ok := splitGA(req.Package)
	if !ok {
		return notSupported("Maven package %q is not in group:artifact form", req.Package)
	}
	pending := map[string][]edit{}
	contents := map[string][]byte{}
	var props []string // properties to update (any pom)
	for _, rel := range files {
		if base(rel) != "pom.xml" {
			continue
		}
		data, ok := read(root, rel)
		if !ok {
			continue
		}
		contents[rel] = data
		for _, loc := range mvnDepRe.FindAllSubmatchIndex(data, -1) {
			blk := data[loc[2]:loc[3]]
			gm, am := mvnGroupRe.FindSubmatch(blk), mvnArtifactRe.FindSubmatch(blk)
			if gm == nil || am == nil || string(gm[1]) != g || string(am[1]) != a {
				continue
			}
			vm := mvnVersionRe.FindSubmatchIndex(blk)
			if vm == nil {
				continue // managed elsewhere (dependencyManagement, parent, BOM)
			}
			v := string(blk[vm[4]:vm[5]])
			if pm := mvnPropRe.FindStringSubmatch(v); pm != nil {
				props = append(props, pm[1])
				continue
			}
			if v != req.Current {
				continue
			}
			pending[rel] = append(pending[rel], edit{loc[2] + vm[4], loc[2] + vm[5], req.Target})
		}
	}
	for _, prop := range props {
		tagRe := regexp.MustCompile(`<` + regexp.QuoteMeta(prop) + `>(\s*)([^<]*?)(\s*)</` + regexp.QuoteMeta(prop) + `>`)
		for rel, data := range contents {
			for _, pl := range propsRe.FindAllSubmatchIndex(data, -1) {
				blk := data[pl[2]:pl[3]]
				for _, tm := range tagRe.FindAllSubmatchIndex(blk, -1) {
					if string(blk[tm[4]:tm[5]]) == req.Current {
						pending[rel] = append(pending[rel], edit{pl[2] + tm[4], pl[2] + tm[5], req.Target})
					}
				}
			}
		}
	}
	if err := fixGradle(root, files, g, a, req, pending, contents); err != nil {
		return err
	}
	for rel, eds := range pending {
		r.Changes = append(r.Changes, Change{Path: rel, Content: applyEdits(contents[rel], dedupe(eds))})
	}
	if len(props) > 0 && len(r.Changes) == 0 {
		return notSupported("the version of %s comes from a property defined outside this repository (parent POM or BOM)", req.Package)
	}
	return nil
}

func dedupe(eds []edit) []edit {
	seen := map[[2]int]bool{}
	out := eds[:0]
	for _, e := range eds {
		k := [2]int{e.start, e.end}
		if !seen[k] {
			seen[k] = true
			out = append(out, e)
		}
	}
	return out
}

func gradleFile(rel string) bool {
	b := base(rel)
	return strings.HasSuffix(b, ".gradle") || strings.HasSuffix(b, ".gradle.kts") || strings.HasSuffix(b, ".versions.toml")
}

func fixGradle(root string, files []string, g, a string, req Request, pending map[string][]edit, contents map[string][]byte) error {
	q := regexp.QuoteMeta
	coord := regexp.MustCompile(`["']` + q(g+":"+a+":") + `(` + q(req.Current) + `)(?::[^"'$]*)?["']`)
	mapForm := regexp.MustCompile(`group\s*[:=]\s*["']` + q(g) + `["']\s*,\s*name\s*[:=]\s*["']` + q(a) + `["']\s*,\s*version\s*[:=]\s*["'](` + q(req.Current) + `)["']`)
	tomlModule := regexp.MustCompile(`module\s*=\s*"` + q(g+":"+a) + `"\s*,\s*version\s*=\s*"(` + q(req.Current) + `)"`)
	tomlRef := regexp.MustCompile(`module\s*=\s*"` + q(g+":"+a) + `"\s*,\s*version\.ref\s*=\s*"([A-Za-z0-9._-]+)"`)
	lockLine := g + ":" + a + ":" + req.Current + "="
	for _, rel := range files {
		if base(rel) == "gradle.lockfile" || strings.HasSuffix(base(rel), ".lockfile") {
			if data, ok := read(root, rel); ok && strings.Contains(string(data), lockLine) {
				return notSupported("%s locks %s %s; dependency locks must be rewritten with Gradle (--write-locks)", rel, req.Package, req.Current)
			}
		}
	}
	for _, rel := range files {
		if !gradleFile(rel) {
			continue
		}
		data, ok := read(root, rel)
		if !ok {
			continue
		}
		contents[rel] = data
		for _, re := range []*regexp.Regexp{coord, mapForm, tomlModule} {
			for _, m := range re.FindAllSubmatchIndex(data, -1) {
				pending[rel] = append(pending[rel], edit{m[2], m[3], req.Target})
			}
		}
		if strings.HasSuffix(rel, ".versions.toml") {
			for _, m := range tomlRef.FindAllSubmatch(data, -1) {
				keyRe := regexp.MustCompile(`(?m)^\s*` + q(string(m[1])) + `\s*=\s*"(` + q(req.Current) + `)"`)
				for _, km := range keyRe.FindAllSubmatchIndex(data, -1) {
					pending[rel] = append(pending[rel], edit{km[2], km[3], req.Target})
				}
			}
		}
	}
	return nil
}

// --- NuGet -------------------------------------------------------------------

func nugetFile(rel string) bool {
	b := strings.ToLower(base(rel))
	return strings.HasSuffix(b, ".csproj") || strings.HasSuffix(b, ".fsproj") || strings.HasSuffix(b, ".vbproj") ||
		b == "directory.packages.props" || b == "packages.config"
}

func fixNuGet(root string, files []string, req Request, r *Result) error {
	for _, rel := range files {
		if strings.EqualFold(base(rel), "packages.lock.json") {
			return notSupported("%s is a NuGet lock file; it must be regenerated with dotnet restore --force-evaluate", rel)
		}
	}
	q := regexp.QuoteMeta
	// <PackageReference Include="X" Version="1.2.3" />, <PackageVersion …>,
	// packages.config <package id="X" version="1.2.3" />, in either
	// attribute order; and <PackageReference Include="X"><Version>…</Version>.
	elemRe := regexp.MustCompile(`(?is)<(?:PackageReference|PackageVersion|package)\b[^>]*?(?:Include|id)\s*=\s*"` + q(req.Package) + `"[^>]*>`)
	attrRe := regexp.MustCompile(`(?i)\b(?:Version|version)\s*=\s*"(` + q(req.Current) + `)"`)
	childRe := regexp.MustCompile(`(?is)^\s*<Version>\s*(` + q(req.Current) + `)\s*</Version>`)
	for _, rel := range files {
		if !nugetFile(rel) {
			continue
		}
		data, ok := read(root, rel)
		if !ok {
			continue
		}
		var eds []edit
		for _, m := range elemRe.FindAllIndex(data, -1) {
			tag := data[m[0]:m[1]]
			if am := attrRe.FindSubmatchIndex(tag); am != nil {
				eds = append(eds, edit{m[0] + am[2], m[0] + am[3], req.Target})
				continue
			}
			if cm := childRe.FindSubmatchIndex(data[m[1]:]); cm != nil {
				eds = append(eds, edit{m[1] + cm[2], m[1] + cm[3], req.Target})
			}
		}
		if len(eds) > 0 {
			r.Changes = append(r.Changes, Change{Path: rel, Content: applyEdits(data, eds)})
		}
	}
	return nil
}

// --- npm -----------------------------------------------------------------------

var npmLockfiles = []string{"package-lock.json", "npm-shrinkwrap.json", "yarn.lock", "pnpm-lock.yaml", "bun.lockb", "bun.lock"}

func fixNPM(root string, files []string, req Request, r *Result) error {
	for _, rel := range files {
		for _, l := range npmLockfiles {
			if base(rel) == l {
				return notSupported("%s must be regenerated with npm, yarn or pnpm (resolved versions and integrity hashes), which are not in the worker image; PATHOS does not edit lockfiles by hand", rel)
			}
		}
	}
	q := regexp.QuoteMeta
	sectRe := regexp.MustCompile(`(?s)"(dependencies|devDependencies|optionalDependencies)"\s*:\s*\{[^{}]*\}`)
	depRe := regexp.MustCompile(`"` + q(req.Package) + `"\s*:\s*"([~^]?)([^"]*)"`)
	for _, rel := range files {
		if base(rel) != "package.json" {
			continue
		}
		data, ok := read(root, rel)
		if !ok {
			continue
		}
		var eds []edit
		for _, s := range sectRe.FindAllIndex(data, -1) {
			blk := data[s[0]:s[1]]
			for _, m := range depRe.FindAllSubmatchIndex(blk, -1) {
				prefix, spec := string(blk[m[2]:m[3]]), string(blk[m[4]:m[5]])
				if !npmSpecAllows(spec, req.Current) {
					continue
				}
				eds = append(eds, edit{s[0] + m[2], s[0] + m[5], prefix + req.Target})
			}
		}
		if len(eds) > 0 {
			r.Changes = append(r.Changes, Change{Path: rel, Content: applyEdits(data, eds)})
		}
	}
	return nil
}

// npmSpecAllows is deliberately narrow: only plain versions (optionally
// with ^ or ~ already stripped) equal to the vulnerable version, or whose
// major (^) or minor (~) line contains it. Ranges, tags, URLs and
// workspace protocols are left alone.
func npmSpecAllows(spec, current string) bool {
	if spec == current {
		return true
	}
	if !ValidVersion(spec) {
		return false
	}
	sp, cp := numParts(spec), numParts(current)
	return len(sp) > 0 && len(cp) > 0 && sp[0] == cp[0]
}

func numParts(v string) []int {
	v = strings.TrimPrefix(v, "v")
	var out []int
	for _, p := range strings.Split(v, ".") {
		n, err := strconv.Atoi(p)
		if err != nil {
			break
		}
		out = append(out, n)
	}
	return out
}

var fixedSplitRe = regexp.MustCompile(`\s*(?:,|\|\||;|\s)\s*`)

// PickTarget chooses the version to upgrade to from a scanner's fixed
// version field, which may list several versions ("2.31.0, 3.0.1") or carry
// operators (">= 1.2.3"). It prefers the lowest fixed version above current
// on current's major line, then the lowest fixed version above current.
// Returns "" when nothing usable is listed.
func PickTarget(current, fixed string) string {
	var cands []string
	for _, f := range fixedSplitRe.Split(strings.TrimSpace(fixed), -1) {
		f = strings.TrimLeft(f, "=<>~^!v ")
		if ValidVersion(f) && len(numParts(f)) > 0 {
			cands = append(cands, f)
		}
	}
	sort.Slice(cands, func(i, j int) bool { return Compare(cands[i], cands[j]) < 0 })
	// Releases first; a pre-release only when no release is listed.
	sort.SliceStable(cands, func(i, j int) bool { return !strings.Contains(cands[i], "-") && strings.Contains(cands[j], "-") })
	cur := numParts(current)
	above := func(v string) bool { return len(cur) == 0 || Compare(v, current) > 0 }
	for _, c := range cands {
		if p := numParts(c); len(cur) > 0 && p[0] == cur[0] && above(c) {
			return c
		}
	}
	for _, c := range cands {
		if above(c) {
			return c
		}
	}
	return ""
}

// Compare orders dotted numeric versions; a pre-release suffix sorts before
// the release. Non-numeric parts compare as strings.
func Compare(a, b string) int {
	split := func(v string) ([]string, string) {
		v = strings.TrimPrefix(v, "v")
		main, pre, _ := strings.Cut(v, "-")
		main, _, _ = strings.Cut(main, "+")
		return strings.Split(main, "."), pre
	}
	ap, apre := split(a)
	bp, bpre := split(b)
	for i := 0; i < max(len(ap), len(bp)); i++ {
		x, y := "0", "0"
		if i < len(ap) && ap[i] != "" {
			x = ap[i]
		}
		if i < len(bp) && bp[i] != "" {
			y = bp[i]
		}
		xn, xe := strconv.Atoi(x)
		yn, ye := strconv.Atoi(y)
		switch {
		case xe == nil && ye == nil:
			if xn != yn {
				if xn < yn {
					return -1
				}
				return 1
			}
		case x != y:
			return strings.Compare(x, y)
		}
	}
	switch {
	case apre == bpre:
		return 0
	case apre == "":
		return 1
	case bpre == "":
		return -1
	}
	return strings.Compare(apre, bpre)
}
