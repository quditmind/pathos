package rea

import (
	"fmt"
	"path"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

// Source ↔ binary diff. The binary side is the analysis document; the
// source side is the CodeGraph snapshot of the commit the artifact was built
// from. Four kinds of items are compared:
//
//   - function: the artifact's own functions (not library code) with the
//     source functions. Go binaries carry exact symbol names, which map to
//     CodeGraph qualified names through the module path; other binaries are
//     matched by plain symbol name.
//   - package: Go packages linked into the binary with the packages of the
//     main module, the source's third-party components and the sensitive
//     standard-library imports CodeGraph records per file.
//   - route: HTTP paths in the binary's strings with the source routes (the
//     API inventory). A debug or admin route only in the binary is the
//     classic case (net/http/pprof registers /debug/pprof/ handlers).
//   - string: URLs referenced by the artifact's own code with the source's
//     external services.
//
// Library code is not compared item by item (it is not in the source), but
// sensitive library packages and imports are reported. Every item carries
// evidence: binary file offsets with the tool, source file:line references.

// SourceNode is a node of the source snapshot the diff reads.
type SourceNode struct {
	Key, Type, Label, File string
	Line                   int
	Attrs                  map[string]any
}

// DiffItem is one compared item.
type DiffItem struct {
	Side, Kind, Name             string
	BinaryKey, SourceKey         string
	SourceFile                   string
	SourceLine                   int
	BinaryOffset                 int64
	HasOffset                    bool
	Tool                         string
	Sensitive                    bool
	SensitiveReason, SensitiveID string
	Evidence                     []EvidenceItem
}

// EvidenceItem is one piece of diff evidence (API Ref).
type EvidenceItem struct {
	Evidence string `json:"evidence"`
	Kind     string `json:"kind"`
	Ref      string `json:"ref"`
	Detail   string `json:"detail"`
}

func binEv(off int64, t, what string) EvidenceItem {
	return EvidenceItem{Evidence: "verified", Kind: "binary", Ref: hexRef(off), Detail: text(t+": "+what, 500)}
}

func srcEv(file string, line int, what string) EvidenceItem {
	ref := file
	if line > 0 {
		ref += ":" + strconv.Itoa(line)
	}
	return EvidenceItem{Evidence: "verified", Kind: "file_line", Ref: text(ref, 1000), Detail: text("CodeGraph: "+what, 500)}
}

// sensitiveRule describes a sensitive API.
type sensitiveRule struct {
	ID, Reason, Title, Severity, CWE, Category string
}

// Sensitive Go packages (linked into the binary).
var sensitiveGoPackages = map[string]sensitiveRule{
	"net/http/pprof": {"rea/go-pprof", "net/http/pprof registers /debug/pprof/ profiling handlers (memory, goroutines, command line)",
		"Profiling endpoints (/debug/pprof) shipped in the binary", "high", "CWE-215", "information_disclosure"},
	"expvar": {"rea/go-expvar", "expvar publishes /debug/vars (command line and memory statistics)",
		"Debug variables endpoint (/debug/vars) shipped in the binary", "medium", "CWE-215", "information_disclosure"},
	"net/http/cgi": {"rea/go-cgi", "net/http/cgi runs external programs for HTTP requests",
		"CGI handler shipped in the binary", "medium", "CWE-78", "elevation_of_privilege"},
	"os/exec": {"rea/go-exec", "os/exec starts operating-system commands",
		"Command execution capability in the binary", "medium", "CWE-78", "elevation_of_privilege"},
	"plugin": {"rea/go-plugin", "plugin loads code at run time",
		"Dynamic code loading in the binary", "medium", "CWE-829", "tampering"},
	"crypto/des": {"rea/go-weak-crypto", "weak cryptography (DES, RC4, MD5, SHA-1) is linked",
		"Weak cryptography linked into the binary", "low", "CWE-327", "information_disclosure"},
}

func init() {
	for _, p := range []string{"crypto/rc4", "crypto/md5", "crypto/sha1"} {
		sensitiveGoPackages[p] = sensitiveGoPackages["crypto/des"]
	}
}

// Sensitive native imports (C library functions).
var sensitiveImports = map[string]sensitiveRule{}

func init() {
	exec := sensitiveRule{"rea/native-exec", "the binary imports a command-execution function", "Command execution imported by the binary", "medium", "CWE-78", "elevation_of_privilege"}
	for _, n := range []string{"system", "popen", "execve", "execv", "execvp", "execvpe", "execl", "execlp", "execle", "posix_spawn", "posix_spawnp", "WinExec", "ShellExecuteA", "ShellExecuteW", "CreateProcessA", "CreateProcessW"} {
		sensitiveImports[n] = exec
	}
	unsafeFn := sensitiveRule{"rea/native-unsafe-string", "the binary imports an unbounded string function", "Unbounded string functions imported by the binary", "low", "CWE-676", "tampering"}
	for _, n := range []string{"gets", "strcpy", "strcat", "sprintf", "vsprintf", "_mbscpy", "lstrcpyA", "lstrcpyW"} {
		sensitiveImports[n] = unsafeFn
	}
	load := sensitiveRule{"rea/native-dlopen", "the binary loads libraries at run time", "Dynamic library loading in the binary", "low", "CWE-829", "tampering"}
	for _, n := range []string{"dlopen", "LoadLibraryA", "LoadLibraryW", "LoadLibraryExA", "LoadLibraryExW"} {
		sensitiveImports[n] = load
	}
	priv := sensitiveRule{"rea/native-privilege", "the binary changes privileges or traces processes", "Privilege changes or process tracing in the binary", "medium", "CWE-250", "elevation_of_privilege"}
	for _, n := range []string{"setuid", "setgid", "seteuid", "setresuid", "ptrace", "mprotect"} {
		sensitiveImports[n] = priv
	}
}

// Sensitive routes (debug and administration endpoints).
var sensitiveRouteRe = regexp.MustCompile(`^/(debug|actuator|admin|console|_debug|__debug__|_internal|internal/debug|metrics/debug)(/|$)`)

var routeRule = sensitiveRule{"rea/hidden-route", "a debug or administration route is compiled into the binary but not in the API inventory",
	"Undeclared debug or administration route in the binary", "medium", "CWE-489", "information_disclosure"}

var debugRouteRule = map[string]string{"/debug/pprof": "net/http/pprof", "/debug/vars": "expvar"}

var (
	routeLikeRe = regexp.MustCompile(`^/[A-Za-z0-9_\-./{}:*~]{0,200}$`)
	notRouteRe  = regexp.MustCompile(`^/(etc|proc|dev|usr|lib|lib64|sys|tmp|var|bin|sbin|opt|home|root|run|mnt|nix|private|System|Library|Applications|Users|snap|boot)(/|$)`)
	fileExtRe   = regexp.MustCompile(`\.(so(\.\d+)*|go|c|h|s|txt|conf|json|yaml|yml|pem|crt|key|log|sock|pid|lock|py|sh|dll|exe|a)$`)
	goClosureRe = regexp.MustCompile(`(\.func\d+(\.\d+)*|\.gowrap\d+|\.deferwrap\d+|-fm|\.stkobj|\.arginfo\d+|\.args_stackmap|\.abi0)$`)
	goSkipRe    = regexp.MustCompile(`(^|\.)init(\.\d+)?$|^type:|^go:|\.\.inittask$|^runtime\.|\.glob\.\.`)
	paramRe     = regexp.MustCompile(`\{[^}]*\}|:[A-Za-z_][A-Za-z0-9_]*|<[^>]*>|\*`)
)

// routeLike reports whether a string looks like an HTTP path (not a file
// system path).
func routeLike(s string) bool {
	if len(s) < 2 || !routeLikeRe.MatchString(s) || notRouteRe.MatchString(s) || fileExtRe.MatchString(s) || strings.Contains(s, "//") {
		return false
	}
	return strings.ContainsAny(s[1:], "abcdefghijklmnopqrstuvwxyz")
}

// normRoute is the comparable form of a route path: parameters as {},
// no trailing slash.
func normRoute(p string) string {
	p = paramRe.ReplaceAllString(strings.TrimSpace(p), "{}")
	if len(p) > 1 {
		p = strings.TrimRight(p, "/")
	}
	return p
}

// goPackageOf returns the package import path of a Go symbol name
// ("net/http/pprof.Index" → "net/http/pprof",
// "example.com/a/b.(*T).M" → "example.com/a/b").
func goPackageOf(sym string) string {
	// Type arguments of generic instantiations may contain slashes.
	if i := strings.IndexByte(sym, '['); i >= 0 {
		sym = sym[:i]
	}
	slash := strings.LastIndexByte(sym, '/')
	dot := strings.IndexByte(sym[slash+1:], '.')
	if dot < 0 {
		return ""
	}
	return sym[:slash+1+dot]
}

// Compare computes the diff items. Drafts are derived from them by
// Drafts.
func Compare(d *Doc, source []SourceNode) []DiffItem {
	var items []DiffItem
	isGo := d.Go != nil || d.Artifact.Language == "go"
	mainMod, mainPkg := "", ""
	if d.Go != nil {
		mainMod, mainPkg = d.Go.MainModule.Path, d.Go.Path
	}
	// --- source indexes ---
	modulePath := map[string]string{} // source dir → import path
	var funcs, routes, services []SourceNode
	components := map[string]SourceNode{} // module path (purl base) → node
	type srcImport struct {
		node SourceNode
		line int
	}
	stdImports := map[string]srcImport{}
	for _, n := range source {
		switch n.Type {
		case "module":
			if qn, _ := n.Attrs["qualified_name"].(string); qn != "" {
				dir := firstNonEmpty(attr(n, "path"), attr(n, "dir"), n.File)
				modulePath[strings.Trim(dir, "/")] = qn
			}
		case "function":
			funcs = append(funcs, n)
		case "route":
			routes = append(routes, n)
		case "external_service":
			services = append(services, n)
		case "component":
			if purl := attr(n, "purl"); strings.HasPrefix(purl, "pkg:golang/") {
				base := strings.TrimPrefix(purl, "pkg:golang/")
				if i := strings.IndexByte(base, '@'); i >= 0 {
					base = base[:i]
				}
				components[base] = n
			}
		case "file":
			for _, f := range strings.Fields(attr(n, "sensitive_imports")) {
				i := strings.LastIndexByte(f, ':')
				if i <= 0 {
					continue
				}
				line, _ := strconv.Atoi(f[i+1:])
				ip := f[:i]
				if _, ok := stdImports[ip]; !ok {
					stdImports[ip] = srcImport{n, line}
				}
			}
		}
	}
	// --- functions ---
	srcByName := map[string][]SourceNode{}
	srcPkgs := map[string]bool{}
	for _, f := range funcs {
		if strings.Contains(f.Key, "#") || strings.HasSuffix(f.File, "_test.go") {
			continue // tests are not in the binary
		}
		for _, k := range sourceFuncKeys(f, isGo, mainMod, modulePath) {
			srcByName[k] = append(srcByName[k], f)
			if isGo {
				srcPkgs[goPackageOf(k)] = true
			}
		}
	}
	matchedSrc := map[string]bool{}
	binPkgs := map[string]bool{}
	// pkgFirst: the first function of each linked package (its offset is
	// the evidence of a package without an import table entry).
	pkgFirst := map[string]Function{}
	for _, f := range d.Functions {
		name := f.Name
		if isGo {
			pkg := firstNonEmpty(f.Package, goPackageOf(name))
			binPkgs[pkg] = true
			if cur, ok := pkgFirst[pkg]; f.Offset > 0 && (!ok || f.Offset < cur.Offset) {
				pkgFirst[pkg] = f
			}
			if f.Library || goSkipRe.MatchString(name) {
				continue
			}
			name = goClosureRe.ReplaceAllString(name, "")
			if strings.HasPrefix(name, "main.") && mainPkg != "" {
				name = mainPkg + strings.TrimPrefix(name, "main")
			}
		} else if f.Library || strings.HasPrefix(name, "fcn.") || strings.HasPrefix(name, "sub_") || strings.HasPrefix(name, "FUN_") {
			continue
		}
		it := DiffItem{Kind: "function", Name: f.Name, BinaryKey: f.ID, BinaryOffset: f.Offset, HasOffset: true, Tool: f.Tool,
			Evidence: []EvidenceItem{binEv(f.Offset, f.Tool, "function "+f.Name+" at "+f.Addr)}}
		if cands := srcByName[name]; len(cands) > 0 {
			s := cands[0]
			it.Side, it.SourceKey, it.SourceFile, it.SourceLine = "matched", s.Key, s.File, s.Line
			it.Evidence = append(it.Evidence, srcEv(s.File, s.Line, "function "+s.Label))
			for _, c := range cands {
				matchedSrc[c.Key] = true
			}
		} else {
			it.Side = "binary_only"
		}
		items = append(items, it)
	}
	if isGo {
		seen := map[string]bool{}
		for _, f := range funcs {
			if seen[f.Key] || matchedSrc[f.Key] || strings.Contains(f.Key, "#") || strings.HasSuffix(f.File, "_test.go") {
				continue
			}
			seen[f.Key] = true
			keys := sourceFuncKeys(f, true, mainMod, modulePath)
			if len(keys) == 0 || !binPkgs[goPackageOf(keys[0])] || strings.HasSuffix(keys[0], ".init") {
				// A package that is not linked at all is not part of this
				// binary (another command of the repository).
				continue
			}
			items = append(items, DiffItem{Side: "source_only", Kind: "function", Name: f.Label, SourceKey: f.Key, SourceFile: f.File,
				SourceLine: f.Line, Evidence: []EvidenceItem{srcEv(f.File, f.Line, "function "+f.Label+
					" (not in the binary: inlined, removed as unused, or excluded by build tags)")}})
		}
	}
	// --- packages (Go) and imports ---
	for _, m := range d.Imports {
		pkg := m.Name
		if m.Kind == "package" || strings.HasPrefix(m.ID, "imp:go:") {
			pkg = strings.TrimPrefix(m.ID, "imp:go:")
			ev := binEv(m.Offset, m.Tool, "package "+pkg+" linked")
			off := m.Offset
			if f, ok := pkgFirst[pkg]; off <= 0 && ok {
				off = f.Offset
				ev = binEv(off, f.Tool, "package "+pkg+" linked: function "+f.Name+" at "+f.Addr)
			}
			it := DiffItem{Kind: "package", Name: pkg, BinaryKey: m.ID, BinaryOffset: off, HasOffset: off > 0, Tool: m.Tool,
				Evidence: []EvidenceItem{ev}}
			rule, sensitive := sensitiveGoPackages[pkg]
			switch {
			case mainMod != "" && (pkg == mainMod || strings.HasPrefix(pkg, mainMod+"/")):
				if dir := moduleDir(pkg, mainMod, modulePath); dir != "" || srcPkgs[pkg] {
					it.Side, it.SourceFile = "matched", dir
					it.Evidence = append(it.Evidence, srcEv(firstNonEmpty(dir, "."), 0, "package "+pkg))
				} else {
					it.Side = "binary_only"
				}
			case stdImports[pkg].node.Key != "":
				si := stdImports[pkg]
				it.Side, it.SourceKey, it.SourceFile, it.SourceLine = "matched", si.node.Key, si.node.File, si.line
				it.Evidence = append(it.Evidence, srcEv(si.node.File, si.line, "import \""+pkg+"\""))
			case componentFor(pkg, components) != nil:
				c := componentFor(pkg, components)
				it.Side, it.SourceKey = "matched", c.Key
				it.Evidence = append(it.Evidence, EvidenceItem{Evidence: "verified", Kind: "file_line", Ref: firstNonEmpty(c.File, "go.mod"),
					Detail: "CodeGraph: component " + c.Label})
			case sensitive && rule.ID == "rea/go-weak-crypto":
				// The standard library links weak hashes and ciphers for
				// TLS and legacy formats in every network program: not
				// reported unless the source imports them.
				continue
			case sensitive:
				it.Side = "binary_only"
				it.Evidence = append(it.Evidence, EvidenceItem{Evidence: "verified", Kind: "file_line", Ref: "go.mod",
					Detail: "CodeGraph: no import of " + pkg + " in the source; linked through a dependency"})
			default:
				continue // library package of the standard library or a dependency: not compared
			}
			if sensitive {
				it.Sensitive, it.SensitiveReason, it.SensitiveID = true, rule.Reason, rule.ID
			}
			items = append(items, it)
			continue
		}
		if rule, ok := sensitiveImports[strings.TrimPrefix(pkg, "_")]; ok {
			name := m.Name
			if m.Library != "" {
				name = m.Library + "!" + m.Name
			}
			items = append(items, DiffItem{Side: "binary_only", Kind: "package", Name: name, BinaryKey: m.ID,
				BinaryOffset: m.Offset, HasOffset: true, Tool: m.Tool, Sensitive: true, SensitiveReason: rule.Reason, SensitiveID: rule.ID,
				Evidence: []EvidenceItem{binEv(m.Offset, m.Tool, "import "+name)}})
		}
	}
	// --- routes ---
	srcRoutes := map[string]SourceNode{}
	for _, r := range routes {
		p := firstNonEmpty(attr(r, "path"), routePath(r.Label))
		if p != "" {
			srcRoutes[normRoute(p)] = r
		}
	}
	ownRefs := ownStringRefs(d)
	foundRoutes := map[string]bool{}
	seenRoute := map[string]bool{}
	for _, s := range d.Strings {
		if s.Redacted || !(s.Kind == "route" || routeLike(s.Value)) {
			continue
		}
		nr := normRoute(s.Value)
		if seenRoute[nr] {
			continue
		}
		seenRoute[nr] = true
		it := DiffItem{Kind: "route", Name: s.Value, BinaryKey: s.ID, BinaryOffset: s.Offset, HasOffset: true, Tool: s.Tool,
			Evidence: []EvidenceItem{binEv(s.Offset, s.Tool, "string \""+text(s.Value, 200)+"\"")}}
		if r, ok := srcRoutes[nr]; ok {
			foundRoutes[nr] = true
			it.Side, it.SourceKey, it.SourceFile, it.SourceLine = "matched", r.Key, r.File, r.Line
			it.Evidence = append(it.Evidence, srcEv(r.File, r.Line, "route "+r.Label))
			items = append(items, it)
			continue
		}
		sensitive := sensitiveRouteRe.MatchString(s.Value)
		if !sensitive && !ownRefs[s.ID] {
			continue // a path-like string not referenced by the artifact's own code: not a route claim
		}
		it.Side = "binary_only"
		if sensitive {
			it.Sensitive, it.SensitiveReason, it.SensitiveID = true, routeRule.Reason, routeRule.ID
			for prefix, pkg := range debugRouteRule {
				if strings.HasPrefix(s.Value, prefix) {
					if rule, ok := sensitiveGoPackages[pkg]; ok && binPkgs[pkg] {
						it.SensitiveReason, it.SensitiveID = rule.Reason+" (route not in the API inventory)", rule.ID
					}
					if si := stdImports[pkg]; si.node.Key != "" {
						it.Evidence = append(it.Evidence, srcEv(si.node.File, si.line, "registered by import \""+pkg+"\""))
					}
				}
			}
		}
		items = append(items, it)
	}
	for nr, r := range srcRoutes {
		if !foundRoutes[nr] {
			items = append(items, DiffItem{Side: "source_only", Kind: "route", Name: r.Label, SourceKey: r.Key, SourceFile: r.File, SourceLine: r.Line,
				Evidence: []EvidenceItem{srcEv(r.File, r.Line, "route "+r.Label+" (path not found as a string in the binary; it may be built at run time)")}})
		}
	}
	// --- URLs referenced by the artifact's own code ---
	hosts := map[string]SourceNode{}
	for _, s := range services {
		if h := strings.ToLower(firstNonEmpty(attr(s, "host"), s.Label)); h != "" {
			hosts[h] = s
		}
	}
	seenURL := map[string]bool{}
	for _, s := range d.Strings {
		if s.Redacted || s.Kind != "url" || !ownRefs[s.ID] || seenURL[s.Value] {
			continue
		}
		seenURL[s.Value] = true
		it := DiffItem{Kind: "string", Name: s.Value, BinaryKey: s.ID, BinaryOffset: s.Offset, HasOffset: true, Tool: s.Tool,
			Evidence: []EvidenceItem{binEv(s.Offset, s.Tool, "URL referenced by the artifact's code")}, Side: "binary_only"}
		if svc, ok := hosts[urlHostOf(s.Value)]; ok {
			it.Side, it.SourceKey, it.SourceFile, it.SourceLine = "matched", svc.Key, svc.File, svc.Line
			it.Evidence = append(it.Evidence, srcEv(firstNonEmpty(svc.File, "."), svc.Line, "external service "+svc.Label))
		}
		items = append(items, it)
	}
	sort.SliceStable(items, func(i, j int) bool {
		if items[i].Sensitive != items[j].Sensitive {
			return items[i].Sensitive
		}
		if items[i].Kind != items[j].Kind {
			return items[i].Kind < items[j].Kind
		}
		return items[i].Name < items[j].Name
	})
	for i := range items {
		items[i].Name = text(items[i].Name, 500)
		if items[i].Name == "" {
			items[i].Name = "(unnamed)"
		}
		if len(items[i].Evidence) > 6 {
			items[i].Evidence = items[i].Evidence[:6]
		}
	}
	return items
}

// sourceFuncKeys are the comparable names of a source function: the Go
// import path plus the qualified name's tail, or the plain label.
func sourceFuncKeys(f SourceNode, isGo bool, mainMod string, modulePath map[string]string) []string {
	if !isGo {
		return []string{f.Label}
	}
	qn := attr(f, "qualified_name")
	if !strings.HasPrefix(f.Key, "fn:go:") || qn == "" {
		return nil
	}
	// qn = "<dir>.<rest>" with dir "." for the module root.
	dir, rest := splitQN(qn)
	if rest == "" {
		return nil
	}
	ip := modulePath[dir]
	if ip == "" && mainMod != "" {
		ip = mainMod
		if dir != "." && dir != "" {
			ip = mainMod + "/" + dir
		}
	}
	if ip == "" {
		return nil
	}
	return []string{ip + "." + rest}
}

// splitQN splits "cmd/api.(*T).M" into "cmd/api" and "(*T).M".
func splitQN(qn string) (string, string) {
	slash := strings.LastIndexByte(qn, '/')
	dot := strings.IndexByte(qn[slash+1:], '.')
	if dot < 0 {
		return "", ""
	}
	return qn[:slash+1+dot], qn[slash+1+dot+1:]
}

func moduleDir(pkg, mainMod string, modulePath map[string]string) string {
	for dir, ip := range modulePath {
		if ip == pkg {
			return dir
		}
	}
	return ""
}

func componentFor(pkg string, comps map[string]SourceNode) *SourceNode {
	for p := pkg; p != "." && p != "/" && p != ""; p = path.Dir(p) {
		if c, ok := comps[p]; ok {
			return &c
		}
	}
	return nil
}

func routePath(label string) string {
	if i := strings.IndexByte(label, ' '); i >= 0 {
		label = label[i+1:]
	}
	if strings.HasPrefix(label, "/") {
		return label
	}
	return ""
}

func urlHostOf(u string) string {
	u = strings.TrimPrefix(strings.TrimPrefix(strings.ToLower(u), "https://"), "http://")
	if i := strings.IndexAny(u, "/:?#"); i >= 0 {
		u = u[:i]
	}
	if i := strings.LastIndexByte(u, '@'); i >= 0 {
		u = u[i+1:]
	}
	return u
}

func attr(n SourceNode, k string) string {
	if v, ok := n.Attrs[k].(string); ok {
		return v
	}
	return ""
}

// ownStringRefs are the strings referenced by the artifact's own (not
// library) functions.
func ownStringRefs(d *Doc) map[string]bool {
	lib := map[string]bool{}
	for _, f := range d.Functions {
		if f.Library {
			lib[f.ID] = true
		}
	}
	out := map[string]bool{}
	for _, r := range d.StringRefs {
		if !lib[r.From] {
			out[r.To] = true
		}
	}
	return out
}

// Draft is a finding proposal for sensitive binary-only items.
type Draft struct {
	Title, Description, Severity, RuleID, Category string
	CWE                                            []string
	ItemIndex                                      int // the representative diff item
	Evidence                                       []EvidenceItem
}

// Drafts groups sensitive binary-only items by rule into proposals. A
// sensitive package that the source does import is not a binary-only item,
// but its source line is added as evidence to the route draft it explains.
func Drafts(items []DiffItem, artifact string) []Draft {
	rules := map[string]sensitiveRule{routeRule.ID: routeRule}
	for _, r := range sensitiveGoPackages {
		rules[r.ID] = r
	}
	for _, r := range sensitiveImports {
		rules[r.ID] = r
	}
	byRule := map[string][]int{}
	var order []string
	for i, it := range items {
		if !it.Sensitive || it.Side != "binary_only" {
			continue
		}
		if _, ok := byRule[it.SensitiveID]; !ok {
			order = append(order, it.SensitiveID)
		}
		byRule[it.SensitiveID] = append(byRule[it.SensitiveID], i)
	}
	var out []Draft
	for _, id := range order {
		r := rules[id]
		idx := byRule[id]
		var names []string
		var ev []EvidenceItem
		for _, i := range idx {
			if len(names) < 10 {
				names = append(names, items[i].Name)
			}
			for _, e := range items[i].Evidence {
				if len(ev) < 8 && !containsEv(ev, e) {
					ev = append(ev, e)
				}
			}
		}
		desc := fmt.Sprintf("Static analysis of %s found %d item(s) that are in the shipped binary but not in the source of the same commit: %s. %s.",
			firstNonEmpty(artifact, "the artifact"), len(idx), strings.Join(names, ", "), capitalise(r.Reason))
		if len(idx) > len(names) {
			desc += fmt.Sprintf(" (%d more)", len(idx)-len(names))
		}
		desc += " This is a proposal from the source ↔ binary diff: a person must confirm it before it becomes a finding."
		out = append(out, Draft{Title: r.Title, Description: text(desc, 8000), Severity: r.Severity, RuleID: r.ID, Category: r.Category,
			CWE: []string{r.CWE}, ItemIndex: idx[0], Evidence: ev})
	}
	return out
}

func containsEv(list []EvidenceItem, e EvidenceItem) bool {
	for _, x := range list {
		if x.Ref == e.Ref && x.Kind == e.Kind {
			return true
		}
	}
	return false
}

func capitalise(s string) string {
	if s == "" {
		return s
	}
	return strings.ToUpper(s[:1]) + s[1:]
}
