package reachscan

import (
	"sort"
	"strings"
	"unicode"
	"unicode/utf8"
)

// --- values -----------------------------------------------------------------

// What a name or an expression stands for.
type valKind uint8

const (
	vNone    valKind = iota // unknown (member: a method name awaiting a call)
	vExt                    // an external module or a member of it: mod, path
	vInst                   // an instance of an external class mod.path (member: pending method)
	vDerived                // a value obtained from external module mod (member: pending method)
	vFn                     // a function of the repository: file, idx
	vLocal                  // a repository module (name "") or one of its exports
	vChain                  // the result of chain idx of file (resolved lazily)
	vMember                 // member name of base (resolved lazily)
	vOther                  // a value known not to come from an external module (member: pending method)
	vType                   // a Java variable of declared type name (resolved lazily)
)

type value struct {
	k      valKind
	mod    string
	path   []string
	member string
	file   string
	name   string
	idx    int
	base   *value
	self   bool // vNone: the receiver is this/self (calls stay in the file)
}

func extVal(mod string, path ...string) value { return value{k: vExt, mod: mod, path: path} }

func (v value) withPath(name string) value {
	p := make([]string, 0, len(v.path)+1)
	p = append(append(p, v.path...), name)
	v.path = p
	return v
}

// --- per-file analysis (phase 1) ------------------------------------------------

type seg struct {
	name     string
	call     bool
	computed bool
	byName   bool // a member looked up by a computed name (getattr)
	line     int
}

// chain is an expression rooted at a name: root.member(...).member...
type chain struct {
	rootName string
	root     *value // a literal root (require("x"), import("x")); nil: look the name up
	segs     []seg
	line     int
	fn       int // enclosing function (local index), -1 at top level
	isNew    bool
	escape   bool // a bare name in a value position (argument, return, ...)
}

type fnDef struct {
	name, display string
	line, end     int
}

type dynSite struct {
	mod, reason string
	line        int
}

type fileAn struct {
	key, eco string
	test     bool
	funcs    []fnDef
	env      map[string][]value
	exports  map[string][]value
	stars    []value // re-exported (JS) or star-imported (Python, Java) namespaces
	chains   []*chain
	dynamic  []dynSite
	imports  map[string]int // external module -> first line
	// Python: the file is a package's __init__.py; Java: the package.
	pyPackage bool
	javaPkg   string
	topName   string // display name of top-level code
}

func newFile(key, eco string) *fileAn {
	top := "<top level>"
	if eco == "pypi" {
		top = "<module>"
	}
	return &fileAn{key: key, eco: eco, test: isTestPath(key), env: map[string][]value{}, exports: map[string][]value{},
		imports: map[string]int{}, topName: top}
}

func (f *fileAn) bind(name string, v value) {
	if name == "" || len(f.env[name]) >= 8 {
		return
	}
	f.env[name] = append(f.env[name], v)
}

func (f *fileAn) export(name string, v value) {
	if name == "" || len(f.exports[name]) >= 8 {
		return
	}
	f.exports[name] = append(f.exports[name], v)
}

func (f *fileAn) imported(mod string, line int) {
	if mod == "" {
		return
	}
	if _, ok := f.imports[mod]; !ok {
		f.imports[mod] = line
	}
}

func (f *fileAn) dyn(mod, reason string, line int) {
	if len(f.dynamic) < 200 {
		f.dynamic = append(f.dynamic, dynSite{mod, reason, line})
	}
}

func (f *fileAn) addChain(c *chain) int {
	f.chains = append(f.chains, c)
	return len(f.chains) - 1
}

func capitalized(s string) bool {
	r, _ := utf8.DecodeRuneInString(s)
	return unicode.IsUpper(r)
}

func last(p []string) string {
	if len(p) == 0 {
		return ""
	}
	return p[len(p)-1]
}

// isTestPath: test files and directories of the usual layouts.
func isTestPath(p string) bool {
	lp := "/" + strings.ToLower(p)
	for _, d := range []string{"/test/", "/tests/", "/__tests__/", "/spec/", "/specs/", "/testing/", "/e2e/", "/__mocks__/", "/fixtures/"} {
		if strings.Contains(lp, d) {
			return true
		}
	}
	base := p[strings.LastIndex(p, "/")+1:]
	lb := strings.ToLower(base)
	switch {
	case strings.HasPrefix(lb, "test_") && strings.HasSuffix(lb, ".py"), strings.HasSuffix(lb, "_test.py"), lb == "conftest.py",
		strings.Contains(lb, ".test."), strings.Contains(lb, ".spec."),
		strings.HasSuffix(base, "Test.java"), strings.HasSuffix(base, "Tests.java"), strings.HasSuffix(base, "IT.java"),
		strings.HasSuffix(lb, "_test.go"):
		return true
	}
	return false
}

// --- bracket matching -------------------------------------------------------

// matchBrackets returns, for every bracket token, the index of its partner
// (-1 when unbalanced).
func matchBrackets(toks []token) []int {
	m := make([]int, len(toks))
	var stack []int
	pairs := map[string]string{")": "(", "]": "[", "}": "{"}
	for i, t := range toks {
		m[i] = -1
		if t.kind != tPunct {
			continue
		}
		switch t.text {
		case "(", "[", "{":
			stack = append(stack, i)
		case ")", "]", "}":
			// pop to the nearest matching opener (tolerates stray brackets)
			for j := len(stack) - 1; j >= 0; j-- {
				if toks[stack[j]].text == pairs[t.text] {
					m[i], m[stack[j]] = stack[j], i
					stack = stack[:j]
					break
				}
			}
		}
	}
	return m
}

func isP(toks []token, i int, s string) bool {
	return i >= 0 && i < len(toks) && toks[i].kind == tPunct && toks[i].text == s
}

func isI(toks []token, i int, s string) bool {
	return i >= 0 && i < len(toks) && toks[i].kind == tIdent && toks[i].text == s
}

func isIdent(toks []token, i int) bool { return i >= 0 && i < len(toks) && toks[i].kind == tIdent }

// parseChain reads the segments after the root identifier at i: .name,
// ?.name, ["literal"], [computed], (call). Arguments are not consumed: the
// caller still scans them. It returns the segments, the index after the
// chain and the member identifiers it consumed.
func parseChain(toks []token, i int, match []int, javaRefs bool) ([]seg, int, []int) {
	var segs []seg
	var used []int
	j := i + 1
	for j < len(toks) && len(segs) < 64 {
		t := toks[j]
		if t.kind != tPunct {
			break
		}
		switch {
		case (t.text == "." || t.text == "?." || (javaRefs && t.text == "::")) && isIdent(toks, j+1):
			segs = append(segs, seg{name: toks[j+1].text, line: toks[j+1].line})
			used = append(used, j+1)
			j += 2
		case t.text == "?." && isP(toks, j+1, "("), t.text == "(":
			if t.text == "?." {
				j++
			}
			segs = append(segs, seg{call: true, line: toks[j].line})
			if match[j] < 0 {
				return segs, len(toks), used
			}
			j = match[j] + 1
		case t.text == "?." && isP(toks, j+1, "["), t.text == "[":
			if t.text == "?." {
				j++
			}
			if j+2 < len(toks) && toks[j+1].kind == tString && isP(toks, j+2, "]") {
				segs = append(segs, seg{name: toks[j+1].text, line: toks[j].line})
				j += 3
				continue
			}
			if isP(toks, j+1, "]") { // Java array types, empty index
				j += 2
				continue
			}
			segs = append(segs, seg{computed: true, line: toks[j].line})
			if match[j] < 0 {
				return segs, len(toks), used
			}
			j = match[j] + 1
		case t.text == "!" && (isP(toks, j+1, ".") || isP(toks, j+1, "(")) && !javaRefs:
			j++ // TypeScript non-null assertion
		default:
			return segs, j, used
		}
	}
	return segs, j, used
}

// --- cross-file analysis (phase 2) ----------------------------------------

type gfn struct {
	file    *fileAn
	display string
	line    int
}

type callerRef struct {
	fn, line int
}

type useKey struct{ eco, mod, sym, kind string }

type siteRef struct {
	file *fileAn
	line int
	fn   int // global function id
}

type useAgg struct {
	sites   []siteRef
	count   int
	nonTest int
}

type methAgg struct {
	sites   []siteRef
	count   int
	nonTest int
}

type importAgg struct {
	files, nonTest int
	first          siteRef
}

type analysis struct {
	files    []*fileAn
	byKey    map[string]*fileAn
	fnBase   map[*fileAn]int
	gfns     []gfn
	fnByName map[string][]int
	callers  map[int][]callerRef
	calls    map[string]int // eco -> call sites
	uses     map[useKey]*useAgg
	methods  map[[2]string]*methAgg
	imports  map[[2]string]*importAgg
	dynamic  []Dynamic
	dynSeen  map[string]bool
	// javaClasses: class names declared in the repository.
	javaClasses map[string]bool
	memo        map[*chain][]value
	busy        map[*chain]bool
	exportMemo  map[string][]value
	exportBusy  map[string]bool
	truncated   bool
	emitting    bool
}

func newAnalysis(files []*fileAn) *analysis {
	a := &analysis{files: files, byKey: map[string]*fileAn{}, fnBase: map[*fileAn]int{}, fnByName: map[string][]int{},
		callers: map[int][]callerRef{}, calls: map[string]int{}, uses: map[useKey]*useAgg{}, methods: map[[2]string]*methAgg{},
		imports: map[[2]string]*importAgg{}, dynSeen: map[string]bool{}, javaClasses: map[string]bool{},
		memo: map[*chain][]value{}, busy: map[*chain]bool{}, exportMemo: map[string][]value{}, exportBusy: map[string]bool{}}
	for _, f := range files {
		a.byKey[f.key] = f
		a.fnBase[f] = len(a.gfns)
		for _, d := range f.funcs {
			id := len(a.gfns)
			a.gfns = append(a.gfns, gfn{f, d.display, d.line})
			if len(a.fnByName[d.name]) < 50 {
				a.fnByName[d.name] = append(a.fnByName[d.name], id)
			}
		}
		// the file's top-level code
		a.gfns = append(a.gfns, gfn{f, f.topName, 0})
		if f.eco == "maven" {
			for name, vs := range f.env {
				for _, v := range vs {
					if v.k == vOther && strings.HasPrefix(v.name, "class:") {
						a.javaClasses[name] = true
					}
				}
			}
		}
	}
	return a
}

func (a *analysis) fnID(f *fileAn, local int) int {
	if local < 0 || local >= len(f.funcs) {
		return a.fnBase[f] + len(f.funcs)
	}
	return a.fnBase[f] + local
}

// lookupExport resolves name exported by file t (memoized; a cycle of
// re-exports resolves to nothing).
func (a *analysis) lookupExport(t *fileAn, name string, depth int) []value {
	key := t.key + "\x00" + name
	if r, ok := a.exportMemo[key]; ok {
		return r
	}
	if depth > 12 || a.exportBusy[key] {
		return nil
	}
	a.exportBusy[key] = true
	r := a.lookupExportUncached(t, name, depth)
	delete(a.exportBusy, key)
	if len(r) > 8 {
		r = r[:8]
	}
	a.exportMemo[key] = r
	return r
}

func (a *analysis) lookupExportUncached(t *fileAn, name string, depth int) []value {
	var vs []value
	if t.eco == "pypi" {
		vs = t.env[name]
		if len(vs) == 0 {
			for i, d := range t.funcs {
				if d.name == name && d.display == name {
					vs = append(vs, value{k: vFn, file: t.key, idx: i})
				}
			}
		}
	} else {
		vs = t.exports[name]
	}
	var out []value
	for _, v := range vs {
		out = append(out, a.resolve(t, v, depth+1)...)
	}
	if len(out) > 0 {
		return out
	}
	for _, s := range t.stars {
		for _, b := range a.resolve(t, s, depth+1) {
			out = append(out, a.member(t, b, name, depth+1)...)
		}
	}
	if len(out) == 0 && t.eco == "pypi" {
		// a submodule of a package
		dir := strings.TrimSuffix(t.key, "__init__.py")
		if t.pyPackage || strings.HasSuffix(t.key, "/") {
			for _, k := range []string{dir + name + ".py", dir + name + "/__init__.py", dir + name + "/"} {
				if _, ok := a.byKey[k]; ok {
					return []value{{k: vLocal, file: k}}
				}
			}
		}
	}
	return out
}

// resolve turns a value into resolved values (vExt, vInst, vDerived, vFn,
// vLocal namespaces, vOther, vNone).
func (a *analysis) resolve(f *fileAn, v value, depth int) []value {
	if depth > 12 {
		return []value{{k: vNone}}
	}
	switch v.k {
	case vLocal:
		t := a.byKey[v.file]
		if t == nil {
			return []value{{k: vNone}}
		}
		if v.name == "" {
			return []value{v}
		}
		out := a.lookupExport(t, v.name, depth+1)
		if len(out) == 0 {
			return []value{{k: vNone}}
		}
		return out
	case vChain:
		t := a.byKey[v.file]
		if t == nil || v.idx >= len(t.chains) {
			return []value{{k: vNone}}
		}
		return a.chainResult(t, t.chains[v.idx], depth+1)
	case vMember:
		var out []value
		for _, b := range a.resolve(f, *v.base, depth+1) {
			out = append(out, a.member(f, b, v.name, depth+1)...)
		}
		return out
	case vType:
		return a.javaType(v)
	}
	return []value{v}
}

// javaType is the value of a variable declared with a Java type.
func (a *analysis) javaType(v value) []value {
	t := a.byKey[v.file]
	if t == nil || javaPrimitive[v.name] {
		return []value{{k: vOther}}
	}
	for _, b := range t.env[v.name] {
		switch b.k {
		case vExt:
			return []value{{k: vInst, mod: b.mod, path: b.path}}
		case vOther:
			return []value{{k: vOther}}
		}
	}
	if a.javaClasses[v.name] || javaLang[v.name] {
		return []value{{k: vOther}}
	}
	var out []value
	for _, s := range t.stars {
		if s.k == vExt && len(s.path) == 0 {
			out = append(out, value{k: vInst, mod: s.mod, path: []string{v.name}})
		}
	}
	if len(out) > 0 {
		return out
	}
	return []value{{k: vOther}}
}

// member is b.name.
func (a *analysis) member(f *fileAn, b value, name string, depth int) []value {
	switch b.k {
	case vExt:
		return []value{b.withPath(name)}
	case vInst, vDerived:
		if b.member != "" {
			return []value{{k: vDerived, mod: b.mod, member: name}}
		}
		b.member = name
		return []value{b}
	case vLocal:
		t := a.byKey[b.file]
		if t == nil || b.name != "" {
			return []value{{k: vNone, member: name}}
		}
		out := a.lookupExport(t, name, depth+1)
		if len(out) == 0 {
			return []value{{k: vNone, member: name}}
		}
		return out
	case vOther:
		return []value{{k: vOther, member: name}}
	}
	return []value{{k: vNone, member: name, self: b.self && b.member == ""}}
}

func (a *analysis) chainResult(f *fileAn, c *chain, depth int) []value {
	if r, ok := a.memo[c]; ok {
		return r
	}
	if a.busy[c] {
		return []value{{k: vNone}}
	}
	a.busy[c] = true
	saved := a.emitting
	a.emitting = false
	r := a.eval(f, c, depth)
	a.emitting = saved
	delete(a.busy, c)
	a.memo[c] = r
	return r
}

// roots are the values a chain's root name stands for.
func (a *analysis) roots(f *fileAn, c *chain, depth int) ([]value, []seg) {
	segs := c.segs
	if c.root != nil {
		return a.resolve(f, *c.root, depth+1), segs
	}
	name := c.rootName
	if (name == "this" || name == "self") && len(segs) > 0 && !segs[0].call && !segs[0].computed {
		vs := f.env[name+"."+segs[0].name]
		if f.eco == "maven" && len(vs) == 0 {
			vs = f.env[segs[0].name] // fields
		}
		if len(vs) > 0 {
			var out []value
			for _, v := range vs {
				out = append(out, a.resolve(f, v, depth+1)...)
			}
			return out, segs[1:]
		}
		return []value{{k: vNone, self: true}}, segs
	}
	if vs := f.env[name]; len(vs) > 0 {
		var out []value
		for _, v := range vs {
			out = append(out, a.resolve(f, v, depth+1)...)
		}
		return out, segs
	}
	// Unbound names.
	if f.eco == "maven" && capitalized(name) {
		switch {
		case a.javaClasses[name] || javaLang[name]:
			return []value{{k: vOther}}, segs
		case len(f.stars) > 0:
			var out []value
			for _, s := range f.stars {
				if s.k == vExt && len(s.path) == 0 { // import pkg.*;
					out = append(out, extVal(s.mod, name))
				}
			}
			if len(out) > 0 {
				return out, segs
			}
		}
		return []value{{k: vOther}}, segs
	}
	if len(segs) > 0 && segs[0].call {
		// a bare call: a function of this file, or a star import
		var out []value
		for i, d := range f.funcs {
			if d.name == name && !strings.Contains(d.display, ".") {
				out = append(out, value{k: vFn, file: f.key, idx: i})
			}
		}
		if f.eco == "maven" && len(out) == 0 {
			for i, d := range f.funcs {
				if d.name == name {
					out = append(out, value{k: vFn, file: f.key, idx: i})
				}
			}
		}
		if f.eco == "pypi" && pyBuiltins[name] && len(out) == 0 {
			return []value{{k: vOther}}, segs
		}
		if len(out) == 0 {
			for _, s := range f.stars {
				for _, b := range a.resolve(f, s, depth+1) {
					if b.k == vExt && f.eco == "maven" && len(b.path) == 0 {
						continue // import pkg.*: classes, not functions
					}
					out = append(out, a.member(f, b, name, depth+1)...)
				}
			}
		}
		if len(out) > 0 {
			return out, segs
		}
		if f.eco == "pypi" && pyBuiltins[name] {
			return []value{{k: vOther}}, segs
		}
	}
	return []value{{k: vNone}}, segs
}

var javaLang = map[string]bool{"String": true, "Object": true, "System": true, "Math": true, "Integer": true, "Long": true, "Short": true,
	"Byte": true, "Double": true, "Float": true, "Boolean": true, "Character": true, "Thread": true, "Class": true, "StringBuilder": true,
	"StringBuffer": true, "Exception": true, "RuntimeException": true, "Error": true, "Throwable": true, "Override": true,
	"Iterable": true, "Runnable": true, "Number": true, "Enum": true, "Record": true, "Void": true, "CharSequence": true,
	"IllegalArgumentException": true, "IllegalStateException": true, "NullPointerException": true, "Deprecated": true,
	"SuppressWarnings": true, "FunctionalInterface": true, "ClassLoader": true, "Process": true, "Runtime": true}

var pyBuiltins = map[string]bool{"print": true, "len": true, "str": true, "int": true, "float": true, "dict": true, "list": true,
	"set": true, "tuple": true, "open": true, "range": true, "isinstance": true, "super": true, "repr": true, "sorted": true,
	"enumerate": true, "zip": true, "map": true, "filter": true, "any": true, "all": true, "min": true, "max": true, "type": true,
	"bool": true, "bytes": true, "hasattr": true, "setattr": true, "iter": true, "next": true, "abs": true, "sum": true}

// eval evaluates a chain; with a.emitting it records uses, calls,
// dynamic constructs and call edges.
func (a *analysis) eval(f *fileAn, c *chain, depth int) []value {
	roots, segs := a.roots(f, c, depth)
	if len(roots) > 4 {
		roots = roots[:4]
	}
	site := siteRef{file: f, line: c.line, fn: a.fnID(f, c.fn)}
	var results []value
	for _, root := range roots {
		cur := []value{root}
		newPending := c.isNew
		for _, s := range segs {
			site.line = s.line
			var next []value
			for _, v := range cur {
				switch {
				case s.computed:
					// JavaScript: module[name] selects a member by a computed
					// name. Python and Java subscripts index a value.
					if v.k == vExt && (f.eco == "npm" || s.byName) && a.emitting {
						a.addDynamic(f, v.mod, "member selected by a computed name", s.line)
					}
					if v.k == vExt || v.k == vDerived || v.k == vInst {
						next = append(next, value{k: vDerived, mod: v.mod})
					} else {
						next = append(next, value{k: vNone})
					}
				case !s.call:
					next = append(next, a.member(f, v, s.name, depth+1)...)
				default:
					next = append(next, a.call(f, v, site, newPending, depth+1)...)
				}
			}
			if s.call {
				newPending = false
			}
			if len(next) > 4 {
				next = next[:4]
			}
			cur = next
		}
		if a.emitting && (len(segs) == 0 || !segs[len(segs)-1].call) {
			for _, v := range cur {
				switch {
				case v.k == vExt && len(v.path) > 0 && len(segs) > 0:
					a.addUse(f, v.mod, strings.Join(v.path, "."), "ref", site)
				case v.k == vExt && len(v.path) > 0 && c.escape:
					a.addUse(f, v.mod, strings.Join(v.path, "."), "ref", site)
				case v.k == vExt && len(v.path) == 0 && c.escape:
					a.addDynamic(f, v.mod, "the module is passed around as a value", c.line)
				case v.k == vInst && v.member != "":
					a.addUse(f, v.mod, strings.Join(v.path, ".")+"."+v.member, "ref", site)
				case v.k == vFn && c.escape:
					a.edge(site, v)
				}
			}
		}
		results = append(results, cur...)
	}
	return results
}

// call applies a call to v.
func (a *analysis) call(f *fileAn, v value, site siteRef, isNew bool, depth int) []value {
	if a.emitting {
		a.calls[f.eco]++
	}
	switch v.k {
	case vExt:
		sym := strings.Join(v.path, ".")
		if sym == "" {
			sym = "default"
		}
		if a.emitting {
			a.addUse(f, v.mod, sym, "call", site)
		}
		if isNew || capitalized(last(v.path)) {
			return []value{{k: vInst, mod: v.mod, path: v.path}}
		}
		return []value{{k: vDerived, mod: v.mod}}
	case vInst:
		if v.member != "" && a.emitting {
			a.addUse(f, v.mod, strings.Join(v.path, ".")+"."+v.member, "call", site)
		}
		return []value{{k: vDerived, mod: v.mod}}
	case vDerived:
		if v.member != "" && a.emitting {
			a.addUse(f, v.mod, v.member, "method", site)
		}
		return []value{{k: vDerived, mod: v.mod}}
	case vFn:
		if a.emitting {
			a.edge(site, v)
		}
	case vLocal:
		if v.name == "" {
			var out []value
			if t := a.byKey[v.file]; t != nil {
				for _, b := range a.lookupExport(t, "default", depth+1) {
					out = append(out, a.call(f, b, site, isNew, depth+1)...)
				}
			}
			return out
		}
	case vNone, vOther:
		if v.member != "" && a.emitting {
			if v.k == vNone && !v.self {
				a.addMethod(f, v.member, site)
			}
			// call edges to the repository's functions of that name
			for _, id := range a.fnByName[v.member] {
				if v.self && a.gfns[id].file != f {
					continue
				}
				a.callers[id] = appendCaller(a.callers[id], callerRef{site.fn, site.line})
			}
		}
		if v.k == vOther {
			if cls, ok := strings.CutPrefix(v.name, "class:"); ok && v.member == "" && a.emitting {
				// instantiating a repository class runs its constructor
				for _, ctor := range []string{"__init__", "constructor", cls} {
					for _, id := range a.fnByName[ctor] {
						if a.gfns[id].display == cls+"."+ctor {
							a.callers[id] = appendCaller(a.callers[id], callerRef{site.fn, site.line})
						}
					}
				}
			}
			// a known repository or standard-library value stays one
			return []value{{k: vOther}}
		}
	}
	return []value{{k: vNone}}
}

func appendCaller(cs []callerRef, c callerRef) []callerRef {
	if len(cs) >= 100 {
		return cs
	}
	for _, x := range cs {
		if x == c {
			return cs
		}
	}
	return append(cs, c)
}

func (a *analysis) edge(site siteRef, v value) {
	t := a.byKey[v.file]
	if t == nil {
		return
	}
	id := a.fnID(t, v.idx)
	a.callers[id] = appendCaller(a.callers[id], callerRef{site.fn, site.line})
}

func (a *analysis) addUse(f *fileAn, mod, sym, kind string, site siteRef) {
	if mod == "" || len(sym) > 300 {
		return
	}
	k := useKey{f.eco, mod, sym, kind}
	u := a.uses[k]
	if u == nil {
		if len(a.uses) >= MaxUses {
			a.truncated = true
			return
		}
		u = &useAgg{}
		a.uses[k] = u
	}
	u.count++
	if !f.test {
		u.nonTest++
	}
	u.sites = addSite(u.sites, site, MaxSites)
}

// addSite keeps up to n sites, application code before test code.
func addSite(sites []siteRef, s siteRef, n int) []siteRef {
	for _, x := range sites {
		if x.file == s.file && x.line == s.line {
			return sites
		}
	}
	if len(sites) < n {
		return append(sites, s)
	}
	if !s.file.test {
		for i, x := range sites {
			if x.file.test {
				sites[i] = s
				return sites
			}
		}
	}
	return sites
}

func (a *analysis) addMethod(f *fileAn, name string, site siteRef) {
	k := [2]string{f.eco, name}
	m := a.methods[k]
	if m == nil {
		if len(a.methods) >= MaxMethods {
			a.truncated = true
			return
		}
		m = &methAgg{}
		a.methods[k] = m
	}
	m.count++
	if !f.test {
		m.nonTest++
	}
	m.sites = addSite(m.sites, site, MaxMethodSites)
}

func (a *analysis) addDynamic(f *fileAn, mod, reason string, line int) {
	key := f.eco + "\x00" + mod + "\x00" + reason + "\x00" + f.key
	if a.dynSeen[key] {
		return
	}
	if len(a.dynamic) >= MaxDynamic {
		a.truncated = true
		return
	}
	a.dynSeen[key] = true
	a.dynamic = append(a.dynamic, Dynamic{Ecosystem: f.eco, Module: mod, Reason: reason, File: f.key, Line: line, Test: f.test})
}

func (a *analysis) frame(fn, line int) Frame {
	g := a.gfns[fn]
	return Frame{File: g.file.key, Line: line, Function: g.display}
}

// path is one caller chain from a function without callers in the
// repository (or top-level code) to the site, outermost first.
func (a *analysis) path(s siteRef) []Frame {
	type node struct {
		fn, line, prev, depth int
	}
	nodes := []node{{s.fn, s.line, -1, 1}}
	seen := map[int]bool{s.fn: true}
	end := 0
	// Breadth-first towards the callers: the first function without
	// callers ends the chain (the shortest way in); with only cycles, the
	// deepest function reached does.
	for i := 0; i < len(nodes) && i < 2000; i++ {
		n := nodes[i]
		end = i
		cs := a.callers[n.fn]
		if len(cs) == 0 || n.depth >= MaxPathFrames {
			break
		}
		for _, c := range cs {
			if !seen[c.fn] {
				seen[c.fn] = true
				nodes = append(nodes, node{c.fn, c.line, i, n.depth + 1})
			}
		}
	}
	var out []Frame
	for p := end; p >= 0; p = nodes[p].prev {
		out = append(out, a.frame(nodes[p].fn, nodes[p].line))
	}
	return out
}

// run evaluates every chain and builds the report.
func (a *analysis) run(stats map[string]*LangStats) *Report {
	a.emitting = true
	for _, f := range a.files {
		for _, c := range f.chains {
			a.eval(f, c, 0)
		}
		for _, d := range f.dynamic {
			a.addDynamic(f, d.mod, d.reason, d.line)
		}
		for mod, line := range f.imports {
			k := [2]string{f.eco, mod}
			im := a.imports[k]
			if im == nil {
				im = &importAgg{first: siteRef{f, line, a.fnID(f, -1)}}
				a.imports[k] = im
			}
			im.files++
			if !f.test {
				if im.nonTest == 0 {
					im.first = siteRef{f, line, a.fnID(f, -1)}
				}
				im.nonTest++
			}
		}
	}
	r := &Report{Tool: "pathos-reach", Schema: Schema, Languages: stats, Truncated: a.truncated,
		Uses: []Use{}, Methods: []MethodUse{}, Dynamic: append([]Dynamic{}, a.dynamic...), Imports: []Import{}}
	for _, f := range a.files {
		if st := stats[f.eco]; st != nil {
			st.Functions += len(f.funcs)
		}
	}
	for eco, n := range a.calls {
		if st := stats[eco]; st != nil {
			st.Calls = n
		}
	}
	for k, u := range a.uses {
		use := Use{Ecosystem: k.eco, Module: k.mod, Symbol: k.sym, Kind: k.kind, Test: u.nonTest == 0, Count: u.count, Sites: []Frame{}, Paths: [][]Frame{}}
		sort.SliceStable(u.sites, func(i, j int) bool { return !u.sites[i].file.test && u.sites[j].file.test })
		for _, s := range u.sites {
			use.Sites = append(use.Sites, a.frame(s.fn, s.line))
			if len(use.Paths) < MaxPaths {
				use.Paths = append(use.Paths, a.path(s))
			}
		}
		r.Uses = append(r.Uses, use)
	}
	for k, m := range a.methods {
		mu := MethodUse{Ecosystem: k[0], Name: k[1], Count: m.count, Test: m.nonTest == 0, Sites: []Frame{}}
		for _, s := range m.sites {
			mu.Sites = append(mu.Sites, a.frame(s.fn, s.line))
		}
		r.Methods = append(r.Methods, mu)
	}
	for k, im := range a.imports {
		r.Imports = append(r.Imports, Import{Ecosystem: k[0], Module: k[1], Files: im.files, TestOnly: im.nonTest == 0,
			First: Frame{File: im.first.file.key, Line: im.first.line, Function: im.first.file.topName}})
	}
	sort.Slice(r.Uses, func(i, j int) bool {
		x, y := r.Uses[i], r.Uses[j]
		if x.Ecosystem != y.Ecosystem {
			return x.Ecosystem < y.Ecosystem
		}
		if x.Module != y.Module {
			return x.Module < y.Module
		}
		if x.Symbol != y.Symbol {
			return x.Symbol < y.Symbol
		}
		return x.Kind < y.Kind
	})
	sort.Slice(r.Methods, func(i, j int) bool {
		if r.Methods[i].Ecosystem != r.Methods[j].Ecosystem {
			return r.Methods[i].Ecosystem < r.Methods[j].Ecosystem
		}
		return r.Methods[i].Name < r.Methods[j].Name
	})
	sort.Slice(r.Imports, func(i, j int) bool {
		if r.Imports[i].Ecosystem != r.Imports[j].Ecosystem {
			return r.Imports[i].Ecosystem < r.Imports[j].Ecosystem
		}
		return r.Imports[i].Module < r.Imports[j].Module
	})
	sort.SliceStable(r.Dynamic, func(i, j int) bool {
		x, y := r.Dynamic[i], r.Dynamic[j]
		if x.Ecosystem != y.Ecosystem {
			return x.Ecosystem < y.Ecosystem
		}
		if x.File != y.File {
			return x.File < y.File
		}
		return x.Line < y.Line
	})
	return r
}
