package reachscan

import (
	"path"
	"strings"
)

var jsKeywords = map[string]bool{"if": true, "for": true, "while": true, "switch": true, "catch": true, "return": true, "typeof": true,
	"instanceof": true, "new": true, "delete": true, "void": true, "throw": true, "case": true, "do": true, "else": true, "in": true,
	"of": true, "let": true, "const": true, "var": true, "function": true, "class": true, "extends": true, "import": true,
	"export": true, "default": true, "await": true, "yield": true, "try": true, "finally": true, "break": true, "continue": true,
	"true": true, "false": true, "null": true, "undefined": true, "debugger": true, "with": true, "interface": true, "type": true,
	"enum": true, "implements": true, "declare": true, "namespace": true, "abstract": true, "private": true, "public": true,
	"protected": true, "readonly": true, "static": true, "as": true, "satisfies": true, "keyof": true, "super": true}

// value positions: a bare module name after these tokens is passed around.
var jsEscapeAfter = map[string]bool{"(": true, ",": true, "return": true, "[": true, "=": true, "?": true, ":": true, "||": true,
	"&&": true, "...": true, "yield": true, "<": true, "??": true}

// jsFiles resolves import specifiers to repository files.
type jsFiles map[string]bool

var jsExts = []string{".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs", ".mts", ".cts", ".vue", ".svelte"}

func (fs jsFiles) resolve(from, spec string) string {
	var bases []string
	switch {
	case strings.HasPrefix(spec, "./") || strings.HasPrefix(spec, "../") || spec == "." || spec == "..":
		bases = []string{path.Join(path.Dir(from), spec)}
	case strings.HasPrefix(spec, "@/") || strings.HasPrefix(spec, "~/"):
		bases = []string{path.Join("src", spec[2:]), spec[2:]}
	default:
		return ""
	}
	for _, b := range bases {
		cands := []string{b}
		if ext := path.Ext(b); ext == ".js" || ext == ".jsx" || ext == ".mjs" || ext == ".cjs" {
			stem := strings.TrimSuffix(b, ext)
			cands = append(cands, stem+".ts", stem+".tsx", stem+".mts", stem+".cts")
		}
		for _, e := range jsExts {
			cands = append(cands, b+e)
		}
		for _, e := range jsExts {
			cands = append(cands, b+"/index"+e)
		}
		for _, c := range cands {
			if fs[c] {
				return c
			}
		}
	}
	return ""
}

// jsPackage maps an import specifier to its npm package and the path
// inside it ("" for relative paths, Node built-ins and URLs).
func jsPackage(spec string) (string, []string) {
	if spec == "" || strings.HasPrefix(spec, ".") || strings.HasPrefix(spec, "/") || strings.HasPrefix(spec, "node:") ||
		strings.Contains(spec, "://") || strings.HasPrefix(spec, "#") || strings.HasPrefix(spec, "~") || strings.HasPrefix(spec, "@/") {
		return "", nil
	}
	parts := strings.Split(spec, "/")
	n := 1
	if strings.HasPrefix(spec, "@") {
		if len(parts) < 2 {
			return "", nil
		}
		n = 2
	}
	mod := strings.ToLower(strings.Join(parts[:n], "/"))
	var sub []string
	for _, p := range parts[n:] {
		p = strings.TrimSuffix(strings.TrimSuffix(strings.TrimSuffix(p, ".js"), ".cjs"), ".mjs")
		if p != "" && p != "index" {
			sub = append(sub, p)
		}
	}
	return mod, sub
}

type jsFront struct {
	f     *fileAn
	toks  []token
	match []int
	files jsFiles
	skip  []bool
	// pending bindings keyed by the index of a right-hand side's first token
	assign      map[int]string
	destructure map[int][][2]string // {property, local name}
	aliases     [][2]string         // export name -> local name
	exportNext  string              // export name of the next function or class
	fn          int                 // the function being read (local index, -1 at top level)
}

func (j *jsFront) importValue(spec string, line int) (value, bool) {
	if k := j.files.resolve(j.f.key, spec); k != "" {
		return value{k: vLocal, file: k}, true
	}
	mod, sub := jsPackage(spec)
	if mod == "" {
		return value{}, false
	}
	j.f.imported(mod, line)
	return extVal(mod, sub...), true
}

// named is export or property name of an imported module value.
func named(v value, name string) value {
	if v.k == vLocal {
		return value{k: vLocal, file: v.file, name: name}
	}
	return v.withPath(name)
}

// defaultOf is the default import of a module.
func defaultOf(v value) value {
	if v.k == vLocal {
		return value{k: vLocal, file: v.file, name: "default"}
	}
	return v // CommonJS interoperability: the module object
}

func analyzeJS(f *fileAn, toks []token, files jsFiles) {
	j := &jsFront{f: f, toks: toks, match: matchBrackets(toks), files: files, skip: make([]bool, len(toks)),
		assign: map[int]string{}, destructure: map[int][][2]string{}}
	j.run()
	for _, al := range j.aliases {
		for _, v := range f.env[al[1]] {
			f.export(al[0], v)
		}
	}
}

func (j *jsFront) run() {
	toks, f := j.toks, j.f
	type scope struct {
		fn, depth, line int
		expr            bool // an arrow function with an expression body
		class           string
	}
	var scopes []scope
	openFn := map[int]int{}       // "{" index -> function
	openClass := map[int]string{} // "{" index -> class
	depth := 0
	cur := func() int {
		for k := len(scopes) - 1; k >= 0; k-- {
			if scopes[k].fn >= 0 {
				return scopes[k].fn
			}
		}
		return -1
	}
	className := func() string {
		if n := len(scopes); n > 0 && scopes[n-1].class != "" && scopes[n-1].depth == depth {
			return scopes[n-1].class
		}
		return ""
	}
	topLevel := func() bool { return cur() < 0 }
	newFn := func(name, display string, line int) int {
		f.funcs = append(f.funcs, fnDef{name: name, display: display, line: line, end: line})
		return len(f.funcs) - 1
	}
	// bodyBrace finds the "{" of a function body after its parameter list
	// ending at close (skipping a TypeScript return type).
	bodyBrace := func(close int) int {
		k := close + 1
		if isP(toks, k, ":") {
			for k < len(toks) && k < close+40 && !isP(toks, k, "{") && !isP(toks, k, ";") && !isP(toks, k, "=>") {
				k++
			}
		}
		if isP(toks, k, "{") {
			return k
		}
		return -1
	}
	for i := 0; i < len(toks); i++ {
		t := toks[i]
		// expression-bodied arrow functions end at the next line at their depth
		for len(scopes) > 0 && scopes[len(scopes)-1].expr {
			s := scopes[len(scopes)-1]
			if depth < s.depth || (depth == s.depth && t.line > s.line) || (depth == s.depth && t.kind == tPunct && (t.text == ";" || t.text == ",")) {
				f.funcs[s.fn].end = t.line
				scopes = scopes[:len(scopes)-1]
				continue
			}
			break
		}
		j.fn = cur()
		if t.kind == tPunct {
			switch t.text {
			case "{":
				depth++
				if fn, ok := openFn[i]; ok {
					scopes = append(scopes, scope{fn: fn, depth: depth})
				} else if c, ok := openClass[i]; ok {
					scopes = append(scopes, scope{fn: -1, depth: depth, class: c})
				}
			case "}":
				for len(scopes) > 0 && scopes[len(scopes)-1].depth >= depth {
					if s := scopes[len(scopes)-1]; s.fn >= 0 {
						f.funcs[s.fn].end = t.line
					}
					scopes = scopes[:len(scopes)-1]
				}
				if depth > 0 {
					depth--
				}
			case "=>":
				// const name = (args) => ..., name: async x => ...
				p := i - 1
				if isP(toks, p, ")") && j.match[p] >= 0 {
					p = j.match[p]
				} else if !isIdent(toks, p) {
					continue
				}
				q := p - 1
				if isI(toks, q, "async") {
					q--
				}
				if (isP(toks, q, "=") || isP(toks, q, ":")) && isIdent(toks, q-1) && !jsKeywords[toks[q-1].text] {
					name := toks[q-1].text
					display := name
					if c := className(); c != "" {
						display = c + "." + name
					}
					fn := newFn(name, display, toks[q-1].line)
					if topLevel() && isP(toks, q, "=") {
						f.bind(name, value{k: vFn, file: f.key, idx: fn})
					}
					if isP(toks, i+1, "{") {
						openFn[i+1] = fn
					} else {
						scopes = append(scopes, scope{fn: fn, depth: depth, line: t.line, expr: true})
					}
				}
			}
			continue
		}
		if t.kind != tIdent || j.skip[i] {
			continue
		}
		if isP(toks, i-1, ".") || isP(toks, i-1, "?.") {
			continue
		}
		bound := len(f.env[t.text]) > 0
		switch t.text {
		case "import":
			if isP(toks, i+1, "(") {
				// import("x") or import(expr)
				if i+3 < len(toks) && toks[i+2].kind == tString && isP(toks, i+3, ")") {
					if v, ok := j.importValue(toks[i+2].text, t.line); ok {
						j.chainAt(i, &v, i+3)
					}
				} else {
					f.dyn("", "import() of a computed module name", t.line)
				}
				continue
			}
			if isP(toks, i+1, ".") {
				continue // import.meta
			}
			i = j.staticImport(i)
			continue
		case "export":
			i = j.export(i)
			continue
		case "require":
			if bound || !isP(toks, i+1, "(") {
				break
			}
			if i+3 < len(toks) && toks[i+2].kind == tString && isP(toks, i+3, ")") {
				if v, ok := j.importValue(toks[i+2].text, t.line); ok {
					j.chainAt(i, &v, i+3)
				}
			} else {
				f.dyn("", "require() of a computed module name", t.line)
			}
			continue
		case "eval":
			if !bound && isP(toks, i+1, "(") {
				f.dyn("", "eval()", t.line)
			}
		case "Function":
			if isI(toks, i-1, "new") {
				f.dyn("", "new Function()", t.line)
			}
		case "function":
			k := i + 1
			if isP(toks, k, "*") {
				k++
			}
			name := ""
			if isIdent(toks, k) {
				name = toks[k].text
				j.skip[k] = true
				k++
			} else if (isP(toks, i-1, "=") || isP(toks, i-1, ":")) && isIdent(toks, i-2) {
				name = toks[i-2].text
			} else if isI(toks, i-1, "async") && (isP(toks, i-2, "=") || isP(toks, i-2, ":")) && isIdent(toks, i-3) {
				name = toks[i-3].text
			}
			if !isP(toks, k, "(") || j.match[k] < 0 {
				continue
			}
			if name == "" {
				continue // anonymous: its calls belong to the enclosing function
			}
			fn := newFn(name, name, t.line)
			if topLevel() {
				f.bind(name, value{k: vFn, file: f.key, idx: fn})
			}
			if j.exportNext != "" {
				f.export(j.exportNext, value{k: vFn, file: f.key, idx: fn})
				j.exportNext = ""
			}
			if b := bodyBrace(j.match[k]); b >= 0 {
				openFn[b] = fn
			}
			continue
		case "class":
			k := i + 1
			name := ""
			if isIdent(toks, k) && toks[k].text != "extends" {
				name = toks[k].text
				j.skip[k] = true
			}
			if name != "" && cur() < 0 {
				f.bind(name, value{k: vOther, name: "class:" + name})
			}
			if j.exportNext != "" && name != "" {
				f.export(j.exportNext, value{k: vOther, name: "class:" + name})
			}
			j.exportNext = ""
			for ; k < len(toks) && k < i+200; k++ {
				if isP(toks, k, "{") {
					if name == "" {
						name = "<class>"
					}
					openClass[k] = name
					break
				}
			}
			continue
		case "const", "let", "var":
			k := i + 1
			switch {
			case isIdent(toks, k) && isP(toks, k+1, "="):
				j.skip[k] = true
				j.assign[rhsStart(toks, k+2)] = toks[k].text
			case isIdent(toks, k) && isP(toks, k+1, ":"):
				// TypeScript annotation: const x: T = ...
				j.skip[k] = true
				for m := k + 2; m < len(toks) && m < k+40; m++ {
					if isP(toks, m, "=") {
						j.assign[rhsStart(toks, m+1)] = toks[k].text
						break
					}
					if isP(toks, m, ";") {
						break
					}
				}
			case isP(toks, k, "{") && j.match[k] > 0 && isP(toks, j.match[k]+1, "="):
				end := j.match[k]
				var pairs [][2]string
				for m := k + 1; m < end; m++ {
					switch {
					case isP(toks, m, "...") && isIdent(toks, m+1):
						pairs = append(pairs, [2]string{"", toks[m+1].text})
						j.skip[m+1] = true
						m++
					case isIdent(toks, m) && isP(toks, m+1, ":") && isIdent(toks, m+2):
						pairs = append(pairs, [2]string{toks[m].text, toks[m+2].text})
						j.skip[m], j.skip[m+2] = true, true
						m += 2
					case isIdent(toks, m) && (isP(toks, m+1, ",") || isP(toks, m+1, "}") || isP(toks, m+1, "=") || m+1 == end):
						pairs = append(pairs, [2]string{toks[m].text, toks[m].text})
						j.skip[m] = true
					}
				}
				j.destructure[rhsStart(toks, end+2)] = pairs
			}
			continue
		}
		if jsKeywords[t.text] && !bound && t.text != "super" {
			continue
		}
		if t.text == "async" && !bound {
			continue
		}
		// method definitions: name(args) { ... } in a class body or an
		// object literal
		if isP(toks, i+1, "(") && j.match[i+1] > 0 && !isI(toks, i-1, "new") {
			if b := bodyBrace(j.match[i+1]); b >= 0 {
				c := className()
				prev := ""
				if i > 0 {
					prev = toks[i-1].text
				}
				if c != "" || prev == "," || prev == "{" || prev == "async" || prev == "get" || prev == "set" || prev == "static" || prev == "*" {
					display := t.text
					if c != "" && c != "<class>" {
						display = c + "." + t.text
					}
					openFn[b] = newFn(t.text, display, t.line)
					continue
				}
			}
		}
		j.chainAt(i, nil, i)
	}
}

// chainAt records the chain whose root is the token at i (a name, or a
// literal root ending at rootEnd).
func (j *jsFront) chainAt(i int, root *value, rootEnd int) {
	toks, f := j.toks, j.f
	segs, end, used := parseChain(toks, rootEnd, j.match, false)
	for _, u := range used {
		j.skip[u] = true
	}
	// assignment targets
	if isP(toks, end, "=") && (len(segs) == 0 || !segs[len(segs)-1].call) && root == nil {
		target := ""
		name := toks[i].text
		switch {
		case name == "module" && len(segs) == 1 && segs[0].name == "exports":
			target = "module.exports"
		case name == "module" && len(segs) == 2 && segs[0].name == "exports":
			target = "export:" + segs[1].name
		case name == "exports" && len(segs) == 1:
			target = "export:" + segs[0].name
		case name == "this" && len(segs) == 1:
			target = "this." + segs[0].name
		case len(segs) == 0:
			target = name
		}
		if target != "" {
			k := rhsStart(toks, end+1)
			if target == "module.exports" && isP(toks, k, "{") && j.match[k] > 0 {
				// module.exports = { a, b: c }
				for m := k + 1; m < j.match[k]; m++ {
					switch {
					case isIdent(toks, m) && isP(toks, m+1, ":") && isIdent(toks, m+2) && (isP(toks, m+3, ",") || isP(toks, m+3, "}")):
						j.aliases = append(j.aliases, [2]string{toks[m].text, toks[m+2].text})
						m += 2
					case isIdent(toks, m) && (isP(toks, m+1, ",") || isP(toks, m+1, "}")) && (isP(toks, m-1, "{") || isP(toks, m-1, ",")):
						j.aliases = append(j.aliases, [2]string{toks[m].text, toks[m].text})
					}
				}
			} else {
				j.assign[k] = target
			}
			if len(segs) > 0 {
				return
			}
		}
	}
	if isP(toks, end, "=>") {
		return // a parameter of an arrow function
	}
	target, assigned := j.assign[i]
	pairs, destructured := j.destructure[i]
	escape := false
	if len(segs) == 0 && !assigned && !destructured && i > 0 {
		escape = jsEscapeAfter[toks[i-1].text]
	}
	if len(segs) == 0 && !escape && !assigned && !destructured && root == nil {
		return
	}
	c := &chain{rootName: toks[i].text, root: root, segs: segs, line: toks[i].line, fn: j.fn, escape: escape,
		isNew: isI(toks, i-1, "new")}
	idx := f.addChain(c)
	res := value{k: vChain, file: f.key, idx: idx}
	if assigned && (isP(toks, end, ";") || end >= len(toks) || toks[end].line > toks[i].line || isP(toks, end, ")") || isP(toks, end, "}") || isP(toks, end, ",")) {
		j.bindTarget(target, res)
	}
	if destructured {
		for _, p := range pairs {
			if p[0] == "" {
				f.bind(p[1], res)
			} else {
				base := res
				f.bind(p[1], value{k: vMember, base: &base, name: p[0]})
			}
		}
	}
}

func (j *jsFront) bindTarget(target string, v value) {
	switch {
	case target == "module.exports":
		j.f.stars = append(j.f.stars, v)
		j.f.export("default", v)
	case strings.HasPrefix(target, "export:"):
		j.f.export(strings.TrimPrefix(target, "export:"), v)
	default:
		j.f.bind(target, v)
	}
}

// staticImport handles import ... from "x" at i and returns the last
// token index of the statement.
func (j *jsFront) staticImport(i int) int {
	toks, f := j.toks, j.f
	k := i + 1
	if isI(toks, k, "type") && !isP(toks, k+1, ",") && !isI(toks, k+1, "from") {
		k++
	}
	if k < len(toks) && toks[k].kind == tString {
		j.importValue(toks[k].text, toks[i].line)
		return k
	}
	var def, ns string
	var specs [][2]string
	if isIdent(toks, k) && !isI(toks, k, "from") {
		def = toks[k].text
		k++
		if isP(toks, k, "=") && isI(toks, k+1, "require") && isP(toks, k+2, "(") && k+3 < len(toks) && toks[k+3].kind == tString {
			if v, ok := j.importValue(toks[k+3].text, toks[i].line); ok {
				f.bind(def, v)
			}
			return k + 4
		}
		if isP(toks, k, ",") {
			k++
		}
	}
	if isP(toks, k, "*") && isI(toks, k+1, "as") && isIdent(toks, k+2) {
		ns = toks[k+2].text
		k += 3
	}
	if isP(toks, k, "{") && j.match[k] > k {
		end := j.match[k]
		for m := k + 1; m < end; m++ {
			if !isIdent(toks, m) || isI(toks, m, "type") && isIdent(toks, m+1) {
				continue
			}
			if isI(toks, m+1, "as") && isIdent(toks, m+2) {
				specs = append(specs, [2]string{toks[m].text, toks[m+2].text})
				m += 2
				continue
			}
			specs = append(specs, [2]string{toks[m].text, toks[m].text})
		}
		k = end + 1
	}
	if !isI(toks, k, "from") || k+1 >= len(toks) || toks[k+1].kind != tString {
		return i
	}
	v, ok := j.importValue(toks[k+1].text, toks[i].line)
	if !ok {
		return k + 1
	}
	if def != "" {
		f.bind(def, defaultOf(v))
	}
	if ns != "" {
		f.bind(ns, v)
	}
	for _, s := range specs {
		if s[0] == "default" {
			f.bind(s[1], defaultOf(v))
			continue
		}
		f.bind(s[1], named(v, s[0]))
	}
	return k + 1
}

// export handles the export forms at i and returns the index to continue
// from.
func (j *jsFront) export(i int) int {
	toks, f := j.toks, j.f
	k := i + 1
	switch {
	case isP(toks, k, "*"):
		// export * from "x"; export * as ns from "x"
		ns := ""
		m := k + 1
		if isI(toks, m, "as") && isIdent(toks, m+1) {
			ns = toks[m+1].text
			m += 2
		}
		if isI(toks, m, "from") && m+1 < len(toks) && toks[m+1].kind == tString {
			if v, ok := j.importValue(toks[m+1].text, toks[i].line); ok {
				if ns != "" {
					f.export(ns, v)
				} else {
					f.stars = append(f.stars, v)
				}
			}
			return m + 1
		}
		return k
	case isP(toks, k, "{") && j.match[k] > k:
		end := j.match[k]
		var specs [][2]string // local or imported name, exported name
		for m := k + 1; m < end; m++ {
			if !isIdent(toks, m) || isI(toks, m, "type") && isIdent(toks, m+1) {
				continue
			}
			if isI(toks, m+1, "as") && isIdent(toks, m+2) {
				specs = append(specs, [2]string{toks[m].text, toks[m+2].text})
				m += 2
				continue
			}
			specs = append(specs, [2]string{toks[m].text, toks[m].text})
		}
		if isI(toks, end+1, "from") && end+2 < len(toks) && toks[end+2].kind == tString {
			if v, ok := j.importValue(toks[end+2].text, toks[i].line); ok {
				for _, s := range specs {
					if s[0] == "default" {
						f.export(s[1], defaultOf(v))
					} else {
						f.export(s[1], named(v, s[0]))
					}
				}
			}
			return end + 2
		}
		for _, s := range specs {
			j.aliases = append(j.aliases, [2]string{s[1], s[0]})
		}
		return end
	case isI(toks, k, "default"):
		m := k + 1
		if isI(toks, m, "async") {
			m++
		}
		if isI(toks, m, "function") || isI(toks, m, "class") {
			j.exportNext = "default"
			return k
		}
		if isIdent(toks, m) {
			j.assign[m] = "export:default"
		}
		return k
	case isI(toks, k, "const") || isI(toks, k, "let") || isI(toks, k, "var"):
		if isIdent(toks, k+1) {
			j.aliases = append(j.aliases, [2]string{toks[k+1].text, toks[k+1].text})
		}
		return i // the declaration is handled next
	case isI(toks, k, "function") || isI(toks, k, "async") && isI(toks, k+1, "function"):
		m := k
		if isI(toks, m, "async") {
			m++
		}
		if isIdent(toks, m+1) {
			j.exportNext = toks[m+1].text
		} else if isP(toks, m+1, "*") && isIdent(toks, m+2) {
			j.exportNext = toks[m+2].text
		}
		return i
	case isP(toks, k, "="):
		// TypeScript: export = x
		j.assign[k+1] = "module.exports"
		return k
	}
	return i
}

// rhsStart skips await, yield and new before an assigned expression.
func rhsStart(toks []token, k int) int {
	for isI(toks, k, "await") || isI(toks, k, "new") || isI(toks, k, "yield") {
		k++
	}
	return k
}
