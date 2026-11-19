package reachscan

import (
	"math"
	"path"
	"strings"
)

var pyKeywords = map[string]bool{"if": true, "elif": true, "else": true, "for": true, "while": true, "in": true, "not": true, "and": true,
	"or": true, "is": true, "return": true, "yield": true, "lambda": true, "with": true, "as": true, "def": true, "class": true,
	"import": true, "from": true, "pass": true, "raise": true, "try": true, "except": true, "finally": true, "global": true,
	"nonlocal": true, "assert": true, "del": true, "True": true, "False": true, "None": true, "await": true, "async": true,
	"break": true, "continue": true, "match": true, "case": true}

var pyEscapeAfter = map[string]bool{"(": true, ",": true, "return": true, "[": true, "=": true, ":": true, "or": true, "and": true,
	"yield": true, "{": true}

// pyModules maps dotted module names to repository files: every suffix of
// a file's path counts, as the import root (the project directory, src/,
// a package's parent) is not known.
type pyModules struct {
	byDotted map[string][]string
	keys     map[string]bool
}

func newPyModules(files []string) pyModules {
	m := pyModules{byDotted: map[string][]string{}, keys: map[string]bool{}}
	dirs := map[string]bool{}
	for _, k := range files {
		m.keys[k] = true
		mod := strings.TrimSuffix(k, ".py")
		if path.Base(mod) == "__init__" {
			mod = path.Dir(mod)
		}
		m.add(mod, k)
		for d := path.Dir(k); d != "." && d != "/" && !dirs[d]; d = path.Dir(d) {
			dirs[d] = true
		}
	}
	for d := range dirs {
		if !m.keys[d+"/__init__.py"] {
			m.keys[d+"/"] = true
			m.add(d, d+"/")
		}
	}
	return m
}

func (m pyModules) add(mod, key string) {
	if mod == "." || mod == "" {
		return
	}
	parts := strings.Split(mod, "/")
	for i := range parts {
		d := strings.Join(parts[i:], ".")
		if len(m.byDotted[d]) < 20 {
			m.byDotted[d] = append(m.byDotted[d], key)
		}
	}
}

// find picks the candidate closest to the importing file.
func (m pyModules) find(dotted, from string) string {
	best, score := "", math.MinInt
	for _, k := range m.byDotted[dotted] {
		s := commonDirs(k, from)*1000 - len(k)
		if s > score {
			best, score = k, s
		}
	}
	return best
}

func commonDirs(a, b string) int {
	pa, pb := strings.Split(path.Dir(a), "/"), strings.Split(path.Dir(b), "/")
	n := 0
	for n < len(pa) && n < len(pb) && pa[n] == pb[n] {
		n++
	}
	return n
}

// relative resolves a relative import (level dots) to a repository key.
func (m pyModules) relative(from string, level int, dotted string) string {
	dir := path.Dir(from)
	for i := 1; i < level; i++ {
		dir = path.Dir(dir)
	}
	target := dir
	if dotted != "" {
		target = path.Join(dir, strings.ReplaceAll(dotted, ".", "/"))
	}
	for _, k := range []string{target + ".py", target + "/__init__.py", target + "/"} {
		if m.keys[k] {
			return k
		}
	}
	return ""
}

type pyFront struct {
	f      *fileAn
	toks   []token
	match  []int
	skip   []bool
	mods   pyModules
	assign map[int]string
}

// moduleValue is the value of an imported module (absolute when level is
// 0).
func (p *pyFront) moduleValue(dotted string, level, line int) value {
	if level > 0 {
		if k := p.mods.relative(p.f.key, level, dotted); k != "" {
			return value{k: vLocal, file: k}
		}
		return value{k: vNone}
	}
	parts := strings.Split(dotted, ".")
	// the longest prefix that is a repository module, then its members
	for n := len(parts); n > 0; n-- {
		if k := p.mods.find(strings.Join(parts[:n], "."), p.f.key); k != "" {
			v := value{k: vLocal, file: k}
			for _, rest := range parts[n:] {
				base := v
				v = value{k: vMember, base: &base, name: rest}
			}
			return v
		}
	}
	p.f.imported(parts[0], line)
	return extVal(parts[0], parts[1:]...)
}

func (p *pyFront) dotted(k int) (string, int) {
	var parts []string
	for isIdent(p.toks, k) {
		parts = append(parts, p.toks[k].text)
		p.skip[k] = true
		if isP(p.toks, k+1, ".") && isIdent(p.toks, k+2) {
			k += 2
			continue
		}
		k++
		break
	}
	return strings.Join(parts, "."), k
}

func analyzePython(f *fileAn, toks []token, mods pyModules) {
	p := &pyFront{f: f, toks: toks, match: matchBrackets(toks), skip: make([]bool, len(toks)), mods: mods, assign: map[int]string{}}
	p.run()
}

func (p *pyFront) run() {
	toks, f := p.toks, p.f
	type scope struct {
		fn, col int
		class   string
	}
	var scopes []scope
	stmt := 0 // first token of the logical line
	cur := func() int {
		for k := len(scopes) - 1; k >= 0; k-- {
			if scopes[k].fn >= 0 {
				return scopes[k].fn
			}
		}
		return -1
	}
	className := func() string {
		if n := len(scopes); n > 0 && scopes[n-1].class != "" {
			return scopes[n-1].class
		}
		return ""
	}
	for i := 0; i < len(toks); i++ {
		t := toks[i]
		if t.first {
			for len(scopes) > 0 && scopes[len(scopes)-1].col >= t.col {
				if s := scopes[len(scopes)-1]; s.fn >= 0 && i > 0 {
					f.funcs[s.fn].end = toks[i-1].line
				}
				scopes = scopes[:len(scopes)-1]
			}
			stmt = i
		}
		if t.kind != tIdent || p.skip[i] || isP(toks, i-1, ".") {
			continue
		}
		bound := len(f.env[t.text]) > 0
		atStmt := i == stmt || isP(toks, i-1, ";") || isP(toks, i-1, ":") && toks[i-1].line == t.line && i-1 > stmt
		switch {
		case t.text == "import" && atStmt:
			k := i + 1
			for {
				name, next := p.dotted(k)
				if name == "" {
					break
				}
				k = next
				if isI(toks, k, "as") && isIdent(toks, k+1) {
					p.skip[k+1] = true
					f.bind(toks[k+1].text, p.moduleValue(name, 0, t.line))
					k += 2
				} else {
					top := strings.SplitN(name, ".", 2)[0]
					f.bind(top, p.moduleValue(top, 0, t.line))
					if top != name {
						p.moduleValue(name, 0, t.line)
					}
				}
				if !isP(toks, k, ",") {
					break
				}
				k++
			}
			i = k - 1
			continue
		case t.text == "from" && atStmt:
			k := i + 1
			level := 0
			for isP(toks, k, ".") || isP(toks, k, "...") {
				level += len(toks[k].text)
				k++
			}
			name, next := p.dotted(k)
			k = next
			if !isI(toks, k, "import") {
				continue
			}
			k++
			base := p.moduleValue(name, level, t.line)
			if isP(toks, k, "*") {
				f.stars = append(f.stars, base)
				i = k
				continue
			}
			end := len(toks)
			if isP(toks, k, "(") && p.match[k] > k {
				end = p.match[k]
				k++
			}
			for k < end && isIdent(toks, k) && (!toks[k].first || end < len(toks)) {
				orig, alias := toks[k].text, toks[k].text
				p.skip[k] = true
				k++
				if isI(toks, k, "as") && isIdent(toks, k+1) {
					alias = toks[k+1].text
					p.skip[k+1] = true
					k += 2
				}
				switch base.k {
				case vLocal:
					f.bind(alias, value{k: vLocal, file: base.file, name: orig})
				case vNone:
					f.bind(alias, value{k: vNone})
				default:
					b := base
					f.bind(alias, value{k: vMember, base: &b, name: orig})
				}
				if !isP(toks, k, ",") {
					break
				}
				k++
			}
			i = k - 1
			continue
		case t.text == "def" && isIdent(toks, i+1):
			name := toks[i+1].text
			p.skip[i+1] = true
			display := name
			if c := className(); c != "" {
				display = c + "." + name
			}
			f.funcs = append(f.funcs, fnDef{name: name, display: display, line: t.line, end: t.line})
			fn := len(f.funcs) - 1
			if len(scopes) == 0 {
				f.bind(name, value{k: vFn, file: f.key, idx: fn})
			}
			scopes = append(scopes, scope{fn: fn, col: toks[stmt].col})
			p.skipParams(i + 2)
			continue
		case t.text == "class" && isIdent(toks, i+1):
			name := toks[i+1].text
			p.skip[i+1] = true
			if c := className(); c != "" {
				name = c + "." + name
			}
			if len(scopes) == 0 {
				f.bind(name, value{k: vOther, name: "class:" + name})
			}
			scopes = append(scopes, scope{fn: -1, col: toks[stmt].col, class: name})
			continue
		case t.text == "lambda":
			for k := i + 1; k < len(toks) && !isP(toks, k, ":"); k++ {
				if isIdent(toks, k) {
					p.skip[k] = true
				}
			}
			continue
		case (t.text == "eval" || t.text == "exec") && !bound && isP(toks, i+1, "("):
			f.dyn("", t.text+"()", t.line)
		case t.text == "__import__" && !bound && isP(toks, i+1, "(") && p.match[i+1] > i:
			if i+3 < len(toks) && toks[i+2].kind == tString && (isP(toks, i+3, ")") || isP(toks, i+3, ",")) {
				v := p.moduleValue(strings.SplitN(toks[i+2].text, ".", 2)[0], 0, t.line)
				p.chainAt(i, &v, p.match[i+1], cur())
			} else {
				f.dyn("", "__import__() of a computed module name", t.line)
			}
			continue
		case t.text == "importlib" && isP(toks, i+1, ".") && isI(toks, i+2, "import_module") && isP(toks, i+3, "(") && p.match[i+3] > i:
			if i+5 < len(toks) && toks[i+4].kind == tString && !strings.HasPrefix(toks[i+4].text, ".") && (isP(toks, i+5, ")") || isP(toks, i+5, ",")) {
				v := p.moduleValue(toks[i+4].text, 0, t.line)
				p.skip[i+2] = true
				p.chainAt(i, &v, p.match[i+3], cur())
			} else {
				f.dyn("", "importlib.import_module() of a computed module name", t.line)
				p.skip[i+2] = true
			}
			continue
		case t.text == "getattr" && !bound && isP(toks, i+1, "(") && isIdent(toks, i+2) && isP(toks, i+3, ",") && p.match[i+1] > i:
			x := i + 2
			p.skip[x] = true
			var first seg
			if i+5 < len(toks) && toks[i+4].kind == tString && (isP(toks, i+5, ")") || isP(toks, i+5, ",")) {
				first = seg{name: toks[i+4].text, line: t.line}
			} else {
				first = seg{computed: true, byName: true, line: t.line}
			}
			rest, _, used := parseChain(toks, p.match[i+1], p.match, false)
			for _, u := range used {
				p.skip[u] = true
			}
			if len(f.chains) < 1<<20 {
				f.addChain(&chain{rootName: toks[x].text, segs: append([]seg{first}, rest...), line: t.line, fn: cur()})
			}
			continue
		}
		if pyKeywords[t.text] && !bound {
			continue
		}
		p.chainAt(i, nil, i, cur())
	}
	for _, s := range scopes {
		if s.fn >= 0 && len(toks) > 0 {
			f.funcs[s.fn].end = toks[len(toks)-1].line
		}
	}
}

// skipParams marks the parameter names of a def whose "(" is at k.
func (p *pyFront) skipParams(k int) {
	if !isP(p.toks, k, "(") || p.match[k] < 0 {
		return
	}
	for m := k + 1; m < p.match[k]; m++ {
		if isIdent(p.toks, m) && (isP(p.toks, m-1, "(") || isP(p.toks, m-1, ",") || isP(p.toks, m-1, "*") || isP(p.toks, m-1, "**")) {
			p.skip[m] = true
		}
	}
}

func (p *pyFront) chainAt(i int, root *value, rootEnd, fn int) {
	toks, f := p.toks, p.f
	segs, end, used := parseChain(toks, rootEnd, p.match, false)
	for _, u := range used {
		p.skip[u] = true
	}
	name := toks[i].text
	// assignment targets: x = ..., x: T = ..., self.x = ...
	if root == nil && toks[i].first && (len(segs) == 0 || len(segs) == 1 && name == "self" && !segs[0].call) {
		k := end
		if isP(toks, k, ":") {
			for k < len(toks) && !isP(toks, k, "=") && !toks[k].first {
				k++
			}
		}
		if isP(toks, k, "=") {
			target := name
			if len(segs) == 1 {
				target = "self." + segs[0].name
			}
			p.assign[rhsStart(toks, k+1)] = target
			return
		}
	}
	target, assigned := p.assign[i]
	escape := false
	if len(segs) == 0 && !assigned && i > 0 && !isP(toks, end, "=") {
		escape = pyEscapeAfter[toks[i-1].text]
	}
	withAs := isI(toks, end, "as") && isIdent(toks, end+1)
	if len(segs) == 0 && !escape && !assigned && !withAs && root == nil {
		return
	}
	c := &chain{rootName: name, root: root, segs: segs, line: toks[i].line, fn: fn, escape: escape}
	idx := f.addChain(c)
	res := value{k: vChain, file: f.key, idx: idx}
	if assigned && (end >= len(toks) || toks[end].first || isP(toks, end, ";") || isP(toks, end, ")")) {
		f.bind(target, res)
	}
	if withAs {
		p.skip[end+1] = true
		f.bind(toks[end+1].text, res)
	}
}
