package reachscan

import (
	"strings"
)

var javaKeywords = map[string]bool{"if": true, "for": true, "while": true, "switch": true, "catch": true, "return": true, "new": true,
	"throw": true, "case": true, "do": true, "else": true, "try": true, "finally": true, "synchronized": true, "assert": true,
	"break": true, "continue": true, "instanceof": true, "class": true, "interface": true, "enum": true, "extends": true,
	"implements": true, "import": true, "package": true, "static": true, "final": true, "public": true, "private": true,
	"protected": true, "abstract": true, "native": true, "transient": true, "volatile": true, "strictfp": true, "default": true,
	"yield": true, "permits": true, "sealed": true, "throws": true, "true": true, "false": true, "null": true, "super": true,
	"void": true, "record": true}

var javaPrimitive = map[string]bool{"int": true, "long": true, "short": true, "byte": true, "char": true, "boolean": true,
	"double": true, "float": true, "void": true}

var javaEscapeAfter = map[string]bool{"(": true, ",": true, "return": true, "=": true, "?": true, ":": true}

// reflective lookups of methods by name
var javaReflect = map[string]bool{"getMethod": true, "getDeclaredMethod": true, "findVirtual": true, "findStatic": true, "findSpecial": true}

type javaFront struct {
	f      *fileAn
	toks   []token
	match  []int
	skip   []bool
	assign map[int]string
}

func analyzeJava(f *fileAn, toks []token) {
	j := &javaFront{f: f, toks: toks, match: matchBrackets(toks), skip: make([]bool, len(toks)), assign: map[int]string{}}
	j.run()
}

// importValue binds a single-type, static or wildcard import.
func (j *javaFront) importDecl(i int) int {
	toks, f := j.toks, j.f
	k := i + 1
	static := false
	if isI(toks, k, "static") {
		static = true
		k++
	}
	var parts []string
	wild := false
	for k < len(toks) && !isP(toks, k, ";") && k < i+100 {
		switch {
		case isIdent(toks, k):
			parts = append(parts, toks[k].text)
		case isP(toks, k, "*"):
			wild = true
		}
		k++
	}
	if len(parts) == 0 {
		return k
	}
	// the package ends before the first capitalized segment
	p := len(parts)
	for n, s := range parts {
		if capitalized(s) {
			p = n
			break
		}
	}
	if p == len(parts) && !wild {
		p = len(parts) - 1
	}
	pkg := strings.Join(parts[:p], ".")
	rest := parts[p:]
	f.imported(pkg, toks[i].line)
	v := extVal(pkg, rest...)
	switch {
	case wild:
		f.stars = append(f.stars, v)
	case static && len(rest) >= 2, len(rest) >= 1:
		f.bind(last(rest), v)
	}
	return k
}

func (j *javaFront) run() {
	toks, f := j.toks, j.f
	type scope struct {
		fn, depth int
		class     string
	}
	var scopes []scope
	openFn := map[int]int{}
	openClass := map[int]string{}
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
		for k := len(scopes) - 1; k >= 0; k-- {
			if scopes[k].class != "" {
				return scopes[k].class
			}
		}
		return ""
	}
	for i := 0; i < len(toks); i++ {
		t := toks[i]
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
			}
			continue
		}
		if t.kind != tIdent {
			continue
		}
		// reflection: getMethod("name") finds a method by name
		if javaReflect[t.text] && isP(toks, i-1, ".") && isP(toks, i+1, "(") && j.match[i+1] > i {
			name := ""
			for k := i + 2; k < j.match[i+1]; k++ {
				if toks[k].kind == tString {
					name = toks[k].text
					break
				}
			}
			if name != "" {
				f.addChain(&chain{rootName: "", root: &value{k: vNone}, segs: []seg{{name: name, line: t.line}, {call: true, line: t.line}},
					line: t.line, fn: cur()})
			} else {
				f.dyn("", "reflective method lookup with a computed name ("+t.text+")", t.line)
			}
		}
		if (t.text == "getMethods" || t.text == "getDeclaredMethods" || t.text == "loadClass") && isP(toks, i-1, ".") && isP(toks, i+1, "(") {
			f.dyn("", "reflection ("+t.text+")", t.line)
		}
		if j.skip[i] || isP(toks, i-1, ".") || isP(toks, i-1, "::") || isP(toks, i-1, "@") {
			continue
		}
		switch t.text {
		case "package":
			var parts []string
			k := i + 1
			for ; k < len(toks) && !isP(toks, k, ";"); k++ {
				if isIdent(toks, k) {
					parts = append(parts, toks[k].text)
				}
			}
			f.javaPkg = strings.Join(parts, ".")
			i = k
			continue
		case "import":
			i = j.importDecl(i)
			continue
		case "class", "interface", "enum", "record":
			if !isIdent(toks, i+1) {
				break
			}
			name := toks[i+1].text
			j.skip[i+1] = true
			f.bind(name, value{k: vOther, name: "class:" + name})
			if c := className(); c != "" {
				name = c + "." + name
			}
			for k := i + 2; k < len(toks) && k < i+400; k++ {
				if isP(toks, k, "(") && j.match[k] > k { // record components
					k = j.match[k]
					continue
				}
				if isP(toks, k, "{") {
					openClass[k] = name
					break
				}
				if isP(toks, k, ";") {
					break
				}
			}
			continue
		case "Class":
			if isP(toks, i+1, ".") && isI(toks, i+2, "forName") && isP(toks, i+3, "(") {
				if i+5 < len(toks) && toks[i+4].kind == tString && (isP(toks, i+5, ")") || isP(toks, i+5, ",")) {
					parts := strings.Split(toks[i+4].text, ".")
					p := len(parts) - 1
					for n, s := range parts {
						if capitalized(s) {
							p = n
							break
						}
					}
					pkg := strings.Join(parts[:p], ".")
					f.imported(pkg, t.line)
					v := extVal(pkg, strings.Split(strings.ReplaceAll(strings.Join(parts[p:], "."), "$", "."), ".")...)
					f.addChain(&chain{rootName: "Class", root: &v, line: t.line, fn: cur(), escape: true})
				} else {
					f.dyn("", "Class.forName() with a computed class name", t.line)
				}
				j.skip[i+2] = true
				continue
			}
		}
		if javaKeywords[t.text] {
			continue
		}
		// method and constructor declarations: name(params) [throws X] {
		if isP(toks, i+1, "(") && j.match[i+1] > i && !isI(toks, i-1, "new") {
			k := j.match[i+1] + 1
			if isI(toks, k, "throws") {
				for k < len(toks) && !isP(toks, k, "{") && !isP(toks, k, ";") && k < j.match[i+1]+40 {
					k++
				}
			}
			if isP(toks, k, "{") {
				display := t.text
				if c := className(); c != "" {
					display = c + "." + t.text
				}
				f.funcs = append(f.funcs, fnDef{name: t.text, display: display, line: t.line, end: t.line})
				openFn[k] = len(f.funcs) - 1
				continue
			}
		}
		// typed declarations: Type name (=|;|,|)|:)
		if n := j.declName(i); n > 0 {
			name := toks[n].text
			j.skip[n] = true
			if t.text == "var" {
				if isP(toks, n+1, "=") {
					j.assign[rhsStart(toks, n+2)] = name
				}
			} else {
				f.bind(name, value{k: vType, name: t.text, file: f.key})
			}
			continue
		}
		j.chainAt(i, cur())
	}
}

// declName returns the index of the declared name when the type at i
// starts a declaration (0 otherwise).
func (j *javaFront) declName(i int) int {
	toks := j.toks
	t := toks[i].text
	if !(capitalized(t) || javaPrimitive[t] || t == "var") || javaKeywords[t] && !javaPrimitive[t] {
		return 0
	}
	k := i + 1
	if isP(toks, k, "<") {
		d := 0
		for ; k < len(toks) && k < i+60; k++ {
			if isP(toks, k, "<") {
				d++
			} else if isP(toks, k, ">") {
				d--
				if d == 0 {
					k++
					break
				}
			} else if isP(toks, k, ";") || isP(toks, k, "{") || isP(toks, k, "(") {
				return 0
			}
		}
	}
	for isP(toks, k, "[") && isP(toks, k+1, "]") {
		k += 2
	}
	if isP(toks, k, "...") {
		k++
	}
	if !isIdent(toks, k) || javaKeywords[toks[k].text] {
		return 0
	}
	switch {
	case isP(toks, k+1, "="), isP(toks, k+1, ";"), isP(toks, k+1, ","), isP(toks, k+1, ")"), isP(toks, k+1, ":"):
		return k
	}
	return 0
}

func (j *javaFront) chainAt(i, fn int) {
	toks, f := j.toks, j.f
	rootEnd := i
	if isP(toks, i+1, "<") { // new Foo<Bar>(...), Foo.<T>bar()
		for k := i + 1; k < len(toks) && k < i+40; k++ {
			if isP(toks, k, ">") && isP(toks, k+1, "(") {
				rootEnd = k
				break
			}
			if isP(toks, k, ";") || isP(toks, k, "=") || isP(toks, k, "{") {
				break
			}
		}
	}
	segs, end, used := parseChain(toks, rootEnd, j.match, true)
	for _, u := range used {
		j.skip[u] = true
	}
	name := toks[i].text
	var root *value
	// a fully qualified name: org.example.Foo.bar()
	if len(f.env[name]) == 0 && !capitalized(name) && name != "this" {
		for n, s := range segs {
			if s.call || s.computed {
				break
			}
			if capitalized(s.name) && n >= 1 {
				parts := []string{name}
				for _, x := range segs[:n] {
					parts = append(parts, x.name)
				}
				pkg := strings.Join(parts, ".")
				f.imported(pkg, toks[i].line)
				v := extVal(pkg, s.name)
				root, segs = &v, segs[n+1:]
				break
			}
		}
	}
	if isP(toks, end, "=") && len(segs) <= 1 && (len(segs) == 0 || !segs[0].call) && root == nil {
		target := name
		if len(segs) == 1 {
			if name != "this" {
				target = ""
			} else {
				target = segs[0].name
			}
		}
		if target != "" {
			j.assign[rhsStart(toks, end+1)] = target
			return
		}
	}
	if isP(toks, end, "->") {
		return // a lambda parameter
	}
	target, assigned := j.assign[i]
	escape := false
	if len(segs) == 0 && !assigned && i > 0 {
		escape = javaEscapeAfter[toks[i-1].text]
	}
	if len(segs) == 0 && !escape && !assigned && root == nil {
		return
	}
	c := &chain{rootName: name, root: root, segs: segs, line: toks[i].line, fn: fn, escape: escape, isNew: isI(toks, i-1, "new")}
	idx := f.addChain(c)
	if assigned {
		f.bind(target, value{k: vChain, file: f.key, idx: idx})
	}
}
