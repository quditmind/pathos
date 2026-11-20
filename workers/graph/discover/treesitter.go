package main

import (
	"path"
	"regexp"
	"strings"

	ts "github.com/tree-sitter/go-tree-sitter"
	csharp "github.com/tree-sitter/tree-sitter-c-sharp/bindings/go"
	java "github.com/tree-sitter/tree-sitter-java/bindings/go"
	javascript "github.com/tree-sitter/tree-sitter-javascript/bindings/go"
	php "github.com/tree-sitter/tree-sitter-php/bindings/go"
	python "github.com/tree-sitter/tree-sitter-python/bindings/go"
	ruby "github.com/tree-sitter/tree-sitter-ruby/bindings/go"
	typescript "github.com/tree-sitter/tree-sitter-typescript/bindings/go"
)

// Java, Python, JavaScript/TypeScript, C#, PHP and Ruby are parsed with
// tree-sitter. Each file yields classes, functions, imports, call sites
// and the declared types of variables and fields; calls are resolved
// afterwards within the repository (same class, same file, imported
// symbol or module, typed variable, same package). Calls that cannot be
// resolved that way are left out.

type tsSpec struct {
	lang    func() *ts.Language
	classes map[string]bool
	funcs   map[string]bool
}

func set(v ...string) map[string]bool {
	m := map[string]bool{}
	for _, s := range v {
		m[s] = true
	}
	return m
}

var tsSpecs = map[string]tsSpec{
	"java": {func() *ts.Language { return ts.NewLanguage(java.Language()) },
		set("class_declaration", "interface_declaration", "enum_declaration", "record_declaration"),
		set("method_declaration", "constructor_declaration")},
	"cs": {func() *ts.Language { return ts.NewLanguage(csharp.Language()) },
		set("class_declaration", "interface_declaration", "struct_declaration", "record_declaration"),
		set("method_declaration", "constructor_declaration", "local_function_statement")},
	"py": {func() *ts.Language { return ts.NewLanguage(python.Language()) },
		set("class_definition"), set("function_definition")},
	"js": {func() *ts.Language { return ts.NewLanguage(javascript.Language()) },
		set("class_declaration", "class"), set("function_declaration", "generator_function_declaration", "method_definition")},
	"ts": {func() *ts.Language { return ts.NewLanguage(typescript.LanguageTypescript()) },
		set("class_declaration", "abstract_class_declaration", "class"),
		set("function_declaration", "generator_function_declaration", "method_definition")},
	"tsx": {func() *ts.Language { return ts.NewLanguage(typescript.LanguageTSX()) },
		set("class_declaration", "abstract_class_declaration", "class"),
		set("function_declaration", "generator_function_declaration", "method_definition")},
	"php": {func() *ts.Language { return ts.NewLanguage(php.LanguagePHP()) },
		set("class_declaration", "interface_declaration", "trait_declaration", "enum_declaration"),
		set("function_definition", "method_declaration")},
	"rb": {func() *ts.Language { return ts.NewLanguage(ruby.Language()) },
		set("class", "module"), set("method", "singleton_method")},
}

// keyLang is the language part of node keys (tsx shares ts).
func keyLang(l string) string {
	if l == "tsx" {
		return "ts"
	}
	return l
}

type tsCall struct {
	caller, qual, name, class string
	line                      int
}

type tsImport struct {
	spec  string            // module path / package / file spec
	alias string            // local name bound to the whole module ("" if none)
	names map[string]string // local name -> imported name
	line  int
	text  string
}

type tsFile struct {
	f        *srcFile
	pkg      string            // package / namespace
	classes  map[string]string // simple name -> class key (this file)
	methods  map[string]map[string]string
	topFuncs map[string]string // top-level function name -> key
	calls    []tsCall
	imports  []tsImport
	varTypes map[string]string // variable or field -> type name
	// resolved after all files are parsed
	aliasFile map[string]string // alias -> file
	nameFile  map[string]string // imported name -> file
	classRef  map[string]string // imported class simple name -> class key
	imported  []string          // files this file imports
}

var genericRe = regexp.MustCompile(`<.*>|\[\]|\?$`)

func cleanType(t string) string {
	t = strings.TrimSpace(genericRe.ReplaceAllString(t, ""))
	t = strings.TrimPrefix(t, "?")
	if i := strings.LastIndexAny(t, `.\`); i >= 0 {
		t = t[i+1:]
	}
	return t
}

func text(n *ts.Node, src []byte) string {
	if n == nil {
		return ""
	}
	return n.Utf8Text(src)
}

func field(n *ts.Node, name string) *ts.Node {
	if n == nil {
		return nil
	}
	return n.ChildByFieldName(name)
}

func line(n *ts.Node) int { return int(n.StartPosition().Row) + 1 }

func endLine(n *ts.Node) int { return int(n.EndPosition().Row) + 1 }

func unquote(s string) string {
	s = strings.TrimSpace(s)
	for _, q := range []string{`"`, `'`, "`"} {
		if len(s) >= 2 && strings.HasPrefix(s, q) && strings.HasSuffix(s, q) {
			return s[1 : len(s)-1]
		}
	}
	return s
}

// normQual normalises a call receiver: "$this->svc" -> "this.svc".
func normQual(q string) string {
	q = strings.ReplaceAll(q, "->", ".")
	q = strings.ReplaceAll(q, "::", ".")
	q = strings.ReplaceAll(q, "$", "")
	q = strings.ReplaceAll(q, "?.", ".")
	if strings.ContainsAny(q, "()[] \n\t\"'") {
		return "?"
	}
	return q
}

func (p *project) extractTreeSitter() []*tsFile {
	parsers := map[string]*ts.Parser{}
	defer func() {
		for _, ps := range parsers {
			ps.Close()
		}
	}()
	var out []*tsFile
	for _, f := range p.files {
		spec, ok := tsSpecs[f.lang]
		if !ok {
			continue
		}
		ps := parsers[f.lang]
		if ps == nil {
			ps = ts.NewParser()
			if err := ps.SetLanguage(spec.lang()); err != nil {
				p.skip(f.rel, "tree-sitter grammar: "+err.Error())
				continue
			}
			parsers[f.lang] = ps
		}
		tree := ps.Parse(f.data, nil)
		if tree == nil {
			p.skip(f.rel, "tree-sitter parse failed")
			continue
		}
		f.key = p.fileNode(f.rel, f.lang)
		f.module = p.g.Node(f.key).Parent
		tf := &tsFile{f: f, classes: map[string]string{}, methods: map[string]map[string]string{}, topFuncs: map[string]string{},
			varTypes: map[string]string{}, aliasFile: map[string]string{}, nameFile: map[string]string{}, classRef: map[string]string{}}
		w := &tsWalker{p: p, tf: tf, spec: spec, src: f.data, lang: f.lang}
		w.visit(tree.RootNode(), nil, "")
		tree.Close()
		out = append(out, tf)
	}
	return out
}

type tsWalker struct {
	p    *project
	tf   *tsFile
	spec tsSpec
	src  []byte
	lang string
}

type scope struct {
	name, key string
	class     bool
}

func qualName(stack []scope, name string) string {
	parts := make([]string, 0, len(stack)+1)
	for _, s := range stack {
		parts = append(parts, s.name)
	}
	return strings.Join(append(parts, name), ".")
}

func currentClass(stack []scope) (string, string) {
	for i := len(stack) - 1; i >= 0; i-- {
		if stack[i].class {
			return stack[i].name, stack[i].key
		}
	}
	return "", ""
}

func (w *tsWalker) defineClass(n *ts.Node, name string, stack []scope) (string, bool) {
	f := w.tf.f
	qn := qualName(stack, name)
	key := "class:" + keyLang(w.lang) + ":" + f.rel + "#" + qn
	parent := f.key
	if _, ck := currentClass(stack); ck != "" {
		parent = ck
	}
	attrs := map[string]any{"language": langDisplay(w.lang), "file": f.rel, "line": line(n), "end_line": endLine(n), "qualified_name": qn}
	if w.tf.pkg != "" {
		attrs["qualified_name"] = w.tf.pkg + "." + qn
	}
	if !w.p.g.AddNode(key, "class", name, parent, attrs) {
		return "", false
	}
	if len(stack) == 0 || stack[len(stack)-1].class {
		w.tf.classes[name] = key
	}
	f.syms = append(f.syms, &symbol{key: key, name: name, kind: "class", start: line(n), end: endLine(n)})
	w.p.g.AddEdge(parent, "defines", key, fileLine(f.rel, line(n), "class "+name))
	return key, true
}

func (w *tsWalker) defineFunc(n *ts.Node, name string, stack []scope) (string, bool) {
	f := w.tf.f
	qn := qualName(stack, name)
	key := "fn:" + keyLang(w.lang) + ":" + f.rel + "#" + qn
	parent := f.key
	cls, ck := "", ""
	if len(stack) > 0 && stack[len(stack)-1].class {
		cls, ck = stack[len(stack)-1].name, stack[len(stack)-1].key
		parent = ck
	} else if len(stack) > 0 {
		parent = stack[len(stack)-1].key
	}
	if !w.p.g.AddNode(key, "function", name, parent, map[string]any{"language": langDisplay(w.lang), "file": f.rel, "line": line(n),
		"end_line": endLine(n), "qualified_name": qn, "class": cls}) {
		return "", false
	}
	f.syms = append(f.syms, &symbol{key: key, name: name, class: cls, kind: "function", start: line(n), end: endLine(n)})
	if ck != "" {
		if w.tf.methods[ck] == nil {
			w.tf.methods[ck] = map[string]string{}
		}
		if _, dup := w.tf.methods[ck][name]; !dup {
			w.tf.methods[ck][name] = key
		}
	} else if len(stack) == 0 {
		if _, dup := w.tf.topFuncs[name]; !dup {
			w.tf.topFuncs[name] = key
		}
	}
	w.p.g.AddEdge(parent, "defines", key, fileLine(f.rel, line(n), name))
	return key, true
}

var fnValues = set("arrow_function", "function_expression", "function", "generator_function")

func (w *tsWalker) visit(n *ts.Node, stack []scope, curFn string) {
	if n == nil {
		return
	}
	k := n.Kind()
	src := w.src
	switch {
	case w.spec.classes[k]:
		nameNode := field(n, "name")
		name := text(nameNode, src)
		if w.lang == "rb" {
			name = cleanType(strings.ReplaceAll(name, "::", "."))
		}
		if name != "" {
			if key, ok := w.defineClass(n, name, stack); ok {
				stack = append(stack, scope{name: name, key: key, class: true})
			}
		}
	case w.spec.funcs[k]:
		name := text(field(n, "name"), src)
		if name != "" {
			if key, ok := w.defineFunc(n, name, stack); ok {
				stack = append(stack, scope{name: name, key: key})
				curFn = key
			}
		}
	case k == "variable_declarator" && (w.lang == "js" || w.lang == "ts" || w.lang == "tsx"):
		val := field(n, "value")
		nameNode := field(n, "name")
		if val != nil && fnValues[val.Kind()] && nameNode != nil && nameNode.Kind() == "identifier" {
			if key, ok := w.defineFunc(n, text(nameNode, src), stack); ok {
				for i := uint(0); i < n.NamedChildCount(); i++ {
					w.visit(n.NamedChild(i), append(stack, scope{name: text(nameNode, src), key: key}), key)
				}
				return
			}
		}
		if val != nil && nameNode != nil {
			w.noteVar(text(nameNode, src), val)
		}
	case k == "package_declaration" && w.lang == "java":
		for i := uint(0); i < n.NamedChildCount(); i++ {
			c := n.NamedChild(i)
			if c.Kind() == "scoped_identifier" || c.Kind() == "identifier" {
				w.tf.pkg = text(c, src)
			}
		}
	case (k == "namespace_declaration" || k == "file_scoped_namespace_declaration") && w.lang == "cs":
		w.tf.pkg = text(field(n, "name"), src)
	case k == "namespace_definition" && w.lang == "php":
		w.tf.pkg = text(field(n, "name"), src)
	}
	w.collect(n, stack, curFn)
	for i := uint(0); i < n.NamedChildCount(); i++ {
		w.visit(n.NamedChild(i), stack, curFn)
	}
}

// noteVar records "x = new T()" style declarations.
func (w *tsWalker) noteVar(name string, val *ts.Node) {
	src := w.src
	switch val.Kind() {
	case "new_expression":
		w.tf.varTypes[name] = cleanType(text(field(val, "constructor"), src))
	case "object_creation_expression":
		t := field(val, "type")
		if t == nil && val.NamedChildCount() > 0 {
			t = val.NamedChild(0)
		}
		w.tf.varTypes[name] = cleanType(text(t, src))
	case "call":
		if w.lang == "py" {
			fn := field(val, "function")
			if fn != nil && fn.Kind() == "identifier" && isCapital(text(fn, src)) {
				w.tf.varTypes[name] = text(fn, src)
			}
		}
		if w.lang == "rb" && text(field(val, "method"), src) == "new" {
			if r := field(val, "receiver"); r != nil && r.Kind() == "constant" {
				w.tf.varTypes[name] = text(r, src)
			}
		}
	}
}

func isCapital(s string) bool { return s != "" && s[0] >= 'A' && s[0] <= 'Z' }

// collect records calls, imports and declared types at node n.
func (w *tsWalker) collect(n *ts.Node, stack []scope, curFn string) {
	src, tf := w.src, w.tf
	k := n.Kind()
	cls, _ := currentClass(stack)
	addCall := func(qual, name string) {
		if name == "" {
			return
		}
		caller := curFn
		if caller == "" {
			caller = tf.f.key
		}
		tf.calls = append(tf.calls, tsCall{caller: caller, qual: normQual(qual), name: name, class: cls, line: line(n)})
	}
	setType := func(name, typ string) {
		name, typ = strings.TrimPrefix(strings.TrimSpace(name), "$"), cleanType(typ)
		if name != "" && isCapital(typ) {
			if prev, ok := tf.varTypes[name]; ok && prev != typ {
				tf.varTypes[name] = "" // conflicting declarations: unknown
				return
			}
			tf.varTypes[name] = typ
		}
	}
	switch w.lang {
	case "java":
		switch k {
		case "method_invocation":
			addCall(text(field(n, "object"), src), text(field(n, "name"), src))
		case "import_declaration":
			t := strings.TrimSuffix(strings.TrimSpace(strings.TrimPrefix(text(n, src), "import")), ";")
			t = strings.TrimSpace(strings.TrimPrefix(t, "static"))
			tf.imports = append(tf.imports, tsImport{spec: strings.TrimSpace(t), line: line(n), text: text(n, src)})
		case "field_declaration", "local_variable_declaration":
			typ := text(field(n, "type"), src)
			for i := uint(0); i < n.NamedChildCount(); i++ {
				if c := n.NamedChild(i); c.Kind() == "variable_declarator" {
					setType(text(field(c, "name"), src), typ)
				}
			}
		case "formal_parameter":
			setType(text(field(n, "name"), src), text(field(n, "type"), src))
		}
	case "cs":
		switch k {
		case "invocation_expression":
			fn := field(n, "function")
			switch {
			case fn == nil:
			case fn.Kind() == "identifier":
				addCall("", text(fn, src))
			case fn.Kind() == "generic_name":
				if fn.NamedChildCount() > 0 {
					addCall("", text(fn.NamedChild(0), src))
				}
			case fn.Kind() == "member_access_expression":
				name := field(fn, "name")
				nm := text(name, src)
				if name != nil && name.Kind() == "generic_name" && name.NamedChildCount() > 0 {
					nm = text(name.NamedChild(0), src)
				}
				addCall(text(field(fn, "expression"), src), nm)
			}
		case "using_directive":
			for i := uint(0); i < n.NamedChildCount(); i++ {
				c := n.NamedChild(i)
				if c.Kind() == "qualified_name" || c.Kind() == "identifier" {
					tf.imports = append(tf.imports, tsImport{spec: text(c, src), line: line(n), text: text(n, src)})
					break
				}
			}
		case "variable_declaration":
			typ := text(field(n, "type"), src)
			for i := uint(0); i < n.NamedChildCount(); i++ {
				c := n.NamedChild(i)
				if c.Kind() != "variable_declarator" {
					continue
				}
				nm := text(field(c, "name"), src)
				if typ == "var" {
					for j := uint(0); j < c.NamedChildCount(); j++ {
						if v := c.NamedChild(j); v.Kind() == "object_creation_expression" {
							w.noteVar(nm, v)
						}
					}
				} else {
					setType(nm, typ)
				}
			}
		case "parameter":
			setType(text(field(n, "name"), src), text(field(n, "type"), src))
		case "property_declaration":
			setType(text(field(n, "name"), src), text(field(n, "type"), src))
		}
	case "py":
		switch k {
		case "call":
			fn := field(n, "function")
			if fn != nil && fn.Kind() == "identifier" {
				addCall("", text(fn, src))
			} else if fn != nil && fn.Kind() == "attribute" {
				addCall(text(field(fn, "object"), src), text(field(fn, "attribute"), src))
			}
		case "import_statement":
			for i := uint(0); i < n.NamedChildCount(); i++ {
				c := n.NamedChild(i)
				switch c.Kind() {
				case "dotted_name":
					tf.imports = append(tf.imports, tsImport{spec: text(c, src), alias: text(c, src), line: line(n), text: text(n, src)})
				case "aliased_import":
					tf.imports = append(tf.imports, tsImport{spec: text(field(c, "name"), src), alias: text(field(c, "alias"), src), line: line(n), text: text(n, src)})
				}
			}
		case "import_from_statement":
			imp := tsImport{spec: text(field(n, "module_name"), src), names: map[string]string{}, line: line(n), text: text(n, src)}
			for i := uint(0); i < n.NamedChildCount(); i++ {
				c := n.NamedChild(i)
				if n.FieldNameForNamedChild(uint32(i)) != "name" {
					continue
				}
				switch c.Kind() {
				case "dotted_name":
					imp.names[text(c, src)] = text(c, src)
				case "aliased_import":
					imp.names[text(field(c, "alias"), src)] = text(field(c, "name"), src)
				}
			}
			tf.imports = append(tf.imports, imp)
		case "assignment":
			l, r := field(n, "left"), field(n, "right")
			if l != nil && r != nil {
				w.noteVar(strings.TrimPrefix(text(l, src), "self."), r)
			}
		case "typed_parameter":
			if n.NamedChildCount() > 0 {
				setType(text(n.NamedChild(0), src), text(field(n, "type"), src))
			}
		}
	case "js", "ts", "tsx":
		switch k {
		case "call_expression":
			fn := field(n, "function")
			if fn == nil {
				break
			}
			switch fn.Kind() {
			case "identifier":
				name := text(fn, src)
				if name == "require" {
					args := field(n, "arguments")
					if args != nil && args.NamedChildCount() == 1 && args.NamedChild(0).Kind() == "string" {
						imp := tsImport{spec: unquote(text(args.NamedChild(0), src)), names: map[string]string{}, line: line(n), text: text(n, src)}
						if par := n.Parent(); par != nil && par.Kind() == "variable_declarator" {
							if nm := field(par, "name"); nm != nil && nm.Kind() == "identifier" {
								imp.alias = text(nm, src)
							} else if nm != nil && nm.Kind() == "object_pattern" {
								// const { a, b: c } = require("./m")
								for i := uint(0); i < nm.NamedChildCount(); i++ {
									c := nm.NamedChild(i)
									switch c.Kind() {
									case "shorthand_property_identifier_pattern":
										imp.names[text(c, src)] = text(c, src)
									case "pair_pattern":
										imp.names[text(field(c, "value"), src)] = text(field(c, "key"), src)
									}
								}
							}
						}
						tf.imports = append(tf.imports, imp)
					}
					break
				}
				addCall("", name)
			case "member_expression":
				addCall(text(field(fn, "object"), src), text(field(fn, "property"), src))
			}
		case "import_statement":
			imp := tsImport{spec: unquote(text(field(n, "source"), src)), names: map[string]string{}, line: line(n), text: text(n, src)}
			for i := uint(0); i < n.NamedChildCount(); i++ {
				c := n.NamedChild(i)
				if c.Kind() != "import_clause" {
					continue
				}
				for j := uint(0); j < c.NamedChildCount(); j++ {
					d := c.NamedChild(j)
					switch d.Kind() {
					case "identifier": // default import
						imp.names[text(d, src)] = "default"
					case "namespace_import":
						if d.NamedChildCount() > 0 {
							imp.alias = text(d.NamedChild(0), src)
						}
					case "named_imports":
						for m := uint(0); m < d.NamedChildCount(); m++ {
							s := d.NamedChild(m)
							if s.Kind() != "import_specifier" {
								continue
							}
							nm := text(field(s, "name"), src)
							local := nm
							if a := field(s, "alias"); a != nil {
								local = text(a, src)
							}
							imp.names[local] = nm
						}
					}
				}
			}
			tf.imports = append(tf.imports, imp)
		case "required_parameter", "optional_parameter":
			if t := field(n, "type"); t != nil {
				setType(text(field(n, "pattern"), src), strings.TrimPrefix(strings.TrimSpace(text(t, src)), ":"))
			}
		case "public_field_definition":
			if t := field(n, "type"); t != nil {
				setType(text(field(n, "name"), src), strings.TrimPrefix(strings.TrimSpace(text(t, src)), ":"))
			}
		}
	case "php":
		switch k {
		case "function_call_expression":
			nm := text(field(n, "function"), src)
			if i := strings.LastIndex(nm, `\`); i >= 0 {
				nm = nm[i+1:]
			}
			addCall("", nm)
		case "member_call_expression", "nullsafe_member_call_expression":
			addCall(text(field(n, "object"), src), text(field(n, "name"), src))
		case "scoped_call_expression":
			addCall(text(field(n, "scope"), src), text(field(n, "name"), src))
		case "namespace_use_clause":
			var qn, alias string
			for i := uint(0); i < n.NamedChildCount(); i++ {
				c := n.NamedChild(i)
				if c.Kind() == "qualified_name" || c.Kind() == "name" && qn == "" {
					qn = text(c, src)
				}
			}
			if a := field(n, "alias"); a != nil {
				alias = text(a, src)
			}
			tf.imports = append(tf.imports, tsImport{spec: strings.TrimPrefix(qn, `\`), alias: alias, line: line(n), text: text(n, src)})
		case "simple_parameter", "property_promotion_parameter":
			setType(text(field(n, "name"), src), text(field(n, "type"), src))
		case "property_declaration":
			typ := text(field(n, "type"), src)
			for i := uint(0); i < n.NamedChildCount(); i++ {
				if c := n.NamedChild(i); c.Kind() == "property_element" && c.NamedChildCount() > 0 {
					setType(text(c.NamedChild(0), src), typ)
				}
			}
		case "assignment_expression":
			l, r := field(n, "left"), field(n, "right")
			if l != nil && r != nil {
				w.noteVar(strings.TrimPrefix(strings.ReplaceAll(text(l, src), "->", "."), "$this."), r)
				w.noteVar(strings.TrimPrefix(text(l, src), "$"), r)
			}
		}
	case "rb":
		switch k {
		case "call":
			method := text(field(n, "method"), src)
			if method == "require" || method == "require_relative" {
				args := field(n, "arguments")
				if args != nil && args.NamedChildCount() == 1 && args.NamedChild(0).Kind() == "string" {
					spec := unquote(text(args.NamedChild(0), src))
					if method == "require_relative" {
						spec = "./" + spec
					}
					tf.imports = append(tf.imports, tsImport{spec: spec, line: line(n), text: text(n, src)})
				}
				break
			}
			if method == "new" {
				break
			}
			addCall(text(field(n, "receiver"), src), method)
		case "assignment":
			l, r := field(n, "left"), field(n, "right")
			if l != nil && r != nil {
				w.noteVar(strings.TrimPrefix(text(l, src), "@"), r)
			}
		}
	}
}

// ---------------------------------------------------------------- resolve

type tsIndex struct {
	files     map[string]*tsFile             // rel -> file
	pyModules map[string][]string            // dotted suffix -> files
	fqn       map[string]string              // package.Class -> class key (java, php, cs)
	classes   map[string]map[string][]string // lang -> simple name -> class keys
	classFile map[string]*tsFile
	pkgFiles  map[string]map[string][]*tsFile // lang -> package/namespace -> files
	byModule  map[string][]*tsFile            // module key -> files
}

func (p *project) resolveTreeSitter(files []*tsFile) {
	ix := &tsIndex{files: map[string]*tsFile{}, pyModules: map[string][]string{}, fqn: map[string]string{},
		classes: map[string]map[string][]string{}, classFile: map[string]*tsFile{}, pkgFiles: map[string]map[string][]*tsFile{},
		byModule: map[string][]*tsFile{}}
	p.ts = ix
	for _, tf := range files {
		rel, lang := tf.f.rel, keyLang(tf.f.lang)
		ix.files[rel] = tf
		ix.byModule[tf.f.module] = append(ix.byModule[tf.f.module], tf)
		if lang == "py" {
			mod := strings.TrimSuffix(rel, ".py")
			mod = strings.TrimSuffix(mod, "/__init__")
			parts := strings.Split(mod, "/")
			for i := range parts {
				d := strings.Join(parts[i:], ".")
				ix.pyModules[d] = append(ix.pyModules[d], rel)
			}
		}
		if ix.classes[lang] == nil {
			ix.classes[lang] = map[string][]string{}
			ix.pkgFiles[lang] = map[string][]*tsFile{}
		}
		ix.pkgFiles[lang][tf.pkg] = append(ix.pkgFiles[lang][tf.pkg], tf)
		for name, key := range tf.classes {
			ix.classes[lang][name] = append(ix.classes[lang][name], key)
			ix.classFile[key] = tf
			if tf.pkg != "" {
				sep := "."
				if lang == "php" {
					sep = `\`
				}
				ix.fqn[tf.pkg+sep+name] = key
			}
		}
	}
	for _, tf := range files {
		p.resolveImports(ix, tf)
	}
	for _, tf := range files {
		for _, c := range tf.calls {
			if target := p.resolveCall(ix, tf, c); target != "" && target != c.caller {
				p.g.AddEdge(c.caller, "calls", target, fileLine(tf.f.rel, c.line, callText(c)))
			}
		}
	}
}

func callText(c tsCall) string {
	if c.qual == "" {
		return c.name + "()"
	}
	return c.qual + "." + c.name + "()"
}

var jsBuiltins = set("fs", "path", "http", "https", "crypto", "os", "url", "util", "events", "stream", "child_process", "net",
	"zlib", "buffer", "assert", "querystring", "tls", "dns", "readline", "cluster", "worker_threads", "perf_hooks", "timers",
	"module", "process", "vm", "v8", "http2", "string_decoder", "async_hooks", "inspector", "dgram", "punycode", "constants")

func (p *project) resolveImports(ix *tsIndex, tf *tsFile) {
	f := tf.f
	addFile := func(target string, ev Ref) {
		if p.g.AddEdge(f.key, "imports", "file:"+target, ev) {
			tf.imported = append(tf.imported, target)
		}
	}
	dir := path.Dir(f.rel)
	lang := keyLang(f.lang)
	for _, imp := range tf.imports {
		ev := fileLine(f.rel, imp.line, imp.text)
		f.imports = append(f.imports, imp.spec)
		switch lang {
		case "py":
			target := ""
			spec := imp.spec
			if strings.HasPrefix(spec, ".") {
				ups := len(spec) - len(strings.TrimLeft(spec, "."))
				base := dir
				for i := 1; i < ups; i++ {
					base = path.Dir(base)
				}
				rest := strings.ReplaceAll(strings.TrimLeft(spec, "."), ".", "/")
				for _, cand := range []string{path.Join(base, rest) + ".py", path.Join(base, rest, "__init__.py")} {
					if _, ok := ix.files[cand]; ok && rest != "" {
						target = cand
						break
					}
				}
				if rest == "" {
					// from . import x: x is a module of the package
					for local, orig := range imp.names {
						if _, ok := ix.files[path.Join(base, orig+".py")]; ok {
							tf.aliasFile[local] = path.Join(base, orig+".py")
							addFile(path.Join(base, orig+".py"), ev)
						}
					}
					continue
				}
			} else if c := ix.pyModules[spec]; len(c) == 1 {
				target = c[0]
			}
			if target == "" {
				if !strings.HasPrefix(spec, ".") {
					top := strings.SplitN(spec, ".", 2)[0]
					if ck := "comp:pkg:pypi/" + strings.ReplaceAll(strings.ToLower(top), "_", "-"); p.g.Has(ck) {
						p.g.AddEdge(f.key, "imports", ck, ev)
					}
				}
				continue
			}
			addFile(target, ev)
			if imp.alias != "" {
				tf.aliasFile[imp.alias] = target
			}
			for local, orig := range imp.names {
				// "from pkg import mod" (a module) or "from mod import name".
				if c := ix.pyModules[spec+"."+orig]; len(c) == 1 {
					tf.aliasFile[local] = c[0]
				} else {
					tf.nameFile[local] = target
					tf.names(orig, local)
				}
			}
		case "js", "ts":
			spec := imp.spec
			if !strings.HasPrefix(spec, ".") {
				if spec == "" || strings.HasPrefix(spec, "node:") || jsBuiltins[strings.SplitN(spec, "/", 2)[0]] || strings.HasPrefix(spec, "@/") || strings.HasPrefix(spec, "~") {
					continue
				}
				if ck := p.componentForImport("npm", spec); ck != "" {
					p.g.AddEdge(f.key, "imports", ck, ev)
				}
				continue
			}
			base := path.Join(dir, spec)
			target := ""
			for _, suf := range []string{"", ".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs", "/index.ts", "/index.tsx", "/index.js", "/index.jsx"} {
				if _, ok := ix.files[base+suf]; ok {
					target = base + suf
					break
				}
			}
			if target == "" && (strings.HasSuffix(base, ".js") || strings.HasSuffix(base, ".jsx")) {
				// TypeScript sources imported with their compiled extension.
				for _, suf := range []string{".ts", ".tsx"} {
					if _, ok := ix.files[strings.TrimSuffix(strings.TrimSuffix(base, ".js"), ".jsx")+suf]; ok {
						target = strings.TrimSuffix(strings.TrimSuffix(base, ".js"), ".jsx") + suf
					}
				}
			}
			if target == "" {
				continue
			}
			addFile(target, ev)
			if imp.alias != "" {
				tf.aliasFile[imp.alias] = target
			}
			for local, orig := range imp.names {
				tf.nameFile[local] = target
				tf.names(orig, local)
			}
		case "java", "php":
			spec := imp.spec
			sep := "."
			if lang == "php" {
				sep = `\`
			}
			if strings.HasSuffix(spec, sep+"*") {
				pkg := strings.TrimSuffix(spec, sep+"*")
				for _, other := range ix.pkgFiles[lang][pkg] {
					p.g.AddEdge(f.key, "imports", other.f.module, ev)
					for n, k := range other.classes {
						tf.classRef[n] = k
					}
					break
				}
				continue
			}
			key := ix.fqn[spec]
			if key == "" && lang == "java" {
				// static import of a member: package.Class.member
				key = ix.fqn[spec[:max(strings.LastIndex(spec, "."), 0)]]
			}
			if key == "" {
				continue
			}
			other := ix.classFile[key]
			addFile(other.f.rel, ev)
			simple := spec[strings.LastIndex(spec, sep)+1:]
			if imp.alias != "" {
				simple = imp.alias
			}
			tf.classRef[simple] = key
		case "cs":
			files := ix.pkgFiles[lang][imp.spec]
			seen := map[string]bool{}
			for _, other := range files {
				if !seen[other.f.module] && len(seen) < 5 {
					seen[other.f.module] = true
					p.g.AddEdge(f.key, "imports", other.f.module, ev)
				}
				for n, k := range other.classes {
					if _, dup := tf.classRef[n]; !dup {
						tf.classRef[n] = k
					}
				}
			}
		case "rb":
			spec := imp.spec
			var cands []string
			if strings.HasPrefix(spec, "./") {
				cands = []string{path.Join(dir, spec) + ".rb", path.Join(dir, spec)}
			} else {
				cands = []string{"lib/" + spec + ".rb", spec + ".rb", "app/" + spec + ".rb"}
			}
			target := ""
			for _, c := range cands {
				if _, ok := ix.files[c]; ok {
					target = c
					break
				}
			}
			if target != "" {
				addFile(target, ev)
				tf.aliasFile[path.Base(strings.TrimSuffix(target, ".rb"))] = target
				continue
			}
			if !strings.HasPrefix(spec, "./") {
				if ck := "comp:pkg:gem/" + strings.SplitN(spec, "/", 2)[0]; p.g.Has(ck) {
					p.g.AddEdge(f.key, "imports", ck, ev)
				}
			}
		}
	}
}

// names records that local refers to orig in the imported file (aliased
// named imports keep the original name for lookups).
func (tf *tsFile) names(orig, local string) {
	if orig != local && orig != "default" {
		tf.nameFile["\x00"+local] = orig
	}
}

func (tf *tsFile) origName(local string) string {
	if o, ok := tf.nameFile["\x00"+local]; ok {
		return o
	}
	return local
}

// classByName finds a class visible from tf: defined in the file,
// imported, in the same package, or unique in the language.
func (ix *tsIndex) classByName(tf *tsFile, name string) string {
	if name == "" {
		return ""
	}
	if k, ok := tf.classes[name]; ok {
		return k
	}
	if k, ok := tf.classRef[name]; ok {
		return k
	}
	lang := keyLang(tf.f.lang)
	if file, ok := tf.nameFile[name]; ok {
		if other := ix.files[file]; other != nil {
			if k, ok := other.classes[tf.origName(name)]; ok {
				return k
			}
		}
	}
	for _, rel := range tf.imported {
		if other := ix.files[rel]; other != nil {
			if k, ok := other.classes[name]; ok {
				return k
			}
		}
	}
	if tf.pkg != "" {
		for _, other := range ix.pkgFiles[lang][tf.pkg] {
			if k, ok := other.classes[name]; ok {
				return k
			}
		}
	}
	if c := ix.classes[lang][name]; len(c) == 1 && (lang == "java" || lang == "cs" || lang == "php" || lang == "ts") {
		return c[0]
	}
	return ""
}

func (ix *tsIndex) method(classKey, name string) string {
	if tf := ix.classFile[classKey]; tf != nil {
		return tf.methods[classKey][name]
	}
	return ""
}

var selfQuals = set("this", "self", "cls", "static", "base", "super", "parent")

func (p *project) resolveCall(ix *tsIndex, tf *tsFile, c tsCall) string {
	ownClass := ""
	if c.class != "" {
		ownClass = tf.classes[c.class]
		if ownClass == "" {
			for _, s := range tf.f.syms {
				if s.kind == "class" && s.name == c.class {
					ownClass = s.key
				}
			}
		}
	}
	switch {
	case c.qual == "":
		if ownClass != "" {
			if k := ix.method(ownClass, c.name); k != "" {
				return k
			}
		}
		if k, ok := tf.topFuncs[c.name]; ok {
			return k
		}
		if file, ok := tf.nameFile[c.name]; ok {
			if other := ix.files[file]; other != nil {
				return other.topFuncs[tf.origName(c.name)]
			}
		}
		// Same directory (Python, JS, Ruby, PHP global functions): only
		// when exactly one file of the module defines it.
		found := ""
		for _, other := range ix.byModule[tf.f.module] {
			if other == tf || other.f.module != tf.f.module || keyLang(other.f.lang) != keyLang(tf.f.lang) {
				continue
			}
			if k, ok := other.topFuncs[c.name]; ok {
				if found != "" {
					return ""
				}
				found = k
			}
		}
		return found
	case c.qual == "?":
		return ""
	case selfQuals[c.qual]:
		if ownClass != "" && c.qual != "super" && c.qual != "base" && c.qual != "parent" {
			return ix.method(ownClass, c.name)
		}
		return ""
	}
	q := c.qual
	for _, pre := range []string{"this.", "self.", "@"} {
		q = strings.TrimPrefix(q, pre)
	}
	if t, ok := tf.varTypes[q]; ok && t != "" {
		if ck := ix.classByName(tf, t); ck != "" {
			return ix.method(ck, c.name)
		}
		return ""
	}
	if file, ok := tf.aliasFile[q]; ok {
		if other := ix.files[file]; other != nil {
			if k := other.topFuncs[c.name]; k != "" {
				return k
			}
		}
		return ""
	}
	if isCapital(q) && !strings.Contains(q, ".") {
		if ck := ix.classByName(tf, q); ck != "" {
			return ix.method(ck, c.name)
		}
	}
	return ""
}
