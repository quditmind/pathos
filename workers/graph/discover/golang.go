package main

import (
	"go/ast"
	"go/parser"
	"go/token"
	"path"
	"sort"
	"strconv"
	"strings"
)

// Go extraction uses the language's own parser (go/parser, go/ast). No
// package loading or type checking: imports are matched to the
// repository's go.mod modules, and calls are resolved syntactically
// (same-package functions, functions of imported repository packages,
// methods on the receiver's own type). Anything else is left out.

type goMod struct{ dir, path string }

type goPkg struct {
	dir   string
	key   string                       // module node key
	funcs map[string]string            // top-level function name -> node key
	meths map[string]map[string]string // type -> method -> node key
	types map[string]string            // type name -> class node key
	// fields and results are resolved after every package is known.
	fieldExprs  map[string]map[string]goExpr // type -> field -> type expression
	resultExprs map[string]goExpr            // function -> first result type
	fields      map[string]map[string]typeRef
	results     map[string]typeRef
}

// goExpr is a type expression with the file it appears in (for import
// aliases).
type goExpr struct {
	e  ast.Expr
	st *goFileState
}

// typeRef is a named type of a repository package.
type typeRef struct {
	pkg  *goPkg
	name string
}

func (t typeRef) ok() bool { return t.pkg != nil && t.name != "" }

func (t typeRef) method(name string) string {
	if !t.ok() {
		return ""
	}
	return t.pkg.meths[t.name][name]
}

type goFileState struct {
	f       *srcFile
	ast     *ast.File
	pkg     *goPkg
	imports map[string]string // local name -> import path
}

func goModules(p *project) []goMod {
	var mods []goMod
	for _, rel := range p.paths {
		if path.Base(rel) != "go.mod" {
			continue
		}
		data, err := p.read(rel)
		if err != nil {
			continue
		}
		for _, line := range strings.Split(string(data), "\n") {
			fs := strings.Fields(line)
			if len(fs) >= 2 && fs[0] == "module" {
				mp, err := strconv.Unquote(fs[1])
				if err != nil {
					mp = fs[1]
				}
				mods = append(mods, goMod{dir: path.Dir(rel), path: mp})
				break
			}
		}
	}
	// Longest module path first: nested modules win.
	sort.Slice(mods, func(i, j int) bool { return len(mods[i].path) > len(mods[j].path) })
	return mods
}

// internalDir maps an import path to a repository directory ("" if external).
func internalDir(mods []goMod, imp string) string {
	for _, m := range mods {
		if imp == m.path || strings.HasPrefix(imp, m.path+"/") {
			rest := strings.TrimPrefix(strings.TrimPrefix(imp, m.path), "/")
			return path.Clean(path.Join(m.dir, rest))
		}
	}
	return ""
}

func recvType(fd *ast.FuncDecl) (name string, ptr bool) {
	if fd.Recv == nil || len(fd.Recv.List) == 0 {
		return "", false
	}
	t := fd.Recv.List[0].Type
	if st, ok := t.(*ast.StarExpr); ok {
		t, ptr = st.X, true
	}
	switch x := t.(type) {
	case *ast.Ident:
		return x.Name, ptr
	case *ast.IndexExpr:
		if id, ok := x.X.(*ast.Ident); ok {
			return id.Name, ptr
		}
	case *ast.IndexListExpr:
		if id, ok := x.X.(*ast.Ident); ok {
			return id.Name, ptr
		}
	}
	return "", ptr
}

func (p *project) extractGo() {
	mods := goModules(p)
	fset := token.NewFileSet()
	pkgs := map[string]*goPkg{}
	var states []*goFileState
	for _, f := range p.files {
		if f.lang != "go" {
			continue
		}
		af, err := parser.ParseFile(fset, f.rel, f.data, parser.SkipObjectResolution)
		if err != nil || af == nil {
			msg := "Go parse error"
			if err != nil {
				msg += ": " + clip(oneLine(err.Error()), 160)
			}
			p.skip(f.rel, msg)
			continue
		}
		dir := path.Dir(f.rel)
		pkgID := dir
		if strings.HasSuffix(af.Name.Name, "_test") {
			pkgID = dir + "#" + af.Name.Name // external test package
		}
		pkg := pkgs[pkgID]
		if pkg == nil {
			pkg = &goPkg{dir: dir, key: p.moduleOf(f.rel, "go"), funcs: map[string]string{}, meths: map[string]map[string]string{}, types: map[string]string{},
				fieldExprs: map[string]map[string]goExpr{}, resultExprs: map[string]goExpr{}, fields: map[string]map[string]typeRef{}, results: map[string]typeRef{}}
			if ip := importPathOf(mods, dir); ip != "" {
				if n := p.g.Node(pkg.key); n != nil {
					n.Attrs["qualified_name"] = ip
				}
			}
			pkgs[pkgID] = pkg
		}
		f.module = pkg.key
		f.key = p.fileNode(f.rel, "go")
		st := &goFileState{f: f, ast: af, pkg: pkg, imports: map[string]string{}}
		for _, is := range af.Imports {
			ip, err := strconv.Unquote(is.Path.Value)
			if err != nil {
				continue
			}
			f.imports = append(f.imports, ip)
			local := path.Base(ip)
			if is.Name != nil {
				local = is.Name.Name
			} else if strings.HasPrefix(local, "v") && len(local) <= 3 && strings.Contains(ip, "/") {
				// .../pkg/v2: the package name is the element before.
				local = path.Base(path.Dir(ip))
			}
			st.imports[local] = ip
		}
		ns := pkgID
		// Types (classes).
		for _, d := range af.Decls {
			gd, ok := d.(*ast.GenDecl)
			if !ok || gd.Tok != token.TYPE {
				continue
			}
			for _, sp := range gd.Specs {
				ts, ok := sp.(*ast.TypeSpec)
				if !ok {
					continue
				}
				kind := ""
				switch tt := ts.Type.(type) {
				case *ast.StructType:
					kind = "struct"
					for _, fl := range tt.Fields.List {
						for _, nm := range fl.Names {
							if pkg.fieldExprs[ts.Name.Name] == nil {
								pkg.fieldExprs[ts.Name.Name] = map[string]goExpr{}
							}
							pkg.fieldExprs[ts.Name.Name][nm.Name] = goExpr{fl.Type, st}
						}
					}
				case *ast.InterfaceType:
					kind = "interface"
				default:
					continue
				}
				key := "class:go:" + ns + "." + ts.Name.Name
				start, end := fset.Position(ts.Pos()).Line, fset.Position(ts.End()).Line
				if p.g.AddNode(key, "class", ts.Name.Name, f.key, map[string]any{"language": "Go", "file": f.rel, "line": start,
					"end_line": end, "qualified_name": ns + "." + ts.Name.Name, "kind": kind}) {
					pkg.types[ts.Name.Name] = key
					f.syms = append(f.syms, &symbol{key: key, name: ts.Name.Name, kind: "class", start: start, end: end})
					p.g.AddEdge(f.key, "defines", key, fileLine(f.rel, start, "type "+ts.Name.Name))
				}
			}
		}
		states = append(states, st)
	}
	// Functions and methods (after all types, so methods find their class).
	for _, st := range states {
		f, pkg := st.f, st.pkg
		ns := pkg.dir
		if strings.HasSuffix(st.ast.Name.Name, "_test") {
			ns = pkg.dir + "#" + st.ast.Name.Name
		}
		for _, d := range st.ast.Decls {
			fd, ok := d.(*ast.FuncDecl)
			if !ok || fd.Name.Name == "_" {
				continue
			}
			start, end := fset.Position(fd.Pos()).Line, fset.Position(fd.End()).Line
			name := fd.Name.Name
			recv, ptr := recvType(fd)
			qn := ns + "." + name
			parent := f.key
			if recv != "" {
				r := recv
				if ptr {
					r = "*" + r
				}
				qn = ns + ".(" + r + ")." + name
				if ck, ok := pkg.types[recv]; ok {
					parent = ck
				}
			} else if name == "init" {
				qn = ns + ".init@" + path.Base(f.rel)
			}
			key := "fn:go:" + qn
			if !p.g.AddNode(key, "function", name, parent, map[string]any{"language": "Go", "file": f.rel, "line": start, "end_line": end,
				"qualified_name": qn, "receiver": recv}) {
				continue
			}
			f.syms = append(f.syms, &symbol{key: key, name: name, class: recv, kind: "function", start: start, end: end})
			if recv != "" {
				if pkg.meths[recv] == nil {
					pkg.meths[recv] = map[string]string{}
				}
				pkg.meths[recv][name] = key
				if parent != f.key {
					p.g.AddEdge(parent, "defines", key, fileLine(f.rel, start, "method "+name))
					continue
				}
			} else if name != "init" {
				pkg.funcs[name] = key
				if fd.Type.Results != nil && len(fd.Type.Results.List) > 0 {
					pkg.resultExprs[name] = goExpr{fd.Type.Results.List[0].Type, st}
				}
			}
			p.g.AddEdge(f.key, "defines", key, fileLine(f.rel, start, "func "+name))
		}
	}
	// Imports and calls.
	pkgByDir := map[string]*goPkg{}
	for id, pk := range pkgs {
		if !strings.Contains(id, "#") {
			pkgByDir[pk.dir] = pk
		}
	}
	resolve := func(ge goExpr) typeRef { return resolveGoType(mods, pkgByDir, ge.st, ge.e) }
	for _, pk := range pkgs {
		for typ, fs := range pk.fieldExprs {
			for fname, ge := range fs {
				if t := resolve(ge); t.ok() {
					if pk.fields[typ] == nil {
						pk.fields[typ] = map[string]typeRef{}
					}
					pk.fields[typ][fname] = t
				}
			}
		}
		for fn, ge := range pk.resultExprs {
			if t := resolve(ge); t.ok() {
				pk.results[fn] = t
			}
		}
	}
	for _, st := range states {
		f := st.f
		for _, is := range st.ast.Imports {
			ip, err := strconv.Unquote(is.Path.Value)
			if err != nil {
				continue
			}
			line := fset.Position(is.Pos()).Line
			if dir := internalDir(mods, ip); dir != "" {
				if pk := pkgByDir[dir]; pk != nil {
					p.g.AddEdge(f.key, "imports", pk.key, fileLine(f.rel, line, "import \""+ip+"\""))
				}
				continue
			}
			first := strings.SplitN(ip, "/", 2)[0]
			if !strings.Contains(first, ".") || ip == "C" {
				continue // standard library
			}
			if ck := p.componentForImport("golang", ip); ck != "" {
				p.g.AddEdge(f.key, "imports", ck, fileLine(f.rel, line, "import \""+ip+"\""))
			}
		}
		for _, d := range st.ast.Decls {
			fd, ok := d.(*ast.FuncDecl)
			if !ok || fd.Body == nil {
				continue
			}
			caller := p.enclosing(f.rel, fset.Position(fd.Pos()).Line)
			if !strings.HasPrefix(caller, "fn:") {
				continue
			}
			vars := map[string]typeRef{}
			if fd.Recv != nil && len(fd.Recv.List) > 0 {
				t := resolveGoType(mods, pkgByDir, st, fd.Recv.List[0].Type)
				for _, nm := range fd.Recv.List[0].Names {
					vars[nm.Name] = t
				}
			}
			for _, fl := range fd.Type.Params.List {
				t := resolveGoType(mods, pkgByDir, st, fl.Type)
				for _, nm := range fl.Names {
					vars[nm.Name] = t
				}
			}
			p.goCalls(st, mods, pkgByDir, caller, fd.Body, vars, fset)
		}
	}
}

// pkgOf returns the repository package an identifier names in a file
// (its own package for "", else an imported one).
func pkgOf(mods []goMod, pkgByDir map[string]*goPkg, st *goFileState, alias string) *goPkg {
	if alias == "" {
		return st.pkg
	}
	ip, ok := st.imports[alias]
	if !ok {
		return nil
	}
	if dir := internalDir(mods, ip); dir != "" {
		return pkgByDir[dir]
	}
	return nil
}

// resolveGoType resolves T, *T, pkg.T and *pkg.T to a repository type.
func resolveGoType(mods []goMod, pkgByDir map[string]*goPkg, st *goFileState, e ast.Expr) typeRef {
	if se, ok := e.(*ast.StarExpr); ok {
		e = se.X
	}
	switch x := e.(type) {
	case *ast.Ident:
		if _, ok := st.pkg.types[x.Name]; ok {
			return typeRef{st.pkg, x.Name}
		}
	case *ast.SelectorExpr:
		if id, ok := x.X.(*ast.Ident); ok {
			if pk := pkgOf(mods, pkgByDir, st, id.Name); pk != nil {
				if _, ok := pk.types[x.Sel.Name]; ok {
					return typeRef{pk, x.Sel.Name}
				}
			}
		}
	}
	return typeRef{}
}

// goCalls resolves the calls of one function body: package functions,
// functions of imported repository packages, and methods of variables,
// parameters, receivers and their fields whose type is known.
func (p *project) goCalls(st *goFileState, mods []goMod, pkgByDir map[string]*goPkg, caller string, body *ast.BlockStmt,
	vars map[string]typeRef, fset *token.FileSet) {
	f := st.f
	// callTarget returns the function a call expression calls ("" when
	// unknown) and the type it returns.
	var callTarget func(ce *ast.CallExpr) (string, typeRef, string)
	exprType := func(e ast.Expr) typeRef {
		switch x := e.(type) {
		case *ast.Ident:
			return vars[x.Name]
		case *ast.SelectorExpr:
			if id, ok := x.X.(*ast.Ident); ok {
				if t, ok := vars[id.Name]; ok && t.ok() {
					return t.pkg.fields[t.name][x.Sel.Name]
				}
			}
		case *ast.UnaryExpr:
			if cl, ok := x.X.(*ast.CompositeLit); ok {
				return resolveGoType(mods, pkgByDir, st, cl.Type)
			}
		case *ast.CompositeLit:
			return resolveGoType(mods, pkgByDir, st, x.Type)
		case *ast.CallExpr:
			_, t, _ := callTarget(x)
			return t
		}
		return typeRef{}
	}
	callTarget = func(ce *ast.CallExpr) (string, typeRef, string) {
		switch fn := ce.Fun.(type) {
		case *ast.Ident:
			if _, shadow := vars[fn.Name]; shadow {
				return "", typeRef{}, ""
			}
			return st.pkg.funcs[fn.Name], st.pkg.results[fn.Name], fn.Name + "()"
		case *ast.SelectorExpr:
			text := fn.Sel.Name + "()"
			if id, ok := fn.X.(*ast.Ident); ok {
				text = id.Name + "." + text
				if _, isVar := vars[id.Name]; !isVar {
					if pk := pkgOf(mods, pkgByDir, st, id.Name); pk != nil && id.Name != "" {
						return pk.funcs[fn.Sel.Name], pk.results[fn.Sel.Name], text
					}
				}
			} else if inner, ok := fn.X.(*ast.SelectorExpr); ok {
				if id, ok := inner.X.(*ast.Ident); ok {
					text = id.Name + "." + inner.Sel.Name + "." + fn.Sel.Name + "()"
				}
			}
			t := exprType(fn.X)
			return t.method(fn.Sel.Name), typeRef{}, text
		}
		return "", typeRef{}, ""
	}
	ast.Inspect(body, func(n ast.Node) bool {
		switch x := n.(type) {
		case *ast.AssignStmt:
			if len(x.Rhs) == 1 {
				if t := exprType(x.Rhs[0]); t.ok() {
					if id, ok := x.Lhs[0].(*ast.Ident); ok {
						vars[id.Name] = t
					}
				}
			} else if len(x.Rhs) == len(x.Lhs) {
				for i, r := range x.Rhs {
					if id, ok := x.Lhs[i].(*ast.Ident); ok {
						if t := exprType(r); t.ok() {
							vars[id.Name] = t
						}
					}
				}
			}
		case *ast.ValueSpec:
			if x.Type != nil {
				if t := resolveGoType(mods, pkgByDir, st, x.Type); t.ok() {
					for _, nm := range x.Names {
						vars[nm.Name] = t
					}
				}
			}
		case *ast.CallExpr:
			if target, _, text := callTarget(x); target != "" {
				p.g.AddEdge(caller, "calls", target, fileLine(f.rel, fset.Position(x.Pos()).Line, text))
			}
		}
		return true
	})
}

func importPathOf(mods []goMod, dir string) string {
	for _, m := range mods {
		if dir == m.dir {
			return m.path
		}
		if m.dir == "." || strings.HasPrefix(dir, m.dir+"/") {
			rest := strings.TrimPrefix(dir, m.dir)
			rest = strings.TrimPrefix(rest, "/")
			if m.dir == "." {
				rest = dir
			}
			return m.path + "/" + rest
		}
	}
	return ""
}
