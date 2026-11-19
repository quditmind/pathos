package reachscan

import (
	"path"
	"strings"
)

// Go is analysed by govulncheck (a call graph of the whole program,
// dependencies included). This pass only finds what govulncheck's static
// call graph cannot see: methods looked up by name with reflect
// (reflect.Value.MethodByName, Value.Method, Type.Method) and symbols
// loaded from plugins. Every module imported by a package that does so is
// marked dynamic, so that "not called" from govulncheck becomes unknown
// for it.

type goFile struct {
	f       *fileAn
	imports map[string]int
	marker  *dynSite
}

func analyzeGo(f *fileAn, toks []token) goFile {
	g := goFile{f: f, imports: map[string]int{}}
	addImport := func(k int) {
		if k < len(toks) && toks[k].kind == tString {
			g.imports[toks[k].text] = toks[k].line
		}
	}
	for i := 0; i < len(toks); i++ {
		t := toks[i]
		if t.kind != tIdent {
			continue
		}
		switch {
		case t.text == "import" && isP(toks, i+1, "("):
			k := i + 2
			for ; k < len(toks) && !isP(toks, k, ")"); k++ {
				addImport(k)
			}
			i = k
		case t.text == "import":
			if isIdent(toks, i+1) || isP(toks, i+1, ".") || isP(toks, i+1, "_") {
				addImport(i + 2)
			} else {
				addImport(i + 1)
			}
		case g.marker == nil && isP(toks, i-1, ".") && isP(toks, i+1, "("):
			_, refl := g.imports["reflect"]
			_, plug := g.imports["plugin"]
			switch {
			case refl && (t.text == "MethodByName" || t.text == "Method"):
				g.marker = &dynSite{reason: "methods called through reflect (" + t.text + ")", line: t.line}
			case plug && t.text == "Lookup":
				g.marker = &dynSite{reason: "symbols loaded from a plugin (plugin.Lookup)", line: t.line}
			}
		}
	}
	return g
}

// goModules marks the modules imported by every package (directory) that
// uses reflection or plugins, and records each file's imports.
func goModules(files []goFile) {
	byDir := map[string][]goFile{}
	for _, g := range files {
		byDir[path.Dir(g.f.key)] = append(byDir[path.Dir(g.f.key)], g)
		for imp, line := range g.imports {
			if first := strings.SplitN(imp, "/", 2)[0]; strings.Contains(first, ".") {
				g.f.imported(imp, line)
			}
		}
	}
	for _, gs := range byDir {
		var marker *goFile
		for k := range gs {
			if gs[k].marker != nil && (marker == nil || marker.f.test && !gs[k].f.test) {
				marker = &gs[k]
			}
		}
		if marker == nil {
			continue
		}
		seen := map[string]bool{}
		for _, g := range gs {
			if g.f.test != marker.f.test && !marker.f.test {
				continue
			}
			for imp := range g.imports {
				if first := strings.SplitN(imp, "/", 2)[0]; strings.Contains(first, ".") && !seen[imp] {
					seen[imp] = true
					marker.f.dyn(imp, marker.marker.reason, marker.marker.line)
				}
			}
		}
	}
}
