package diag

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"testing"
)

func TestCatalogueIsComplete(t *testing.T) {
	all := All()
	if len(all) < 60 {
		t.Fatalf("catalogue has %d entries, want at least 60", len(all))
	}
	areas := map[string]bool{}
	for _, a := range Areas {
		areas[a.Key] = true
		if a.Slug != strings.ToLower(a.Key) {
			t.Errorf("area %s: slug %q must be the lower-case key", a.Key, a.Slug)
		}
	}
	for _, e := range all {
		if err := e.check(); err != nil {
			t.Error(err)
		}
		if !areas[e.Area] {
			t.Errorf("%s: unknown area %s", e.Code, e.Area)
		}
		if e.HTTPStatus != 0 && (e.HTTPStatus < 400 || e.HTTPStatus > 599) {
			t.Errorf("%s: HTTP status %d is not an error status", e.Code, e.HTTPStatus)
		}
		if !strings.HasPrefix(e.DocsURL(), "/help/troubleshooting/"+strings.ToLower(e.Area)+"#"+e.Code) {
			t.Errorf("%s: docs URL %s", e.Code, e.DocsURL())
		}
		// Every entry names where it is raised; the paths must exist.
		for _, src := range sourcePaths(e.Source) {
			if _, err := os.Stat(filepath.Join("..", "..", "..", src)); err != nil {
				t.Errorf("%s: source %s does not exist", e.Code, src)
			}
		}
	}
	if _, ok := Lookup(Fallback); !ok {
		t.Fatal("the fallback code must be in the catalogue")
	}
}

var pathRe = regexp.MustCompile(`(?:internal|cmd)/[a-z0-9_/.-]+`)

func sourcePaths(s string) []string {
	var out []string
	for _, m := range pathRe.FindAllString(s, -1) {
		out = append(out, strings.TrimSuffix(m, "."))
	}
	return out
}

func TestResolveAndDetail(t *testing.T) {
	if got := Resolve("", "not_found", 404); got != "PTH-PLAT-0004" {
		t.Errorf("legacy mapping: %s", got)
	}
	if got := Resolve("PTH-AI-1008", "rate_limited", 429); got != "PTH-AI-1008" {
		t.Errorf("explicit code wins: %s", got)
	}
	if got := Resolve("PTH-NOPE-0001", "never_seen", 418); got != Fallback {
		t.Errorf("unknown: %s", got)
	}
	if got := Resolve("", "never_seen", 403); got != "PTH-AUTH-1002" {
		t.Errorf("status fallback: %s", got)
	}
	d := DetailFor("PTH-AUTH-1004", "", "req1")
	if !d.Cause.Confirmed || d.Cause.Text == "" || d.RequestID != "req1" || d.DocsURL != "/help/troubleshooting/auth#PTH-AUTH-1004" || len(d.Actions) == 0 {
		t.Errorf("proven entry: %+v", d)
	}
	d = DetailFor("PTH-CONN-1001", "", "")
	if d.Cause.Confirmed {
		t.Errorf("an unproven entry must not report a confirmed cause: %+v", d.Cause)
	}
	d = DetailFor("PTH-CONN-1001", "dial tcp: connection refused", "")
	if !d.Cause.Confirmed || d.Cause.Text != "dial tcp: connection refused" {
		t.Errorf("raise-site cause: %+v", d.Cause)
	}
	if DetailFor("bogus", "", "").ErrorCode != Fallback {
		t.Error("unknown codes fall back")
	}
}

// backendFiles parses every non-test Go file of the backend.
func backendFiles(t *testing.T) map[string]*ast.File {
	t.Helper()
	out := map[string]*ast.File{}
	fset := token.NewFileSet()
	for _, root := range []string{filepath.Join("..", "..", "..", "internal"), filepath.Join("..", "..", "..", "cmd")} {
		err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
			if err != nil || d.IsDir() || !strings.HasSuffix(p, ".go") || strings.HasSuffix(p, "_test.go") {
				return err
			}
			if strings.Contains(filepath.ToSlash(p), "internal/platform/diag/") {
				return nil
			}
			f, err := parser.ParseFile(fset, p, nil, 0)
			if err != nil {
				return err
			}
			out[p] = f
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	if len(out) < 200 {
		t.Fatalf("parsed only %d files", len(out))
	}
	return out
}

// Every PTH code written in the backend source exists in the catalogue.
func TestCodesUsedInSourceExist(t *testing.T) {
	lit := regexp.MustCompile(`PTH-[A-Z]+-[0-9]{4}`)
	used := 0
	for p, f := range backendFiles(t) {
		ast.Inspect(f, func(n ast.Node) bool {
			bl, ok := n.(*ast.BasicLit)
			if !ok || bl.Kind != token.STRING {
				return true
			}
			for _, c := range lit.FindAllString(bl.Value, -1) {
				used++
				if _, ok := Lookup(c); !ok {
					t.Errorf("%s: %s is not in the catalogue", p, c)
				}
			}
			return true
		})
	}
	if used < 30 {
		t.Errorf("only %d codes are attached in the source", used)
	}
}

// Every short API error code raised in the source maps to a catalogue
// entry (so no API error falls back to the generic code by accident).
func TestLegacyCodesRaisedInSourceAreMapped(t *testing.T) {
	seen := map[string]string{}
	for p, f := range backendFiles(t) {
		ast.Inspect(f, func(n ast.Node) bool {
			switch x := n.(type) {
			case *ast.CallExpr:
				sel, ok := x.Fun.(*ast.SelectorExpr)
				if !ok || sel.Sel.Name != "E" || len(x.Args) != 3 {
					return true
				}
				if id, ok := sel.X.(*ast.Ident); !ok || id.Name != "httpx" {
					return true
				}
				if bl, ok := x.Args[1].(*ast.BasicLit); ok && bl.Kind == token.STRING {
					v, _ := strconv.Unquote(bl.Value)
					seen[v] = p
				}
			case *ast.KeyValueExpr:
				k, ok := x.Key.(*ast.Ident)
				if !ok || k.Name != "Code" {
					return true
				}
				if bl, ok := x.Value.(*ast.BasicLit); ok && bl.Kind == token.STRING {
					v, _ := strconv.Unquote(bl.Value)
					if regexp.MustCompile(`^[a-z][a-z_]+$`).MatchString(v) && strings.Contains(p, filepath.Join("internal")) && isHTTPErrorLit(f, x) {
						seen[v] = p
					}
				}
			}
			return true
		})
	}
	if len(seen) < 40 {
		t.Fatalf("found only %d short codes", len(seen))
	}
	for code, p := range seen {
		if ForLegacy(code) == "" {
			t.Errorf("%s: short code %q has no catalogue entry (add it to an entry's Legacy)", p, code)
		}
	}
}

// isHTTPErrorLit reports whether kv sits in an httpx.Error composite literal.
func isHTTPErrorLit(f *ast.File, kv *ast.KeyValueExpr) bool {
	found := false
	ast.Inspect(f, func(n ast.Node) bool {
		cl, ok := n.(*ast.CompositeLit)
		if !ok || found {
			return !found
		}
		sel, ok := cl.Type.(*ast.SelectorExpr)
		if !ok || sel.Sel.Name != "Error" {
			return true
		}
		if id, ok := sel.X.(*ast.Ident); !ok || id.Name != "httpx" {
			return true
		}
		if slices.Contains(cl.Elts, ast.Expr(kv)) {
			found = true
		}
		return !found
	})
	return found
}

// The generated pages match the catalogue: every code has docs and every
// page belongs to an area with codes. Run `make docs-errors` after
// changing the catalogue.
func TestGeneratedDocsMatchCatalogue(t *testing.T) {
	dir := filepath.Join("..", "..", "..", "..", "docs", "troubleshooting")
	want := DocFiles()
	got, err := filepath.Glob(filepath.Join(dir, "*.md"))
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range got {
		name := filepath.Base(p)
		if _, ok := want[name]; !ok {
			t.Errorf("docs/troubleshooting/%s has no codes in the catalogue; run make docs-errors", name)
		}
	}
	for name, content := range want {
		b, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			t.Errorf("docs/troubleshooting/%s is missing; run make docs-errors", name)
			continue
		}
		if string(b) != content {
			t.Errorf("docs/troubleshooting/%s is out of date; run make docs-errors", name)
		}
	}
	for _, e := range All() {
		page := want[strings.ToLower(e.Area)+".md"]
		if !strings.Contains(page, `<a id="`+e.Code+`"></a>`) || !strings.Contains(page, "## "+e.Code+": ") {
			t.Errorf("%s has no section in its page", e.Code)
		}
	}
	for name, content := range want {
		if !strings.HasPrefix(content, "---\ntitle: ") || !strings.Contains(content, "\nsection: troubleshooting\n") {
			t.Errorf("%s: front matter missing", name)
		}
		for _, c := range regexp.MustCompile(`## (PTH-[A-Z]+-[0-9]{4}): `).FindAllStringSubmatch(content, -1) {
			if _, ok := Lookup(c[1]); !ok {
				t.Errorf("%s documents %s, which is not in the catalogue", name, c[1])
			}
		}
	}
}
