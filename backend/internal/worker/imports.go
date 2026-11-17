package worker

import (
	"bufio"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

// ImportInventory lists the packages a repository's code uses, for
// dependency reachability: imported modules per ecosystem, plus string
// literals that look like package names (frameworks load some packages by
// name, e.g. Express view engines or Django apps). It is computed by
// reading source files only; nothing is executed.
type ImportInventory struct {
	Version      int                 `json:"version"`
	FilesScanned int                 `json:"files_scanned"`
	Truncated    bool                `json:"truncated"`
	Imports      map[string][]string `json:"imports"` // npm, pypi, go
	Strings      map[string][]string `json:"strings"` // npm, pypi
}

const (
	maxImportFiles   = 50000
	maxImportFileLen = 1 << 20
	maxImportNames   = 20000
)

var (
	jsImportRe = regexp.MustCompile(`(?:\brequire\s*\(\s*|\bimport\s*\(\s*|\bfrom\s+|\bimport\s+)['"]([^'"\n]{1,214})['"]`)
	jsStringRe = regexp.MustCompile(`['"\x60](@?[a-z0-9][a-z0-9._-]{0,100}(?:/[a-z0-9][a-z0-9._-]{0,100})?)['"\x60]`)
	pyImportRe = regexp.MustCompile(`(?m)^\s*(?:from\s+([A-Za-z_][\w.]*)\s+import\b|import\s+([A-Za-z_][\w.]*(?:\s*,\s*[A-Za-z_][\w.]*)*))`)
	pyStringRe = regexp.MustCompile(`['"]([A-Za-z_][A-Za-z0-9_]{0,100})(?:\.[A-Za-z_][\w.]*)?['"]`)
	goImportRe = regexp.MustCompile(`"([a-zA-Z0-9][\w.\-~]*\.[a-z]{2,}(?:/[\w.\-~]+)+)"`)
	// Templates and HTML: packages loaded by the browser (<script src>,
	// <link href>), e.g. /node_modules/jquery/dist/jquery.min.js or
	// /js/jquery-1.8.3.min.js.
	assetRe       = regexp.MustCompile(`(?i)\b(?:src|href)\s*=\s*["']([^"'\s>]{1,500})["']`)
	nodeModulesRe = regexp.MustCompile(`node_modules/(@[a-z0-9._-]+/[a-z0-9._-]+|[a-z0-9._-]+)/`)
	assetFileRe   = regexp.MustCompile(`(?i)([a-z][a-z0-9_-]*?)(?:[-.@]v?\d+(?:\.\d+)*)?(?:\.min)?\.(?:m?js|css)(?:[?#].*)?$`)
)

// assetPackages guesses npm package names from a script or stylesheet URL.
func assetPackages(u string) []string {
	var out []string
	if m := nodeModulesRe.FindStringSubmatch(strings.ToLower(u)); m != nil {
		out = append(out, m[1])
	}
	base := u
	if i := strings.LastIndexAny(base, "/\\"); i >= 0 {
		base = base[i+1:]
	}
	if m := assetFileRe.FindStringSubmatch(base); m != nil {
		out = append(out, strings.ToLower(m[1]))
	}
	return out
}

var skipDirs = map[string]bool{
	"node_modules": true, "vendor": true, ".git": true, "bower_components": true, "jspm_packages": true,
	"site-packages": true, ".venv": true, "venv": true, "__pycache__": true, "dist": true, "build": true, ".next": true,
	"coverage": true, "third_party": true,
}

// jsPackage maps an import specifier to its npm package ("" for relative
// paths, Node built-ins and URLs).
func jsPackage(spec string) string {
	if spec == "" || strings.HasPrefix(spec, ".") || strings.HasPrefix(spec, "/") || strings.HasPrefix(spec, "node:") ||
		strings.Contains(spec, "://") || strings.HasPrefix(spec, "#") || strings.HasPrefix(spec, "~") {
		return ""
	}
	parts := strings.Split(spec, "/")
	if strings.HasPrefix(spec, "@") {
		if len(parts) < 2 {
			return ""
		}
		return strings.ToLower(parts[0] + "/" + parts[1])
	}
	return strings.ToLower(parts[0])
}

type nameSet map[string]struct{}

func (s nameSet) add(v string) bool {
	if v == "" || len(s) >= maxImportNames {
		return false
	}
	s[v] = struct{}{}
	return true
}

func (s nameSet) sorted() []string {
	out := make([]string, 0, len(s))
	for k := range s {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// collectImports walks src and builds the import inventory.
func collectImports(src string) ImportInventory {
	inv := ImportInventory{Version: 1, Imports: map[string][]string{}, Strings: map[string][]string{}}
	imp := map[string]nameSet{"npm": {}, "pypi": {}, "go": {}}
	str := map[string]nameSet{"npm": {}, "pypi": {}}
	// Files are read through a root-scoped handle, so a symbolic link
	// swapped in during the walk can never make a read escape the checkout.
	root, err := os.OpenRoot(src)
	if err != nil {
		return inv
	}
	defer root.Close()
	_ = filepath.WalkDir(src, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if d.IsDir() {
			if path != src && (skipDirs[d.Name()] || strings.HasPrefix(d.Name(), ".")) {
				return filepath.SkipDir
			}
			return nil
		}
		if !d.Type().IsRegular() {
			return nil // never follow symlinks
		}
		if inv.FilesScanned >= maxImportFiles {
			inv.Truncated = true
			return filepath.SkipAll
		}
		ext := strings.ToLower(filepath.Ext(path))
		var eco string
		switch ext {
		case ".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx", ".mts", ".cts", ".vue", ".svelte":
			eco = "npm"
		case ".py":
			eco = "pypi"
		case ".go":
			eco = "go"
		case ".html", ".htm", ".ejs", ".hbs", ".handlebars", ".pug", ".jade", ".njk", ".twig", ".erb", ".mustache", ".dust":
			eco = "web"
		default:
			return nil
		}
		if strings.HasSuffix(path, ".min.js") {
			return nil
		}
		info, err := d.Info()
		if err != nil || info.Size() > maxImportFileLen {
			return nil
		}
		rel, err := filepath.Rel(src, path)
		if err != nil {
			return nil
		}
		f, err := root.Open(rel)
		if err != nil {
			return nil
		}
		data, err := io.ReadAll(io.LimitReader(f, maxImportFileLen))
		_ = f.Close()
		if err != nil {
			return nil
		}
		inv.FilesScanned++
		text := string(data)
		switch eco {
		case "npm":
			for _, m := range jsImportRe.FindAllStringSubmatch(text, -1) {
				imp["npm"].add(jsPackage(m[1]))
			}
			for _, m := range jsStringRe.FindAllStringSubmatch(text, -1) {
				str["npm"].add(jsPackage(m[1]))
			}
		case "pypi":
			for _, m := range pyImportRe.FindAllStringSubmatch(text, -1) {
				for _, mod := range strings.Split(m[1]+","+m[2], ",") {
					if mod = strings.TrimSpace(mod); mod != "" {
						imp["pypi"].add(strings.ToLower(strings.SplitN(mod, ".", 2)[0]))
					}
				}
			}
			for _, m := range pyStringRe.FindAllStringSubmatch(text, -1) {
				str["pypi"].add(strings.ToLower(m[1]))
			}
		case "web":
			for _, m := range assetRe.FindAllStringSubmatch(text, -1) {
				for _, p := range assetPackages(m[1]) {
					str["npm"].add(p)
				}
			}
			for _, m := range jsStringRe.FindAllStringSubmatch(text, -1) {
				str["npm"].add(jsPackage(m[1]))
			}
		case "go":
			sc := bufio.NewScanner(strings.NewReader(text))
			sc.Buffer(make([]byte, 0, 64<<10), maxImportFileLen)
			inBlock := false
			for sc.Scan() {
				line := strings.TrimSpace(sc.Text())
				switch {
				case strings.HasPrefix(line, "import ("):
					inBlock = true
				case inBlock && line == ")":
					inBlock = false
				case inBlock || strings.HasPrefix(line, "import "):
					if m := goImportRe.FindStringSubmatch(line); m != nil {
						imp["go"].add(m[1])
					}
				case strings.HasPrefix(line, "func ") || strings.HasPrefix(line, "type "):
					// imports come first; stop at the first declaration
					return nil
				}
			}
		}
		return nil
	})
	for k, s := range imp {
		inv.Imports[k] = s.sorted()
	}
	for k, s := range str {
		inv.Strings[k] = s.sorted()
	}
	return inv
}
