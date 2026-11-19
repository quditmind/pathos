package main

import (
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"

	"github.com/go-enry/go-enry/v2"
)

// Options bound a discovery run.
type Options struct {
	MaxFiles     int
	MaxFileBytes int64
	MaxNodes     int
	MaxEdges     int
	Opengrep     string // path of the opengrep binary ("" = skip rule-based extraction)
	RulesDir     string
	Syft         string // path of the syft binary ("" = skip SBOM components)
	// Recorded tool outputs (tests): used instead of running the tools.
	opengrepJSON, sbomJSON []byte
}

// DefaultOptions are the limits used by the CLI.
func DefaultOptions() Options {
	return Options{MaxFiles: 50000, MaxFileBytes: 1 << 20, MaxNodes: 300000, MaxEdges: 300000}
}

// skipDirs are never descended into (dependencies, build output, VCS data).
var skipDirs = map[string]bool{
	".git": true, ".hg": true, ".svn": true, "node_modules": true, "vendor": true, "third_party": true, "dist": true,
	"build": true, "target": true, ".venv": true, "venv": true, "__pycache__": true, ".idea": true, ".gradle": true,
	"bower_components": true, ".next": true, ".nuxt": true, "coverage": true, ".terraform": true, ".tox": true,
	".mypy_cache": true, ".pytest_cache": true, "Pods": true,
}

// symbol is a function or class found in a source file.
type symbol struct {
	key, name, class string
	kind             string // function | class
	start, end       int
}

// srcFile is one analysed file.
type srcFile struct {
	rel, lang string
	data      []byte
	module    string // module node key
	key       string // file node key
	syms      []*symbol
	imports   []string // raw import paths or names (technology hints)
}

// project is the state of one run.
type project struct {
	root  string
	opts  Options
	g     *Graph
	stats *Stats
	files []*srcFile
	byRel map[string]*srcFile
	// all regular files considered (relative paths), for config extractors
	paths []string
	ts    *tsIndex // tree-sitter symbol index (handler resolution)
}

// extractor languages (enry names).
var codeLanguages = map[string]string{
	"Go": "go", "Java": "java", "Python": "py", "JavaScript": "js", "TypeScript": "ts", "TSX": "tsx",
	"C#": "cs", "PHP": "php", "Ruby": "rb",
}

func (p *project) skip(rel, reason string) {
	if len(p.stats.Skipped) < 500 {
		p.stats.Skipped = append(p.stats.Skipped, Skipped{Path: rel, Reason: reason})
	}
}

// walk collects the files of the repository within the limits.
func (p *project) walk() error {
	var rels []string
	err := filepath.WalkDir(p.root, func(abs string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil // unreadable entries are ignored
		}
		rel, rerr := filepath.Rel(p.root, abs)
		if rerr != nil {
			return nil
		}
		rel = filepath.ToSlash(rel)
		if d.IsDir() {
			if rel != "." && (skipDirs[d.Name()] || (strings.HasPrefix(d.Name(), ".") && d.Name() != ".github")) {
				return filepath.SkipDir
			}
			return nil
		}
		if !d.Type().IsRegular() { // symlinks and devices are never followed
			return nil
		}
		if len(rels) >= p.opts.MaxFiles {
			p.stats.Truncated = true
			return filepath.SkipAll
		}
		rels = append(rels, rel)
		return nil
	})
	if err != nil {
		return err
	}
	sort.Strings(rels)
	p.paths = rels
	for _, rel := range rels {
		if enry.IsVendor(rel) && !strings.HasPrefix(rel, ".github/") {
			continue
		}
		lang, ok := codeLanguages[langByName(rel)]
		if !ok {
			continue
		}
		data, err := p.read(rel)
		if err != nil {
			continue
		}
		if enry.IsGenerated(rel, data) || isMinified(rel, data) {
			p.skip(rel, "generated or minified")
			continue
		}
		name := enry.GetLanguage(path.Base(rel), data)
		if l, ok := codeLanguages[name]; ok {
			lang = l
		}
		p.stats.Languages[langDisplay(lang)]++
		p.stats.FilesScanned++
		f := &srcFile{rel: rel, lang: lang, data: data}
		p.files = append(p.files, f)
		p.byRel[rel] = f
	}
	return nil
}

// read returns a file's content when it is within the size limit.
func (p *project) read(rel string) ([]byte, error) {
	abs := filepath.Join(p.root, filepath.FromSlash(rel))
	st, err := os.Lstat(abs)
	if err != nil || !st.Mode().IsRegular() {
		return nil, fs.ErrNotExist
	}
	if st.Size() > p.opts.MaxFileBytes {
		p.skip(rel, "larger than the file size limit")
		return nil, fs.ErrInvalid
	}
	// #nosec G304 -- a regular file inside the source directory (no symlinks)
	return os.ReadFile(abs)
}

func langByName(rel string) string {
	base := path.Base(rel)
	switch strings.ToLower(path.Ext(base)) {
	case ".go":
		return "Go"
	case ".java":
		return "Java"
	case ".py":
		return "Python"
	case ".js", ".mjs", ".cjs", ".jsx":
		return "JavaScript"
	case ".ts", ".mts", ".cts":
		if strings.HasSuffix(base, ".d.ts") {
			return ""
		}
		return "TypeScript"
	case ".tsx":
		return "TSX"
	case ".cs":
		return "C#"
	case ".php":
		return "PHP"
	case ".rb", ".rake":
		return "Ruby"
	}
	return ""
}

func langDisplay(l string) string {
	for k, v := range codeLanguages {
		if v == l {
			return k
		}
	}
	return l
}

// isMinified: very long lines in JavaScript are bundles, not source.
func isMinified(rel string, data []byte) bool {
	if !strings.HasSuffix(rel, ".js") && !strings.HasSuffix(rel, ".mjs") && !strings.HasSuffix(rel, ".cjs") {
		return false
	}
	if strings.Contains(rel, ".min.") {
		return true
	}
	lines := 1 + strings.Count(string(data), "\n")
	return len(data) > 20000 && len(data)/lines > 500
}

// moduleOf returns (creating) the module node of a file's directory.
func (p *project) moduleOf(rel, lang string) string {
	dir := path.Dir(rel)
	key := "mod:" + dir
	label := dir
	if dir == "." {
		label = "/"
	}
	p.g.AddNode(key, "module", label, "repository", map[string]any{"path": dir, "language": langDisplay(lang)})
	return key
}

// fileNode creates the node of a file (inside its module).
func (p *project) fileNode(rel, lang string) string {
	key := "file:" + rel
	if p.g.Has(key) {
		return key
	}
	mod := p.moduleOf(rel, lang)
	attrs := map[string]any{"file": rel, "line": 1}
	if isTestPath(rel) {
		attrs["role"] = "test" // test code and fixtures (filterable)
	}
	if lang != "" {
		attrs["language"] = langDisplay(lang)
	}
	p.g.AddNode(key, "file", path.Base(rel), mod, attrs)
	return key
}

// enclosing returns the innermost function containing line, else the
// innermost class, else the file node.
func (p *project) enclosing(rel string, line int) string {
	f := p.byRel[rel]
	if f == nil {
		if p.g.Has("file:" + rel) {
			return "file:" + rel
		}
		return ""
	}
	best, bestClass := (*symbol)(nil), (*symbol)(nil)
	for _, s := range f.syms {
		if line < s.start || line > s.end || !p.g.Has(s.key) {
			continue
		}
		if s.kind == "function" {
			if best == nil || s.end-s.start < best.end-best.start {
				best = s
			}
		} else if bestClass == nil || s.end-s.start < bestClass.end-bestClass.start {
			bestClass = s
		}
	}
	if best != nil {
		return best.key
	}
	if bestClass != nil {
		return bestClass.key
	}
	return f.key
}

// functionNear returns the function at line or starting just after it
// (annotations and decorators precede the function they apply to).
func (p *project) functionNear(rel string, line int) string {
	f := p.byRel[rel]
	if f == nil {
		return ""
	}
	if k := p.enclosing(rel, line); k != f.key && strings.HasPrefix(k, "fn:") {
		return k
	}
	var best *symbol
	for _, s := range f.syms {
		if s.kind == "function" && s.start > line && s.start <= line+4 && (best == nil || s.start < best.start) {
			best = s
		}
	}
	if best != nil && p.g.Has(best.key) {
		return best.key
	}
	return ""
}
