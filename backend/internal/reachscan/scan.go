package reachscan

import (
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

var skipDirs = map[string]bool{
	"node_modules": true, "vendor": true, ".git": true, "bower_components": true, "jspm_packages": true,
	"site-packages": true, ".venv": true, "venv": true, "__pycache__": true, "dist": true, "build": true, ".next": true,
	"coverage": true, "third_party": true, "target": true, ".gradle": true, ".tox": true, "out": true,
}

func ecosystemOf(name string) string {
	lower := strings.ToLower(name)
	switch {
	case strings.HasSuffix(lower, ".d.ts"), strings.HasSuffix(lower, ".min.js"):
		return ""
	}
	switch strings.ToLower(filepath.Ext(name)) {
	case ".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx", ".mts", ".cts", ".vue", ".svelte":
		return "npm"
	case ".py":
		return "pypi"
	case ".java":
		return "maven"
	case ".go":
		return "go"
	}
	return ""
}

var scriptRe = regexp.MustCompile(`(?is)<script\b[^>]*>(.*?)</script>`)

// scriptOnly keeps the <script> blocks of a Vue or Svelte component, with
// the other lines blanked so line numbers stay right.
func scriptOnly(src string) string {
	b := []byte(src)
	keep := make([]bool, len(b))
	for _, m := range scriptRe.FindAllStringSubmatchIndex(src, -1) {
		for k := m[2]; k < m[3]; k++ {
			keep[k] = true
		}
	}
	for k := range b {
		if !keep[k] && b[k] != '\n' {
			b[k] = ' '
		}
	}
	return string(b)
}

// Scan analyses the repository at dir.
func Scan(dir string) (*Report, error) {
	root, err := os.OpenRoot(dir)
	if err != nil {
		return nil, err
	}
	defer root.Close()
	stats := map[string]*LangStats{}
	type file struct{ key, eco string }
	var files []file
	truncated := false
	err = filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if d.IsDir() {
			if p != dir && (skipDirs[d.Name()] || strings.HasPrefix(d.Name(), ".")) {
				return filepath.SkipDir
			}
			return nil
		}
		if !d.Type().IsRegular() {
			return nil // never follow symbolic links
		}
		eco := ecosystemOf(d.Name())
		if eco == "" {
			return nil
		}
		if len(files) >= MaxFiles {
			truncated = true
			return filepath.SkipAll
		}
		rel, err := filepath.Rel(dir, p)
		if err != nil {
			return nil
		}
		files = append(files, file{filepath.ToSlash(rel), eco})
		return nil
	})
	if err != nil {
		return nil, err
	}
	sort.Slice(files, func(i, j int) bool { return files[i].key < files[j].key })
	js := jsFiles{}
	var pyKeys []string
	for _, f := range files {
		switch f.eco {
		case "npm":
			js[f.key] = true
		case "pypi":
			pyKeys = append(pyKeys, f.key)
		}
	}
	mods := newPyModules(pyKeys)
	var analysed []*fileAn
	var goFiles []goFile
	for _, file := range files {
		st := stats[file.eco]
		if st == nil {
			st = &LangStats{}
			stats[file.eco] = st
		}
		src, ok := readFile(root, file.key)
		if !ok {
			st.Skipped++
			continue
		}
		f := newFile(file.key, file.eco)
		st.Files++
		if f.test {
			st.TestFiles++
		}
		switch file.eco {
		case "npm":
			if ext := strings.ToLower(filepath.Ext(file.key)); ext == ".vue" || ext == ".svelte" {
				src = scriptOnly(src)
			}
			analyzeJS(f, lexJS(src), js)
		case "pypi":
			f.pyPackage = strings.HasSuffix(file.key, "__init__.py")
			analyzePython(f, lexPython(src), mods)
		case "maven":
			analyzeJava(f, lexJava(src))
		case "go":
			goFiles = append(goFiles, analyzeGo(f, lexJS(src)))
		}
		analysed = append(analysed, f)
	}
	// Python namespace packages (directories without __init__.py)
	for k := range mods.keys {
		if strings.HasSuffix(k, "/") {
			f := newFile(k, "pypi")
			f.pyPackage = true
			analysed = append(analysed, f)
		}
	}
	sort.SliceStable(analysed, func(i, j int) bool { return analysed[i].key < analysed[j].key })
	goModules(goFiles)
	a := newAnalysis(analysed)
	r := a.run(stats)
	r.Truncated = r.Truncated || truncated
	return r, nil
}

func readFile(root *os.Root, key string) (string, bool) {
	fh, err := root.Open(filepath.FromSlash(key))
	if err != nil {
		return "", false
	}
	defer fh.Close()
	st, err := fh.Stat()
	if err != nil || !st.Mode().IsRegular() || st.Size() > MaxFileBytes {
		return "", false
	}
	b, err := io.ReadAll(io.LimitReader(fh, MaxFileBytes+1))
	if err != nil || len(b) > MaxFileBytes {
		return "", false
	}
	return string(b), true
}
