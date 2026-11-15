package worker

import (
	"bufio"
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

const (
	contextLines   = 5 // lines before and after a finding
	maxLineLen     = 300
	maxContextSize = 4 << 20 // per report
)

var workspacePrefix = regexp.MustCompile(`^/?work/[^/]+/src/`)

// enrichSARIF adds the code around each result (properties.pathos_context)
// so AI review has evidence after the checkout is deleted. Paths are
// resolved strictly inside src; the API redacts the text again on ingest.
func enrichSARIF(path, src string) error {
	// #nosec G304 -- report path is created by the worker in its job directory
	raw, err := os.ReadFile(path)
	if err != nil || len(raw) == 0 {
		return err
	}
	var doc map[string]any
	if err := json.Unmarshal(raw, &doc); err != nil {
		return nil // leave unparseable output for the API to report
	}
	runs, _ := doc["runs"].([]any)
	budget := maxContextSize
	cache := map[string][]string{}
	for _, r := range runs {
		run, _ := r.(map[string]any)
		results, _ := run["results"].([]any)
		for _, rr := range results {
			res, _ := rr.(map[string]any)
			uri, start, end := location(res)
			if uri == "" || start <= 0 || budget <= 0 {
				continue
			}
			lines, ok := cache[uri]
			if !ok {
				lines = readLines(src, uri)
				cache[uri] = lines
			}
			if len(lines) == 0 {
				continue
			}
			from := max(start-contextLines, 1)
			to := min(max(end, start)+contextLines, len(lines), from+40)
			var b strings.Builder
			for i := from; i <= to; i++ {
				l := lines[i-1]
				if len(l) > maxLineLen {
					l = l[:maxLineLen] + "…"
				}
				b.WriteString(l)
				b.WriteByte('\n')
			}
			props, _ := res["properties"].(map[string]any)
			if props == nil {
				props = map[string]any{}
				res["properties"] = props
			}
			props["pathos_context"] = b.String()
			props["pathos_context_start"] = from
			budget -= b.Len()
		}
	}
	out, err := json.Marshal(doc)
	if err != nil {
		return err
	}
	return os.WriteFile(path, out, 0o600)
}

func location(res map[string]any) (string, int, int) {
	locs, _ := res["locations"].([]any)
	if len(locs) == 0 {
		return "", 0, 0
	}
	loc, _ := locs[0].(map[string]any)
	pl, _ := loc["physicalLocation"].(map[string]any)
	al, _ := pl["artifactLocation"].(map[string]any)
	reg, _ := pl["region"].(map[string]any)
	uri, _ := al["uri"].(string)
	start, _ := reg["startLine"].(float64)
	end, _ := reg["endLine"].(float64)
	return uri, int(start), int(end)
}

// readLines reads a file only if it resolves inside src.
func readLines(src, uri string) []string {
	uri = strings.TrimPrefix(uri, "file://")
	rel := workspacePrefix.ReplaceAllString(uri, "")
	if filepath.IsAbs(rel) {
		r, err := filepath.Rel(src, rel)
		if err != nil {
			return nil
		}
		rel = r
	}
	full := filepath.Join(src, rel)
	if !within(src, full) {
		return nil
	}
	// Resolve symlinks in every path component, so a symlinked directory in
	// the scanned repository cannot point outside the checkout (the clone
	// disables symlinks; this is defence in depth).
	realSrc, err := filepath.EvalSymlinks(src)
	if err != nil {
		return nil
	}
	real, err := filepath.EvalSymlinks(full)
	if err != nil || !within(realSrc, real) {
		return nil
	}
	full = real
	st, err := os.Lstat(full)
	if err != nil || !st.Mode().IsRegular() || st.Size() > 5<<20 {
		return nil
	}
	// #nosec G304 -- path is resolved with EvalSymlinks and verified to be inside the checkout
	f, err := os.Open(full)
	if err != nil {
		return nil
	}
	defer f.Close()
	var lines []string
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 64<<10), 1<<20)
	for sc.Scan() && len(lines) < 200000 {
		lines = append(lines, sc.Text())
	}
	return lines
}

// within reports whether path is inside (or equal to) dir; both are cleaned.
func within(dir, path string) bool {
	r, err := filepath.Rel(dir, path)
	return err == nil && r != ".." && !strings.HasPrefix(r, ".."+string(filepath.Separator)) && !filepath.IsAbs(r)
}
