// Package material detects security-material changes between two scanned
// commits of a repository with explainable, deterministic rules: new or
// changed authentication and authorization code, new HTTP endpoints,
// cryptography changes, infrastructure-as-code exposure, secrets handling,
// CI/CD pipeline changes and sensitive data model fields. New dependencies
// are detected by the API from the SBOMs of the two scans.
//
// The package is pure: the worker feeds it a unified diff (git diff -U0)
// and sends the matches to the API. No code is executed and no AI is
// involved.
package material

import (
	"bufio"
	"bytes"
	"strconv"
	"strings"
)

// Line is one added or removed line of a file diff.
type Line struct {
	No   int    // line number in the new file (added) or old file (removed)
	Text string // without the leading +/-
}

// FileDiff is the change of one file.
type FileDiff struct {
	Path    string // new path ("" when deleted: OldPath is set)
	OldPath string // old path ("" when added)
	Status  string // added | modified | deleted | renamed
	Binary  bool
	Added   []Line
	Removed []Line
}

// DisplayPath is the path a change is shown at.
func (f FileDiff) DisplayPath() string {
	if f.Path != "" {
		return f.Path
	}
	return f.OldPath
}

const (
	maxLineLen      = 2000
	maxLinesPerFile = 20000
)

// ParseUnified parses the output of `git diff --no-color -U0` (with the
// default a/ b/ prefixes). Unknown lines are ignored; it never fails.
func ParseUnified(data []byte) []FileDiff {
	var out []FileDiff
	var cur *FileDiff
	oldNo, newNo := 0, 0
	flush := func() {
		if cur != nil {
			if cur.Status == "" {
				cur.Status = "modified"
				if cur.OldPath != "" && cur.Path != "" && cur.OldPath != cur.Path {
					cur.Status = "renamed"
				}
			}
			out = append(out, *cur)
		}
		cur = nil
	}
	sc := bufio.NewScanner(bytes.NewReader(data))
	sc.Buffer(make([]byte, 64<<10), 4<<20)
	inHunk := false
	for sc.Scan() {
		l := sc.Text()
		switch {
		case strings.HasPrefix(l, "diff --git "):
			flush()
			cur = &FileDiff{}
			inHunk = false
			// Paths from the header are a fallback for binary and
			// mode-only changes that have no ---/+++ lines.
			if a, b, ok := splitGitHeader(strings.TrimPrefix(l, "diff --git ")); ok {
				cur.OldPath, cur.Path = a, b
			}
			continue
		case cur == nil:
			continue
		}
		if !inHunk || strings.HasPrefix(l, "@@") {
			switch {
			case strings.HasPrefix(l, "new file mode"):
				cur.Status = "added"
				continue
			case strings.HasPrefix(l, "deleted file mode"):
				cur.Status = "deleted"
				continue
			case strings.HasPrefix(l, "rename from "):
				cur.OldPath, cur.Status = unquote(strings.TrimPrefix(l, "rename from ")), "renamed"
				continue
			case strings.HasPrefix(l, "rename to "):
				cur.Path, cur.Status = unquote(strings.TrimPrefix(l, "rename to ")), "renamed"
				continue
			case strings.HasPrefix(l, "Binary files "):
				cur.Binary = true
				continue
			case strings.HasPrefix(l, "--- "):
				p := unquote(strings.TrimPrefix(l, "--- "))
				if p == "/dev/null" {
					cur.OldPath = ""
					cur.Status = "added"
				} else {
					cur.OldPath = strings.TrimPrefix(p, "a/")
				}
				continue
			case strings.HasPrefix(l, "+++ "):
				p := unquote(strings.TrimPrefix(l, "+++ "))
				if p == "/dev/null" {
					cur.Path = ""
					cur.Status = "deleted"
				} else {
					cur.Path = strings.TrimPrefix(p, "b/")
				}
				continue
			case strings.HasPrefix(l, "@@"):
				o, n, ok := parseHunk(l)
				if ok {
					oldNo, newNo, inHunk = o, n, true
				}
				continue
			}
			if !inHunk {
				continue
			}
		}
		if l == "" {
			continue
		}
		text := l[1:]
		if len(text) > maxLineLen {
			text = text[:maxLineLen]
		}
		switch l[0] {
		case '+':
			if len(cur.Added) < maxLinesPerFile {
				cur.Added = append(cur.Added, Line{No: newNo, Text: text})
			}
			newNo++
		case '-':
			if len(cur.Removed) < maxLinesPerFile {
				cur.Removed = append(cur.Removed, Line{No: oldNo, Text: text})
			}
			oldNo++
		case ' ':
			oldNo++
			newNo++
		}
	}
	flush()
	return out
}

// parseHunk reads "@@ -a,b +c,d @@".
func parseHunk(l string) (int, int, bool) {
	f := strings.Fields(l)
	if len(f) < 3 || !strings.HasPrefix(f[1], "-") || !strings.HasPrefix(f[2], "+") {
		return 0, 0, false
	}
	start := func(s string) (int, bool) {
		s = s[1:]
		if i := strings.IndexByte(s, ','); i >= 0 {
			s = s[:i]
		}
		n, err := strconv.Atoi(s)
		return n, err == nil
	}
	o, ok1 := start(f[1])
	n, ok2 := start(f[2])
	return o, n, ok1 && ok2
}

// splitGitHeader splits "a/x b/y" (unquoted paths without " b/" inside).
func splitGitHeader(s string) (string, string, bool) {
	if strings.HasPrefix(s, `"`) {
		return "", "", false
	}
	i := strings.Index(s, " b/")
	if i < 0 || !strings.HasPrefix(s, "a/") {
		return "", "", false
	}
	return s[2:i], s[i+3:], true
}

// unquote handles git's C-style quoted paths ("a/\303\251.txt").
func unquote(p string) string {
	if len(p) >= 2 && p[0] == '"' && p[len(p)-1] == '"' {
		if u, err := strconv.Unquote(p); err == nil {
			return u
		}
		return p[1 : len(p)-1]
	}
	return p
}
