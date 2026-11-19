// Package aifix parses, checks and applies AI-proposed code fixes (unified
// diffs) and compares scanner results before and after a fix.
//
// Nothing here trusts the diff: it is parsed strictly, confined to the
// finding's file (or a small set of files next to it) by Policy, applied
// only where its context matches the file, and a fix is "verified" only
// when the scanner that reported the finding no longer reports it and
// reports nothing new in the changed files (Compare).
package aifix

import (
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"pathos/internal/scm"
)

// Limits on one proposed diff.
const (
	MaxDiffBytes    = 20000
	MaxFiles        = 3
	MaxChangedLines = 200
	MaxHunks        = 30
	// MaxFileBytes bounds a file the diff is applied to.
	MaxFileBytes = 1 << 20
)

// Placeholder is the redaction marker the AI saw in place of secrets.
const Placeholder = "[REDACTED]"

// Hunk is one @@ block. Lines keep their prefix: ' ' context, '-' removed,
// '+' added.
type Hunk struct {
	OldStart int
	Lines    []string
}

// FileDiff is the change to one file.
type FileDiff struct {
	Path  string
	Hunks []Hunk
}

// Diff is a parsed unified diff.
type Diff struct {
	Files   []FileDiff
	Added   int
	Removed int
}

// Paths lists the changed files.
func (d Diff) Paths() []string {
	out := make([]string, len(d.Files))
	for i, f := range d.Files {
		out[i] = f.Path
	}
	return out
}

var hunkRe = regexp.MustCompile(`^@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@`)

// Parse reads a unified diff (git or plain format). Code fences and prose
// before the first file header are ignored. File creation, deletion,
// renames, mode changes and binary patches are refused: a fix edits
// existing text files in place.
func Parse(diff string) (Diff, error) {
	if len(diff) > MaxDiffBytes {
		return Diff{}, fmt.Errorf("the diff is larger than %d bytes", MaxDiffBytes)
	}
	lines := strings.Split(strings.ReplaceAll(diff, "\r\n", "\n"), "\n")
	var d Diff
	var cur *FileDiff
	var hunk *Hunk
	flush := func() {
		if hunk != nil && cur != nil {
			// Blank lines at the end of a hunk are separators, not context.
			for len(hunk.Lines) > 0 && hunk.Lines[len(hunk.Lines)-1] == " " {
				hunk.Lines = hunk.Lines[:len(hunk.Lines)-1]
			}
			cur.Hunks = append(cur.Hunks, *hunk)
		}
		hunk = nil
	}
	for i := 0; i < len(lines); i++ {
		l := lines[i]
		switch {
		case strings.HasPrefix(l, "--- ") && i+1 < len(lines) && strings.HasPrefix(lines[i+1], "+++ "):
			flush()
			from, to := headerPath(l[4:]), headerPath(lines[i+1][4:])
			if from == "/dev/null" || to == "/dev/null" {
				return Diff{}, errors.New("the diff creates or deletes a file; a fix may only edit existing files")
			}
			if from != to {
				return Diff{}, fmt.Errorf("the diff renames %q to %q", from, to)
			}
			if !scm.ValidRepoPath(to) {
				return Diff{}, fmt.Errorf("invalid path %q in the diff", to)
			}
			for _, f := range d.Files {
				if f.Path == to {
					return Diff{}, fmt.Errorf("the diff changes %q twice", to)
				}
			}
			d.Files = append(d.Files, FileDiff{Path: to})
			cur = &d.Files[len(d.Files)-1]
			i++
		case strings.HasPrefix(l, "@@"):
			flush()
			if cur == nil {
				return Diff{}, errors.New("a hunk appears before any file header")
			}
			m := hunkRe.FindStringSubmatch(l)
			if m == nil {
				return Diff{}, fmt.Errorf("malformed hunk header %q", clip(l, 80))
			}
			start, _ := strconv.Atoi(m[1])
			hunk = &Hunk{OldStart: start}
		case strings.HasPrefix(l, "diff --git "), strings.HasPrefix(l, "index "):
			flush()
		case strings.HasPrefix(l, "new file mode"), strings.HasPrefix(l, "deleted file mode"),
			strings.HasPrefix(l, "rename from"), strings.HasPrefix(l, "rename to"), strings.HasPrefix(l, "similarity index"),
			strings.HasPrefix(l, "copy from"), strings.HasPrefix(l, "copy to"):
			return Diff{}, errors.New("the diff creates, deletes, copies or renames a file; a fix may only edit existing files")
		case strings.HasPrefix(l, "old mode"), strings.HasPrefix(l, "new mode"):
			return Diff{}, errors.New("the diff changes file modes")
		case strings.HasPrefix(l, "GIT binary patch"), strings.HasPrefix(l, "Binary files"):
			return Diff{}, errors.New("the diff contains a binary patch")
		case hunk != nil && l == "":
			hunk.Lines = append(hunk.Lines, " ")
		case hunk != nil && (l[0] == ' ' || l[0] == '+' || l[0] == '-'):
			hunk.Lines = append(hunk.Lines, l)
		case hunk != nil && l[0] == '\\':
			// "\ No newline at end of file"
		case strings.HasPrefix(l, "```"):
			flush()
		case hunk != nil:
			return Diff{}, fmt.Errorf("unexpected line in a hunk: %q", clip(l, 80))
		}
	}
	flush()
	if len(d.Files) == 0 {
		return Diff{}, errors.New("the response contains no unified diff")
	}
	hunks := 0
	for _, f := range d.Files {
		if len(f.Hunks) == 0 {
			return Diff{}, fmt.Errorf("the diff has no changes for %q", f.Path)
		}
		for _, h := range f.Hunks {
			hunks++
			old := 0
			for _, l := range h.Lines {
				switch l[0] {
				case '+':
					d.Added++
				case '-':
					d.Removed++
					old++
				default:
					old++
				}
			}
			if old == 0 {
				return Diff{}, errors.New("every hunk needs at least one context or removed line to locate it")
			}
		}
	}
	if hunks > MaxHunks {
		return Diff{}, fmt.Errorf("the diff has more than %d hunks", MaxHunks)
	}
	if d.Added+d.Removed == 0 {
		return Diff{}, errors.New("the diff changes nothing")
	}
	if d.Added+d.Removed > MaxChangedLines {
		return Diff{}, fmt.Errorf("the diff changes more than %d lines", MaxChangedLines)
	}
	return d, nil
}

// headerPath strips the a/ or b/ prefix and a trailing timestamp.
func headerPath(s string) string {
	if i := strings.IndexByte(s, '\t'); i >= 0 {
		s = s[:i]
	}
	s = strings.TrimSpace(s)
	if s == "/dev/null" {
		return s
	}
	if strings.HasPrefix(s, "a/") || strings.HasPrefix(s, "b/") {
		s = s[2:]
	}
	// Not cleaned: "..", "." and empty components are refused by
	// scm.ValidRepoPath instead of being resolved.
	return s
}

func clip(s string, n int) string {
	if len(s) > n {
		return s[:n] + "…"
	}
	return s
}
