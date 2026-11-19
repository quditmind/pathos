package aifix

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"regexp"
	"strings"
)

// Span records where one hunk was applied (1-based line numbers): Old
// lines starting at OldStart became New lines starting at NewStart.
type Span struct {
	OldStart, OldCount, NewStart, NewCount int
}

// Applied is the result of applying a diff to one file.
type Applied struct {
	Path     string
	Original []byte
	Patched  []byte
	Spans    []Span
}

// MapLine maps a line of the original file to the range of lines it
// occupies after the fix (a changed line maps to its hunk's new lines).
func (a Applied) MapLine(line int) (from, to int) {
	delta := 0
	for _, s := range a.Spans {
		if line < s.OldStart {
			break
		}
		if line < s.OldStart+s.OldCount {
			if s.NewCount == 0 {
				return s.NewStart, s.NewStart
			}
			return s.NewStart, s.NewStart + s.NewCount - 1
		}
		delta += s.NewCount - s.OldCount
	}
	return line + delta, line + delta
}

// Apply applies d to the files under root and returns the patched
// contents; it does not write them. Each hunk is placed where its context
// and removed lines match the file (nearest to the line the hunk header
// gives). A line of the diff containing Placeholder matches a file line
// with any non-empty text in its place: the AI saw secrets redacted.
// Files must be regular, at most MaxFileBytes and not binary; symbolic
// links are refused, as is any path that leaves root.
func Apply(root string, d Diff) ([]Applied, error) {
	r, err := os.OpenRoot(root)
	if err != nil {
		return nil, err
	}
	defer r.Close()
	out := make([]Applied, 0, len(d.Files))
	for _, f := range d.Files {
		orig, err := readFile(r, f.Path)
		if err != nil {
			return nil, err
		}
		patched, spans, err := applyFile(orig, f)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", f.Path, err)
		}
		out = append(out, Applied{Path: f.Path, Original: orig, Patched: patched, Spans: spans})
	}
	return out, nil
}

func readFile(r *os.Root, p string) ([]byte, error) {
	// Every component is checked: os.Root follows links that stay inside
	// root, and a fix must not edit a file through a link at all.
	parts := strings.Split(p, "/")
	for i := range parts {
		st, err := r.Lstat(strings.Join(parts[:i+1], "/"))
		if errors.Is(err, fs.ErrNotExist) {
			return nil, fmt.Errorf("%s does not exist in the checkout", p)
		}
		if err != nil {
			return nil, err
		}
		if st.Mode()&fs.ModeSymlink != 0 {
			return nil, fmt.Errorf("%s is or goes through a symbolic link", p)
		}
		if i == len(parts)-1 && !st.Mode().IsRegular() {
			return nil, fmt.Errorf("%s is not a regular file", p)
		}
		if i == len(parts)-1 && st.Size() > MaxFileBytes {
			return nil, fmt.Errorf("%s is larger than %d bytes", p, MaxFileBytes)
		}
	}
	fh, err := r.Open(p)
	if err != nil {
		return nil, err
	}
	defer fh.Close()
	b, err := io.ReadAll(io.LimitReader(fh, MaxFileBytes+1))
	if err != nil {
		return nil, err
	}
	if len(b) > MaxFileBytes {
		return nil, fmt.Errorf("%s is larger than %d bytes", p, MaxFileBytes)
	}
	if bytes.IndexByte(b, 0) >= 0 {
		return nil, fmt.Errorf("%s is a binary file", p)
	}
	return b, nil
}

type matcher func(string) bool

func lineMatcher(want string) matcher {
	if strings.Contains(want, Placeholder) {
		parts := strings.Split(strings.TrimRight(want, " \t"), Placeholder)
		for i, p := range parts {
			parts[i] = regexp.QuoteMeta(p)
		}
		re := regexp.MustCompile(`^` + strings.Join(parts, `.+?`) + `[ \t]*$`)
		return re.MatchString
	}
	trimmed := strings.TrimRight(want, " \t")
	return func(got string) bool { return got == want || strings.TrimRight(got, " \t") == trimmed }
}

func applyFile(orig []byte, f FileDiff) ([]byte, []Span, error) {
	text := string(orig)
	crlf := strings.Contains(text, "\r\n")
	if crlf {
		text = strings.ReplaceAll(text, "\r\n", "\n")
	}
	finalNL := strings.HasSuffix(text, "\n")
	src := strings.Split(strings.TrimSuffix(text, "\n"), "\n")
	if text == "" {
		src = nil
	}
	var dst []string
	var spans []Span
	pos := 0 // next unconsumed source line (0-based)
	delta := 0
	for hi, h := range f.Hunks {
		var old []matcher
		for _, l := range h.Lines {
			if l[0] != '+' {
				old = append(old, lineMatcher(l[1:]))
			}
		}
		at := locate(src, old, pos, h.OldStart-1+delta)
		if at < 0 {
			return nil, nil, fmt.Errorf("hunk %d does not match the file (its context or removed lines differ from the code)", hi+1)
		}
		dst = append(dst, src[pos:at]...)
		newStart := len(dst) + 1
		i := at
		added := 0
		for _, l := range h.Lines {
			switch l[0] {
			case '+':
				dst = append(dst, l[1:])
				added++
			case '-':
				i++
			default:
				dst = append(dst, src[i]) // the file's own text (may be redacted in the diff)
				i++
				added++
			}
		}
		spans = append(spans, Span{OldStart: at + 1, OldCount: len(old), NewStart: newStart, NewCount: added})
		delta += added - len(old)
		pos = i
	}
	dst = append(dst, src[pos:]...)
	out := strings.Join(dst, "\n")
	if finalNL && len(dst) > 0 {
		out += "\n"
	}
	if crlf {
		out = strings.ReplaceAll(out, "\n", "\r\n")
	}
	return []byte(out), spans, nil
}

// locate finds where the old lines match, at or after min, nearest to
// want (-1 when they match nowhere).
func locate(src []string, old []matcher, min, want int) int {
	matches := func(at int) bool {
		if at < min || at+len(old) > len(src) {
			return false
		}
		for k, m := range old {
			if !m(src[at+k]) {
				return false
			}
		}
		return true
	}
	if want < min {
		want = min
	}
	for d := 0; d <= len(src); d++ {
		if matches(want + d) {
			return want + d
		}
		if d > 0 && matches(want-d) {
			return want - d
		}
	}
	return -1
}
