package reachscan

import (
	"strings"
	"unicode"
	"unicode/utf8"
)

// The lexers turn source text into identifiers, string literals, numbers
// and punctuation, without comments. They are deliberately forgiving: a
// construct they do not understand costs at most the rest of its line,
// never the file.

type tokKind byte

const (
	tIdent  tokKind = 'i'
	tString tokKind = 's'
	tNumber tokKind = 'n'
	tPunct  tokKind = 'p'
)

type token struct {
	kind tokKind
	text string // identifier, string value or punctuation
	line int
	// first: the first token of a logical line (Python), with its
	// indentation in col.
	first bool
	col   int
}

func isIdentStart(r rune) bool { return r == '_' || r == '$' || unicode.IsLetter(r) }
func isIdentPart(r rune) bool  { return isIdentStart(r) || unicode.IsDigit(r) }

// multi-character punctuation that matters to the analyzers.
var puncts = []string{"...", "=>", "->", "::", "?.", "==", "!=", "<=", ">=", "&&", "||", "**", "+=", "-="}

type lexer struct {
	src  string
	pos  int
	line int
	out  []token
}

func (l *lexer) emit(k tokKind, s string, line int) {
	l.out = append(l.out, token{kind: k, text: s, line: line})
}

func (l *lexer) peekRune(off int) rune {
	if l.pos+off >= len(l.src) {
		return 0
	}
	r, _ := utf8.DecodeRuneInString(l.src[l.pos+off:])
	return r
}

// ident reads an identifier at pos.
func (l *lexer) ident() string {
	start := l.pos
	for l.pos < len(l.src) {
		r, n := utf8.DecodeRuneInString(l.src[l.pos:])
		if !isIdentPart(r) {
			break
		}
		l.pos += n
	}
	return l.src[start:l.pos]
}

func (l *lexer) number() {
	start := l.pos
	for l.pos < len(l.src) {
		c := l.src[l.pos]
		if c == '.' || c == '_' || (c >= '0' && c <= '9') || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') {
			l.pos++
			continue
		}
		break
	}
	l.emit(tNumber, l.src[start:l.pos], l.line)
}

// quoted reads a single-line string literal opened by q (pos after the
// quote). An unterminated literal ends at the end of the line, so stray
// apostrophes (JSX text) cost one line at most.
func (l *lexer) quoted(q byte) string {
	var b strings.Builder
	for l.pos < len(l.src) {
		c := l.src[l.pos]
		switch {
		case c == '\\' && l.pos+1 < len(l.src):
			if l.src[l.pos+1] == '\n' {
				l.line++
			}
			b.WriteByte(l.src[l.pos+1])
			l.pos += 2
			continue
		case c == q:
			l.pos++
			return b.String()
		case c == '\n':
			return b.String()
		}
		b.WriteByte(c)
		l.pos++
	}
	return b.String()
}

// punct emits the punctuation at pos.
func (l *lexer) punct() {
	for _, p := range puncts {
		if strings.HasPrefix(l.src[l.pos:], p) {
			l.emit(tPunct, p, l.line)
			l.pos += len(p)
			return
		}
	}
	l.emit(tPunct, l.src[l.pos:l.pos+1], l.line)
	l.pos++
}

// --- JavaScript and TypeScript ----------------------------------------------

// jsRegexAfter: after these tokens a slash starts a regular expression.
func jsSlashIsRegex(prev *token) bool {
	if prev == nil {
		return true
	}
	switch prev.kind {
	case tNumber, tString:
		return false
	case tIdent:
		switch prev.text {
		case "return", "typeof", "instanceof", "in", "of", "new", "delete", "void", "throw", "case", "do", "else", "yield", "await":
			return true
		}
		return false
	}
	switch prev.text {
	case ")", "]", "}":
		return false
	}
	return true
}

func lexJS(src string) []token {
	l := &lexer{src: src, line: 1}
	// braces counts open braces per template substitution level: a "}"
	// that closes a substitution resumes the template literal.
	var braces []int
	for l.pos < len(l.src) {
		c := l.src[l.pos]
		switch {
		case c == '\n':
			l.line++
			l.pos++
		case c == ' ' || c == '\t' || c == '\r' || c == '\f' || c == '\v':
			l.pos++
		case strings.HasPrefix(l.src[l.pos:], "//"):
			for l.pos < len(l.src) && l.src[l.pos] != '\n' {
				l.pos++
			}
		case strings.HasPrefix(l.src[l.pos:], "/*"):
			end := strings.Index(l.src[l.pos+2:], "*/")
			if end < 0 {
				end = len(l.src) - l.pos - 2
			}
			l.line += strings.Count(l.src[l.pos:l.pos+2+end], "\n")
			l.pos += end + 4
		case c == '"' || c == '\'':
			line := l.line
			l.pos++
			l.emit(tString, l.quoted(c), line)
		case c == '`':
			l.pos++
			if l.template() {
				braces = append(braces, 0)
			}
		case c == '/':
			var prev *token
			if len(l.out) > 0 {
				prev = &l.out[len(l.out)-1]
			}
			if jsSlashIsRegex(prev) {
				l.regex()
			} else {
				l.punct()
			}
		case c == '{':
			if len(braces) > 0 {
				braces[len(braces)-1]++
			}
			l.punct()
		case c == '}':
			if len(braces) > 0 {
				if braces[len(braces)-1] == 0 {
					// End of a ${...} substitution: back in the template.
					braces = braces[:len(braces)-1]
					l.pos++
					l.emit(tPunct, ")", l.line)
					if l.template() {
						braces = append(braces, 0)
					}
					continue
				}
				braces[len(braces)-1]--
			}
			l.punct()
		case c >= '0' && c <= '9':
			l.number()
		default:
			r := l.peekRune(0)
			if isIdentStart(r) || r == '#' && isIdentStart(l.peekRune(1)) {
				line := l.line
				if r == '#' {
					l.pos++
				}
				l.emit(tIdent, l.ident(), line)
				continue
			}
			if r >= utf8.RuneSelf {
				_, n := utf8.DecodeRuneInString(l.src[l.pos:])
				l.pos += n
				continue
			}
			l.punct()
		}
	}
	return l.out
}

// template reads a template literal from after "`" (or after the "}" of a
// substitution) to the closing "`" or to "${". The literal is emitted as a
// string; a substitution is emitted as "(" so that its expression reads as
// an argument. It reports whether a substitution was opened.
func (l *lexer) template() bool {
	line := l.line
	var b strings.Builder
	for l.pos < len(l.src) {
		c := l.src[l.pos]
		switch {
		case c == '\\' && l.pos+1 < len(l.src):
			if l.src[l.pos+1] == '\n' {
				l.line++
			}
			b.WriteByte(l.src[l.pos+1])
			l.pos += 2
			continue
		case c == '`':
			l.pos++
			l.emit(tString, b.String(), line)
			return false
		case c == '$' && l.pos+1 < len(l.src) && l.src[l.pos+1] == '{':
			l.pos += 2
			l.emit(tString, b.String(), line)
			l.emit(tPunct, "(", l.line)
			return true
		case c == '\n':
			l.line++
		}
		b.WriteByte(c)
		l.pos++
	}
	l.emit(tString, b.String(), line)
	return false
}

// regex skips a regular expression literal (pos at the slash).
func (l *lexer) regex() {
	l.pos++
	inClass := false
	for l.pos < len(l.src) {
		c := l.src[l.pos]
		switch {
		case c == '\\':
			l.pos += 2
			continue
		case c == '\n':
			return
		case c == '[':
			inClass = true
		case c == ']':
			inClass = false
		case c == '/' && !inClass:
			l.pos++
			for l.pos < len(l.src) && (l.src[l.pos] >= 'a' && l.src[l.pos] <= 'z') {
				l.pos++
			}
			l.emit(tString, "", l.line)
			return
		}
		l.pos++
	}
}

// --- Python -----------------------------------------------------------------

func lexPython(src string) []token {
	l := &lexer{src: src, line: 1}
	depth := 0 // brackets: newlines inside them do not end a logical line
	lineStart := true
	col := 0
	for l.pos < len(l.src) {
		c := l.src[l.pos]
		if lineStart {
			col = 0
			for l.pos < len(l.src) && (l.src[l.pos] == ' ' || l.src[l.pos] == '\t') {
				if l.src[l.pos] == '\t' {
					col += 8 - col%8
				} else {
					col++
				}
				l.pos++
			}
			if l.pos >= len(l.src) {
				break
			}
			c = l.src[l.pos]
			if c == '\n' || c == '#' || c == '\r' {
				// blank or comment-only line: the indentation does not count
				for l.pos < len(l.src) && l.src[l.pos] != '\n' {
					l.pos++
				}
				if l.pos < len(l.src) {
					l.line++
					l.pos++
				}
				continue
			}
		}
		first := lineStart && depth == 0
		lineStart = false
		n := len(l.out)
		switch {
		case c == '\n':
			l.line++
			l.pos++
			if depth == 0 {
				lineStart = true
			}
		case c == '\\' && l.pos+1 < len(l.src) && l.src[l.pos+1] == '\n':
			l.line++
			l.pos += 2
		case c == ' ' || c == '\t' || c == '\r' || c == '\f':
			l.pos++
		case c == '#':
			for l.pos < len(l.src) && l.src[l.pos] != '\n' {
				l.pos++
			}
		case c == '"' || c == '\'':
			l.pyString("")
		case c >= '0' && c <= '9':
			l.number()
		default:
			r := l.peekRune(0)
			if isIdentStart(r) && r != '$' {
				line := l.line
				id := l.ident()
				// string prefixes: r, b, u, f and their combinations
				if len(id) <= 2 && l.pos < len(l.src) && (l.src[l.pos] == '"' || l.src[l.pos] == '\'') &&
					strings.Trim(strings.ToLower(id), "rbuf") == "" {
					l.pyString(strings.ToLower(id))
					break
				}
				l.emit(tIdent, id, line)
				break
			}
			if r >= utf8.RuneSelf {
				_, sz := utf8.DecodeRuneInString(l.src[l.pos:])
				l.pos += sz
				break
			}
			switch c {
			case '(', '[', '{':
				depth++
			case ')', ']', '}':
				if depth > 0 {
					depth--
				}
			}
			l.punct()
		}
		if first && len(l.out) > n {
			l.out[n].first, l.out[n].col = true, col
		}
	}
	return l.out
}

// pyString reads a string literal (pos at the quote). Expressions in
// f-string replacement fields are lexed as code.
func (l *lexer) pyString(prefix string) {
	q := l.src[l.pos]
	triple := strings.HasPrefix(l.src[l.pos:], strings.Repeat(string(q), 3))
	line := l.line
	start := l.pos + 1
	if triple {
		start = l.pos + 3
	}
	end := start
	raw := strings.Contains(prefix, "r")
	for end < len(l.src) {
		c := l.src[end]
		if c == '\\' && !raw && end+1 < len(l.src) {
			end += 2
			continue
		}
		if c == '\\' && raw && end+1 < len(l.src) && l.src[end+1] == q {
			end += 2
			continue
		}
		if triple && strings.HasPrefix(l.src[end:], strings.Repeat(string(q), 3)) {
			break
		}
		if !triple && (c == q || c == '\n') {
			break
		}
		end++
	}
	body := l.src[start:min(end, len(l.src))]
	l.pos = end
	if l.pos < len(l.src) && l.src[l.pos] != '\n' {
		if triple {
			l.pos += 3
		} else {
			l.pos++
		}
	}
	l.pos = min(l.pos, len(l.src))
	if strings.Contains(prefix, "f") {
		// replacement fields {expr} (not {{ }}) are code
		bodyLine := line
		for i := 0; i < len(body); i++ {
			switch body[i] {
			case '\n':
				bodyLine++
			case '{':
				if i+1 < len(body) && body[i+1] == '{' {
					i++
					continue
				}
				j := strings.IndexByte(body[i:], '}')
				if j < 0 {
					break
				}
				for _, t := range lexPython(body[i+1 : i+j]) {
					t.line += bodyLine - 1
					t.first = false
					l.out = append(l.out, t)
				}
				i += j
			}
		}
	}
	l.emit(tString, body, line)
	l.line += strings.Count(l.src[start-1:l.pos], "\n")
}

// --- Java -------------------------------------------------------------------

func lexJava(src string) []token {
	l := &lexer{src: src, line: 1}
	for l.pos < len(l.src) {
		c := l.src[l.pos]
		switch {
		case c == '\n':
			l.line++
			l.pos++
		case c == ' ' || c == '\t' || c == '\r' || c == '\f':
			l.pos++
		case strings.HasPrefix(l.src[l.pos:], "//"):
			for l.pos < len(l.src) && l.src[l.pos] != '\n' {
				l.pos++
			}
		case strings.HasPrefix(l.src[l.pos:], "/*"):
			end := strings.Index(l.src[l.pos+2:], "*/")
			if end < 0 {
				end = len(l.src) - l.pos - 2
			}
			l.line += strings.Count(l.src[l.pos:l.pos+2+end], "\n")
			l.pos += end + 4
		case strings.HasPrefix(l.src[l.pos:], `"""`):
			line := l.line
			end := strings.Index(l.src[l.pos+3:], `"""`)
			if end < 0 {
				end = len(l.src) - l.pos - 3
			}
			body := l.src[l.pos+3 : l.pos+3+end]
			l.line += strings.Count(body, "\n")
			l.pos = min(l.pos+6+end, len(l.src))
			l.emit(tString, body, line)
		case c == '"' || c == '\'':
			line := l.line
			l.pos++
			l.emit(tString, l.quoted(c), line)
		case c >= '0' && c <= '9':
			l.number()
		default:
			r := l.peekRune(0)
			if isIdentStart(r) {
				line := l.line
				l.emit(tIdent, l.ident(), line)
				continue
			}
			if r >= utf8.RuneSelf {
				_, n := utf8.DecodeRuneInString(l.src[l.pos:])
				l.pos += n
				continue
			}
			l.punct()
		}
	}
	return l.out
}
