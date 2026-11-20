// Package rea is reverse engineering, static tier (PATHOS 3.0 M10,
// docs/aspm/PATHOS_REVERSE_ENGINEERING.md, ADR-009): the input policy (own
// builds by default), analyses queued in their own lane for worker-rea (the
// analyser runs in the sandbox runner and never executes the artifact),
// the facts stored as a binary graph in the CodeGraph store, the source ↔
// binary diff against the CodeGraph snapshot of the artifact's commit, and
// finding drafts (proposals only) for sensitive code found only in the
// binary.
package rea

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"unicode/utf8"

	"pathos/internal/ai"
	"pathos/internal/codegraph"
	"pathos/internal/platform/logging"
)

// Schema is the analysis document schema (pathos-rea output).
const Schema = "pathos.rea/v1"

// Doc is an analysis document.
type Doc struct {
	Schema     string             `json:"schema"`
	Generator  map[string]string  `json:"generator"`
	Artifact   Artifact           `json:"artifact"`
	Tools      map[string]ToolRun `json:"tools"`
	Sections   []Section          `json:"sections"`
	Functions  []Function         `json:"functions"`
	Imports    []Import           `json:"imports"`
	Exports    []Export           `json:"exports"`
	Strings    []String           `json:"strings"`
	Calls      []Ref              `json:"calls"`
	StringRefs []Ref              `json:"string_refs"`
	Go         *GoInfo            `json:"go"`
	Firmware   *Firmware          `json:"firmware"`
	Code       []Code             `json:"code"`
	Stats      map[string]any     `json:"stats"`
}

// Artifact describes the analysed file.
type Artifact struct {
	FileName string `json:"file_name"`
	SHA256   string `json:"sha256"`
	Size     int64  `json:"size"`
	Format   string `json:"format"`
	Arch     string `json:"arch"`
	Bits     int    `json:"bits"`
	OS       string `json:"os"`
	Language string `json:"language"`
	Stripped bool   `json:"stripped"`
	Entry    string `json:"entry"`
	BuildID  string `json:"build_id"`
}

// ToolRun is one analysis tool's outcome.
type ToolRun struct {
	Version    string `json:"version"`
	Status     string `json:"status"`
	Detail     string `json:"detail"`
	DurationMS int64  `json:"duration_ms"`
}

// Section of the artifact.
type Section struct {
	Name    string  `json:"name"`
	Offset  int64   `json:"offset"`
	VAddr   flexInt `json:"vaddr"`
	Size    int64   `json:"size"`
	VSize   int64   `json:"vsize"`
	Perm    string  `json:"perm"`
	Entropy float64 `json:"entropy"`
	Tool    string  `json:"tool"`
}

// Function found in the artifact.
type Function struct {
	ID      string `json:"id"`
	Name    string `json:"name"`
	Addr    string `json:"addr"`
	Offset  int64  `json:"offset"`
	Size    int64  `json:"size"`
	Section string `json:"section"`
	Tool    string `json:"tool"`
	Library bool   `json:"library"`
	Package string `json:"package"`
}

// Import is an imported function, object or (Go) linked package.
type Import struct {
	ID      string `json:"id"`
	Name    string `json:"name"`
	Library string `json:"library"`
	Kind    string `json:"kind"`
	Addr    string `json:"addr"`
	Offset  int64  `json:"offset"`
	Tool    string `json:"tool"`
}

// Export is an exported symbol.
type Export struct {
	Name   string `json:"name"`
	Addr   string `json:"addr"`
	Offset int64  `json:"offset"`
	Tool   string `json:"tool"`
}

// String found in the artifact (secrets already redacted by pathos-rea).
type String struct {
	ID       string  `json:"id"`
	Value    string  `json:"value"`
	Offset   int64   `json:"offset"`
	VAddr    flexInt `json:"vaddr"`
	Section  string  `json:"section"`
	Kind     string  `json:"kind"`
	Redacted bool    `json:"redacted"`
	Tool     string  `json:"tool"`
}

// Ref is a call or a string reference (from a function to a function,
// import or string) at a call site.
type Ref struct {
	From   string `json:"from"`
	To     string `json:"to"`
	Offset int64  `json:"offset"`
	Tool   string `json:"tool"`
}

// GoInfo is the Go build information embedded in a Go binary.
type GoInfo struct {
	GoVersion  string `json:"go_version"`
	Path       string `json:"path"`
	MainModule struct {
		Path    string `json:"path"`
		Version string `json:"version"`
	} `json:"main_module"`
	Deps []struct {
		Path    string `json:"path"`
		Version string `json:"version"`
	} `json:"deps"`
	Settings map[string]string `json:"settings"`
}

// Firmware is what binwalk found and extracted.
type Firmware struct {
	Entries []struct {
		Offset      int64  `json:"offset"`
		Type        string `json:"type"`
		Description string `json:"description"`
		Size        int64  `json:"size"`
		Extracted   bool   `json:"extracted"`
	} `json:"entries"`
	Files []struct {
		Path   string `json:"path"`
		Size   int64  `json:"size"`
		Type   string `json:"type"`
		SHA256 string `json:"sha256"`
	} `json:"files"`
}

// Code is a function's pseudo-C or disassembly.
type Code struct {
	Function string `json:"function"`
	Tool     string `json:"tool"`
	Kind     string `json:"kind"`
	Text     string `json:"text"`
}

// flexInt is an address given as a number or as a "0x…" string.
type flexInt int64

func (f *flexInt) UnmarshalJSON(b []byte) error {
	var n int64
	if err := json.Unmarshal(b, &n); err == nil {
		*f = flexInt(n)
		return nil
	}
	var s string
	if err := json.Unmarshal(b, &s); err != nil {
		return err
	}
	v, err := strconv.ParseInt(strings.TrimPrefix(strings.ToLower(s), "0x"), 16, 64)
	if err != nil && s != "" {
		return fmt.Errorf("invalid address %q", s)
	}
	*f = flexInt(v)
	return nil
}

// Limits of a stored analysis.
const (
	maxFunctions = 100_000
	maxImports   = 50_000
	maxStrings   = 100_000
	maxSections  = 2_000
	maxCalls     = 300_000
	maxCode      = 1_000
	maxCodeText  = 20_000
	maxValue     = 500
)

// ValidationError is a document that cannot be stored (PTH-REA-1005).
type ValidationError struct{ Msg string }

func (e *ValidationError) Error() string { return "invalid analysis document: " + e.Msg }

func invalid(format string, a ...any) error { return &ValidationError{Msg: fmt.Sprintf(format, a...)} }

var (
	toolNames  = map[string]bool{"radare2": true, "binwalk": true, "ghidra": true, "jadx": true, "ilspy": true, "pathos-rea": true, "go": true}
	idRe       = regexp.MustCompile(`^(fn|imp|str):[\x20-\x7e]{1,280}$`)
	sha256Re   = regexp.MustCompile(`^[0-9a-f]{64}$`)
	toolStatus = map[string]bool{"succeeded": true, "failed": true, "skipped": true, "timed_out": true}
	codeKinds  = map[string]bool{"pseudo_c": true, "disassembly": true, "java": true, "csharp": true}
)

// ParseDoc decodes and validates a document. Strings and code are
// redacted again (defence in depth: the analyser redacts first) and every
// text field is clipped and made valid UTF-8.
func ParseDoc(raw []byte, wantSHA256 string) (*Doc, error) {
	var d Doc
	dec := json.NewDecoder(bytes.NewReader(raw))
	if err := dec.Decode(&d); err != nil {
		return nil, invalid("not JSON: %v", err)
	}
	if d.Schema != Schema {
		return nil, invalid("schema %q, want %q", d.Schema, Schema)
	}
	a := &d.Artifact
	a.SHA256 = strings.ToLower(a.SHA256)
	if !sha256Re.MatchString(a.SHA256) {
		return nil, invalid("artifact sha256 missing")
	}
	if wantSHA256 != "" && a.SHA256 != wantSHA256 {
		return nil, invalid("the document describes artifact %s, not %s", a.SHA256[:12], wantSHA256[:min(12, len(wantSHA256))])
	}
	a.FileName, a.Format, a.Arch, a.OS, a.Language = text(a.FileName, 255), word(a.Format), word(a.Arch), word(a.OS), word(a.Language)
	a.Entry, a.BuildID = text(a.Entry, 32), text(a.BuildID, 128)
	switch {
	case len(d.Functions) > maxFunctions, len(d.Imports) > maxImports, len(d.Strings) > maxStrings, len(d.Sections) > maxSections,
		len(d.Calls)+len(d.StringRefs) > maxCalls, len(d.Code) > maxCode, len(d.Exports) > maxImports:
		return nil, invalid("the document exceeds the store limits")
	}
	for k, t := range d.Tools {
		if !toolNames[k] || !toolStatus[t.Status] {
			return nil, invalid("unknown tool %q or status %q", k, t.Status)
		}
		t.Version, t.Detail = text(t.Version, 100), logging.RedactString(text(t.Detail, 1000))
		d.Tools[k] = t
	}
	// Ids are graph node keys (at most 280 printable ASCII characters).
	// Names of generic Go instantiations can be far longer: such ids are
	// replaced by a hash, consistently in every reference.
	rename := map[string]string{}
	fix := func(id *string) {
		if idRe.MatchString(*id) {
			return
		}
		if r, ok := rename[*id]; ok {
			*id = r
			return
		}
		prefix, _, _ := strings.Cut(*id, ":")
		if prefix != "fn" && prefix != "imp" && prefix != "str" {
			return
		}
		h := sha256.Sum256([]byte(*id))
		r := prefix + ":h:" + hex.EncodeToString(h[:16])
		rename[*id] = r
		*id = r
	}
	for i := range d.Functions {
		fix(&d.Functions[i].ID)
	}
	for i := range d.Imports {
		fix(&d.Imports[i].ID)
	}
	for i := range d.Strings {
		fix(&d.Strings[i].ID)
	}
	for _, list := range [][]Ref{d.Calls, d.StringRefs} {
		for i := range list {
			if r, ok := rename[list[i].From]; ok {
				list[i].From = r
			}
			if r, ok := rename[list[i].To]; ok {
				list[i].To = r
			}
		}
	}
	for i := range d.Code {
		if r, ok := rename[d.Code[i].Function]; ok {
			d.Code[i].Function = r
		}
	}
	ids := map[string]bool{}
	checkID := func(id, prefix string) error {
		if !idRe.MatchString(id) || !strings.HasPrefix(id, prefix) {
			return invalid("invalid id %q", id)
		}
		if ids[id] {
			return invalid("duplicate id %q", id)
		}
		ids[id] = true
		return nil
	}
	for i := range d.Sections {
		s := &d.Sections[i]
		s.Name, s.Perm, s.Tool = text(s.Name, 200), text(s.Perm, 8), tool(s.Tool)
		// The analyser reports -1 for offsets it cannot determine.
		s.Offset, s.Size = max(s.Offset, 0), max(s.Size, 0)
	}
	for i := range d.Functions {
		f := &d.Functions[i]
		if err := checkID(f.ID, "fn:"); err != nil {
			return nil, err
		}
		f.Name, f.Addr, f.Section, f.Tool, f.Package = text(f.Name, maxValue), text(f.Addr, 32), text(f.Section, 200), tool(f.Tool), text(f.Package, 300)
		if f.Name == "" {
			f.Name = f.Addr
		}
		f.Offset, f.Size = max(f.Offset, 0), max(f.Size, 0)
	}
	for i := range d.Imports {
		m := &d.Imports[i]
		if err := checkID(m.ID, "imp:"); err != nil {
			return nil, err
		}
		m.Name, m.Library, m.Kind, m.Addr, m.Tool = text(m.Name, maxValue), text(m.Library, 300), word(m.Kind), text(m.Addr, 32), tool(m.Tool)
		if m.Offset < 0 {
			m.Offset = 0
		}
	}
	for i := range d.Strings {
		s := &d.Strings[i]
		if err := checkID(s.ID, "str:"); err != nil {
			return nil, err
		}
		v := text(s.Value, maxValue)
		if r := redactSecrets(v); r != v {
			v, s.Redacted = r, true
		}
		s.Value, s.Section, s.Kind, s.Tool = v, text(s.Section, 200), word(s.Kind), tool(s.Tool)
		if s.Redacted {
			s.Kind = "secret"
		}
		s.Offset = max(s.Offset, 0)
	}
	for _, list := range [][]Ref{d.Calls, d.StringRefs} {
		for i := range list {
			c := &list[i]
			if !ids[c.From] || !ids[c.To] || !strings.HasPrefix(c.From, "fn:") {
				return nil, invalid("reference %s → %s names an unknown id", c.From, c.To)
			}
			if c.Offset < 0 {
				c.Offset = 0
			}
			c.Tool = tool(c.Tool)
		}
	}
	for i := range d.StringRefs {
		if !strings.HasPrefix(d.StringRefs[i].To, "str:") {
			return nil, invalid("string reference to %q", d.StringRefs[i].To)
		}
	}
	for i := range d.Code {
		c := &d.Code[i]
		if !ids[c.Function] || !strings.HasPrefix(c.Function, "fn:") || !codeKinds[c.Kind] {
			return nil, invalid("code for unknown function %q or kind %q", c.Function, c.Kind)
		}
		c.Tool, c.Text = tool(c.Tool), redactSecrets(text(c.Text, maxCodeText))
	}
	for i := range d.Exports {
		e := &d.Exports[i]
		e.Name, e.Addr, e.Tool = text(e.Name, maxValue), text(e.Addr, 32), tool(e.Tool)
	}
	if g := d.Go; g != nil {
		g.GoVersion, g.Path = text(g.GoVersion, 64), text(g.Path, 300)
		g.MainModule.Path, g.MainModule.Version = text(g.MainModule.Path, 300), text(g.MainModule.Version, 100)
		if len(g.Deps) > 5000 {
			g.Deps = g.Deps[:5000]
		}
		set := map[string]string{}
		for k, v := range g.Settings {
			if len(set) < 100 {
				set[text(k, 64)] = logging.RedactString(text(v, 300))
			}
		}
		g.Settings = set
	}
	return &d, nil
}

// redactSecrets removes secret-looking values (the AI redactor: tokens,
// keys, assignments such as password=…, long hex and base64 blobs, private
// keys). Strings of an artifact are untrusted data and may hold embedded
// credentials; the analyser redacts first, the API again.
func redactSecrets(s string) string { return ai.Redact(s, nil) }

// text makes s valid UTF-8 without control characters (except tab and
// newline) and at most n bytes.
func text(s string, n int) string {
	if !utf8.ValidString(s) {
		s = strings.ToValidUTF8(s, "�")
	}
	s = strings.Map(func(r rune) rune {
		if r < 0x20 && r != '\t' && r != '\n' {
			return -1
		}
		return r
	}, s)
	if len(s) > n {
		for n > 0 && !utf8.RuneStart(s[n]) {
			n--
		}
		s = s[:n]
	}
	return s
}

var wordRe = regexp.MustCompile(`[^a-z0-9._+-]`)

func word(s string) string { return wordRe.ReplaceAllString(strings.ToLower(text(s, 32)), "") }

func tool(s string) string {
	if toolNames[s] {
		return s
	}
	return "pathos-rea"
}

// hexRef is the evidence reference of a file offset.
func hexRef(off int64) string { return "0x" + strconv.FormatInt(max(off, 0), 16) }

// Graph converts a document into a binary graph (CodeGraph store): the
// artifact, its sections, functions, imports and referenced strings, with
// defines, calls, imports and references edges. Every edge carries the
// file offset and the tool as binary evidence.
func (d *Doc) Graph() *codegraph.Doc {
	g := &codegraph.Doc{Schema: "pathos.codegraph.binary/v1", Engines: map[string]string{}}
	for k, t := range d.Tools {
		if t.Status == "succeeded" {
			g.Engines[k] = t.Version
		}
	}
	root := "bin:" + d.Artifact.SHA256
	g.Nodes = append(g.Nodes, codegraph.DocNode{Key: root, Type: "binary", Label: firstNonEmpty(d.Artifact.FileName, d.Artifact.SHA256[:12]),
		Attrs: map[string]any{"sha256": d.Artifact.SHA256, "format": d.Artifact.Format, "arch": d.Artifact.Arch, "language": d.Artifact.Language,
			"os": d.Artifact.OS, "stripped": d.Artifact.Stripped, "entry": d.Artifact.Entry, "size": float64(d.Artifact.Size)}})
	ev := func(off int64, t, what string) []codegraph.EvidenceRef {
		return []codegraph.EvidenceRef{{Kind: "binary", Ref: hexRef(off), Detail: text(t+": "+what, 500)}}
	}
	edge := func(src, typ, dst string, off int64, t, what string) {
		g.Edges = append(g.Edges, codegraph.DocEdge{Source: src, Target: dst, Type: typ, Evidence: codegraph.EvidenceVerified, EvidenceRefs: ev(off, t, what)})
	}
	secKey := map[string]string{}
	for i, s := range d.Sections {
		k := "sec:" + strconv.Itoa(i) + ":" + text(s.Name, 200)
		if _, dup := secKey[s.Name]; !dup {
			secKey[s.Name] = k
		}
		g.Nodes = append(g.Nodes, codegraph.DocNode{Key: k, Type: "section", Label: firstNonEmpty(s.Name, "section "+strconv.Itoa(i)), Parent: root,
			Attrs: map[string]any{"offset": float64(s.Offset), "vaddr": float64(int64(s.VAddr)), "size": float64(s.Size), "perm": s.Perm,
				"entropy": s.Entropy, "tool": s.Tool}})
		edge(root, "defines", k, s.Offset, s.Tool, "section "+s.Name)
	}
	for _, f := range d.Functions {
		parent := secKey[f.Section]
		g.Nodes = append(g.Nodes, codegraph.DocNode{Key: f.ID, Type: "binary_function", Label: f.Name, Parent: parent,
			Attrs: map[string]any{"addr": f.Addr, "offset": float64(f.Offset), "size": float64(f.Size), "section": f.Section, "tool": f.Tool,
				"library": f.Library, "package": f.Package, "language": d.Artifact.Language}})
		if parent != "" {
			edge(parent, "defines", f.ID, f.Offset, f.Tool, "function "+f.Name)
		}
	}
	for _, m := range d.Imports {
		g.Nodes = append(g.Nodes, codegraph.DocNode{Key: m.ID, Type: "import", Label: m.Name,
			Attrs: map[string]any{"library": m.Library, "kind": m.Kind, "addr": m.Addr, "offset": float64(m.Offset), "tool": m.Tool}})
		edge(root, "imports", m.ID, m.Offset, m.Tool, "import "+m.Name)
	}
	// Every string is a node (the strings API lists them); the string view
	// shows the referenced ones.
	for _, s := range d.Strings {
		g.Nodes = append(g.Nodes, codegraph.DocNode{Key: s.ID, Type: "string_ref", Label: text(s.Value, 200),
			Attrs: map[string]any{"offset": float64(s.Offset), "section": s.Section, "kind": s.Kind, "redacted": s.Redacted, "tool": s.Tool}})
	}
	for _, c := range d.Calls {
		edge(c.From, "calls", c.To, c.Offset, c.Tool, "call at "+hexRef(c.Offset))
	}
	for _, r := range d.StringRefs {
		edge(r.From, "references", r.To, r.Offset, r.Tool, "reference at "+hexRef(r.Offset))
	}
	return g
}

func firstNonEmpty(v ...string) string {
	for _, s := range v {
		if s != "" {
			return s
		}
	}
	return ""
}
