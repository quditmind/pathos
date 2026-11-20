package rea

import (
	"encoding/json"
	"errors"
	"slices"
	"strings"
	"testing"

	"pathos/internal/codegraph"
	"pathos/internal/platform/httpx"
)

const sha = "4e1f0a6b2c3d4e5f60718293a4b5c6d7e8f90123456789abcdef0123456789ab"

// testDoc is a small Go server binary with a planted net/http/pprof
// import (labelled test data, shaped like pathos-rea output).
func testDoc(t *testing.T) []byte {
	t.Helper()
	d := map[string]any{
		"schema":    Schema,
		"generator": map[string]string{"name": "pathos-rea", "version": "test"},
		"artifact": map[string]any{"file_name": "server", "sha256": sha, "size": 4096, "format": "elf", "arch": "x86", "bits": 64,
			"os": "linux", "language": "go", "entry": "0x401000"},
		"tools": map[string]any{"radare2": map[string]any{"version": "6.2.6", "status": "succeeded"},
			"binwalk": map[string]any{"version": "3.1.0", "status": "succeeded"}, "ghidra": map[string]any{"status": "skipped"}},
		"sections": []map[string]any{{"name": ".text", "offset": 4096, "vaddr": 4198400, "size": 8192, "perm": "r-x", "tool": "radare2"},
			{"name": ".rodata", "offset": 12288, "vaddr": 4206592, "size": 2048, "perm": "r--", "tool": "radare2"}},
		"functions": []map[string]any{
			{"id": "fn:0x401000", "name": "main.main", "addr": "0x401000", "offset": 4096, "size": 64, "section": ".text", "tool": "radare2", "package": "main"},
			{"id": "fn:0x401100", "name": "example.com/svc/internal/api.(*Server).Orders", "addr": "0x401100", "offset": 4352, "size": 64, "section": ".text", "tool": "radare2", "package": "example.com/svc/internal/api"},
			{"id": "fn:0x401200", "name": "example.com/svc/internal/api.backdoor", "addr": "0x401200", "offset": 4608, "size": 32, "section": ".text", "tool": "radare2", "package": "example.com/svc/internal/api"},
			{"id": "fn:0x402000", "name": "net/http/pprof.Index", "addr": "0x402000", "offset": 8192, "size": 128, "section": ".text", "tool": "radare2", "library": true, "package": "net/http/pprof"},
			{"id": "fn:0x402100", "name": "net/http/pprof.init.0", "addr": "0x402100", "offset": 8448, "size": 96, "section": ".text", "tool": "radare2", "library": true, "package": "net/http/pprof"},
		},
		"imports": []map[string]any{
			{"id": "imp:go:net/http/pprof", "name": "net/http/pprof", "kind": "package", "tool": "go"},
			{"id": "imp:go:example.com/svc/internal/api", "name": "example.com/svc/internal/api", "kind": "package", "tool": "go"},
			{"id": "imp:go:fmt", "name": "fmt", "kind": "package", "tool": "go"},
		},
		"strings": []map[string]any{
			{"id": "str:0x3010", "value": "/debug/pprof/", "offset": 12304, "section": ".rodata", "kind": "route", "tool": "radare2"},
			{"id": "str:0x3020", "value": "/api/orders", "offset": 12320, "section": ".rodata", "kind": "route", "tool": "radare2"},
			{"id": "str:0x3030", "value": "AKIAIOSFODNN7EXAMPLE", "offset": 12336, "section": ".rodata", "kind": "text", "tool": "radare2"},
			{"id": "str:0x3040", "value": "/etc/passwd", "offset": 12352, "section": ".rodata", "kind": "path", "tool": "radare2"},
		},
		"calls": []map[string]any{{"from": "fn:0x401000", "to": "fn:0x401100", "offset": 4100, "tool": "radare2"},
			{"from": "fn:0x401100", "to": "imp:go:fmt", "offset": 4360, "tool": "radare2"}},
		"string_refs": []map[string]any{{"from": "fn:0x402100", "to": "str:0x3010", "offset": 8460, "tool": "radare2"},
			{"from": "fn:0x401000", "to": "str:0x3020", "offset": 4110, "tool": "radare2"}},
		"go": map[string]any{"go_version": "go1.27.4", "path": "example.com/svc/cmd/server",
			"main_module": map[string]string{"path": "example.com/svc", "version": "(devel)"},
			"settings":    map[string]string{"vcs.revision": "0123456789abcdef0123456789abcdef01234567", "-ldflags": "-X main.token=ghp_0123456789abcdefghijklmnopqrstuvwxyzAB"}},
		"code":  []map[string]any{{"function": "fn:0x402100", "tool": "radare2", "kind": "disassembly", "text": "lea rax, str./debug/pprof/"}},
		"stats": map[string]any{"truncated": false},
	}
	b, err := json.Marshal(d)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func testSource() []SourceNode {
	return []SourceNode{
		{Key: "mod:cmd/server", Type: "module", Label: "cmd/server", Attrs: map[string]any{"path": "cmd/server", "qualified_name": "example.com/svc/cmd/server"}},
		{Key: "mod:internal/api", Type: "module", Label: "internal/api", Attrs: map[string]any{"path": "internal/api", "qualified_name": "example.com/svc/internal/api"}},
		{Key: "file:cmd/server/main.go", Type: "file", Label: "main.go", File: "cmd/server/main.go",
			Attrs: map[string]any{"sensitive_imports": "net/http/pprof:7"}},
		{Key: "fn:go:cmd/server.main", Type: "function", Label: "main", File: "cmd/server/main.go", Line: 10,
			Attrs: map[string]any{"qualified_name": "cmd/server.main"}},
		{Key: "fn:go:internal/api.(*Server).Orders", Type: "function", Label: "Orders", File: "internal/api/api.go", Line: 20,
			Attrs: map[string]any{"qualified_name": "internal/api.(*Server).Orders"}},
		{Key: "fn:go:internal/api.unused", Type: "function", Label: "unused", File: "internal/api/api.go", Line: 40,
			Attrs: map[string]any{"qualified_name": "internal/api.unused"}},
		{Key: "route:GET /api/orders", Type: "route", Label: "GET /api/orders", File: "internal/api/api.go", Line: 15,
			Attrs: map[string]any{"path": "/api/orders", "method": "GET"}},
		{Key: "route:GET /healthz", Type: "route", Label: "GET /healthz", File: "internal/api/api.go", Line: 16,
			Attrs: map[string]any{"path": "/healthz", "method": "GET"}},
	}
}

func TestParseDocRedactsAndValidates(t *testing.T) {
	d, err := ParseDoc(testDoc(t), sha)
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range d.Strings {
		if strings.Contains(s.Value, "AKIAIOSFODNN7EXAMPLE") {
			t.Errorf("secret string kept: %+v", s)
		}
	}
	if v := d.Go.Settings["-ldflags"]; strings.Contains(v, "ghp_0123456789") {
		t.Errorf("secret in build settings kept: %q", v)
	}
	if _, err := ParseDoc(testDoc(t), strings.Repeat("0", 64)); err == nil {
		t.Error("a document for another artifact was accepted")
	}
	bad := strings.Replace(string(testDoc(t)), `"to":"fn:0x401100"`, `"to":"fn:0xdead"`, 1)
	var ve *ValidationError
	if _, err := ParseDoc([]byte(bad), sha); !errors.As(err, &ve) {
		t.Errorf("dangling call accepted: %v", err)
	}
	if _, err := ParseDoc([]byte(`{"schema":"pathos.codegraph/v1"}`), ""); !errors.As(err, &ve) {
		t.Error("wrong schema accepted")
	}
}

func TestGraphHasBinaryEvidenceOnEveryEdge(t *testing.T) {
	d, err := ParseDoc(testDoc(t), sha)
	if err != nil {
		t.Fatal(err)
	}
	g := d.Graph()
	if err := codegraph.ValidateBinary(g); err != nil {
		t.Fatal(err)
	}
	types := map[string]int{}
	for _, n := range g.Nodes {
		types[n.Type]++
	}
	for _, typ := range []string{"binary", "binary_function", "import", "string_ref", "section"} {
		if types[typ] == 0 {
			t.Errorf("no %s node", typ)
		}
	}
	edgeTypes := map[string]bool{}
	for _, e := range g.Edges {
		edgeTypes[e.Type] = true
		if e.Evidence != "verified" || len(e.EvidenceRefs) == 0 {
			t.Fatalf("edge %s→%s without verified evidence", e.Source, e.Target)
		}
		for _, r := range e.EvidenceRefs {
			if r.Kind != "binary" || !strings.HasPrefix(r.Ref, "0x") || !strings.Contains(r.Detail, ":") {
				t.Errorf("edge %s→%s: evidence %+v is not offset and tool", e.Source, e.Target, r)
			}
		}
	}
	for _, typ := range []string{"defines", "calls", "imports", "references"} {
		if !edgeTypes[typ] {
			t.Errorf("no %s edge", typ)
		}
	}
	// A source-style reference is refused for a binary graph.
	g.Edges[0].EvidenceRefs = []codegraph.EvidenceRef{{Kind: "file_line", Ref: "main.go:1"}}
	if codegraph.ValidateBinary(g) == nil {
		t.Error("a binary edge with a file_line reference was accepted")
	}
}

func TestCompareGoBinaryWithPlantedPprof(t *testing.T) {
	d, err := ParseDoc(testDoc(t), sha)
	if err != nil {
		t.Fatal(err)
	}
	items := Compare(d, testSource())
	find := func(side, kind, name string) *DiffItem {
		for i := range items {
			if items[i].Side == side && items[i].Kind == kind && items[i].Name == name {
				return &items[i]
			}
		}
		return nil
	}
	if it := find("matched", "function", "main.main"); it == nil || it.SourceFile != "cmd/server/main.go" {
		t.Errorf("main.main not matched: %+v", it)
	}
	if find("matched", "function", "example.com/svc/internal/api.(*Server).Orders") == nil {
		t.Error("method not matched through the module path")
	}
	if find("binary_only", "function", "example.com/svc/internal/api.backdoor") == nil {
		t.Error("a function only in the binary was not reported")
	}
	if find("source_only", "function", "unused") == nil {
		t.Error("a source function missing from the binary was not reported")
	}
	route := find("binary_only", "route", "/debug/pprof/")
	if route == nil || !route.Sensitive || route.SensitiveID != "rea/go-pprof" {
		t.Fatalf("pprof route only in the binary not flagged: %+v", route)
	}
	var hasOffset, hasImportLine bool
	for _, e := range route.Evidence {
		hasOffset = hasOffset || (e.Kind == "binary" && e.Ref == "0x3010")
		hasImportLine = hasImportLine || (e.Kind == "file_line" && e.Ref == "cmd/server/main.go:7")
	}
	if !hasOffset || !hasImportLine {
		t.Errorf("route evidence: %+v", route.Evidence)
	}
	if pkg := find("matched", "package", "net/http/pprof"); pkg == nil || !pkg.Sensitive || pkg.SourceLine != 7 {
		t.Errorf("pprof package: %+v", pkg)
	}
	if find("matched", "route", "/api/orders") == nil || find("source_only", "route", "GET /healthz") == nil {
		t.Error("routes: matched or source-only missing")
	}
	if find("binary_only", "route", "/etc/passwd") != nil {
		t.Error("a file path was taken for a route")
	}
	for _, it := range items {
		if len(it.Evidence) == 0 {
			t.Errorf("item without evidence: %+v", it)
		}
		if it.Kind == "package" && it.Name == "fmt" {
			t.Error("a non-sensitive standard-library package was reported")
		}
	}
	drafts := Drafts(items, "server")
	if len(drafts) != 1 || drafts[0].RuleID != "rea/go-pprof" || drafts[0].Severity != "high" || !strings.Contains(drafts[0].Description, "proposal") {
		t.Fatalf("drafts: %+v", drafts)
	}
	if !slices.ContainsFunc(drafts[0].Evidence, func(e EvidenceItem) bool { return e.Ref == "cmd/server/main.go:7" }) {
		t.Errorf("draft evidence lacks the import line: %+v", drafts[0].Evidence)
	}
}

func TestComparePprofWithoutSourceImport(t *testing.T) {
	d, err := ParseDoc(testDoc(t), sha)
	if err != nil {
		t.Fatal(err)
	}
	src := slices.DeleteFunc(testSource(), func(n SourceNode) bool { return n.Type == "file" })
	items := Compare(d, src)
	var pkg *DiffItem
	for i := range items {
		if items[i].Kind == "package" && items[i].Name == "net/http/pprof" {
			pkg = &items[i]
		}
	}
	if pkg == nil || pkg.Side != "binary_only" || !pkg.Sensitive {
		t.Fatalf("pprof linked without a source import: %+v", pkg)
	}
	if d := Drafts(items, "server"); len(d) != 1 || !strings.Contains(d[0].Description, "/debug/pprof/") {
		t.Errorf("one grouped draft expected: %+v", d)
	}
}

func TestNativeSensitiveImports(t *testing.T) {
	d := &Doc{Artifact: Artifact{Language: "c"}, Imports: []Import{
		{ID: "imp:libc.so.6!system", Name: "system", Library: "libc.so.6", Offset: 100, Tool: "radare2"},
		{ID: "imp:libc.so.6!puts", Name: "puts", Library: "libc.so.6", Offset: 120, Tool: "radare2"}}}
	items := Compare(d, nil)
	if len(items) != 1 || items[0].Name != "libc.so.6!system" || items[0].SensitiveID != "rea/native-exec" {
		t.Fatalf("items: %+v", items)
	}
}

func TestRouteLike(t *testing.T) {
	for _, s := range []string{"/debug/pprof/", "/api/v1/orders/{id}", "/healthz"} {
		if !routeLike(s) {
			t.Errorf("%q should be route-like", s)
		}
	}
	for _, s := range []string{"/etc/passwd", "/proc/self/maps", "/usr/lib/libc.so.6", "/", "/tmp/x", "//double", "/x.go"} {
		if routeLike(s) {
			t.Errorf("%q should not be route-like", s)
		}
	}
	if normRoute("/users/:id/") != normRoute("/users/{id}") {
		t.Error("normRoute")
	}
}

func TestDecompiledCodePolicy(t *testing.T) {
	st := DefaultSettings()
	if st.DecompiledCodeAI != "none" || DecompiledCodeAllowed(st, "self_hosted") == nil {
		t.Fatal("by default no model may see decompiled code")
	}
	st.DecompiledCodeAI = "local"
	if DecompiledCodeAllowed(st, "self_hosted") != nil || DecompiledCodeAllowed(st, "anthropic") == nil {
		t.Error("local: self-hosted only")
	}
	st.DecompiledCodeAI = "cloud"
	if DecompiledCodeAllowed(st, "openai") == nil {
		t.Error("cloud without the AI send-code setting must be refused")
	}
	st.AISendCode = true
	if DecompiledCodeAllowed(st, "openai") != nil {
		t.Error("cloud with explicit permission")
	}
	var he *httpx.Error
	if err := DecompiledCodeAllowed(DefaultSettings(), "openai"); !errors.As(err, &he) || he.DiagCode() != CodeCodeWithheld {
		t.Errorf("withheld error: %v", err)
	}
}

func TestSettingsValidate(t *testing.T) {
	st := DefaultSettings()
	if err := st.validate(false); err != nil {
		t.Fatal(err)
	}
	for _, mut := range []func(*Settings){
		func(s *Settings) { s.EnabledTools = []string{"frida"} },
		func(s *Settings) { s.EnabledTools = nil },
		func(s *Settings) { s.MemoryMB = 100 },
		func(s *Settings) { s.TimeoutMinutes = 1000 },
		func(s *Settings) { s.InputPolicy = "anything" },
		func(s *Settings) { s.DecompiledCodeAI = "cloud" }, // the AI configuration does not allow code
	} {
		s := DefaultSettings()
		mut(&s)
		if s.validate(false) == nil {
			t.Errorf("accepted %+v", s)
		}
	}
	s := DefaultSettings()
	s.DecompiledCodeAI = "cloud"
	if s.validate(true) != nil {
		t.Error("cloud with the AI send-code setting should be accepted")
	}
}

func TestParseVersionLine(t *testing.T) {
	got := parseVersionLine("pathos-rea 3.0.0-dev; radare2 6.2.6; binwalk 3.1.0; ghidra -; jadx -; ilspy -")
	if got["radare2"] != "6.2.6" || got["binwalk"] != "3.1.0" || got["ghidra"] != "" || got["pathos-rea"] != "3.0.0-dev" {
		t.Errorf("%v", got)
	}
}

func TestParseDocAcceptsHexAddressesAndUnknownOffsets(t *testing.T) {
	raw := strings.Replace(string(testDoc(t)), `"vaddr":4198400`, `"vaddr":"0x401000"`, 1)
	raw = strings.Replace(raw, `"offset":4352`, `"offset":-1`, 1)
	d, err := ParseDoc([]byte(raw), sha)
	if err != nil {
		t.Fatal(err)
	}
	if d.Sections[0].VAddr != 0x401000 || d.Functions[1].Offset != 0 {
		t.Errorf("vaddr %x offset %d", d.Sections[0].VAddr, d.Functions[1].Offset)
	}
}

func TestParseDocHashesLongIDs(t *testing.T) {
	long := "fn:0x401000" + strings.Repeat("[go.shape.struct { x/y.z int }]", 20)
	raw := strings.ReplaceAll(string(testDoc(t)), `"fn:0x401000"`, `"`+long+`"`)
	d, err := ParseDoc([]byte(raw), sha)
	if err != nil {
		t.Fatal(err)
	}
	id := d.Functions[0].ID
	if !strings.HasPrefix(id, "fn:h:") || d.Calls[0].From != id || d.StringRefs[1].From != id {
		t.Errorf("renamed id %q not applied: %+v %+v", id, d.Calls[0], d.StringRefs[1])
	}
	if err := codegraph.ValidateBinary(d.Graph()); err != nil {
		t.Error(err)
	}
}

func TestWeakCryptoLinkedByTheStandardLibraryIsNotReported(t *testing.T) {
	d := &Doc{Artifact: Artifact{Language: "go"}, Go: &GoInfo{},
		Functions: []Function{{ID: "fn:0x10", Name: "crypto/md5.Sum", Package: "crypto/md5", Offset: 16, Library: true, Tool: "pathos-rea"}},
		Imports:   []Import{{ID: "imp:go:crypto/md5", Name: "crypto/md5", Kind: "package", Tool: "pathos-rea"}}}
	if items := Compare(d, nil); len(items) != 0 {
		t.Errorf("weak crypto linked by the standard library reported: %+v", items)
	}
	src := []SourceNode{{Key: "file:a.go", Type: "file", File: "a.go", Attrs: map[string]any{"sensitive_imports": "crypto/md5:3"}}}
	items := Compare(d, src)
	if len(items) != 1 || items[0].Side != "matched" || items[0].BinaryOffset != 16 {
		t.Errorf("imported weak crypto: %+v", items)
	}
}
