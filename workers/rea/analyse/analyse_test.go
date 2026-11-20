package main

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestRedact(t *testing.T) {
	cases := []struct {
		in, want string
		red      bool
	}{
		{"AKIAIOSFODNN7EXAMPLE", "[REDACTED:aws_access_key]", true},
		{"key=AKIAIOSFODNN7EXAMPLE;", "key=[REDACTED:aws_access_key];", true},
		{"ghp_" + strings.Repeat("a1B2", 9), "[REDACTED:github_token]", true},
		{"-----BEGIN RSA PRIVATE KEY-----\nMIIabc\n-----END RSA PRIVATE KEY-----", "[REDACTED:private_key]", true},
		{"postgres://app:s3cr3tPass@db:5432/x", "postgres://app:[REDACTED:password]@db:5432/x", true},
		{"password=Hunter2xYz9", "password=[REDACTED:password]", true},
		{"password=%s", "password=%s", false},
		{"hello, %s (%d)", "hello, %s (%d)", false},
		{"/debug/pprof/", "/debug/pprof/", false},
		{"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/", "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/", false},
		{"Zq8vT3kLm9Xr2Pw7Yb4Nc6Hd1Fg5Js0Q", "[REDACTED:high_entropy]", true},
	}
	for _, c := range cases {
		got, red := redact(c.in)
		if got != c.want || red != c.red {
			t.Errorf("redact(%q) = %q, %v; want %q, %v", c.in, got, red, c.want, c.red)
		}
	}
}

func TestClassify(t *testing.T) {
	for in, want := range map[string]string{
		"/debug/pprof/":         "route",
		"/api/orders":           "route",
		"/etc/passwd":           "path",
		"https://x.example/a":   "url",
		"hello, %s":             "format",
		"plain text":            "text",
		"/!/)/1/E":              "text",
		"/v1/users/{id}/orders": "route",
	} {
		if got := classify(in); got != want {
			t.Errorf("classify(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestGoPackage(t *testing.T) {
	for in, want := range map[string]string{
		"net/http/pprof.Index": "net/http/pprof",
		"main.main":            "main",
		"example.com/app/internal/x.(*Server).Handle":                  "example.com/app/internal/x",
		"example.com/app/internal/x.Fn.func1":                          "example.com/app/internal/x",
		"type:.eq.main.T":                                              "",
		"runtime.gcStart":                                              "runtime",
		"gopkg.in/yaml%2ev3.(*parser).parse":                           "gopkg.in/yaml.v3",
		"github.com/a/b.(*T[go.shape.int]).M":                          "github.com/a/b",
		"slices.sortFunc[go.shape.struct { encoding/json/v2.id int }]": "slices",
	} {
		if got := goPackage(in); got != want {
			t.Errorf("goPackage(%q) = %q, want %q", in, got, want)
		}
	}
	if goLibrary("main", "example.com/app") || goLibrary("example.com/app/x", "example.com/app") || !goLibrary("net/http", "example.com/app") {
		t.Error("goLibrary misclassifies")
	}
}

func TestSniff(t *testing.T) {
	for in, want := range map[string]string{"\x7fELF\x02": "elf", "MZ\x90": "pe", "PK\x03\x04": "zip", "dex\n035": "dex", "\x1f\x8b\x08": "archive", "hello": "unknown"} {
		if got := sniff([]byte(in)); got != want {
			t.Errorf("sniff(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestBuildStringsMergedRoutes(t *testing.T) {
	data := []byte("xx<title>/debug/pprof/</title> body /api/orders and https://api.example.com/v1/x tail\x00AKIAIOSFODNN7EXAMPLE\x00")
	i := bytes.IndexByte(data, 0)
	j := bytes.Index(data, []byte("AKIA"))
	raws := []rawString{{off: 2, size: int64(i - 2), tool: "radare2"}, {off: int64(j), size: 20, tool: "radare2"}}
	ss, trunc := buildStrings(bytes.NewReader(data), raws, nil, 100)
	if trunc {
		t.Fatal("unexpected truncation")
	}
	got := map[string]string{}
	for _, s := range ss {
		got[s.Value] = s.Kind
	}
	for v, k := range map[string]string{"/debug/pprof/": "route", "/api/orders": "route", "https://api.example.com/v1/x": "url", "[REDACTED:aws_access_key]": "secret"} {
		if got[v] != k {
			t.Errorf("string %q: kind %q, want %q (all: %v)", v, got[v], k, got)
		}
	}
	for _, s := range ss {
		if strings.Contains(s.Value, "AKIA") {
			t.Errorf("secret not redacted: %q", s.Value)
		}
		if s.Value == "/title" {
			t.Error("closing tag taken as a route")
		}
	}
}

func TestParseGoLens(t *testing.T) {
	out := []byte(r2Marker + "0x6df96e\nlea rax, [0x0074ca26]\nmov ebx, 0xb\n" + r2Marker + "0x10\nmov eax, 1\nmov ebx, 2\n" +
		r2Marker + "0x20\nlea rdi, [0x1]\nmov ecx, 5000\n")
	res := map[uint64]int{}
	parseGoLens(out, res)
	if res[0x6df96e] != 11 || len(res) != 1 {
		t.Fatalf("lens = %v", res)
	}
}

// TestAnalyseGoBinary builds a small Go program (when the go tool is
// available) and checks the built-in parser's Go facts; radare2 and
// binwalk are not required (they are reported as skipped when missing).
func TestAnalyseGoBinary(t *testing.T) {
	goBin, err := exec.LookPath("go")
	if err != nil {
		t.Skip("go tool not available")
	}
	dir := t.TempDir()
	src := "package main\n\nimport (\n\t\"net/http\"\n\t_ \"net/http/pprof\"\n)\n\nfunc main() {\n\thttp.HandleFunc(\"/api/orders\", nil)\n}\n"
	if err := os.WriteFile(filepath.Join(dir, "main.go"), []byte(src), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "go.mod"), []byte("module example.com/fixture\n\ngo 1.22\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	bin := filepath.Join(dir, "fixture")
	cmd := exec.Command(goBin, "build", "-o", bin, ".")
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), "CGO_ENABLED=0", "GOFLAGS=-mod=mod")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Skipf("go build failed: %v %s", err, out)
	}
	cfg := Config{Tools: []string{"radare2", "binwalk"}, TimeoutSeconds: 300, MaxCode: 5}
	cfg.normalise()
	d, err := analyse(context.Background(), cfg, bin, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if d.Schema != Schema || d.Artifact.Format != "elf" || d.Artifact.Language != "go" || d.Go == nil || d.Go.MainModule.Path != "example.com/fixture" {
		t.Fatalf("artifact %+v go %+v", d.Artifact, d.Go)
	}
	names := map[string]Function{}
	for _, f := range d.Functions {
		names[f.Name] = f
	}
	if f, ok := names["main.main"]; !ok || f.Library || f.Offset <= 0 {
		t.Errorf("main.main: %+v", f)
	}
	if f, ok := names["net/http/pprof.Index"]; !ok || !f.Library || f.Package != "net/http/pprof" {
		t.Errorf("net/http/pprof.Index: %+v", f)
	}
	found := false
	for _, im := range d.Imports {
		found = found || (im.ID == "imp:go:net/http/pprof" && im.Kind == "package" && im.Library == "std")
	}
	if !found {
		t.Error("no package import for net/http/pprof")
	}
	if len(d.Sections) == 0 {
		t.Error("no sections")
	}
	b, err := json.Marshal(d)
	if err != nil || !bytes.Contains(b, []byte(`"schema":"pathos.rea/v1"`)) {
		t.Fatalf("marshal: %v", err)
	}
	if _, ok := d.Tools["ghidra"]; !ok {
		t.Error("every known tool must be listed")
	}
}

func TestAnalyseUnknownBlob(t *testing.T) {
	dir := t.TempDir()
	var gz bytes.Buffer
	zw := gzip.NewWriter(&gz)
	_, _ = zw.Write([]byte("rootfs test data"))
	_ = zw.Close()
	blob := append(append([]byte("PATHOSFW"+strings.Repeat("\x00", 56)), gz.Bytes()...), []byte("\x00\x00token=Zq8vT3kLm9Xr2Pw7\x00")...)
	p := filepath.Join(dir, "fw.bin")
	if err := os.WriteFile(p, blob, 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := Config{Tools: []string{"binwalk"}, TimeoutSeconds: 120}
	cfg.normalise()
	d, err := analyse(context.Background(), cfg, p, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range d.Strings {
		if strings.Contains(s.Value, "Zq8vT3kLm9Xr2Pw7") {
			t.Errorf("secret not redacted: %q", s.Value)
		}
	}
	if d.Tools["radare2"].Status != "skipped" {
		t.Errorf("radare2 not enabled but %+v", d.Tools["radare2"])
	}
}

func TestParseBinwalkLog(t *testing.T) {
	raw := []byte(`[
{"Analysis":{"file_path":"/x/fw.bin","file_map":[{"offset":64,"id":"a","size":10,"name":"gzip","description":"gzip"}],"extractions":{"a":{"success":true}}}}
{"Analysis":{"file_path":"/x/app","file_map":[{"offset":0,"id":"b","size":5,"name":"elf","description":"ELF"}],"extractions":{}}}
]`)
	as := parseBinwalkLog(raw)
	if len(as) != 2 || as[0].Analysis.FileMap[0].Name != "gzip" || !as[0].Analysis.Extractions["a"].Success {
		t.Fatalf("parsed %+v", as)
	}
	if len(parseBinwalkLog([]byte(`[{"Analysis":{"file_map":[]}},{"Analysis":{"file_map":[]}}]`))) != 2 {
		t.Fatal("a valid array must parse too")
	}
	// What binwalk 3.1.0 actually writes for a recursive run (append mode).
	if as := parseBinwalkLog([]byte("[\n{\"Analysis\":{\"file_path\":\"/x/a\"}}\n],\n{\"Analysis\":{\"file_path\":\"/x/b\"}}\n],\n{\"Analysis\":{\"file_path\":\"/x/c\"}}\n]")); len(as) != 3 || as[2].Analysis.FilePath != "/x/c" {
		t.Fatalf("binwalk 3.1.0 log: parsed %+v", as)
	}
}

// A recursive binwalk run that ended before analysing what it extracted is
// detected from its log and the extraction directory (binwalk 3.1.0 could
// exit 0 early on a busy CPU, see workers/rea/binwalk-worker-pool-race.patch).
func TestUnanalysedExtractions(t *testing.T) {
	root := t.TempDir()
	write := func(rel, data string) {
		p := filepath.Join(root, rel)
		if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(data), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write("fw.bin", "input")
	write("fw.bin.extracted/40/decompressed.bin", "tar")
	write("fw.bin.extracted/40/decompressed.bin.extracted/0/bin/app", "elf")
	write("fw.bin.extracted/40/decompressed.bin.extracted/0/empty", "")
	write("fw.bin.extracted/90/raw", "not to be recursed into")
	log := func(entries ...string) []bwAnalysis {
		return parseBinwalkLog([]byte("[\n" + strings.Join(entries, "\n],\n") + "\n]")) // as binwalk 3.1.0 writes it
	}
	top := `{"Analysis":{"file_path":"` + root + `/fw.bin","file_map":[{"id":"a","name":"gzip"},{"id":"c","name":"raw"}],"extractions":{` +
		`"a":{"success":true,"output_directory":"` + root + `/fw.bin.extracted/40"},` +
		`"c":{"success":true,"do_not_recurse":true,"output_directory":"` + root + `/fw.bin.extracted/90"}}}}`
	tar := `{"Analysis":{"file_path":"` + root + `/fw.bin.extracted/40/decompressed.bin","file_map":[{"id":"b","name":"tarball"}],"extractions":{` +
		`"b":{"success":true,"output_directory":"` + root + `/fw.bin.extracted/40/decompressed.bin.extracted/0"}}}}`
	app := `{"Analysis":{"file_path":"` + root + `/fw.bin.extracted/40/decompressed.bin.extracted/0/bin/app","file_map":[],"extractions":{}}}`
	rt, err := os.OpenRoot(root)
	if err != nil {
		t.Fatal(err)
	}
	defer rt.Close()
	for _, c := range []struct {
		name string
		as   []bwAnalysis
		want int
	}{
		{"complete", log(top, tar, app), 0},
		{"leaf result lost", log(top, tar), 1},
		{"tar result lost", log(top), 2}, // the tar and what its run extracted
		{"nothing logged", nil, 0},
	} {
		if got := unanalysedExtractions(rt, c.as); got != c.want {
			t.Errorf("%s: %d unanalysed, want %d", c.name, got, c.want)
		}
	}
}
