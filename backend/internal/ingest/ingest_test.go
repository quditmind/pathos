package ingest

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"context"
	"errors"
	"hash/crc32"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
)

type zentry struct {
	name string
	body []byte
	mode fs.FileMode // 0 = 0644 regular
}

func buildZip(t *testing.T, entries ...zentry) []byte {
	t.Helper()
	var b bytes.Buffer
	zw := zip.NewWriter(&b)
	for _, e := range entries {
		h := &zip.FileHeader{Name: e.name, Method: zip.Deflate, Modified: time.Date(2024, 5, 6, 7, 8, 9, 0, time.UTC)}
		mode := e.mode
		if mode == 0 {
			mode = 0o644
		}
		h.SetMode(mode)
		w, err := zw.CreateHeader(h)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := w.Write(e.body); err != nil {
			t.Fatal(err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return b.Bytes()
}

type tentry struct {
	hdr  tar.Header
	body []byte
}

func file(name, body string) tentry {
	return tentry{hdr: tar.Header{Typeflag: tar.TypeReg, Name: name, Mode: 0o644, Size: int64(len(body)),
		ModTime: time.Date(2023, 1, 2, 3, 4, 5, 0, time.UTC)}, body: []byte(body)}
}

func buildTar(t *testing.T, gz bool, entries ...tentry) []byte {
	t.Helper()
	var b bytes.Buffer
	var w io.Writer = &b
	var zw *gzip.Writer
	if gz {
		zw = gzip.NewWriter(&b)
		w = zw
	}
	tw := tar.NewWriter(w)
	for _, e := range entries {
		h := e.hdr
		if err := tw.WriteHeader(&h); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write(e.body); err != nil {
			t.Fatal(err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if zw != nil {
		if err := zw.Close(); err != nil {
			t.Fatal(err)
		}
	}
	return b.Bytes()
}

func normalize(t *testing.T, data []byte, format string, lim Limits) (Result, []byte, error) {
	t.Helper()
	var out bytes.Buffer
	res, err := Normalize(context.Background(), bytes.NewReader(data), format, int64(len(data)), &out, lim)
	return res, out.Bytes(), err
}

type snapEntry struct {
	hdr  *tar.Header
	body string
}

func readSnapshot(t *testing.T, snap []byte) []snapEntry {
	t.Helper()
	zr, err := gzip.NewReader(bytes.NewReader(snap))
	if err != nil {
		t.Fatal(err)
	}
	tr := tar.NewReader(zr)
	var out []snapEntry
	for {
		h, err := tr.Next()
		if err == io.EOF {
			return out
		}
		if err != nil {
			t.Fatal(err)
		}
		b, _ := io.ReadAll(tr)
		out = append(out, snapEntry{h, string(b)})
	}
}

func names(es []snapEntry) []string {
	var n []string
	for _, e := range es {
		n = append(n, e.hdr.Name)
	}
	return n
}

func expectCode(t *testing.T, label string, err error, want Code) {
	t.Helper()
	if CodeOf(err) != want {
		t.Errorf("%s: expected %s, got %v", label, want, err)
	}
}

func TestPathRejections(t *testing.T) {
	cases := map[string]Code{
		"../x":                         CodePathTraversal,
		"a/../../x":                    CodePathTraversal,
		"a/..":                         CodePathTraversal,
		"/etc/x":                       CodeAbsolutePath,
		`C:\x`:                         CodeAbsolutePath,
		"C:/x":                         CodeAbsolutePath,
		`\\server\x`:                   CodeAbsolutePath,
		"//server/x":                   CodeAbsolutePath,
		`a\..\x`:                       CodePathTraversal,
		`a\b`:                          CodeInvalidPath,
		"a\x00b":                       CodeInvalidPath,
		"a\nb":                         CodeInvalidPath,
		"bad\xff\xfe":                  CodeInvalidPath,
		strings.Repeat("a/", 70) + "f": CodeInvalidPath,
		strings.Repeat("x", 1100):      CodeInvalidPath,
	}
	for name, want := range cases {
		_, _, err := normalize(t, buildZip(t, zentry{name: "ok.txt", body: []byte("x")}, zentry{name: name, body: []byte("evil")}), "zip", Limits{})
		expectCode(t, "zip "+name, err, want)
		if strings.ContainsAny(name, "\x00") {
			continue // tar headers cannot carry NUL
		}
		_, _, err = normalize(t, buildTar(t, false, file("ok.txt", "x"), file(name, "evil")), "tar", Limits{})
		expectCode(t, "tar "+name, err, want)
	}
	// Accepted spellings.
	res, snap, err := normalize(t, buildTar(t, true, file("./a/./b.txt", "1"), file("c//d.txt", "2")), "tar.gz", Limits{})
	if err != nil || res.Files != 2 {
		t.Fatalf("benign paths rejected: %v", err)
	}
	if got := names(readSnapshot(t, snap)); !slices.Equal(got, []string{"a/b.txt", "c/d.txt"}) {
		t.Fatalf("normalized names %v", got)
	}
}

func TestLinksAndSpecialFilesSkipped(t *testing.T) {
	tarData := buildTar(t, false,
		file("src/main.go", "package main"),
		tentry{hdr: tar.Header{Typeflag: tar.TypeSymlink, Name: "src/passwd", Linkname: "/etc/passwd"}},
		tentry{hdr: tar.Header{Typeflag: tar.TypeSymlink, Name: "src/up", Linkname: "../../.."}},
		tentry{hdr: tar.Header{Typeflag: tar.TypeLink, Name: "src/hard", Linkname: "../../etc/shadow"}},
		tentry{hdr: tar.Header{Typeflag: tar.TypeChar, Name: "src/null", Devmajor: 1, Devminor: 3}},
		tentry{hdr: tar.Header{Typeflag: tar.TypeFifo, Name: "src/pipe"}},
		file("src/after-link/x.txt", "ok"),
	)
	res, snap, err := normalize(t, tarData, "tar", Limits{})
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]int{SkipSymlink: 2, SkipHardlink: 1, SkipDevice: 1, SkipFifo: 1}
	for k, v := range want {
		if res.Skipped[k] != v {
			t.Errorf("skipped[%s]=%d want %d", k, res.Skipped[k], v)
		}
	}
	es := readSnapshot(t, snap)
	for _, e := range es {
		if e.hdr.Typeflag != tar.TypeReg && e.hdr.Typeflag != tar.TypeDir {
			t.Errorf("non-regular entry in snapshot: %s %c", e.hdr.Name, e.hdr.Typeflag)
		}
	}
	if res.Files != 2 || res.StrippedPrefix != "src" {
		t.Fatalf("result %+v", res)
	}

	// ZIP symlink (Unix mode in external attributes).
	zipData := buildZip(t, zentry{name: "a.txt", body: []byte("a")}, zentry{name: "link", body: []byte("/etc/passwd"), mode: fs.ModeSymlink | 0o777})
	res, snap, err = normalize(t, zipData, "zip", Limits{})
	if err != nil || res.Skipped[SkipSymlink] != 1 || res.Files != 1 {
		t.Fatalf("zip symlink: %+v %v", res, err)
	}
	if got := names(readSnapshot(t, snap)); !slices.Equal(got, []string{"a.txt"}) {
		t.Fatalf("zip snapshot %v", got)
	}

	// Malicious names are rejected even on entries that would be skipped.
	_, _, err = normalize(t, buildTar(t, false, tentry{hdr: tar.Header{Typeflag: tar.TypeSymlink, Name: "../evil", Linkname: "x"}}), "tar", Limits{})
	expectCode(t, "symlink traversal", err, CodePathTraversal)
}

func TestDuplicatePaths(t *testing.T) {
	_, _, err := normalize(t, buildZip(t, zentry{name: "a.txt", body: []byte("1")}, zentry{name: "a.txt", body: []byte("2")}), "zip", Limits{})
	expectCode(t, "zip duplicate", err, CodeDuplicatePath)
	_, _, err = normalize(t, buildTar(t, false, file("x/b", "1"), file("x/./b", "2")), "tar", Limits{})
	expectCode(t, "tar duplicate after cleaning", err, CodeDuplicatePath)
	_, _, err = normalize(t, buildTar(t, false, file("a", "1"), file("a/b", "2")), "tar", Limits{})
	expectCode(t, "file used as directory", err, CodeDuplicatePath)
	_, _, err = normalize(t, buildTar(t, false, file("a/b", "1"), file("a", "2")), "tar", Limits{})
	expectCode(t, "directory replaced by file", err, CodeDuplicatePath)
	// Case-sensitive: these are distinct.
	if _, _, err = normalize(t, buildTar(t, false, file("A.txt", "1"), file("a.txt", "2")), "tar", Limits{}); err != nil {
		t.Fatalf("case variants rejected: %v", err)
	}
	// Repeated directory entries are harmless.
	dir := tentry{hdr: tar.Header{Typeflag: tar.TypeDir, Name: "d/", Mode: 0o755}}
	if _, _, err = normalize(t, buildTar(t, false, dir, dir, file("d/f", "1")), "tar", Limits{}); err != nil {
		t.Fatalf("repeated directory rejected: %v", err)
	}
}

func TestZipBombAndRatio(t *testing.T) {
	zeros := make([]byte, 8<<20)
	data := buildZip(t, zentry{name: "bomb.bin", body: zeros})
	_, _, err := normalize(t, data, "zip", Limits{MaxRatio: 50})
	expectCode(t, "zip ratio", err, CodeCompressionRatio)
	// The same file passes with a generous ratio.
	if _, _, err := normalize(t, data, "zip", Limits{MaxRatio: 100000}); err != nil {
		t.Fatalf("generous ratio: %v", err)
	}
	// Small highly compressible files are not subject to the ratio limit.
	if _, _, err := normalize(t, buildZip(t, zentry{name: "s", body: make([]byte, 512<<10)}), "zip", Limits{MaxRatio: 2}); err != nil {
		t.Fatalf("small file: %v", err)
	}
	// tar.gz: ratio over the whole stream.
	tgz := buildTar(t, true, tentry{hdr: tar.Header{Typeflag: tar.TypeReg, Name: "z", Mode: 0o644, Size: int64(len(zeros))}, body: zeros})
	_, _, err = normalize(t, tgz, "tar.gz", Limits{})
	expectCode(t, "tar.gz ratio", err, CodeCompressionRatio)
}

// rawZip writes one stored entry whose central directory sizes are chosen
// by the caller (to simulate lying headers).
func rawZip(t *testing.T, name string, body []byte, declared uint64, flags uint16) []byte {
	t.Helper()
	var b bytes.Buffer
	zw := zip.NewWriter(&b)
	h := &zip.FileHeader{Name: name, Method: zip.Store, Flags: flags, CRC32: crc32.ChecksumIEEE(body),
		CompressedSize64: uint64(len(body)), UncompressedSize64: declared}
	w, err := zw.CreateRaw(h)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Write(body); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return b.Bytes()
}

func TestSizeLimitsOnActualBytes(t *testing.T) {
	body := bytes.Repeat([]byte("0123456789abcdef"), 1<<16) // 1 MiB
	// The header claims 100 bytes (under the 64 KiB limit); the data is 1 MiB.
	var out bytes.Buffer
	data := rawZip(t, "liar.bin", body, 100, 0)
	_, err := Normalize(context.Background(), bytes.NewReader(data), "zip", int64(len(data)), &out, Limits{MaxFileBytes: 64 << 10})
	if c := CodeOf(err); c != CodeCorruptArchive && c != CodeFileTooLarge {
		t.Fatalf("lying header accepted: %v", err)
	}
	if out.Len() > 64<<10 {
		t.Fatalf("wrote %d bytes despite the limit", out.Len())
	}
	// Honest headers over the limit are rejected before reading content.
	_, _, err = normalize(t, buildZip(t, zentry{name: "big", body: body}), "zip", Limits{MaxFileBytes: 64 << 10})
	expectCode(t, "file limit", err, CodeFileTooLarge)
	_, _, err = normalize(t, buildTar(t, false, file("a", string(body)), file("b", string(body))), "tar", Limits{MaxTotalBytes: 3 << 19})
	expectCode(t, "total limit", err, CodeTooLarge)

	// copyFile counts real bytes even when the header understates them.
	n := normalizer{ctx: context.Background(), lim: Limits{MaxFileBytes: 1000}.withDefaults()}
	_, err = n.copyFile(io.Discard, bytes.NewReader(body), entry{path: "x", size: 10}, nil)
	expectCode(t, "copy counting (file limit)", err, CodeFileTooLarge)
	n.lim.MaxFileBytes = 1 << 30
	_, err = n.copyFile(io.Discard, bytes.NewReader(body), entry{path: "x", size: 10}, nil)
	expectCode(t, "copy counting (declared size)", err, CodeCorruptArchive)
}

func TestTooManyFiles(t *testing.T) {
	var es []zentry
	for i := range 11 {
		es = append(es, zentry{name: strings.Repeat("f", i+1), body: []byte("x")})
	}
	_, _, err := normalize(t, buildZip(t, es...), "zip", Limits{MaxFiles: 10})
	expectCode(t, "too many", err, CodeTooManyFiles)
	if _, _, err := normalize(t, buildZip(t, es...), "zip", Limits{MaxFiles: 11}); err != nil {
		t.Fatal(err)
	}
}

func TestEncryptedZipEntry(t *testing.T) {
	data := rawZip(t, "secret.txt", []byte("ciphertext"), 10, 0x1)
	_, _, err := normalize(t, data, "zip", Limits{})
	expectCode(t, "encrypted", err, CodeEncryptedEntry)
}

func TestStripTopLevelAndModes(t *testing.T) {
	mt := time.Date(2022, 3, 4, 5, 6, 7, 0, time.UTC)
	data := buildTar(t, true,
		tentry{hdr: tar.Header{Typeflag: tar.TypeDir, Name: "repo-main/", Mode: 0o777, ModTime: mt}},
		tentry{hdr: tar.Header{Typeflag: tar.TypeReg, Name: "repo-main/run.sh", Mode: 0o4755 | 0o2000, Size: 2, Uid: 1000, Gid: 1000,
			Uname: "alice", Gname: "staff", ModTime: mt}, body: []byte("hi")},
		tentry{hdr: tar.Header{Typeflag: tar.TypeReg, Name: "repo-main/sub/data.txt", Mode: 0o600, Size: 1, ModTime: mt}, body: []byte("d")},
	)
	res, snap, err := normalize(t, data, "tar.gz", Limits{})
	if err != nil {
		t.Fatal(err)
	}
	if res.StrippedPrefix != "repo-main" {
		t.Fatalf("prefix %q", res.StrippedPrefix)
	}
	es := readSnapshot(t, snap)
	if got := names(es); !slices.Equal(got, []string{"run.sh", "sub/data.txt"}) {
		t.Fatalf("names %v", got)
	}
	for _, e := range es {
		h := e.hdr
		if h.Uid != 0 || h.Gid != 0 || h.Uname != "" || h.Gname != "" || !h.ModTime.Equal(mt) {
			t.Errorf("%s: owner/mtime not normalized: %+v", h.Name, h)
		}
	}
	if es[0].hdr.Mode != 0o755 || es[1].hdr.Mode != 0o644 {
		t.Fatalf("modes %o %o", es[0].hdr.Mode, es[1].hdr.Mode)
	}

	// No stripping when a file lives at the top level or there are two roots.
	res, _, _ = normalize(t, buildZip(t, zentry{name: "top/a.go", body: []byte("1")}, zentry{name: "README", body: []byte("2")}), "zip", Limits{})
	if res.StrippedPrefix != "" {
		t.Fatalf("stripped %q", res.StrippedPrefix)
	}
	res, _, _ = normalize(t, buildZip(t, zentry{name: "a/x", body: []byte("1")}, zentry{name: "b/y", body: []byte("2")}), "zip", Limits{})
	if res.StrippedPrefix != "" {
		t.Fatalf("stripped %q", res.StrippedPrefix)
	}
	// A single file at the root is not a directory to strip.
	res, snap, _ = normalize(t, buildZip(t, zentry{name: "only.txt", body: []byte("1")}), "zip", Limits{})
	if res.StrippedPrefix != "" || !slices.Equal(names(readSnapshot(t, snap)), []string{"only.txt"}) {
		t.Fatalf("single file: %+v", res)
	}
}

func TestNestedArchiveKeptAsFile(t *testing.T) {
	inner := buildZip(t, zentry{name: "../../evil", body: []byte("x")})
	res, snap, err := normalize(t, buildZip(t, zentry{name: "vendor/lib.zip", body: inner}), "zip", Limits{})
	if err != nil || res.Files != 1 {
		t.Fatalf("%+v %v", res, err)
	}
	es := readSnapshot(t, snap)
	if len(es) != 1 || es[0].body != string(inner) {
		t.Fatal("nested archive not copied verbatim")
	}
}

func TestLanguagesAndManifests(t *testing.T) {
	res, _, err := normalize(t, buildZip(t,
		zentry{name: "app/main.go", body: []byte("package main\n")},
		zentry{name: "app/go.mod", body: []byte("module x\n")},
		zentry{name: "app/web/index.ts", body: []byte("export {}")},
		zentry{name: "app/web/package.json", body: []byte("{}")},
		zentry{name: "app/requirements-dev.txt", body: []byte("x")},
		zentry{name: "app/svc/Dockerfile", body: []byte("FROM x")},
		zentry{name: "app/infra/main.tf", body: []byte("x")},
		zentry{name: "app/compose/docker-compose.prod.yml", body: []byte("x")},
		zentry{name: "app/App.csproj", body: []byte("x")},
		zentry{name: "app/notes.unknown", body: []byte("x")},
	), "zip", Limits{})
	if err != nil {
		t.Fatal(err)
	}
	if res.Languages["Go"] != 13 || res.Languages["TypeScript"] != 9 || res.Languages["Dockerfile"] != 6 || res.Languages["HCL/Terraform"] != 1 || res.Languages["YAML"] != 1 {
		t.Fatalf("languages %v", res.Languages)
	}
	want := []string{"go.mod", "web/package.json", "requirements-dev.txt", "svc/Dockerfile", "infra/main.tf", "compose/docker-compose.prod.yml", "App.csproj"}
	if !slices.Equal(res.Manifests, want) {
		t.Fatalf("manifests %v", res.Manifests)
	}
	if res.Files != 10 || res.UncompressedBytes != 13+9+9+2+1+6+1+1+1+1 {
		t.Fatalf("files=%d bytes=%d", res.Files, res.UncompressedBytes)
	}
}

func TestCorruptAndUnsupported(t *testing.T) {
	_, _, err := normalize(t, []byte("not an archive at all"), "zip", Limits{})
	expectCode(t, "corrupt zip", err, CodeCorruptArchive)
	_, _, err = normalize(t, []byte("garbage"), "tar.gz", Limits{})
	expectCode(t, "corrupt gzip", err, CodeCorruptArchive)
	_, _, err = normalize(t, []byte{}, "tar", Limits{})
	expectCode(t, "empty tar", err, CodeCorruptArchive)
	_, _, err = normalize(t, []byte("x"), "rar", Limits{})
	expectCode(t, "rar", err, CodeUnsupportedFormat)
	good := buildTar(t, true, file("a", strings.Repeat("x", 5000)))
	_, _, err = normalize(t, good[:len(good)-20], "tar.gz", Limits{})
	expectCode(t, "truncated tar.gz", err, CodeCorruptArchive)
}

func TestDetectFormat(t *testing.T) {
	z := buildZip(t, zentry{name: "a", body: []byte("1")})
	tr := buildTar(t, false, file("a", "1"))
	tgz := buildTar(t, true, file("a", "1"))
	var emptyZip bytes.Buffer
	_ = zip.NewWriter(&emptyZip).Close()
	var plainGz bytes.Buffer
	gw := gzip.NewWriter(&plainGz)
	_, _ = gw.Write(bytes.Repeat([]byte("hello "), 200))
	_ = gw.Close()
	ok := []struct {
		head []byte
		name string
		want string
	}{
		{z, "src.zip", "zip"}, {emptyZip.Bytes(), "e.ZIP", "zip"}, {tr, "x.tar", "tar"}, {tgz, "x.tar.gz", "tar.gz"},
		{tgz, "x.tgz", "tar.gz"}, {z, "", "zip"}, {tr[:512], "", "tar"},
	}
	for _, c := range ok {
		got, err := DetectFormat(c.head, c.name)
		if err != nil || got != c.want {
			t.Errorf("DetectFormat(%s)=%q,%v want %q", c.name, got, err, c.want)
		}
	}
	bad := []struct {
		head []byte
		name string
	}{
		{z, "x.tar.gz"}, {tr, "x.zip"}, {tgz, "x.tar"}, {[]byte("MZ\x90\x00 executable"), "x.zip"}, {z, "x.rar"},
		{plainGz.Bytes(), "x.tar.gz"}, {[]byte("Rar!\x1a\x07"), ""},
	}
	for _, c := range bad {
		if _, err := DetectFormat(c.head, c.name); CodeOf(err) != CodeUnsupportedFormat {
			t.Errorf("DetectFormat(%s): expected unsupported_format, got %v", c.name, err)
		}
	}
}

func TestExtractSnapshotRoundTrip(t *testing.T) {
	src := buildZip(t,
		zentry{name: "proj/", mode: fs.ModeDir | 0o755},
		zentry{name: "proj/bin/run", body: []byte("#!/bin/sh\n"), mode: 0o4755},
		zentry{name: "proj/a/b/c.txt", body: bytes.Repeat([]byte("c"), 200000)},
		zentry{name: "proj/empty/", mode: fs.ModeDir | 0o700},
		zentry{name: "proj/zero", body: nil},
	)
	_, snap, err := normalize(t, src, "zip", Limits{})
	if err != nil {
		t.Fatal(err)
	}
	dst := filepath.Join(t.TempDir(), "src")
	if err := ExtractSnapshot(context.Background(), bytes.NewReader(snap), dst, Limits{}); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(filepath.Join(dst, "a", "b", "c.txt"))
	if err != nil || len(b) != 200000 {
		t.Fatalf("c.txt: %v", err)
	}
	st, _ := os.Stat(filepath.Join(dst, "bin", "run"))
	if st.Mode().Perm() != 0o755 || st.Mode()&(fs.ModeSetuid|fs.ModeSetgid) != 0 {
		t.Fatalf("run mode %v", st.Mode())
	}
	if !st.ModTime().Equal(time.Date(2024, 5, 6, 7, 8, 9, 0, time.UTC)) {
		t.Fatalf("mtime %v", st.ModTime())
	}
	if st, err := os.Stat(filepath.Join(dst, "empty")); err != nil || !st.IsDir() {
		t.Fatalf("empty dir: %v", err)
	}
	if st, err := os.Stat(filepath.Join(dst, "zero")); err != nil || st.Size() != 0 {
		t.Fatalf("zero: %v", err)
	}
	// Limits apply on extraction too.
	err = ExtractSnapshot(context.Background(), bytes.NewReader(snap), filepath.Join(t.TempDir(), "x"), Limits{MaxTotalBytes: 1000})
	expectCode(t, "extract total", err, CodeTooLarge)
	err = ExtractSnapshot(context.Background(), bytes.NewReader(snap), filepath.Join(t.TempDir(), "x"), Limits{MaxFiles: 2})
	expectCode(t, "extract count", err, CodeTooManyFiles)
}

func TestExtractSnapshotRejectsMaliciousTar(t *testing.T) {
	cases := map[string]struct {
		entries []tentry
		code    Code
	}{
		"traversal": {[]tentry{file("../escape.txt", "x")}, CodePathTraversal},
		"absolute":  {[]tentry{file("/tmp/escape.txt", "x")}, CodeAbsolutePath},
		"symlink":   {[]tentry{{hdr: tar.Header{Typeflag: tar.TypeSymlink, Name: "l", Linkname: "/etc"}}}, CodeUnsupportedEntry},
		"hardlink":  {[]tentry{{hdr: tar.Header{Typeflag: tar.TypeLink, Name: "l", Linkname: "/etc/passwd"}}}, CodeUnsupportedEntry},
		"duplicate": {[]tentry{file("a", "1"), file("a", "2")}, CodeDuplicatePath},
		"backslash": {[]tentry{file(`..\x`, "1")}, CodePathTraversal},
		"device":    {[]tentry{{hdr: tar.Header{Typeflag: tar.TypeChar, Name: "dev"}}}, CodeUnsupportedEntry},
	}
	for name, c := range cases {
		parent := t.TempDir()
		dst := filepath.Join(parent, "src")
		err := ExtractSnapshot(context.Background(), bytes.NewReader(buildTar(t, true, c.entries...)), dst, Limits{})
		expectCode(t, name, err, c.code)
		if _, err := os.Lstat(filepath.Join(parent, "escape.txt")); err == nil {
			t.Fatalf("%s: file escaped", name)
		}
	}
	// Not gzip.
	err := ExtractSnapshot(context.Background(), bytes.NewReader(buildTar(t, false, file("a", "1"))), t.TempDir(), Limits{})
	expectCode(t, "plain tar", err, CodeCorruptArchive)
}

func TestExtractSnapshotDoesNotFollowExistingLinks(t *testing.T) {
	parent := t.TempDir()
	outside := filepath.Join(parent, "outside")
	if err := os.Mkdir(outside, 0o700); err != nil {
		t.Fatal(err)
	}
	dst := filepath.Join(parent, "src")
	if err := os.Mkdir(dst, 0o700); err != nil {
		t.Fatal(err)
	}
	// Planted links (e.g. by a compromised earlier step).
	if err := os.Symlink(outside, filepath.Join(dst, "d")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(outside, "f"), filepath.Join(dst, "f")); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"d/x", "f"} {
		err := ExtractSnapshot(context.Background(), bytes.NewReader(buildTar(t, true, file(name, "pwned"))), dst, Limits{})
		if err == nil {
			t.Fatalf("%s: extraction through a symlink succeeded", name)
		}
	}
	entries, _ := os.ReadDir(outside)
	if len(entries) != 0 {
		t.Fatalf("wrote outside dst: %v", entries)
	}
}

func TestCodeOf(t *testing.T) {
	if CodeOf(errors.New("x")) != "" || CodeOf(nil) != "" {
		t.Fatal("CodeOf on non-ingest error")
	}
	wrapped := errors.Join(errors.New("ctx"), reject(CodeTooLarge, "", "x"))
	if CodeOf(wrapped) != CodeTooLarge {
		t.Fatal("CodeOf through wrapping")
	}
}
