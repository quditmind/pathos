package worker

import (
	"bufio"
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"pathos/internal/scanners"
)

func readNative(t *testing.T, path string) scanners.NativeReport {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var rep scanners.NativeReport
	if err := json.Unmarshal(b, &rep); err != nil {
		t.Fatal(err)
	}
	return rep
}

func writeFiles(t *testing.T, dir string, files map[string]string) {
	t.Helper()
	for name, content := range files {
		p := filepath.Join(dir, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
}

// --- ClamAV ----------------------------------------------------------------

// fakeClamd answers zVERSION and zINSTREAM; streams containing the EICAR
// marker are infected, streams larger than limit exceed the size limit.
func fakeClamd(t *testing.T, limit int) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				br := bufio.NewReader(c)
				cmd, err := br.ReadString(0)
				if err != nil {
					return
				}
				switch cmd {
				case "zVERSION\x00":
					_, _ = c.Write([]byte("ClamAV 1.5.0/27800/Thu Nov 19 08:00:00 2026\x00"))
				case "zINSTREAM\x00":
					var data bytes.Buffer
					for {
						var l [4]byte
						if _, err := io.ReadFull(br, l[:]); err != nil {
							return
						}
						n := binary.BigEndian.Uint32(l[:])
						if n == 0 {
							break
						}
						if data.Len()+int(n) > limit {
							_, _ = c.Write([]byte("INSTREAM size limit exceeded. ERROR\x00"))
							return
						}
						if _, err := io.CopyN(&data, br, int64(n)); err != nil {
							return
						}
					}
					if bytes.Contains(data.Bytes(), []byte("EICAR-STANDARD-ANTIVIRUS-TEST-FILE")) {
						_, _ = c.Write([]byte("stream: Win.Test.EICAR_HDB-1 FOUND\x00"))
						return
					}
					_, _ = c.Write([]byte("stream: OK\x00"))
				}
			}(c)
		}
	}()
	return ln.Addr().String()
}

const eicar = `X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*`

func TestClamAVRepositoryScan(t *testing.T) {
	addr := fakeClamd(t, 1<<20)
	src := t.TempDir()
	writeFiles(t, src, map[string]string{
		"README.md":           "hello",
		"tests/eicar.com":     eicar,
		"assets/big.bin":      strings.Repeat("A", 2<<20),
		"src/main.go":         "package main\n",
		".git/objects/xx/eic": eicar, // history store: never scanned
	})
	if err := os.Symlink("/etc/passwd", filepath.Join(src, "link")); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(t.TempDir(), "clamav.out")
	tool := nativeTools(Config{ClamAVAddress: addr, Version: "1.1.0"})[scanners.ClamAV]
	if v, err := tool.Version(context.Background()); err != nil || v != "1.5.0" {
		t.Fatalf("version %q %v", v, err)
	}
	skipped, err := tool.Run(context.Background(), RunInput{Src: src, Out: out})
	if err != nil || skipped != "" {
		t.Fatalf("run: %q %v", skipped, err)
	}
	rep := readNative(t, out)
	if !strings.HasPrefix(rep.Engine, "ClamAV 1.5.0/27800") || rep.Stats["infected"] != 1 || rep.Stats["not_scanned"] != 1 ||
		rep.Stats["files_scanned"] != 3 || rep.Stats["links_skipped"] != 1 {
		t.Fatalf("report: %+v", rep)
	}
	fs, err := scanners.Parse(scanners.ClamAV, mustRead(t, out))
	if err != nil || len(fs) != 2 {
		t.Fatalf("findings: %v %+v", err, fs)
	}
	var infected, unscanned scanners.Finding
	for _, f := range fs {
		if f.Severity == "critical" {
			infected = f
		} else {
			unscanned = f
		}
	}
	if infected.Category != "malware" || infected.FilePath != "tests/eicar.com" || infected.RuleID != "malware/Win.Test.EICAR_HDB-1" ||
		!strings.Contains(infected.Description, "Win.Test.EICAR_HDB-1") || !strings.Contains(infected.Snippet, "engine: ClamAV 1.5.0") ||
		!strings.Contains(infected.Snippet, "sha256: ") {
		t.Errorf("infected finding: %+v", infected)
	}
	if unscanned.RuleID != "malware/not-scanned" || unscanned.FilePath != "assets/big.bin" || unscanned.Severity != "low" {
		t.Errorf("a file clamd could not scan must be reported, not dropped: %+v", unscanned)
	}
}

func TestClamAVNotConfiguredOrDown(t *testing.T) {
	tool := nativeTools(Config{})[scanners.ClamAV]
	if _, err := tool.Version(context.Background()); err == nil {
		t.Error("an unconfigured clamav reports no version")
	}
	skipped, err := tool.Run(context.Background(), RunInput{Src: t.TempDir(), Out: filepath.Join(t.TempDir(), "x")})
	if err != nil || !strings.Contains(skipped, "PATHOS_CLAMAV_ADDRESS") {
		t.Errorf("skipped with a clear reason: %q %v", skipped, err)
	}
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	addr := ln.Addr().String()
	_ = ln.Close()
	down := nativeTools(Config{ClamAVAddress: addr})[scanners.ClamAV]
	if _, err := down.Run(context.Background(), RunInput{Src: t.TempDir(), Out: filepath.Join(t.TempDir(), "x")}); err == nil {
		t.Error("a configured but unreachable clamd fails the scanner instead of reporting the repository clean")
	}
}

func mustRead(t *testing.T, p string) []byte {
	t.Helper()
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// --- File licences -------------------------------------------------------------

const mitText = `MIT License

Copyright (c) 2026 Example

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
`

func TestLicenseCheck(t *testing.T) {
	src := t.TempDir()
	writeFiles(t, src, map[string]string{
		"LICENSE":             mitText,
		"vendor/gpl/util.c":   "/* SPDX-License-Identifier: GPL-3.0-only */\nint f(void) { return 0; }\n",
		"lib/dual.js":         "// SPDX-License-Identifier: MIT OR GPL-2.0-or-later\nmodule.exports = {};\n",
		"lib/old.py":          "# SPDX-License-Identifier: GPL-2.0+ WITH Classpath-exception-2.0\n",
		"docs/spdx.md":        "Write `SPDX-License-Identifier: <expression>` at the top of every file.\n",
		"src/plain.go":        "package main\n",
		"bin/tool":            "\x00\x01SPDX-License-Identifier: AGPL-3.0-only",
		"NOTICE":              "This product includes software developed at Example.\n",
		"third_party/LICENSE": "random words that are not a licence",
	})
	out := filepath.Join(t.TempDir(), "lc.out")
	tool := nativeTools(Config{Version: "1.1.0"})[scanners.LicenseCheck]
	if skipped, err := tool.Run(context.Background(), RunInput{Src: src, Out: out}); err != nil || skipped != "" {
		t.Fatalf("%q %v", skipped, err)
	}
	ls, err := scanners.ParseFileLicenses(mustRead(t, out))
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]scanners.FileLicense{}
	for _, l := range ls {
		got[l.Path+"|"+l.SPDX] = l
	}
	if l, ok := got["LICENSE|MIT"]; !ok || l.Method != "license-text" {
		t.Errorf("MIT licence text: %+v", ls)
	}
	if l, ok := got["vendor/gpl/util.c|GPL-3.0-only"]; !ok || l.Method != "spdx-tag" || l.Line != 1 || len(l.Alternatives) != 0 {
		t.Errorf("SPDX tag: %+v", l)
	}
	if l := got["lib/dual.js|GPL-2.0-or-later"]; len(l.Alternatives) != 1 || l.Alternatives[0] != "MIT" {
		t.Errorf("OR expression alternatives: %+v", l)
	}
	if _, ok := got["lib/old.py|GPL-2.0-or-later"]; !ok {
		t.Errorf("deprecated X+ maps to X-or-later, WITH exceptions dropped: %+v", ls)
	}
	if _, ok := got["lib/old.py|Classpath-exception-2.0"]; ok {
		t.Error("licence exceptions are not licences")
	}
	for k := range got {
		if strings.HasPrefix(k, "docs/") || strings.HasPrefix(k, "bin/") || strings.HasPrefix(k, "third_party/") || strings.HasPrefix(k, "NOTICE") {
			t.Errorf("unexpected detection %s", k)
		}
	}
	// No findings by themselves: the licence policy decides on the server.
	if fs, err := scanners.Parse(scanners.LicenseCheck, mustRead(t, out)); err != nil || len(fs) != 0 {
		t.Errorf("licence detections are not findings: %v %d", err, len(fs))
	}
}

func TestSPDXExpression(t *testing.T) {
	for _, c := range []struct {
		in     string
		ids    string
		choice bool
	}{
		{"MIT", "MIT", false},
		{"(MIT OR Apache-2.0) */", "MIT,Apache-2.0", true},
		{"GPL-2.0-only WITH Linux-syscall-note", "GPL-2.0-only", false},
		{"LGPL-2.1+ AND BSD-3-Clause", "LGPL-2.1-or-later,BSD-3-Clause", false},
		{"<expression>", "", false},
		{"see the LICENSE file for details", "", false},
	} {
		ids, choice := spdxExpression(c.in)
		if strings.Join(ids, ",") != c.ids || choice != c.choice {
			t.Errorf("%q: %v %v", c.in, ids, choice)
		}
	}
}

// --- Binary hardening ------------------------------------------------------------

// buildGo compiles a tiny Go program for the given target.
func buildGo(t *testing.T, dir, name, goos string, args ...string) string {
	t.Helper()
	goBin, err := exec.LookPath("go")
	if err != nil {
		t.Skip("go toolchain not available")
	}
	srcDir := t.TempDir()
	writeFiles(t, srcDir, map[string]string{"go.mod": "module x\n\ngo 1.21\n", "main.go": "package main\n\nfunc main() { println(\"hi\") }\n"})
	out := filepath.Join(dir, name)
	cmd := exec.Command(goBin, append(append([]string{"build", "-o", out}, args...), ".")...)
	cmd.Dir = srcDir
	cmd.Env = append(os.Environ(), "GOOS="+goos, "GOARCH=amd64", "CGO_ENABLED=0", "GOFLAGS=")
	if b, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("go build: %v\n%s", err, b)
	}
	return out
}

func hardeningFindings(t *testing.T, dir string, target *JobTarget) map[string][]scanners.Finding {
	t.Helper()
	out := filepath.Join(t.TempDir(), "bh.out")
	in := RunInput{Src: dir, Out: out}
	if target != nil {
		in = RunInput{Src: t.TempDir(), Out: out, Target: target, TargetFile: dir}
	}
	if skipped, err := nativeTools(Config{})[scanners.BinaryHardening].Run(context.Background(), in); err != nil || skipped != "" {
		t.Fatalf("%q %v", skipped, err)
	}
	fs, err := scanners.Parse(scanners.BinaryHardening, mustRead(t, out))
	if err != nil {
		t.Fatal(err)
	}
	by := map[string][]scanners.Finding{}
	for _, f := range fs {
		by[f.FilePath] = append(by[f.FilePath], f)
	}
	return by
}

func rulesOf(fs []scanners.Finding) string {
	var r []string
	for _, f := range fs {
		r = append(r, f.RuleID)
	}
	return strings.Join(r, ",")
}

func TestBinaryHardeningGo(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("builds linux binaries")
	}
	dir := t.TempDir()
	buildGo(t, dir, "exe", "linux")
	buildGo(t, dir, "pie", "linux", "-buildmode=pie")
	buildGo(t, dir, "app.exe", "windows")
	buildGo(t, dir, "mac", "darwin")
	writeFiles(t, dir, map[string]string{"notes.txt": strings.Repeat("not a binary ", 20), "fake.exe": "MZ" + strings.Repeat("\x00", 100)})
	by := hardeningFindings(t, dir, &JobTarget{Kind: "artifact"})
	exe := by["exe"]
	if rulesOf(exe) != "binary/elf-no-pie" || exe[0].Severity != "low" || exe[0].Category != "binary" ||
		!strings.Contains(exe[0].Snippet, "language: Go") || !strings.Contains(exe[0].Description, "-buildmode=pie") {
		t.Errorf("non-PIE Go executable: %s %+v", rulesOf(exe), exe)
	}
	if fs := by["pie"]; rulesOf(fs) != "" && !strings.Contains(rulesOf(fs), "relro") {
		t.Errorf("PIE Go executable: %s", rulesOf(fs))
	}
	if strings.Contains(rulesOf(by["pie"]), "no-pie") {
		t.Error("a PIE executable is not reported as non-PIE")
	}
	// Go sets DYNAMICBASE, HIGH_ENTROPY_VA and NX_COMPAT on Windows; CFG,
	// SafeSEH and /GS do not apply to Go.
	if fs := by["app.exe"]; len(fs) != 0 {
		t.Errorf("Go PE: %s", rulesOf(fs))
	}
	if fs := by["mac"]; len(fs) != 0 {
		t.Errorf("Go Mach-O (PIE by default): %s", rulesOf(fs))
	}
	if len(by["notes.txt"])+len(by["fake.exe"]) != 0 {
		t.Error("files that are not executables are ignored")
	}
	// Only artifact targets among targets.
	if skipped, _ := nativeTools(Config{})[scanners.BinaryHardening].Run(context.Background(),
		RunInput{Src: dir, Out: filepath.Join(t.TempDir(), "x"), Target: &JobTarget{Kind: "image"}}); skipped == "" {
		t.Error("image targets are skipped")
	}
}

func TestBinaryHardeningC(t *testing.T) {
	cc, err := exec.LookPath("gcc")
	if err != nil {
		t.Skip("gcc not available")
	}
	dir := t.TempDir()
	src := filepath.Join(t.TempDir(), "m.c")
	writeFiles(t, filepath.Dir(src), map[string]string{"m.c": "#include <string.h>\n#include <stdio.h>\nint main(int c, char **v) { char b[64]; strcpy(b, v[0]); printf(\"%s\\n\", b); return 0; }\n"})
	build := func(name string, flags ...string) {
		cmd := exec.Command(cc, append(append([]string{"-o", filepath.Join(dir, name)}, flags...), src)...)
		if b, err := cmd.CombinedOutput(); err != nil {
			t.Skipf("gcc cannot build test binaries: %v %s", err, b)
		}
	}
	build("weak", "-O0", "-no-pie", "-fno-stack-protector", "-U_FORTIFY_SOURCE", "-D_FORTIFY_SOURCE=0", "-Wl,-z,norelro", "-z", "execstack", "-Wl,-rpath,lib")
	build("strong", "-O2", "-fPIE", "-pie", "-fstack-protector-all", "-D_FORTIFY_SOURCE=2", "-Wl,-z,relro,-z,now", "-Wl,-z,noexecstack")
	build("partial", "-O2", "-fPIE", "-pie", "-fstack-protector-all", "-D_FORTIFY_SOURCE=2", "-Wl,-z,relro,-z,lazy", "-Wl,-z,noexecstack")
	by := hardeningFindings(t, dir, nil)
	weak := rulesOf(by["weak"])
	for _, r := range []string{"binary/elf-no-pie", "binary/elf-no-relro", "binary/elf-executable-stack", "binary/elf-no-stack-canary", "binary/elf-no-fortify", "binary/elf-insecure-rpath"} {
		if !strings.Contains(weak, r) {
			t.Errorf("weak binary misses %s: %s", r, weak)
		}
	}
	if fs := by["strong"]; len(fs) != 0 {
		t.Errorf("hardened binary: %s", rulesOf(fs))
	}
	if got := rulesOf(by["partial"]); got != "binary/elf-partial-relro" {
		t.Errorf("partial RELRO: %s", got)
	}
}

func TestBinaryHardeningMalformed(t *testing.T) {
	dir := t.TempDir()
	// Truncated ELF and PE headers: ignored or reported, never a crash.
	writeFiles(t, dir, map[string]string{
		"bad.so":    "\x7fELF\x02\x01\x01" + strings.Repeat("\xff", 120),
		"bad.dll":   "MZ" + strings.Repeat("\x00", 58) + "\x40\x00\x00\x00PE\x00\x00" + strings.Repeat("\xff", 100),
		"Foo.class": "\xca\xfe\xba\xbe\x00\x00\x00\x34" + strings.Repeat("\x00", 100),
	})
	by := hardeningFindings(t, dir, nil)
	if len(by) != 0 {
		t.Errorf("malformed files produce no findings: %v", by)
	}
}
