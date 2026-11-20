package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

// radare2 (LGPL-3.0) runs as a separate process with its sandbox mode on
// (cfg.sandbox: no shell commands, no file writes, no files outside the
// input's directory), without user rc files (-N) and with an analysis
// timeout. Session 1 is triage (information, sections, imports, exports,
// strings); session 2 is the bounded analysis (functions, call and data
// references); session 3 disassembles the selected functions.

// r2Marker separates command outputs ("#" would start an r2 comment).
const r2Marker = "PATHOS-REA-R2-MARK"

func r2Args(file string, cmds string, analTimeout int) []string {
	return []string{"-N", "-q", "-2", "-e", "cfg.sandbox=true", "-e", "scr.color=0", "-e", "scr.utf8=false", "-e", "scr.interactive=false",
		"-e", "bin.relocs.apply=true", "-e", "anal.timeout=" + strconv.Itoa(analTimeout), "-e", "asm.bytes=false", "-c", cmds, filepath.Base(file)}
}

func r2Version(ctx context.Context) string {
	out, _, err := runTool(ctx, runOpts{timeout: 20 * time.Second}, "r2", "-v")
	if err != nil {
		return ""
	}
	// "radare2 6.2.6 +1 abi:174 @ linux-x86_64"
	f := strings.Fields(string(out))
	if len(f) >= 2 && f[0] == "radare2" {
		return f[1]
	}
	return ""
}

// splitMarked splits r2 output at marker lines.
func splitMarked(out []byte, n int) [][]byte {
	parts := bytes.Split(out, []byte(r2Marker+"\n"))
	for len(parts) < n {
		parts = append(parts, nil)
	}
	return parts
}

type r2Info struct {
	Arch     string `json:"arch"`
	Bits     int    `json:"bits"`
	OS       string `json:"os"`
	Lang     string `json:"lang"`
	BinType  string `json:"bintype"`
	Stripped bool   `json:"stripped"`
	Static   bool   `json:"static"`
}

type r2Section struct {
	Name  string `json:"name"`
	Size  int64  `json:"size"`
	VSize int64  `json:"vsize"`
	Perm  string `json:"perm"`
	PAddr int64  `json:"paddr"`
	VAddr uint64 `json:"vaddr"`
}

type r2Import struct {
	Name string `json:"name"`
	Lib  string `json:"libname"`
	Type string `json:"type"`
	PLT  uint64 `json:"plt"`
}

type r2Symbol struct {
	Name     string `json:"name"`
	RealName string `json:"realname"`
	Type     string `json:"type"`
	VAddr    uint64 `json:"vaddr"`
	PAddr    int64  `json:"paddr"`
	Size     int64  `json:"size"`
	Imported bool   `json:"is_imported"`
}

type r2String struct {
	VAddr   uint64 `json:"vaddr"`
	PAddr   int64  `json:"paddr"`
	Size    int64  `json:"size"`
	Section string `json:"section"`
	String  string `json:"string"`
}

type r2Func struct {
	Addr uint64 `json:"addr"`
	Name string `json:"name"`
	Size int64  `json:"size"`
}

type r2Xref struct {
	Type string `json:"type"`
	At   uint64 `json:"at"`
	Ref  uint64 `json:"ref"`
	Name string `json:"name"`
}

// r2Triage is session 1.
type r2Triage struct {
	info     r2Info
	sections []r2Section
	imports  []r2Import
	exports  []r2Symbol
	strings  []r2String
}

func runR2Triage(ctx context.Context, file string, memMB int, budget time.Duration) (*r2Triage, error) {
	cmds := strings.Join([]string{"iIj", "?e " + r2Marker, "iSj", "?e " + r2Marker, "iij", "?e " + r2Marker, "iEj", "?e " + r2Marker, "izj"}, ";")
	out, _, err := runTool(ctx, runOpts{timeout: budget, memoryMB: memMB, maxStdout: 256 << 20, dir: filepath.Dir(file)}, "r2", r2Args(file, cmds, 0)...)
	if err != nil {
		return nil, err
	}
	p := splitMarked(out, 5)
	t := &r2Triage{}
	_ = json.Unmarshal(bytes.TrimSpace(p[0]), &t.info)
	_ = json.Unmarshal(bytes.TrimSpace(p[1]), &t.sections)
	_ = json.Unmarshal(bytes.TrimSpace(p[2]), &t.imports)
	_ = json.Unmarshal(bytes.TrimSpace(p[3]), &t.exports)
	_ = json.Unmarshal(bytes.TrimSpace(p[4]), &t.strings)
	if t.info.Arch == "" && len(t.sections) == 0 {
		return t, fmt.Errorf("radare2 could not load the file")
	}
	return t, nil
}

// r2Analysis is session 2: functions and their references.
type r2Analysis struct {
	funcs []r2Func
	xrefs map[uint64][]r2Xref // by function address
}

func runR2Analysis(ctx context.Context, file string, memMB int, budget time.Duration) (*r2Analysis, error) {
	// anal.timeout stops the analysis itself; the process budget leaves
	// room for the reference listing.
	analSecs := int(budget.Seconds() * 0.6)
	if analSecs < 10 {
		analSecs = 10
	}
	cmds := "aa;aflj;?e " + r2Marker + ";(pm;?v $$;axffj);.(pm) @@F"
	out, _, err := runTool(ctx, runOpts{timeout: budget, memoryMB: memMB, maxStdout: 512 << 20, dir: filepath.Dir(file)}, "r2", r2Args(file, cmds, analSecs)...)
	if err != nil && err != errTimeout {
		return nil, err
	}
	p := splitMarked(out, 2)
	a := &r2Analysis{xrefs: map[uint64][]r2Xref{}}
	if jerr := json.Unmarshal(bytes.TrimSpace(p[0]), &a.funcs); jerr != nil && err == nil {
		return nil, fmt.Errorf("radare2: unreadable function list")
	}
	sc := bufio.NewScanner(bytes.NewReader(p[1]))
	sc.Buffer(make([]byte, 1<<20), 64<<20)
	var cur uint64
	for sc.Scan() {
		line := bytes.TrimSpace(sc.Bytes())
		switch {
		case bytes.HasPrefix(line, []byte("0x")):
			v, perr := strconv.ParseUint(string(line[2:]), 16, 64)
			if perr == nil {
				cur = v
			}
		case bytes.HasPrefix(line, []byte("[")):
			var xs []r2Xref
			if json.Unmarshal(line, &xs) == nil {
				keep := xs[:0]
				for _, x := range xs {
					if x.Type == "CALL" || x.Type == "DATA" || x.Type == "STRN" || x.Type == "STRING" {
						keep = append(keep, x)
					}
				}
				if len(keep) > 0 {
					a.xrefs[cur] = append(a.xrefs[cur], keep...)
				}
			}
		}
	}
	return a, err
}

var r2HexRe = regexp.MustCompile(`^0x[0-9a-f]+$`)

// runR2Code disassembles the given functions (session 3).
func runR2Code(ctx context.Context, file string, memMB int, budget time.Duration, addrs []string) (map[string]string, error) {
	if len(addrs) == 0 {
		return nil, nil
	}
	var b strings.Builder
	for _, a := range addrs {
		if !r2HexRe.MatchString(a) {
			continue
		}
		fmt.Fprintf(&b, "af @ %s;?e %s%s;pdf @ %s;", a, r2Marker, a, a)
	}
	out, _, err := runTool(ctx, runOpts{timeout: budget, memoryMB: memMB, maxStdout: 128 << 20, dir: filepath.Dir(file)}, "r2", r2Args(file, b.String(), 0)...)
	if err != nil && err != errTimeout {
		return nil, err
	}
	res := map[string]string{}
	chunks := bytes.Split(out, []byte(r2Marker))
	for _, c := range chunks[1:] {
		nl := bytes.IndexByte(c, '\n')
		if nl < 0 {
			continue
		}
		addr := string(c[:nl])
		text := string(c[nl+1:])
		if len(text) > maxCodeBytes {
			text = clip(text, maxCodeBytes-40) + "\n; [truncated by pathos-rea]\n"
		}
		res[addr] = text
	}
	return res, err
}

// r2Name strips radare2's flag prefixes: "sym.imp.puts" → "puts".
func r2Name(n string) string {
	for _, p := range []string{"sym.imp.", "reloc.", "sym.", "fcn.", "dbg.", "loc.", "obj."} {
		if strings.HasPrefix(n, p) {
			return n[len(p):]
		}
	}
	return n
}

// sortedFuncs returns r2 functions ordered by address.
func sortedFuncs(fs []r2Func) []r2Func {
	sort.Slice(fs, func(i, j int) bool { return fs[i].Addr < fs[j].Addr })
	return fs
}

// goLenRe matches the instruction after a Go string's address load that
// sets its length: "mov ebx, 0xb", "mov ecx, 11", "mov r8d, 0x1f".
var goLenRe = regexp.MustCompile(`^mov\s+(?:e[a-z]{2}|r\d{1,2}d?|r[a-z]{2}),\s*(0x[0-9a-f]+|\d+)\s*$`)

// runR2GoStrings reads, for each data reference site, the two instructions
// that load a Go string (lea of the data, then its length) and returns the
// lengths by site address (x86-64 only; Go strings are not
// NUL-terminated, so this is how their exact extent is known).
func runR2GoStrings(ctx context.Context, file string, memMB int, budget time.Duration, sites []uint64) (map[uint64]int, error) {
	res := map[uint64]int{}
	deadline := time.Now().Add(budget)
	// Batches keep each command line well below the kernel's argument
	// size limit (cfg.sandbox forbids script files outside the input's
	// directory).
	const batch = 800
	for i := 0; i < len(sites); i += batch {
		left := time.Until(deadline)
		if left <= time.Second {
			return res, errTimeout
		}
		var b strings.Builder
		for _, a := range sites[i:min(i+batch, len(sites))] {
			fmt.Fprintf(&b, "?e %s0x%x;pi 2 @ 0x%x;", r2Marker, a, a)
		}
		out, _, err := runTool(ctx, runOpts{timeout: left, memoryMB: memMB, maxStdout: 16 << 20, dir: filepath.Dir(file)}, "r2", r2Args(file, b.String(), 0)...)
		if err != nil && err != errTimeout {
			return res, err
		}
		parseGoLens(out, res)
		if err != nil {
			return res, err
		}
	}
	return res, nil
}

func parseGoLens(out []byte, res map[uint64]int) {
	for _, c := range bytes.Split(out, []byte(r2Marker))[1:] {
		lines := strings.Split(strings.TrimSpace(string(c)), "\n")
		if len(lines) < 3 {
			continue
		}
		at, perr := strconv.ParseUint(strings.TrimPrefix(lines[0], "0x"), 16, 64)
		if perr != nil || !strings.HasPrefix(strings.TrimSpace(lines[1]), "lea ") {
			continue
		}
		m := goLenRe.FindStringSubmatch(strings.TrimSpace(lines[2]))
		if m == nil {
			continue
		}
		n, perr := strconv.ParseInt(m[1], 0, 64)
		if perr != nil || n <= 0 || n > 4096 {
			continue
		}
		res[at] = int(n)
	}
}
