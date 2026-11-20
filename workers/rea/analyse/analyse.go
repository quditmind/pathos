package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"
)

// analyse runs the enabled tools on one artifact and builds the document.
// It never executes the artifact: every tool only reads it.
func analyse(ctx context.Context, cfg Config, input, tmp string) (*Doc, error) {
	start := time.Now()
	deadline := start.Add(time.Duration(cfg.TimeoutSeconds) * time.Second)
	// Each step gets a share of what is left; the document is always
	// written before the sandbox's own timeout.
	budget := func(share float64) time.Duration {
		left := time.Until(deadline) - 15*time.Second
		if left < 5*time.Second {
			return 5 * time.Second
		}
		return time.Duration(float64(left) * share)
	}
	// #nosec G304 G703 -- the artifact the worker copied into the sandbox job directory (pathos-rea's argument)
	f, err := os.Open(input)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil || !st.Mode().IsRegular() {
		return nil, errors.New("the input is not a regular file")
	}
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return nil, err
	}
	head := make([]byte, 512)
	hn, _ := f.ReadAt(head, 0)
	head = head[:hn]

	d := &Doc{Schema: Schema, Generator: map[string]string{"name": "pathos-rea", "version": Version},
		Artifact: Artifact{FileName: clip(filepath.Base(input), 255), SHA256: hex.EncodeToString(h.Sum(nil)), Size: st.Size(), Language: "unknown"},
		Tools:    map[string]*ToolState{}, Sections: []Section{}, Functions: []Function{}, Imports: []Import{}, Exports: []Export{},
		Strings: []String{}, Calls: []Ref{}, StrRefs: []Ref{}, Code: []Code{}, Stats: map[string]any{}}
	truncated := false

	format := sniff(head)
	if format == "zip" {
		format = zipKind(input)
	}
	nat, nerr := parseNative(input, f, format)
	if nerr != nil {
		d.Stats["native_error"] = clip(nerr.Error(), 300)
		nat = nil
	}
	amap := addrMap(nil)
	if nat != nil {
		amap = nat.amap
		d.Artifact.Arch, d.Artifact.Bits, d.Artifact.OS = nat.arch, nat.bits, nat.os
		d.Artifact.Stripped, d.Artifact.BuildID = nat.stripped, nat.buildID
		if nat.entry != 0 {
			d.Artifact.Entry = hexAddr(nat.entry)
		}
		d.Sections = append(d.Sections, nat.sections...)
		d.Imports = append(d.Imports, nat.imports...)
		d.Exports = append(d.Exports, nat.exports...)
		if nat.isDotnet {
			format = "dotnet"
			d.Artifact.Language = "dotnet"
		}
	}
	executable := format == "elf" || format == "pe" || format == "macho" || format == "dotnet"
	switch format {
	case "apk", "jar", "dex":
		d.Artifact.Language = "java"
	}
	if executable {
		if gi := goBuildInfo(input); gi != nil {
			d.Go = gi
		}
	}
	mainPath := ""
	if d.Go != nil {
		mainPath = d.Go.MainModule.Path
		d.Artifact.Language = "go"
	}
	if nat != nil && nat.isGo {
		d.Artifact.Language = "go"
	}

	// Functions known before radare2: the Go symbol table.
	funcs := map[uint64]*Function{}
	addFunc := func(fn Function) {
		a, err := strconv.ParseUint(strings.TrimPrefix(fn.Addr, "0x"), 16, 64)
		if err != nil {
			return
		}
		if _, ok := funcs[a]; ok {
			return
		}
		c := fn
		funcs[a] = &c
	}
	if nat != nil {
		for _, fn := range nat.goFuncs {
			fn.Library = goLibrary(fn.Package, mainPath)
			addFunc(fn)
		}
	}

	// radare2: triage, analysis, disassembly.
	var tri *r2Triage
	var ana *r2Analysis
	if cfg.enabled("radare2") {
		ts := &ToolState{Version: r2Version(ctx)}
		d.Tools["radare2"] = ts
		t0 := time.Now()
		switch {
		case ts.Version == "":
			ts.Status, ts.Detail = "skipped", "radare2 is not installed in this image"
		case !executable && format != "unknown" && format != "dex" && format != "wasm":
			ts.Status, ts.Detail = "skipped", "not an executable ("+format+")"
		default:
			tri, err = runR2Triage(ctx, input, cfg.MemoryMB, budget(0.15))
			switch {
			case errors.Is(err, errTimeout):
				ts.Status, ts.Detail = "timed_out", "triage timed out"
			case err != nil && !executable:
				ts.Status, ts.Detail = "skipped", "radare2 does not recognise this format ("+format+")"
				tri = nil
			case err != nil:
				ts.Status, ts.Detail = "failed", clip(err.Error(), 500)
			default:
				ts.Status = "succeeded"
				ana, err = runR2Analysis(ctx, input, cfg.MemoryMB, budget(0.5))
				switch {
				case errors.Is(err, errTimeout):
					ts.Detail = "the function analysis stopped at its time budget; the call graph is partial"
					truncated = true
				case err != nil:
					ts.Detail = "function analysis failed: " + clip(err.Error(), 400)
				}
			}
		}
		ts.DurationMS = time.Since(t0).Milliseconds()
	}
	if tri != nil {
		if d.Artifact.Arch == "" {
			d.Artifact.Arch, d.Artifact.Bits, d.Artifact.OS, d.Artifact.Stripped = tri.info.Arch, tri.info.Bits, tri.info.OS, tri.info.Stripped
		}
		if d.Artifact.Language == "unknown" {
			d.Artifact.Language = r2Lang(tri.info.Lang)
		}
		if len(d.Sections) == 0 {
			for _, s := range tri.sections {
				if s.Name == "" || len(d.Sections) >= maxSections {
					continue
				}
				d.Sections = append(d.Sections, Section{Name: clip(s.Name, 200), Offset: s.PAddr, VAddr: hexAddr(s.VAddr), Size: s.Size,
					VSize: s.VSize, Perm: strings.TrimPrefix(s.Perm, "-"), Entropy: entropyOfReader(f, s.PAddr, s.Size), Tool: "radare2"})
				amap = append(amap, seg{name: s.Name, vaddr: s.VAddr, end: s.VAddr + u64(s.VSize), off: s.PAddr, fileBacked: s.Size > 0})
			}
		}
		if len(d.Imports) == 0 {
			for _, im := range tri.imports {
				if len(d.Imports) >= maxImports {
					break
				}
				d.Imports = append(d.Imports, Import{ID: "imp:" + im.Lib + "!" + im.Name, Name: clip(im.Name, maxNameLength), Library: im.Lib,
					Kind: importKind(im.Type), Addr: addrOrEmpty(im.PLT), Offset: amap.offset(im.PLT), Tool: "radare2"})
			}
		}
		if len(d.Exports) == 0 {
			for _, ex := range tri.exports {
				if len(d.Exports) >= maxExports {
					break
				}
				d.Exports = append(d.Exports, Export{Name: clip(firstNonEmpty(ex.RealName, ex.Name), maxNameLength), Addr: hexAddr(ex.VAddr), Offset: ex.PAddr, Tool: "radare2"})
			}
		}
	}
	// Import addresses and offsets (PLT) from radare2.
	if tri != nil {
		plt := map[string]uint64{}
		for _, im := range tri.imports {
			plt[im.Name] = im.PLT
		}
		for i := range d.Imports {
			if a := plt[d.Imports[i].Name]; a != 0 && d.Imports[i].Addr == "" {
				d.Imports[i].Addr, d.Imports[i].Offset = hexAddr(a), amap.offset(a)
			}
		}
	}
	if ana != nil {
		for _, rf := range sortedFuncs(ana.funcs) {
			name := rf.Name
			if strings.HasPrefix(name, "sym.imp.") || strings.HasPrefix(name, "reloc.") {
				continue // PLT stubs are imports
			}
			lib := crtFunction(r2Name(name))
			pkg := ""
			if d.Artifact.Language == "go" {
				// Not in the Go symbol table: runtime or linker code, or
				// C code linked with cgo.
				lib, pkg = true, goPackage(r2Name(name))
			}
			addFunc(Function{ID: "fn:" + hexAddr(rf.Addr), Name: clip(r2Name(name), maxNameLength), Addr: hexAddr(rf.Addr),
				Offset: amap.offset(rf.Addr), Size: rf.Size, Section: amap.section(rf.Addr), Tool: "radare2", Library: lib, Package: pkg})
		}
	}
	if len(funcs) == 0 && nat != nil {
		for _, fn := range nat.symFuncs {
			fn.Library = crtFunction(fn.Name)
			addFunc(fn)
		}
	}

	// Go: the linked packages as imports.
	if d.Artifact.Language == "go" {
		pk := map[string]bool{}
		for _, fn := range funcs {
			if fn.Package != "" && fn.Library && !pk[fn.Package] {
				pk[fn.Package] = true
			}
		}
		names := make([]string, 0, len(pk))
		for p := range pk {
			names = append(names, p)
		}
		sort.Strings(names)
		for _, p := range names {
			if len(d.Imports) >= maxImports {
				truncated = true
				break
			}
			d.Imports = append(d.Imports, Import{ID: "imp:go:" + p, Name: p, Library: goModuleOf(p, d.Go), Kind: "package", Tool: "pathos-rea"})
		}
	}

	// Functions, ordered by address, capped (main-module code first).
	all := make([]Function, 0, len(funcs))
	for _, fn := range funcs {
		if fn.Offset < 0 {
			fn.Offset = -1
		}
		all = append(all, *fn)
	}
	sort.Slice(all, func(i, j int) bool {
		if all[i].Library != all[j].Library {
			return !all[i].Library
		}
		return addrLess(all[i].Addr, all[j].Addr)
	})
	if len(all) > cfg.MaxFunctions {
		all, truncated = all[:cfg.MaxFunctions], true
	}
	kept := map[string]bool{}
	for _, fn := range all {
		kept[fn.ID] = true
	}
	sort.Slice(all, func(i, j int) bool { return addrLess(all[i].Addr, all[j].Addr) })
	d.Functions = all

	// Strings (secrets redacted), with routes and URLs found inside
	// merged string data (Go) as their own entries.
	var raws []rawString
	if tri != nil && len(tri.strings) > 0 {
		for _, s := range tri.strings {
			raws = append(raws, rawString{off: s.PAddr, size: s.Size, vaddr: s.VAddr, section: s.Section, tool: "radare2"})
		}
	} else {
		raws = scanStrings(f, st.Size(), amap, 6, cfg.MaxStrings*2)
	}
	var strTrunc bool
	d.Strings, strTrunc = buildStrings(f, raws, amap, cfg.MaxStrings)
	truncated = truncated || strTrunc

	// Go string literals referenced by code: their exact extent comes from
	// the instructions that load them.
	goLit := map[uint64]string{} // reference site → string id
	if ana != nil && d.Artifact.Language == "go" && d.Artifact.Arch == "x86" {
		type site struct{ at, ref uint64 }
		var sites []site
		fas := make([]uint64, 0, len(ana.xrefs))
		for a := range ana.xrefs {
			fas = append(fas, a)
		}
		sort.Slice(fas, func(i, j int) bool {
			li, lj := libAt(funcs, fas[i]), libAt(funcs, fas[j])
			if li != lj {
				return !li
			}
			return fas[i] < fas[j]
		})
		for _, fa := range fas {
			for _, x := range ana.xrefs[fa] {
				if x.Type != "CALL" && len(sites) < maxGoLiteralSites && amap.offset(x.Ref) >= 0 && strings.HasPrefix(amap.section(x.Ref), ".rodata") {
					sites = append(sites, site{x.At, x.Ref})
				}
			}
		}
		ats := make([]uint64, len(sites))
		for i, s := range sites {
			ats[i] = s.at
		}
		lens, lerr := runR2GoStrings(ctx, input, cfg.MemoryMB, budget(0.2), ats)
		d.Stats["go_literal_sites"], d.Stats["go_literal_lengths"] = len(sites), len(lens)
		if lerr != nil {
			d.Stats["go_literal_error"] = clip(lerr.Error(), 300)
		}
		have := map[string]bool{}
		for _, s := range d.Strings {
			have[s.ID] = true
		}
		for _, s := range sites {
			n, ok := lens[s.at]
			if !ok {
				continue
			}
			off := amap.offset(s.ref)
			id := "str:" + hexAddr(u64(off))
			buf := make([]byte, n)
			if k, _ := f.ReadAt(buf, off); k != n || !printableText(buf) {
				continue
			}
			if !have[id] {
				if len(d.Strings) >= cfg.MaxStrings {
					truncated = true
					continue
				}
				val, red := redact(clip(string(buf), maxStringLen))
				kind := classify(val)
				if red {
					kind = "secret"
				}
				have[id] = true
				d.Strings = append(d.Strings, String{ID: id, Value: val, Offset: off, VAddr: hexAddr(s.ref), Section: amap.section(s.ref),
					Kind: kind, Redacted: red, Tool: "radare2"})
			}
			goLit[s.at] = id
		}
	}

	// Calls and string references.
	if ana != nil {
		impByName := map[string]string{}
		for _, im := range d.Imports {
			if im.Kind != "package" {
				impByName[im.Name] = im.ID
			}
		}
		strIdx := newStringIndex(d.Strings)
		seenCall, seenRef := map[[2]string]bool{}, map[[2]string]bool{}
		addrs := make([]uint64, 0, len(ana.xrefs))
		for a := range ana.xrefs {
			addrs = append(addrs, a)
		}
		// Calls from the application's own code first (caps).
		sort.Slice(addrs, func(i, j int) bool {
			li, lj := libAt(funcs, addrs[i]), libAt(funcs, addrs[j])
			if li != lj {
				return !li
			}
			return addrs[i] < addrs[j]
		})
		for _, fa := range addrs {
			from := "fn:" + hexAddr(fa)
			if !kept[from] {
				continue
			}
			for _, x := range ana.xrefs[fa] {
				off := amap.offset(x.At)
				switch {
				case x.Type == "CALL":
					to := ""
					if n := strings.TrimPrefix(strings.TrimPrefix(x.Name, "sym.imp."), "reloc."); n != x.Name {
						to = impByName[n]
					} else if kept["fn:"+hexAddr(x.Ref)] {
						to = "fn:" + hexAddr(x.Ref)
					}
					k := [2]string{from, to}
					if to == "" || seenCall[k] {
						continue
					}
					if len(d.Calls) >= maxCalls {
						truncated = true
						continue
					}
					seenCall[k] = true
					d.Calls = append(d.Calls, Ref{From: from, To: to, Offset: off, Tool: "radare2"})
				default:
					sid, ok := goLit[x.At]
					if !ok {
						sid = strIdx.lookup(x.Ref)
					}
					k := [2]string{from, sid}
					if sid == "" || seenRef[k] {
						continue
					}
					if len(d.StrRefs) >= maxStrRefs {
						truncated = true
						continue
					}
					seenRef[k] = true
					d.StrRefs = append(d.StrRefs, Ref{From: from, To: sid, Offset: off, Tool: "radare2"})
				}
			}
		}
	}

	// Disassembly of the application's own functions.
	codeFor := selectCode(d.Functions, cfg.MaxCode)
	if tri != nil && len(codeFor) > 0 && cfg.MaxCode > 0 {
		code, err := runR2Code(ctx, input, cfg.MemoryMB, budget(0.3), codeFor)
		if err != nil && d.Tools["radare2"] != nil && d.Tools["radare2"].Detail == "" {
			d.Tools["radare2"].Detail = "disassembly incomplete: " + clip(err.Error(), 300)
		}
		for _, a := range codeFor {
			if t, ok := code[a]; ok && strings.TrimSpace(t) != "" {
				t, _ = redact(t)
				d.Code = append(d.Code, Code{Function: "fn:" + a, Tool: "radare2", Kind: "disassembly", Text: t})
			}
		}
	}

	// binwalk: firmware images and unknown blobs.
	if cfg.enabled("binwalk") {
		ts := &ToolState{Version: binwalkVersion(ctx)}
		d.Tools["binwalk"] = ts
		t0 := time.Now()
		switch {
		case ts.Version == "":
			ts.Status, ts.Detail = "skipped", "binwalk is not installed in this image"
		case executable || format == "apk" || format == "jar" || format == "dex":
			ts.Status, ts.Detail = "skipped", "not a firmware image ("+format+")"
		default:
			fw, err := runBinwalk(ctx, input, tmp, cfg.MemoryMB, budget(0.4))
			switch {
			case errors.Is(err, errTimeout):
				ts.Status, ts.Detail = "timed_out", "extraction stopped at its time budget"
				d.Firmware = fw
			case errors.Is(err, errBinwalkIncomplete):
				// What it did find is real and kept; the run is not reported
				// as a success.
				ts.Status, ts.Detail = "failed", clip(err.Error(), 500)
				d.Firmware = fw
			case err != nil:
				ts.Status, ts.Detail = "failed", clip(err.Error(), 500)
			default:
				ts.Status, d.Firmware = "succeeded", fw
			}
			if fw != nil && len(fw.Entries) > 0 && (format == "unknown" || format == "archive") {
				format = "firmware"
			}
		}
		ts.DurationMS = time.Since(t0).Milliseconds()
	}

	// Optional JVM and .NET tools.
	runOptional(ctx, cfg, d, input, tmp, format, executable, codeFor, budget)

	if format == "zip" {
		format = "archive"
	}
	d.Artifact.Format = format
	for _, t := range []string{"radare2", "binwalk", "ghidra", "jadx", "ilspy"} {
		if _, ok := d.Tools[t]; !ok {
			d.Tools[t] = &ToolState{Status: "skipped", Detail: "not enabled for this analysis"}
			if v := toolVersions(ctx)[t]; v != "" {
				d.Tools[t].Version = v
			}
		}
	}
	d.Stats["truncated"] = truncated
	d.Stats["functions"] = len(d.Functions)
	d.Stats["imports"] = len(d.Imports)
	d.Stats["exports"] = len(d.Exports)
	d.Stats["strings"] = len(d.Strings)
	d.Stats["sections"] = len(d.Sections)
	d.Stats["calls"] = len(d.Calls)
	d.Stats["string_refs"] = len(d.StrRefs)
	d.Stats["code"] = len(d.Code)
	d.Stats["duration_ms"] = time.Since(start).Milliseconds()
	return d, nil
}

// maxGoLiteralSites bounds the Go string literal resolution.
const maxGoLiteralSites = 5000

// printableText reports UTF-8 text without control characters (but tab
// and newline).
func printableText(b []byte) bool {
	s := string(b)
	if !utf8.ValidString(s) {
		return false
	}
	for _, r := range s {
		if r < 0x20 && r != '\t' && r != '\n' && r != '\r' {
			return false
		}
	}
	return true
}

func r2Lang(l string) string {
	switch l {
	case "c":
		return "c"
	case "cxx", "c++":
		return "cpp"
	case "rust":
		return "rust"
	case "go":
		return "go"
	case "java", "dalvik":
		return "java"
	case "msvc", "dotnet":
		return "dotnet"
	}
	return "unknown"
}

func importKind(t string) string {
	switch strings.ToUpper(t) {
	case "FUNC":
		return "function"
	case "OBJ", "OBJECT":
		return "object"
	}
	return "function"
}

func addrOrEmpty(a uint64) string {
	if a == 0 {
		return ""
	}
	return hexAddr(a)
}

func firstNonEmpty(v ...string) string {
	for _, s := range v {
		if s != "" {
			return s
		}
	}
	return ""
}

func addrLess(a, b string) bool {
	if len(a) != len(b) {
		return len(a) < len(b)
	}
	return a < b
}

// crtFunction reports C runtime start-up and tear-down code.
func crtFunction(n string) bool {
	switch n {
	case "entry0", "_start", "_init", "_fini", "frame_dummy", "register_tm_clones", "deregister_tm_clones", "__do_global_dtors_aux",
		"__libc_csu_init", "__libc_csu_fini", "entry.init0", "entry.fini0", "_dl_relocate_static_pie":
		return true
	}
	return strings.HasPrefix(n, "entry.") || strings.HasPrefix(n, "__x86.")
}

func libAt(funcs map[uint64]*Function, a uint64) bool {
	if f, ok := funcs[a]; ok {
		return f.Library
	}
	return true
}

// goModuleOf is the module that provides a package ("std" for the standard
// library).
func goModuleOf(pkg string, gi *GoInfo) string {
	if gi != nil {
		best := ""
		for _, m := range gi.Deps {
			if (pkg == m.Path || strings.HasPrefix(pkg, m.Path+"/")) && len(m.Path) > len(best) {
				best = m.Path
			}
		}
		if best != "" {
			return best
		}
	}
	first := strings.SplitN(pkg, "/", 2)[0]
	if !strings.Contains(first, ".") {
		return "std"
	}
	return ""
}

// selectCode picks the functions to disassemble: the application's own
// (non-library) functions, largest first is not useful for review, so in
// address order.
func selectCode(fns []Function, max int) []string {
	var out []string
	for _, fn := range fns {
		if len(out) >= max {
			break
		}
		if !fn.Library && fn.Size > 0 {
			out = append(out, fn.Addr)
		}
	}
	return out
}

// rawString is a string location before decoding.
type rawString struct {
	off, size int64
	vaddr     uint64
	section   string
	tool      string
}

// scanStrings finds printable ASCII runs (used without radare2).
func scanStrings(r io.ReaderAt, size int64, amap addrMap, minLen, max int) []rawString {
	var out []rawString
	buf := make([]byte, 1<<16)
	runStart, runLen := int64(-1), int64(0)
	flush := func() {
		if runLen >= int64(minLen) && len(out) < max {
			out = append(out, rawString{off: runStart, size: runLen, vaddr: amap.vaddrOf(runStart), section: amap.section(amap.vaddrOf(runStart)), tool: "pathos-rea"})
		}
		runStart, runLen = -1, 0
	}
	for off := int64(0); off < size && len(out) < max; off += int64(len(buf)) {
		n, err := r.ReadAt(buf, off)
		for i := 0; i < n; i++ {
			c := buf[i]
			if c >= 0x20 && c < 0x7f || c == '\t' {
				if runStart < 0 {
					runStart = off + int64(i)
				}
				runLen++
				continue
			}
			flush()
		}
		if err != nil {
			break
		}
	}
	flush()
	return out
}

var (
	routeInRe = regexp.MustCompile(`/[a-z0-9_][A-Za-z0-9_.~-]*(?:/[A-Za-z0-9_.~{}:-]*)*`)
	urlInRe   = regexp.MustCompile(`[a-z][a-z0-9+.-]{1,15}://[A-Za-z0-9._~:/?#\[\]@!$&'()*+,;=%-]{3,}`)
	routeRe   = regexp.MustCompile(`^/(?:[A-Za-z0-9_.~{}:@%+*-]+/?)*$`)
	formatRe  = regexp.MustCompile(`%[-+ #0-9.]*[sdvqxXfgpTtbcoeEu]`)
)

var fsPrefixes = []string{"/etc/", "/usr/", "/bin/", "/sbin/", "/lib", "/proc/", "/sys/", "/dev/", "/var/", "/tmp/", "/home/", "/opt/", "/root/", "/run/", "/mnt/", "/boot/", "/srv/"}

func classify(v string) string {
	switch {
	case strings.Contains(v, "://"):
		return "url"
	case len(v) < 200 && routeRe.MatchString(v) && strings.ContainsAny(v, "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"):
		for _, p := range fsPrefixes {
			if strings.HasPrefix(v, p) || v == strings.TrimSuffix(p, "/") {
				return "path"
			}
		}
		return "route"
	case formatRe.MatchString(v):
		return "format"
	case strings.Contains(v, "/") && !strings.ContainsAny(v, " \t\n") && (strings.HasPrefix(v, "./") || strings.HasPrefix(v, "~/")):
		return "path"
	}
	return "text"
}

// buildStrings decodes, redacts and classifies strings; long runs (Go's
// merged string data) also yield the routes and URLs inside them.
func buildStrings(r io.ReaderAt, raws []rawString, amap addrMap, max int) ([]String, bool) {
	out := []String{}
	seenSub := map[string]bool{}
	truncated := false
	add := func(s String) bool {
		if len(out) >= max {
			truncated = true
			return false
		}
		out = append(out, s)
		return true
	}
	for _, rs := range raws {
		if rs.size <= 0 || rs.off < 0 {
			continue
		}
		n := rs.size
		if n > 64<<10 {
			n = 64 << 10
		}
		b := make([]byte, n)
		k, _ := r.ReadAt(b, rs.off)
		raw := strings.Trim(strings.ToValidUTF8(string(b[:k]), "?"), "\x00")
		if strings.TrimSpace(raw) == "" {
			continue
		}
		val, red := redact(clip(raw, maxStringLen))
		kind := classify(val)
		if red {
			kind = "secret"
		}
		vaddr := rs.vaddr
		if vaddr == 0 {
			vaddr = amap.vaddrOf(rs.off)
		}
		if !add(String{ID: "str:" + hexAddr(u64(rs.off)), Value: val, Offset: rs.off, VAddr: addrOrEmpty(vaddr), Section: clip(rs.section, 200),
			Kind: kind, Redacted: red, Tool: rs.tool}) {
			break
		}
		if len(raw) <= 40 || red {
			continue
		}
		// Routes and URLs inside merged string data.
		var subs [][]int
		subs = append(subs, urlInRe.FindAllStringIndex(raw, 200)...)
		for _, m := range routeInRe.FindAllStringIndex(raw, 400) {
			if m[0] > 0 {
				prev := raw[m[0]-1]
				if prev != ' ' && prev != '"' && prev != '\'' && prev != '>' && prev != '(' && prev != '=' && prev != '`' && prev != '\t' && prev != '\n' {
					continue
				}
			}
			seg := raw[m[0]:m[1]]
			if strings.Count(seg, "/") < 2 && len(seg) < 6 {
				continue
			}
			subs = append(subs, m)
		}
		for _, m := range subs {
			v := raw[m[0]:m[1]]
			if v == raw || seenSub[v] {
				continue
			}
			seenSub[v] = true
			sv, sred := redact(clip(v, maxStringLen))
			sk := classify(sv)
			if sred {
				sk = "secret"
			}
			off := rs.off + int64(m[0])
			sva := uint64(0)
			if vaddr != 0 {
				sva = vaddr + u64(int64(m[0]))
			}
			if !add(String{ID: "str:" + hexAddr(u64(off)), Value: sv, Offset: off, VAddr: addrOrEmpty(sva), Section: clip(rs.section, 200),
				Kind: sk, Redacted: sred, Tool: "pathos-rea"}) {
				break
			}
		}
	}
	return out, truncated
}

// stringIndex maps a referenced address to the string at (or containing)
// it.
type stringIndex struct {
	exact map[uint64]string
	spans []span
}

type span struct {
	start, end uint64
	id         string
}

func newStringIndex(ss []String) *stringIndex {
	ix := &stringIndex{exact: map[uint64]string{}}
	for _, s := range ss {
		a, err := strconv.ParseUint(strings.TrimPrefix(s.VAddr, "0x"), 16, 64)
		if err != nil || a == 0 {
			continue
		}
		if _, ok := ix.exact[a]; !ok {
			ix.exact[a] = s.ID
		}
		ix.spans = append(ix.spans, span{a, a + u64(int64(len(s.Value))), s.ID})
	}
	sort.Slice(ix.spans, func(i, j int) bool { return ix.spans[i].start < ix.spans[j].start })
	return ix
}

func (ix *stringIndex) lookup(a uint64) string {
	if id, ok := ix.exact[a]; ok {
		return id
	}
	i := sort.Search(len(ix.spans), func(i int) bool { return ix.spans[i].start > a }) - 1
	if i >= 0 && a < ix.spans[i].end {
		return ix.spans[i].id
	}
	return ""
}

// writeDoc writes the document atomically.
func writeDoc(d *Doc, out string) error {
	b, err := json.Marshal(d)
	if err != nil {
		return err
	}
	tmp := out + ".partial"
	// #nosec G703 -- the output path is pathos-rea's argument, in the sandbox job directory
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	// #nosec G703 -- see above
	if err := os.Rename(tmp, out); err != nil {
		return fmt.Errorf("writing the document: %w", err)
	}
	return nil
}
