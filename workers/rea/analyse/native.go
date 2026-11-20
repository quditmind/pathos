package main

import (
	"archive/zip"
	"bytes"
	"debug/buildinfo"
	"debug/elf"
	"debug/gosym"
	"debug/macho"
	"debug/pe"
	"encoding/hex"
	"fmt"
	"io"
	"math"
	"os"
	"sort"
	"strings"
)

// The built-in parser (Go's debug packages; it parses, never executes):
// format, architecture, sections and their entropy, dynamic imports and
// exports, the Go symbol table (pclntab) and Go build information.

// seg maps a virtual address range to file offsets.
type seg struct {
	name       string
	vaddr, end uint64
	off        int64
	fileBacked bool
}

type addrMap []seg

// offset returns the file offset of a virtual address (-1 if not in a
// file-backed section).
func (m addrMap) offset(va uint64) int64 {
	for _, s := range m {
		if s.fileBacked && va >= s.vaddr && va < s.end {
			return s.off + i64(va-s.vaddr)
		}
	}
	return -1
}

// section returns the section name of a virtual address.
func (m addrMap) section(va uint64) string {
	for _, s := range m {
		if va >= s.vaddr && va < s.end {
			return s.name
		}
	}
	return ""
}

// vaddrOf returns the virtual address of a file offset (0 if none).
func (m addrMap) vaddrOf(off int64) uint64 {
	for _, s := range m {
		if s.fileBacked && off >= s.off && off < s.off+i64(s.end-s.vaddr) {
			return s.vaddr + u64(off-s.off)
		}
	}
	return 0
}

func hexAddr(v uint64) string { return fmt.Sprintf("0x%x", v) }

// i64 and u64 convert file offsets and sizes from untrusted headers
// without wrapping around.
func i64(v uint64) int64 {
	if v > math.MaxInt64 {
		return math.MaxInt64
	}
	return int64(v)
}

func u64(v int64) uint64 {
	if v < 0 {
		return 0
	}
	return uint64(v)
}

// native is what the built-in parser found.
type native struct {
	format   string
	arch     string
	bits     int
	os       string
	entry    uint64
	buildID  string
	stripped bool
	sections []Section
	amap     addrMap
	imports  []Import
	exports  []Export
	// Go
	goFuncs  []Function
	symFuncs []Function // ELF function symbols (fallback without radare2)
	goInfo   *GoInfo
	isGo     bool
	isDotnet bool
}

// sniff detects the container format from the first bytes.
func sniff(head []byte) string {
	switch {
	case bytes.HasPrefix(head, []byte("\x7fELF")):
		return "elf"
	case bytes.HasPrefix(head, []byte("MZ")):
		return "pe"
	case bytes.HasPrefix(head, []byte{0xfe, 0xed, 0xfa, 0xce}), bytes.HasPrefix(head, []byte{0xce, 0xfa, 0xed, 0xfe}),
		bytes.HasPrefix(head, []byte{0xfe, 0xed, 0xfa, 0xcf}), bytes.HasPrefix(head, []byte{0xcf, 0xfa, 0xed, 0xfe}),
		bytes.HasPrefix(head, []byte{0xca, 0xfe, 0xba, 0xbe}) && len(head) > 7 && head[7] < 20:
		return "macho"
	case bytes.HasPrefix(head, []byte("\x00asm")):
		return "wasm"
	case bytes.HasPrefix(head, []byte("dex\n")):
		return "dex"
	case bytes.HasPrefix(head, []byte("PK\x03\x04")):
		return "zip"
	case bytes.HasPrefix(head, []byte{0x1f, 0x8b}), bytes.HasPrefix(head, []byte("BZh")), bytes.HasPrefix(head, []byte{0xfd, '7', 'z', 'X', 'Z'}),
		len(head) > 262 && bytes.Equal(head[257:262], []byte("ustar")):
		return "archive"
	}
	return "unknown"
}

// zipKind tells an Android package, a Java archive and other zip files apart.
func zipKind(path string) string {
	zr, err := zip.OpenReader(path)
	if err != nil {
		return "archive"
	}
	defer zr.Close()
	kind := "archive"
	for _, f := range zr.File {
		switch {
		case f.Name == "AndroidManifest.xml" || strings.HasSuffix(f.Name, ".dex"):
			return "apk"
		case f.Name == "META-INF/MANIFEST.MF" || strings.HasSuffix(f.Name, ".class"):
			kind = "jar"
		}
	}
	return kind
}

func entropyOfReader(r io.ReaderAt, off, size int64) float64 {
	if size <= 0 {
		return 0
	}
	if size > 64<<20 {
		size = 64 << 20
	}
	var n [256]int
	buf := make([]byte, 1<<16)
	total := 0
	for done := int64(0); done < size; {
		k := int64(len(buf))
		if size-done < k {
			k = size - done
		}
		m, err := r.ReadAt(buf[:k], off+done)
		for _, b := range buf[:m] {
			n[b]++
		}
		total += m
		done += int64(m)
		if err != nil || m == 0 {
			break
		}
	}
	return entropyCounts(n[:], total)
}

func parseNative(path string, f *os.File, format string) (*native, error) {
	switch format {
	case "elf":
		return parseELF(f)
	case "pe":
		return parsePE(f)
	case "macho":
		return parseMachO(f)
	}
	return nil, nil
}

func parseELF(f *os.File) (*native, error) {
	ef, err := elf.NewFile(f)
	if err != nil {
		return nil, err
	}
	defer ef.Close()
	n := &native{format: "elf", entry: ef.Entry, os: "linux"}
	n.arch, n.bits = elfArch(ef.Machine), 32
	if ef.Class == elf.ELFCLASS64 {
		n.bits = 64
	}
	if ef.OSABI == elf.ELFOSABI_FREEBSD {
		n.os = "freebsd"
	}
	for _, s := range ef.Sections {
		if s.Type == elf.SHT_NULL || len(n.sections) >= maxSections {
			continue
		}
		perm := "r"
		if s.Flags&elf.SHF_WRITE != 0 {
			perm += "w"
		} else {
			perm += "-"
		}
		if s.Flags&elf.SHF_EXECINSTR != 0 {
			perm += "x"
		} else {
			perm += "-"
		}
		fileBacked := s.Type != elf.SHT_NOBITS
		size := i64(s.FileSize)
		if !fileBacked {
			size = 0
		}
		sec := Section{Name: clip(s.Name, 200), Offset: i64(s.Offset), VAddr: hexAddr(s.Addr), Size: size, VSize: i64(s.Size), Perm: perm, Tool: "pathos-rea"}
		if fileBacked {
			sec.Entropy = entropyOfReader(f, i64(s.Offset), size)
		}
		n.sections = append(n.sections, sec)
		if s.Addr != 0 && s.Flags&elf.SHF_ALLOC != 0 {
			n.amap = append(n.amap, seg{name: s.Name, vaddr: s.Addr, end: s.Addr + s.Size, off: i64(s.Offset), fileBacked: fileBacked})
		}
		if s.Name == ".note.gnu.build-id" && s.Type == elf.SHT_NOTE {
			if b, err := s.Data(); err == nil && len(b) > 16 {
				n.buildID = hex.EncodeToString(b[16:])
			}
		}
	}
	if len(n.amap) == 0 {
		// Section headers stripped: fall back to program headers.
		for _, p := range ef.Progs {
			if p.Type == elf.PT_LOAD {
				n.amap = append(n.amap, seg{name: "LOAD", vaddr: p.Vaddr, end: p.Vaddr + p.Filesz, off: i64(p.Off), fileBacked: true})
			}
		}
	}
	syms, symErr := ef.Symbols()
	n.stripped = symErr != nil || len(syms) == 0
	for _, s := range syms {
		if elf.ST_TYPE(s.Info) != elf.STT_FUNC || s.Value == 0 || s.Section == elf.SHN_UNDEF {
			continue
		}
		n.symFuncs = append(n.symFuncs, Function{ID: "fn:" + hexAddr(s.Value), Name: clip(s.Name, maxNameLength), Addr: hexAddr(s.Value),
			Offset: n.amap.offset(s.Value), Size: i64(s.Size), Section: n.amap.section(s.Value), Tool: "pathos-rea"})
	}
	if imps, err := ef.ImportedSymbols(); err == nil {
		for _, s := range imps {
			if len(n.imports) >= maxImports {
				break
			}
			lib := s.Library
			n.imports = append(n.imports, Import{ID: "imp:" + lib + "!" + s.Name, Name: clip(s.Name, maxNameLength), Library: lib, Kind: "function", Tool: "pathos-rea"})
		}
	}
	if dyn, err := ef.DynamicSymbols(); err == nil {
		for _, s := range dyn {
			if s.Section == elf.SHN_UNDEF || s.Value == 0 || elf.ST_BIND(s.Info) == elf.STB_LOCAL || len(n.exports) >= maxExports {
				continue
			}
			n.exports = append(n.exports, Export{Name: clip(s.Name, maxNameLength), Addr: hexAddr(s.Value), Offset: n.amap.offset(s.Value), Tool: "pathos-rea"})
		}
	}
	// Go: the symbol table survives stripping (pclntab).
	if sec := ef.Section(".gopclntab"); sec != nil {
		if data, err := sec.Data(); err == nil {
			text := uint64(0)
			if t := ef.Section(".text"); t != nil {
				text = t.Addr
			}
			n.goFuncs = goFunctions(data, text, n.amap)
			n.isGo = len(n.goFuncs) > 0
		}
	}
	return n, nil
}

func elfArch(m elf.Machine) string {
	switch m {
	case elf.EM_X86_64, elf.EM_386:
		return "x86"
	case elf.EM_AARCH64, elf.EM_ARM:
		return "arm"
	case elf.EM_MIPS:
		return "mips"
	case elf.EM_PPC, elf.EM_PPC64:
		return "ppc"
	case elf.EM_RISCV:
		return "riscv"
	case elf.EM_S390:
		return "s390"
	}
	return strings.ToLower(strings.TrimPrefix(m.String(), "EM_"))
}

func parsePE(f *os.File) (*native, error) {
	pf, err := pe.NewFile(f)
	if err != nil {
		return nil, err
	}
	defer pf.Close()
	n := &native{format: "pe", os: "windows", bits: 32}
	var base uint64
	switch oh := pf.OptionalHeader.(type) {
	case *pe.OptionalHeader64:
		n.bits, base, n.entry = 64, oh.ImageBase, oh.ImageBase+uint64(oh.AddressOfEntryPoint)
		n.isDotnet = len(oh.DataDirectory) > 14 && oh.DataDirectory[14].VirtualAddress != 0
	case *pe.OptionalHeader32:
		base, n.entry = uint64(oh.ImageBase), uint64(oh.ImageBase)+uint64(oh.AddressOfEntryPoint)
		n.isDotnet = len(oh.DataDirectory) > 14 && oh.DataDirectory[14].VirtualAddress != 0
	}
	switch pf.Machine {
	case pe.IMAGE_FILE_MACHINE_AMD64, pe.IMAGE_FILE_MACHINE_I386:
		n.arch = "x86"
	case pe.IMAGE_FILE_MACHINE_ARM64, pe.IMAGE_FILE_MACHINE_ARMNT:
		n.arch = "arm"
	default:
		n.arch = fmt.Sprintf("0x%x", pf.Machine)
	}
	for _, s := range pf.Sections {
		if len(n.sections) >= maxSections {
			break
		}
		perm := "r"
		if s.Characteristics&pe.IMAGE_SCN_MEM_WRITE != 0 {
			perm += "w"
		} else {
			perm += "-"
		}
		if s.Characteristics&pe.IMAGE_SCN_MEM_EXECUTE != 0 {
			perm += "x"
		} else {
			perm += "-"
		}
		va := base + uint64(s.VirtualAddress)
		n.sections = append(n.sections, Section{Name: clip(s.Name, 200), Offset: int64(s.Offset), VAddr: hexAddr(va), Size: int64(s.Size),
			VSize: int64(s.VirtualSize), Perm: perm, Entropy: entropyOfReader(f, int64(s.Offset), int64(s.Size)), Tool: "pathos-rea"})
		n.amap = append(n.amap, seg{name: s.Name, vaddr: va, end: va + uint64(s.Size), off: int64(s.Offset), fileBacked: s.Size > 0})
	}
	if imps, err := pf.ImportedSymbols(); err == nil {
		for _, s := range imps {
			if len(n.imports) >= maxImports {
				break
			}
			name, lib, _ := strings.Cut(s, ":")
			n.imports = append(n.imports, Import{ID: "imp:" + lib + "!" + name, Name: clip(name, maxNameLength), Library: lib, Kind: "function", Tool: "pathos-rea"})
		}
	}
	n.stripped = pf.Symbols == nil || len(pf.Symbols) == 0
	if s := pf.Section(".gopclntab"); s != nil {
		// Not used by current Go PE binaries (pclntab is in .rdata);
		// buildinfo still identifies Go.
		_ = s
	}
	return n, nil
}

func parseMachO(f *os.File) (*native, error) {
	mf, err := macho.NewFile(f)
	if err != nil {
		return nil, err
	}
	defer mf.Close()
	n := &native{format: "macho", os: "darwin", bits: 32}
	switch mf.Cpu {
	case macho.CpuAmd64:
		n.arch, n.bits = "x86", 64
	case macho.Cpu386:
		n.arch = "x86"
	case macho.CpuArm64:
		n.arch, n.bits = "arm", 64
	case macho.CpuArm:
		n.arch = "arm"
	default:
		n.arch = mf.Cpu.String()
	}
	for _, s := range mf.Sections {
		if len(n.sections) >= maxSections {
			break
		}
		fileBacked := s.Offset != 0
		n.sections = append(n.sections, Section{Name: clip(s.Seg+"."+s.Name, 200), Offset: int64(s.Offset), VAddr: hexAddr(s.Addr), Size: i64(s.Size),
			VSize: i64(s.Size), Perm: "r--", Entropy: entropyOfReader(f, int64(s.Offset), i64(s.Size)), Tool: "pathos-rea"})
		n.amap = append(n.amap, seg{name: s.Seg + "." + s.Name, vaddr: s.Addr, end: s.Addr + s.Size, off: int64(s.Offset), fileBacked: fileBacked})
	}
	if imps, err := mf.ImportedSymbols(); err == nil {
		for _, s := range imps {
			if len(n.imports) >= maxImports {
				break
			}
			n.imports = append(n.imports, Import{ID: "imp:!" + s, Name: clip(s, maxNameLength), Kind: "function", Tool: "pathos-rea"})
		}
	}
	n.stripped = mf.Symtab == nil
	if s := mf.Section("__gopclntab"); s != nil {
		if data, err := s.Data(); err == nil {
			text := uint64(0)
			if t := mf.Section("__text"); t != nil {
				text = t.Addr
			}
			n.goFuncs = goFunctions(data, text, n.amap)
			n.isGo = len(n.goFuncs) > 0
		}
	}
	return n, nil
}

// goFunctions reads the Go function table from pclntab.
func goFunctions(pclntab []byte, text uint64, amap addrMap) []Function {
	defer func() { _ = recover() }() // a malformed table is not fatal
	lt := gosym.NewLineTable(pclntab, text)
	tab, err := gosym.NewTable(nil, lt)
	if err != nil {
		return nil
	}
	out := make([]Function, 0, len(tab.Funcs))
	for i := range tab.Funcs {
		fn := &tab.Funcs[i]
		if fn.Entry == 0 {
			continue
		}
		out = append(out, Function{ID: "fn:" + hexAddr(fn.Entry), Name: clip(fn.Name, maxNameLength), Addr: hexAddr(fn.Entry),
			Offset: amap.offset(fn.Entry), Size: i64(fn.End - fn.Entry), Section: amap.section(fn.Entry), Tool: "pathos-rea",
			Package: goPackage(fn.Name)})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Addr < out[j].Addr })
	return out
}

// goPackage is the import path of a Go symbol name:
// "net/http/pprof.Index" → "net/http/pprof",
// "example.com/app/x.(*T).M" → "example.com/app/x", "type:.eq.x" → "".
func goPackage(name string) string {
	if strings.HasPrefix(name, "type:") || strings.HasPrefix(name, "go:") {
		return ""
	}
	// Generic instantiations carry type arguments ("slices.f[go.shape.…]"),
	// which may contain slashes: only the part before "[" names the package.
	if i := strings.IndexByte(name, '['); i >= 0 {
		name = name[:i]
	}
	slash := strings.LastIndexByte(name, '/')
	rest := name[slash+1:]
	dot := strings.IndexByte(rest, '.')
	if dot < 0 {
		return ""
	}
	// The linker escapes dots in the last path element ("yaml%2ev3").
	return strings.ReplaceAll(name[:slash+1+dot], "%2e", ".")
}

// goBuildInfo reads the embedded Go build information.
func goBuildInfo(path string) *GoInfo {
	bi, err := buildinfo.ReadFile(path)
	if err != nil {
		return nil
	}
	gi := &GoInfo{GoVersion: bi.GoVersion, Path: bi.Path, MainModule: Module{Path: bi.Main.Path, Version: bi.Main.Version},
		Deps: []Module{}, Settings: map[string]string{}}
	for _, d := range bi.Deps {
		m := Module{Path: d.Path, Version: d.Version}
		if d.Replace != nil {
			m.Version = d.Replace.Version
		}
		gi.Deps = append(gi.Deps, m)
	}
	for _, s := range bi.Settings {
		v, _ := redact(s.Value)
		gi.Settings[clip(s.Key, 100)] = clip(v, 500)
	}
	return gi
}

// goLibrary reports whether a Go package is not part of the main module.
func goLibrary(pkg, mainPath string) bool {
	switch {
	case pkg == "main" || pkg == "":
		return pkg == ""
	case mainPath != "" && (pkg == mainPath || strings.HasPrefix(pkg, mainPath+"/")):
		return false
	}
	return true
}

func clip(s string, n int) string {
	if len(s) <= n {
		return s
	}
	for n > 0 && s[n]&0xC0 == 0x80 {
		n--
	}
	return s[:n]
}
