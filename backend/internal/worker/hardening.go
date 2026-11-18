package worker

import (
	"bytes"
	"context"
	"crypto/sha256"
	"debug/elf"
	"debug/macho"
	"debug/pe"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"

	"pathos/internal/scanners"
)

// Binary hardening checks (checksec-style) on ELF, PE and Mach-O files,
// implemented with the Go standard library parsers. Binaries are only
// parsed, never executed or loaded.

const (
	maxBinaries    = 5000
	maxBinaryBytes = 1 << 30
)

// hardeningRule describes one check.
type hardeningRule struct {
	title, severity, confidence, cwe, remediation string
}

var hardeningRules = map[string]hardeningRule{
	"binary/elf-no-pie": {"Executable is not position independent (no PIE)", "medium", "high", "CWE-693",
		"Build position-independent executables so ASLR also randomizes the program's own code: compile with -fPIE and link with -pie " +
			"(GCC/Clang), or `go build -buildmode=pie`; Rust and most distributions default to PIE."},
	"binary/elf-no-relro": {"No RELRO: relocation tables stay writable", "medium", "high", "CWE-693",
		"Link with -Wl,-z,relro,-z,now (full RELRO) so the GOT and other relocation data are made read-only after loading."},
	"binary/elf-partial-relro": {"Partial RELRO: the GOT stays writable (no BIND_NOW)", "low", "high", "CWE-693",
		"Add -Wl,-z,now to the existing -Wl,-z,relro so symbols are resolved at load time and the whole GOT becomes read-only (full RELRO)."},
	"binary/elf-executable-stack": {"Executable stack (NX disabled)", "high", "high", "CWE-693",
		"Make the stack non-executable: link with -Wl,-z,noexecstack and find the object that requests an executable stack " +
			"(assembly files without a .note.GNU-stack section, nested functions/trampolines)."},
	"binary/elf-wx-segment": {"Segment is both writable and executable", "medium", "high", "CWE-693",
		"Remove writable and executable (W^X) segments: avoid custom linker scripts that merge code and data, and link with -Wl,-z,separate-code."},
	"binary/elf-no-stack-canary": {"No stack canaries (stack protector not used)", "medium", "medium", "CWE-693",
		"Compile with -fstack-protector-strong (or -fstack-protector-all) so stack buffer overflows are detected before the function returns."},
	"binary/elf-no-fortify": {"FORTIFY_SOURCE not used", "low", "medium", "CWE-693",
		"Compile with optimization and -D_FORTIFY_SOURCE=2 (or 3 with GCC 12+/Clang 16+) so glibc checks buffer sizes of memcpy, strcpy, sprintf and similar calls."},
	"binary/elf-insecure-rpath": {"Insecure RPATH/RUNPATH (relative, empty or world-writable directory)", "high", "high", "CWE-426",
		"Remove the RPATH/RUNPATH entry or use only absolute, root-owned directories or $ORIGIN-relative paths: an attacker who can write " +
			"to a relative or temporary library directory gets code execution. Check -Wl,-rpath flags and libtool/CMake settings (CMAKE_SKIP_RPATH)."},
	"binary/elf-rpath": {"Deprecated DT_RPATH is set", "low", "high", "CWE-426",
		"DT_RPATH overrides LD_LIBRARY_PATH and is searched before system directories; prefer DT_RUNPATH (-Wl,--enable-new-dtags) or no run-time search path."},
	"binary/pe-no-aslr": {"ASLR not enabled (no DYNAMICBASE)", "medium", "high", "CWE-693",
		"Link with /DYNAMICBASE (MSVC) or -Wl,--dynamicbase (MinGW) and keep the relocation table (do not use /FIXED)."},
	"binary/pe-no-high-entropy-va": {"64-bit image without high-entropy ASLR (HIGH_ENTROPY_VA)", "low", "high", "CWE-693",
		"Link with /HIGHENTROPYVA (MSVC) or -Wl,--high-entropy-va (MinGW) so 64-bit ASLR uses the full address space."},
	"binary/pe-no-dep": {"DEP not enabled (no NX_COMPAT)", "high", "high", "CWE-693",
		"Link with /NXCOMPAT (MSVC) or -Wl,--nxcompat (MinGW) so data pages are not executable."},
	"binary/pe-no-cfg": {"Control Flow Guard not enabled", "low", "high", "CWE-693",
		"Compile and link with /guard:cf (MSVC) or -mguard=cf (Clang/MinGW) to validate indirect call targets."},
	"binary/pe-no-safeseh": {"32-bit image without SafeSEH", "medium", "high", "CWE-693",
		"Link 32-bit images with /SAFESEH so only registered exception handlers can run, or mark them /SAFESEH:NO only if they use no SEH."},
	"binary/pe-no-gs": {"No /GS stack cookie", "medium", "medium", "CWE-693",
		"Compile with /GS (MSVC, on by default) or -fstack-protector-strong (MinGW/Clang) so stack buffer overflows are detected."},
	"binary/macho-no-pie": {"Mach-O executable is not position independent (no PIE)", "medium", "high", "CWE-693",
		"Link with -pie (the default for current Xcode toolchains); remove -no_pie."},
	"binary/macho-executable-stack": {"Mach-O executable allows stack execution", "high", "high", "CWE-693",
		"Remove -allow_stack_execute from the linker flags."},
	"binary/macho-no-stack-canary": {"No stack canaries (stack protector not used)", "medium", "medium", "CWE-693",
		"Compile with -fstack-protector-strong so stack buffer overflows are detected."},
}

// binaryReport collects the analysis of one binary.
type binaryReport struct {
	format string            // e.g. "ELF64 x86-64 PIE executable"
	props  map[string]string // RELRO, NX, ... for the evidence
	failed map[string]string // rule -> detail
}

func newBinaryReport(format string) *binaryReport {
	return &binaryReport{format: format, props: map[string]string{}, failed: map[string]string{}}
}

func (b *binaryReport) fail(rule, detail string) { b.failed[rule] = detail }

// fortifiable lists libc functions that have _chk variants.
var fortifiable = map[string]bool{
	"memcpy": true, "memmove": true, "memset": true, "mempcpy": true, "strcpy": true, "stpcpy": true, "strncpy": true, "stpncpy": true,
	"strcat": true, "strncat": true, "sprintf": true, "snprintf": true, "vsprintf": true, "vsnprintf": true, "printf": true,
	"fprintf": true, "vprintf": true, "vfprintf": true, "gets": true, "fgets": true, "read": true, "pread": true, "recv": true,
	"recvfrom": true, "realpath": true, "getcwd": true, "wcscpy": true, "wcsncpy": true, "wmemcpy": true, "readlink": true,
}

// symbolNames returns the base names (version suffix removed) of a
// binary's dynamic and static symbols.
func elfSymbolNames(f *elf.File) map[string]bool {
	out := map[string]bool{}
	for _, get := range []func() ([]elf.Symbol, error){f.DynamicSymbols, f.Symbols} {
		syms, err := get()
		if err != nil {
			continue
		}
		for _, s := range syms {
			name := s.Name
			if i := strings.IndexByte(name, '@'); i >= 0 {
				name = name[:i]
			}
			if name != "" {
				out[name] = true
			}
		}
	}
	return out
}

func hasDynFlag(f *elf.File, tag elf.DynTag, flag uint64) bool {
	vals, err := f.DynValue(tag)
	if err != nil {
		return false
	}
	for _, v := range vals {
		if v&flag != 0 {
			return true
		}
	}
	return false
}

// analyzeELF runs the ELF checks. ok=false means the file is not an
// executable or shared library (objects, core files).
func analyzeELF(r io.ReaderAt) (*binaryReport, bool) {
	f, err := elf.NewFile(r)
	if err != nil {
		return nil, false
	}
	defer f.Close()
	if f.Type != elf.ET_EXEC && f.Type != elf.ET_DYN {
		return nil, false
	}
	var interp, dynamic, relro, gnuStack, execStack, wx bool
	for _, p := range f.Progs {
		switch p.Type {
		case elf.PT_INTERP:
			interp = true
		case elf.PT_DYNAMIC:
			dynamic = true
		case elf.PT_GNU_RELRO:
			relro = true
		case elf.PT_GNU_STACK:
			gnuStack = true
			execStack = p.Flags&elf.PF_X != 0
		case elf.PT_LOAD:
			if p.Flags&elf.PF_W != 0 && p.Flags&elf.PF_X != 0 {
				wx = true
			}
		}
	}
	const df1PIE = 0x08000000
	pieFlag := hasDynFlag(f, elf.DT_FLAGS_1, df1PIE)
	isGo := f.Section(".go.buildinfo") != nil || f.Section(".note.go.buildid") != nil
	kind := "shared library"
	switch {
	case f.Type == elf.ET_EXEC:
		kind = "executable"
	case interp || pieFlag:
		kind = "PIE executable"
	}
	cls := "ELF32"
	if f.Class == elf.ELFCLASS64 {
		cls = "ELF64"
	}
	b := newBinaryReport(fmt.Sprintf("%s %s %s", cls, strings.TrimPrefix(f.Machine.String(), "EM_"), kind))
	if isGo {
		b.props["language"] = "Go"
	}
	if !dynamic {
		b.props["linking"] = "static"
	}

	// PIE: only executables (shared libraries are always position independent).
	if kind == "executable" {
		b.props["PIE"] = "no"
		b.fail("binary/elf-no-pie", "ELF type ET_EXEC: the executable is loaded at a fixed address")
	} else if kind == "PIE executable" {
		b.props["PIE"] = "yes"
	}

	// RELRO: meaningful only for dynamically linked files.
	bindNow := hasDynFlag(f, elf.DT_FLAGS, uint64(elf.DF_BIND_NOW)) || hasDynFlag(f, elf.DT_FLAGS_1, uint64(elf.DF_1_NOW))
	if vals, err := f.DynValue(elf.DT_BIND_NOW); err == nil && len(vals) > 0 {
		bindNow = true
	}
	switch {
	case !dynamic:
		b.props["RELRO"] = "n/a (static)"
	case !relro:
		b.props["RELRO"] = "none"
		b.fail("binary/elf-no-relro", "no PT_GNU_RELRO program header")
	case !bindNow:
		b.props["RELRO"] = "partial"
		b.fail("binary/elf-partial-relro", "PT_GNU_RELRO present without BIND_NOW")
	default:
		b.props["RELRO"] = "full"
	}

	// NX.
	switch {
	case execStack:
		b.props["NX"] = "disabled"
		b.fail("binary/elf-executable-stack", "PT_GNU_STACK requests an executable stack (RWX)")
	case !gnuStack && (f.Machine == elf.EM_386 || f.Machine == elf.EM_X86_64) && !isGo:
		b.props["NX"] = "disabled"
		b.fail("binary/elf-executable-stack", "no PT_GNU_STACK program header: the kernel defaults to an executable stack on x86")
	default:
		b.props["NX"] = "enabled"
	}
	if wx {
		b.fail("binary/elf-wx-segment", "a PT_LOAD segment is mapped writable and executable")
	}

	// RPATH / RUNPATH.
	for _, t := range []struct {
		tag  elf.DynTag
		name string
	}{{elf.DT_RPATH, "RPATH"}, {elf.DT_RUNPATH, "RUNPATH"}} {
		vals, err := f.DynString(t.tag)
		if err != nil || len(vals) == 0 {
			continue
		}
		joined := strings.Join(vals, ":")
		b.props[t.name] = clip(joined, 300)
		var bad []string
		for _, d := range strings.Split(joined, ":") {
			switch {
			case d == "":
				bad = append(bad, "(empty: current directory)")
			case strings.HasPrefix(d, "$ORIGIN") || strings.HasPrefix(d, "${ORIGIN}"):
			case !strings.HasPrefix(d, "/"):
				bad = append(bad, d)
			case strings.HasPrefix(d, "/tmp") || strings.HasPrefix(d, "/var/tmp") || strings.HasPrefix(d, "/dev/shm"):
				bad = append(bad, d)
			}
		}
		if len(bad) > 0 {
			b.fail("binary/elf-insecure-rpath", fmt.Sprintf("%s %q contains %s", t.name, clip(joined, 200), strings.Join(bad, ", ")))
		} else if t.tag == elf.DT_RPATH {
			b.fail("binary/elf-rpath", fmt.Sprintf("DT_RPATH %q", clip(joined, 200)))
		}
	}

	// Stack canaries and FORTIFY_SOURCE need symbol information; Go
	// binaries use neither (the Go runtime checks bounds).
	syms := elfSymbolNames(f)
	switch {
	case isGo:
		b.props["canary"], b.props["FORTIFY"] = "n/a (Go)", "n/a (Go)"
	case len(syms) == 0:
		b.props["canary"], b.props["FORTIFY"] = "unknown (no symbols)", "unknown (no symbols)"
	default:
		canary := syms["__stack_chk_fail"] || syms["__stack_chk_guard"] || syms["__stack_chk_fail_local"] || syms["__intel_security_cookie"]
		if canary {
			b.props["canary"] = "yes"
		} else {
			b.props["canary"] = "no"
			b.fail("binary/elf-no-stack-canary", "no __stack_chk_fail or __stack_chk_guard symbol")
		}
		var fortified, unfortified []string
		for name := range syms {
			if strings.HasPrefix(name, "__") && strings.HasSuffix(name, "_chk") && fortifiable[strings.TrimSuffix(strings.TrimPrefix(name, "__"), "_chk")] {
				fortified = append(fortified, name)
			} else if fortifiable[name] {
				unfortified = append(unfortified, name)
			}
		}
		sort.Strings(unfortified)
		switch {
		case len(fortified) > 0:
			b.props["FORTIFY"] = fmt.Sprintf("yes (%d checked functions)", len(fortified))
		case len(unfortified) > 0:
			b.props["FORTIFY"] = "no"
			b.fail("binary/elf-no-fortify", "uses "+strings.Join(unfortified[:min(len(unfortified), 8)], ", ")+" without the _chk variants")
		default:
			b.props["FORTIFY"] = "n/a (no fortifiable calls)"
		}
	}
	return b, true
}

// PE constants not in debug/pe.
const (
	peDirLoadConfig = 10
	peDirCLR        = 14
)

// peRead reads n bytes at a relative virtual address.
func peRead(f *pe.File, rva uint32, n uint32) []byte {
	for _, s := range f.Sections {
		if rva >= s.VirtualAddress && rva+n <= s.VirtualAddress+max(s.VirtualSize, s.Size) {
			buf := make([]byte, n)
			if _, err := s.ReadAt(buf, int64(rva-s.VirtualAddress)); err != nil {
				return nil
			}
			return buf
		}
	}
	return nil
}

// analyzePE runs the PE checks on executable images (EXE, DLL).
func analyzePE(r io.ReaderAt) (*binaryReport, bool) {
	f, err := pe.NewFile(r)
	if err != nil {
		return nil, false
	}
	defer f.Close()
	if f.Characteristics&pe.IMAGE_FILE_EXECUTABLE_IMAGE == 0 {
		return nil, false
	}
	var dllChars uint16
	var dirs []pe.DataDirectory
	is64 := false
	switch oh := f.OptionalHeader.(type) {
	case *pe.OptionalHeader32:
		dllChars, dirs = oh.DllCharacteristics, oh.DataDirectory[:min(int(oh.NumberOfRvaAndSizes), len(oh.DataDirectory))]
	case *pe.OptionalHeader64:
		dllChars, dirs, is64 = oh.DllCharacteristics, oh.DataDirectory[:min(int(oh.NumberOfRvaAndSizes), len(oh.DataDirectory))], true
	default:
		return nil, false
	}
	dir := func(i int) pe.DataDirectory {
		if i < len(dirs) {
			return dirs[i]
		}
		return pe.DataDirectory{}
	}
	kind := "executable"
	if f.Characteristics&pe.IMAGE_FILE_DLL != 0 {
		kind = "DLL"
	}
	managed := dir(peDirCLR).VirtualAddress != 0
	isGo := false
	if s := f.Section(".data"); s != nil {
		head := make([]byte, min(s.Size, 64<<10))
		if _, err := s.ReadAt(head, 0); err == nil {
			isGo = bytes.Contains(head, []byte("\xff Go buildinf:"))
		}
	}
	bits := "PE32"
	if is64 {
		bits = "PE32+"
	}
	b := newBinaryReport(fmt.Sprintf("%s %s %s", bits, peMachine(f.Machine), kind))
	if managed {
		b.props["language"] = ".NET (managed)"
	} else if isGo {
		b.props["language"] = "Go"
	}

	aslr := dllChars&pe.IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE != 0
	relocsStripped := f.Characteristics&pe.IMAGE_FILE_RELOCS_STRIPPED != 0
	switch {
	case !aslr:
		b.props["ASLR"] = "no"
		b.fail("binary/pe-no-aslr", "IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE is not set")
	case relocsStripped:
		b.props["ASLR"] = "no (relocations stripped)"
		b.fail("binary/pe-no-aslr", "DYNAMIC_BASE is set but the relocation table was stripped, so the image cannot be relocated")
	default:
		b.props["ASLR"] = "yes"
	}
	if is64 {
		if dllChars&pe.IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA != 0 {
			b.props["HIGH_ENTROPY_VA"] = "yes"
		} else {
			b.props["HIGH_ENTROPY_VA"] = "no"
			b.fail("binary/pe-no-high-entropy-va", "IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA is not set")
		}
	}
	if dllChars&pe.IMAGE_DLLCHARACTERISTICS_NX_COMPAT != 0 {
		b.props["DEP"] = "yes"
	} else {
		b.props["DEP"] = "no"
		b.fail("binary/pe-no-dep", "IMAGE_DLLCHARACTERISTICS_NX_COMPAT is not set")
	}
	if managed || isGo {
		// CFG, SafeSEH and /GS apply to native code compiled by C/C++
		// toolchains.
		b.props["CFG"], b.props["SafeSEH"], b.props["GS"] = "n/a", "n/a", "n/a"
		return b, true
	}
	if dllChars&pe.IMAGE_DLLCHARACTERISTICS_GUARD_CF != 0 {
		b.props["CFG"] = "yes"
	} else {
		b.props["CFG"] = "no"
		b.fail("binary/pe-no-cfg", "IMAGE_DLLCHARACTERISTICS_GUARD_CF is not set")
	}
	// Load configuration: SafeSEH table (32-bit x86) and the /GS cookie.
	lc := dir(peDirLoadConfig)
	var cfg []byte
	if lc.VirtualAddress != 0 && lc.Size >= 4 {
		cfg = peRead(f, lc.VirtualAddress, min(lc.Size, 0x100))
		if len(cfg) >= 4 {
			cfg = cfg[:min(len(cfg), int(binary.LittleEndian.Uint32(cfg)))]
		}
	}
	u32 := func(off int) uint64 {
		if off+4 <= len(cfg) {
			return uint64(binary.LittleEndian.Uint32(cfg[off:]))
		}
		return 0
	}
	u64 := func(off int) uint64 {
		if off+8 <= len(cfg) {
			return binary.LittleEndian.Uint64(cfg[off:])
		}
		return 0
	}
	cookie := u32(0x3C)
	if is64 {
		cookie = u64(0x58)
	}
	if cookie != 0 {
		b.props["GS"] = "yes"
	} else {
		b.props["GS"] = "no"
		b.fail("binary/pe-no-gs", "the load configuration has no security cookie")
	}
	if f.Machine == pe.IMAGE_FILE_MACHINE_I386 {
		switch {
		case dllChars&pe.IMAGE_DLLCHARACTERISTICS_NO_SEH != 0:
			b.props["SafeSEH"] = "n/a (NO_SEH)"
		case u32(0x40) != 0:
			b.props["SafeSEH"] = "yes"
		default:
			b.props["SafeSEH"] = "no"
			b.fail("binary/pe-no-safeseh", "the load configuration has no SEHandlerTable")
		}
	}
	return b, true
}

func peMachine(m uint16) string {
	switch m {
	case pe.IMAGE_FILE_MACHINE_I386:
		return "x86"
	case pe.IMAGE_FILE_MACHINE_AMD64:
		return "x86-64"
	case pe.IMAGE_FILE_MACHINE_ARM64:
		return "ARM64"
	case pe.IMAGE_FILE_MACHINE_ARMNT:
		return "ARM"
	}
	return fmt.Sprintf("machine 0x%x", m)
}

// analyzeMachO runs the Mach-O checks on one architecture.
func analyzeMachO(f *macho.File) (*binaryReport, bool) {
	if f.Type != macho.TypeExec && f.Type != macho.TypeDylib && f.Type != macho.TypeBundle {
		return nil, false
	}
	const (
		mhPIE            = 0x200000
		mhAllowStackExec = 0x20000
	)
	kind := map[macho.Type]string{macho.TypeExec: "executable", macho.TypeDylib: "dylib", macho.TypeBundle: "bundle"}[f.Type]
	b := newBinaryReport(fmt.Sprintf("Mach-O %s %s", strings.TrimPrefix(f.Cpu.String(), "Cpu"), kind))
	isGo := f.Section("__go_buildinfo") != nil
	if isGo {
		b.props["language"] = "Go"
	}
	if f.Type == macho.TypeExec {
		if f.Flags&mhPIE != 0 {
			b.props["PIE"] = "yes"
		} else {
			b.props["PIE"] = "no"
			b.fail("binary/macho-no-pie", "MH_PIE flag is not set")
		}
	}
	if f.Flags&mhAllowStackExec != 0 {
		b.props["NX"] = "disabled"
		b.fail("binary/macho-executable-stack", "MH_ALLOW_STACK_EXECUTION flag is set")
	} else {
		b.props["NX"] = "enabled"
	}
	if !isGo {
		imps, _ := f.ImportedSymbols()
		canary := false
		for _, s := range imps {
			canary = canary || s == "___stack_chk_fail" || s == "___stack_chk_guard"
		}
		switch {
		case len(imps) == 0:
			b.props["canary"] = "unknown (no imports)"
		case canary:
			b.props["canary"] = "yes"
		default:
			b.props["canary"] = "no"
			b.fail("binary/macho-no-stack-canary", "no ___stack_chk_fail or ___stack_chk_guard import")
		}
	}
	return b, true
}

// analyzeBinary detects the format of the file at path and analyzes it.
// It returns nil for files that are not executables or libraries.
func analyzeBinary(f *os.File) (reports []*binaryReport, err error) {
	defer func() {
		// The standard library parsers are hardened, but a malformed file
		// must never stop the scan.
		if p := recover(); p != nil {
			reports, err = nil, fmt.Errorf("malformed binary: %v", p)
		}
	}()
	var magic [8]byte
	if n, _ := f.ReadAt(magic[:], 0); n < 8 {
		return nil, nil
	}
	switch {
	case bytes.Equal(magic[:4], []byte("\x7fELF")):
		if r, ok := analyzeELF(f); ok {
			return []*binaryReport{r}, nil
		}
	case magic[0] == 'M' && magic[1] == 'Z':
		if r, ok := analyzePE(f); ok {
			return []*binaryReport{r}, nil
		}
	case binary.BigEndian.Uint32(magic[:4]) == macho.MagicFat:
		// 0xcafebabe is also the Java class file magic: a fat header has
		// few architectures where a class file has its version.
		if binary.BigEndian.Uint32(magic[4:]) > 16 {
			return nil, nil
		}
		ff, err := macho.NewFatFile(f)
		if err != nil {
			return nil, nil
		}
		defer ff.Close()
		for _, a := range ff.Arches {
			if r, ok := analyzeMachO(a.File); ok {
				reports = append(reports, r)
			}
		}
	default:
		m := binary.LittleEndian.Uint32(magic[:4])
		mb := binary.BigEndian.Uint32(magic[:4])
		if m == macho.Magic32 || m == macho.Magic64 || mb == macho.Magic32 || mb == macho.Magic64 {
			mf, err := macho.NewFile(f)
			if err != nil {
				return nil, nil
			}
			defer mf.Close()
			if r, ok := analyzeMachO(mf); ok {
				return []*binaryReport{r}, nil
			}
		}
	}
	return reports, nil
}

func (b *binaryReport) evidence(rel, sum string) string {
	keys := make([]string, 0, len(b.props))
	for k := range b.props {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var sb strings.Builder
	fmt.Fprintf(&sb, "file: %s\nformat: %s\nsha256: %s\n", rel, b.format, sum)
	for _, k := range keys {
		fmt.Fprintf(&sb, "%s: %s\n", k, b.props[k])
	}
	return strings.TrimRight(sb.String(), "\n")
}

// runHardening analyzes every executable and shared library below dir.
func runHardening(ctx context.Context, dir, out, version string) error {
	root, err := os.OpenRoot(dir)
	if err != nil {
		return err
	}
	defer root.Close()
	rep := scanners.NativeReport{Tool: scanners.BinaryHardening, Version: version}
	binaries, candidates, malformed, tooLarge := 0, 0, 0, 0
	links, err := walkFiles(ctx, dir, func(rel string, size int64) error {
		if size < 64 {
			return nil
		}
		if binaries >= maxBinaries {
			return nil
		}
		f, err := openIn(root, rel)
		if err != nil {
			return nil
		}
		defer f.Close()
		candidates++
		reports, err := analyzeBinary(f)
		if err != nil {
			malformed++
			toolLog(ctx, "warning: %s: %v", rel, err)
			return nil
		}
		if len(reports) == 0 {
			return nil
		}
		binaries++
		if size > maxBinaryBytes {
			tooLarge++
		}
		h := sha256.New()
		if _, err := io.Copy(h, io.NewSectionReader(f, 0, min(size, maxBinaryBytes))); err != nil {
			return nil
		}
		sum := hex.EncodeToString(h.Sum(nil))
		for _, b := range reports {
			rules := make([]string, 0, len(b.failed))
			for r := range b.failed {
				rules = append(rules, r)
			}
			sort.Strings(rules)
			for _, rule := range rules {
				hr := hardeningRules[rule]
				sev := hr.severity
				if b.props["language"] == "Go" && rule == "binary/elf-no-pie" {
					sev = "low" // memory-safe code; PIE still hardens cgo and the runtime
				}
				key := rule
				if len(reports) > 1 {
					key += "|" + b.format // one finding per architecture of a fat binary
				}
				rep.Findings = append(rep.Findings, scanners.NativeFinding{
					RuleID: rule, Title: hr.title, Severity: sev, Confidence: hr.confidence, CWE: []string{hr.cwe},
					FilePath: rel, Key: key,
					Description: fmt.Sprintf("%s (%s): %s.\n\nRemediation: %s", rel, b.format, b.failed[rule], hr.remediation),
					Evidence:    b.evidence(rel, sum),
				})
			}
		}
		return nil
	})
	if err != nil {
		return err
	}
	rep.Stats = map[string]int{"files_checked": candidates, "binaries": binaries, "malformed": malformed, "links_skipped": links, "hashed_partially": tooLarge}
	toolLog(ctx, "checked %d files: %d executables or libraries analyzed, %d hardening findings, %d malformed, %d links not followed",
		candidates, binaries, len(rep.Findings), malformed, links)
	if binaries >= maxBinaries {
		toolLog(ctx, "warning: stopped after %d binaries", maxBinaries)
	}
	return writeNative(out, rep)
}
