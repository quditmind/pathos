package main

import (
	"context"
	_ "embed"
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Optional tools, installed only in images built with WITH_GHIDRA,
// WITH_JADX or WITH_ILSPY: Ghidra headless (decompiled pseudo-C, its own
// call graph), Jadx (Android packages and Java archives), ILSpy (.NET
// assemblies). Each runs only when installed and enabled for the analysis.

const (
	ghidraHome  = "/opt/pathos/rea/ghidra"
	ghidraRun   = ghidraHome + "/support/analyzeHeadless"
	jadxBin     = "/opt/pathos/rea/jadx/bin/jadx"
	ilspyBin    = "/opt/pathos/rea/bin/ilspycmd"
	versionsDir = "/opt/pathos/rea/versions"
)

//go:embed ghidra/PathosExport.java
var ghidraScript []byte

var (
	versionsOnce sync.Once
	versions     map[string]string
)

// toolVersions returns the installed tool versions: radare2 and binwalk
// report their own; the optional tools are recorded at image build time in
// /opt/pathos/rea/versions/<tool> (pinned versions).
func toolVersions(ctx context.Context) map[string]string {
	versionsOnce.Do(func() {
		versions = map[string]string{"radare2": r2Version(ctx), "binwalk": binwalkVersion(ctx)}
		for _, t := range []string{"ghidra", "jadx", "ilspy"} {
			// #nosec G304 G703 -- a fixed file of the image
			if b, err := os.ReadFile(filepath.Join(versionsDir, t)); err == nil {
				versions[t] = clip(strings.TrimSpace(string(b)), 40)
			}
		}
	})
	return versions
}

func runOptional(ctx context.Context, cfg Config, d *Doc, input, tmp, format string, executable bool, codeFor []string,
	budget func(float64) time.Duration) {
	v := toolVersions(ctx)
	if cfg.enabled("ghidra") {
		ts := &ToolState{Version: v["ghidra"]}
		d.Tools["ghidra"] = ts
		t0 := time.Now()
		switch {
		case ts.Version == "" || !exists(ghidraRun):
			ts.Status, ts.Detail = "skipped", "Ghidra is not installed in this image (build argument WITH_GHIDRA)"
		case !executable:
			ts.Status, ts.Detail = "skipped", "not an executable ("+format+")"
		default:
			err := runGhidra(ctx, cfg, d, input, tmp, codeFor, budget(0.8))
			ts.Status = "succeeded"
			switch {
			case errors.Is(err, errTimeout):
				ts.Status, ts.Detail = "timed_out", "Ghidra stopped at its time budget"
			case err != nil:
				ts.Status, ts.Detail = "failed", clip(err.Error(), 500)
			}
		}
		ts.DurationMS = time.Since(t0).Milliseconds()
	}
	if cfg.enabled("jadx") {
		ts := &ToolState{Version: v["jadx"]}
		d.Tools["jadx"] = ts
		t0 := time.Now()
		switch {
		case ts.Version == "" || !exists(jadxBin):
			ts.Status, ts.Detail = "skipped", "Jadx is not installed in this image (build argument WITH_JADX)"
		case format != "apk" && format != "jar" && format != "dex":
			ts.Status, ts.Detail = "skipped", "not an Android package or Java archive ("+format+")"
		default:
			err := runDecompiler(ctx, cfg, d, "jadx", jadxBin, []string{"--no-res", "--no-imports", "-j", "1", "-d", filepath.Join(tmp, "jadx"), input},
				filepath.Join(tmp, "jadx"), ".java", "java", budget(0.8), jvmEnv(cfg.MemoryMB))
			ts.Status = "succeeded"
			if err != nil {
				ts.Status, ts.Detail = statusOf(err), clip(err.Error(), 500)
			}
		}
		ts.DurationMS = time.Since(t0).Milliseconds()
	}
	if cfg.enabled("ilspy") {
		ts := &ToolState{Version: v["ilspy"]}
		d.Tools["ilspy"] = ts
		t0 := time.Now()
		switch {
		case ts.Version == "" || !exists(ilspyBin):
			ts.Status, ts.Detail = "skipped", "ILSpy is not installed in this image (build argument WITH_ILSPY)"
		case format != "dotnet":
			ts.Status, ts.Detail = "skipped", "not a .NET assembly ("+format+")"
		default:
			err := runDecompiler(ctx, cfg, d, "ilspy", ilspyBin, []string{"-p", "-o", filepath.Join(tmp, "ilspy"), input},
				filepath.Join(tmp, "ilspy"), ".cs", "csharp", budget(0.8), dotnetEnv(cfg.MemoryMB))
			ts.Status = "succeeded"
			if err != nil {
				ts.Status, ts.Detail = statusOf(err), clip(err.Error(), 500)
			}
		}
		ts.DurationMS = time.Since(t0).Milliseconds()
	}
}

func statusOf(err error) string {
	if errors.Is(err, errTimeout) {
		return "timed_out"
	}
	return "failed"
}

func exists(p string) bool {
	// #nosec G703 -- fixed paths of the image
	_, err := os.Stat(p)
	return err == nil
}

// jvmEnv bounds the JVM heap to the analysis memory (the container limit
// is the hard cap).
func jvmEnv(memMB int) []string {
	heap := memMB * 3 / 4
	if heap < 256 {
		heap = 256
	}
	opts := "-Xmx" + strconv.Itoa(heap) + "m -XX:+UseSerialGC -Djava.awt.headless=true"
	return []string{"JAVA_OPTS=" + opts, "JAVA_TOOL_OPTIONS=" + opts, "JAVA_HOME=/opt/pathos/rea/jdk", "MAXMEM=" + strconv.Itoa(heap) + "M"}
}

// dotnetEnv bounds the .NET garbage-collected heap (ILSpy is a native
// ahead-of-time build; an address-space limit would break its GC).
func dotnetEnv(memMB int) []string {
	return []string{"DOTNET_GCHeapHardLimit=0x" + strconv.FormatInt(int64(memMB*3/4)<<20, 16), "DOTNET_SYSTEM_GLOBALIZATION_INVARIANT=1",
		"DOTNET_CLI_TELEMETRY_OPTOUT=1"}
}

// ghidraOut is what PathosExport.java writes.
type ghidraOut struct {
	Functions []struct {
		Name  string `json:"name"`
		Entry string `json:"entry"`
		Size  int64  `json:"size"`
	} `json:"functions"`
	Calls []struct {
		From string `json:"from"`
		To   string `json:"to"`
	} `json:"calls"`
	Code []struct {
		Entry string `json:"entry"`
		Text  string `json:"text"`
	} `json:"code"`
}

func runGhidra(ctx context.Context, cfg Config, d *Doc, input, tmp string, codeFor []string, budget time.Duration) error {
	dir := filepath.Join(tmp, "ghidra")
	// #nosec G703 -- under the job's temporary directory (pathos-rea's argument)
	if err := os.MkdirAll(filepath.Join(dir, "project"), 0o700); err != nil {
		return err
	}
	// #nosec G703 -- see above
	if err := os.WriteFile(filepath.Join(dir, "PathosExport.java"), ghidraScript, 0o600); err != nil {
		return err
	}
	// The script works with file offsets (Ghidra may rebase the image).
	byOff := map[int64]string{}
	for _, fn := range d.Functions {
		if fn.Offset >= 0 {
			byOff[fn.Offset] = fn.ID
		}
	}
	want := map[string]bool{}
	for _, a := range codeFor {
		want["fn:"+a] = true
	}
	var offs []string
	for _, fn := range d.Functions {
		if want[fn.ID] && fn.Offset >= 0 {
			offs = append(offs, strconv.FormatInt(fn.Offset, 10))
		}
	}
	// #nosec G703 -- see above
	if err := os.WriteFile(filepath.Join(dir, "offsets.txt"), []byte(strings.Join(offs, "\n")), 0o600); err != nil {
		return err
	}
	out := filepath.Join(dir, "out.json")
	_, _, err := runTool(ctx, runOpts{timeout: budget, dir: dir, env: jvmEnv(cfg.MemoryMB)}, ghidraRun,
		filepath.Join(dir, "project"), "pathos", "-import", input, "-scriptPath", dir,
		"-postScript", "PathosExport.java", out, filepath.Join(dir, "offsets.txt"),
		"-deleteProject", "-analysisTimeoutPerFile", strconv.Itoa(int(budget.Seconds()*0.7)), "-max-cpu", "2")
	// #nosec G304 G703 -- written by the script into the job's temporary directory
	raw, rerr := os.ReadFile(out)
	if rerr != nil {
		if err != nil {
			return err
		}
		return errors.New("Ghidra wrote no output")
	}
	var g ghidraOut
	if jerr := json.Unmarshal(raw, &g); jerr != nil {
		return errors.New("unreadable Ghidra output")
	}
	idOf := func(off string) string {
		o, perr := strconv.ParseInt(off, 10, 64)
		if perr != nil {
			return ""
		}
		return byOff[o]
	}
	seen := map[[2]string]bool{}
	for _, c := range d.Calls {
		seen[[2]string{c.From, c.To}] = true
	}
	added := 0
	for _, c := range g.Calls {
		k := [2]string{idOf(c.From), idOf(c.To)}
		if k[0] == "" || k[1] == "" || seen[k] || len(d.Calls) >= maxCalls {
			continue
		}
		seen[k] = true
		d.Calls = append(d.Calls, Ref{From: k[0], To: k[1], Offset: -1, Tool: "ghidra"})
		added++
	}
	// Decompiled pseudo-C replaces the disassembly of the same function.
	byFn := map[string]int{}
	for i, c := range d.Code {
		byFn[c.Function] = i
	}
	decompiled := 0
	for _, c := range g.Code {
		id := idOf(c.Entry)
		if id == "" {
			continue
		}
		text, _ := redact(c.Text)
		if len(text) > maxCodeBytes {
			text = clip(text, maxCodeBytes-40) + "\n/* [truncated by pathos-rea] */\n"
		}
		code := Code{Function: id, Tool: "ghidra", Kind: "pseudo_c", Text: text}
		if i, ok := byFn[id]; ok {
			d.Code[i] = code
		} else if len(d.Code) < cfg.MaxCode {
			d.Code = append(d.Code, code)
		}
		decompiled++
	}
	d.Stats["ghidra_functions"] = len(g.Functions)
	d.Stats["ghidra_calls_added"] = added
	d.Stats["ghidra_decompiled"] = decompiled
	if errors.Is(err, errTimeout) {
		return err
	}
	return nil
}

var (
	packageRe = regexp.MustCompile(`(?m)^\s*(?:package|namespace)\s+([A-Za-z_][\w.]*)`)
	classRe   = regexp.MustCompile(`(?m)^\s*(?:(?:public|private|protected|internal|static|final|abstract|sealed|partial|unsafe)\s+)*(?:class|interface|enum|record|struct)\s+([A-Za-z_]\w*)`)
	methodRe  = regexp.MustCompile(`(?m)^\s+(?:(?:public|private|protected|internal|static|final|abstract|synchronized|native|virtual|override|async|unsafe|extern|sealed|new)\s+)+[\w<>\[\],.? ]+?\s+([A-Za-z_]\w*)\s*\([^;{}]*\)\s*(?:throws\s+[\w., ]+)?\s*\{`)
)

// runDecompiler runs Jadx or ILSpy and reads classes and methods from the
// decompiled sources (functions without addresses: id fn:<lang>:<Type>.<method>).
func runDecompiler(ctx context.Context, cfg Config, d *Doc, tool, bin string, args []string, outDir, ext, kind string, budget time.Duration, env []string) error {
	_, _, err := runTool(ctx, runOpts{timeout: budget, dir: filepath.Dir(outDir), env: env}, bin, args...)
	if err != nil && !errors.Is(err, errTimeout) && !exists(outDir) {
		return err
	}
	lang := "java"
	if kind == "csharp" {
		lang = "dotnet"
	}
	n := 0
	rt, rerr := os.OpenRoot(outDir)
	if rerr != nil {
		return err
	}
	defer rt.Close()
	// Decompiler output is read inside its directory (os.Root): a symbolic
	// link cannot lead out.
	_ = fs.WalkDir(rt.FS(), ".", func(p string, de fs.DirEntry, werr error) error {
		if werr != nil || !de.Type().IsRegular() || !strings.HasSuffix(p, ext) {
			return nil
		}
		if len(d.Functions) >= cfg.MaxFunctions {
			return fs.SkipAll
		}
		b, rerr := rt.ReadFile(p)
		if rerr != nil || len(b) > 4<<20 {
			return nil
		}
		src := string(b)
		pkg := ""
		if m := packageRe.FindStringSubmatch(src); m != nil {
			pkg = m[1]
		}
		cls := strings.TrimSuffix(filepath.Base(p), ext)
		if m := classRe.FindStringSubmatch(src); m != nil {
			cls = m[1]
		}
		qual := cls
		if pkg != "" {
			qual = pkg + "." + cls
		}
		first := ""
		for _, m := range methodRe.FindAllStringSubmatch(src, 2000) {
			id := "fn:" + lang + ":" + qual + "." + m[1]
			if first == "" {
				first = id
			}
			d.Functions = append(d.Functions, Function{ID: clip(id, maxNameLength), Name: clip(qual+"."+m[1], maxNameLength), Offset: -1, Tool: tool,
				Package: pkg, Library: libraryNamespace(pkg)})
			if len(d.Functions) >= cfg.MaxFunctions {
				break
			}
		}
		if first != "" && !libraryNamespace(pkg) && n < cfg.MaxCode {
			text, _ := redact(src)
			if len(text) > maxCodeBytes {
				text = clip(text, maxCodeBytes-40) + "\n// [truncated by pathos-rea]\n"
			}
			d.Code = append(d.Code, Code{Function: clip(first, maxNameLength), Tool: tool, Kind: kind, Text: text})
			n++
		}
		return nil
	})
	if d.Artifact.Language == "unknown" {
		d.Artifact.Language = lang
	}
	if errors.Is(err, errTimeout) {
		return err
	}
	return nil
}

func libraryNamespace(pkg string) bool {
	for _, p := range []string{"android.", "androidx.", "java.", "javax.", "kotlin.", "kotlinx.", "com.google.", "System.", "Microsoft."} {
		if strings.HasPrefix(pkg+".", p) {
			return true
		}
	}
	return false
}
