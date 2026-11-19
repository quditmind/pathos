package scanners

import (
	"bufio"
	"bytes"
	"fmt"
	"regexp"
	"strings"
)

// libFuzzer and Jazzer crash logs: the text a fuzz target prints when it
// finds a crash (`./fuzz_target ... 2> fuzz.log`, also the logs
// ClusterFuzzLite, OSS-Fuzz reproducers and cargo-fuzz print). The
// structured parts are parsed:
//
//   - sanitizer reports: "==PID==ERROR: AddressSanitizer: <type> ...",
//     the stack frames ("#0 0x... in func file:line:col") and the
//     "SUMMARY: <Sanitizer>: <type> file:line:col in func" line
//     (AddressSanitizer, LeakSanitizer, MemorySanitizer, ThreadSanitizer,
//     UndefinedBehaviorSanitizer)
//   - libFuzzer's own crashes: deadly signal, timeout, out-of-memory,
//     fuzz target exited
//   - Jazzer: "== Java Exception: <class>: <message>" and its "at" frames;
//     FuzzerSecurityIssue{Critical,High,Medium,Low} carry the severity
//
// One finding per crash; identity is the crash type and the crashing
// frame (libFuzzer's DEDUP_TOKEN when printed). The crash input file
// ("Test unit written to ./crash-<sha1>") is named in the description.
// A log longer than 64 KiB before the first crash is not detected
// automatically: import it with format libfuzzer.

var (
	lfErrorRe   = regexp.MustCompile(`^==\d+==\s*ERROR: (\w+Sanitizer|libFuzzer): (.+)$`)
	lfUBSanRe   = regexp.MustCompile(`^(\S+?):(\d+):(?:\d+:)? runtime error: (.+)$`)
	lfSummaryRe = regexp.MustCompile(`^SUMMARY: (\w+Sanitizer|libFuzzer): (\S+)(.*)$`)
	lfSumLocRe  = regexp.MustCompile(`^ (\S+?):(\d+)(?::\d+)? in (.+?)\s*$`)
	lfFrameRe   = regexp.MustCompile(`^\s*#\d+ 0x[0-9a-fA-F]+\s`)
	lfFrameLoc  = regexp.MustCompile(`^\s*#\d+ 0x[0-9a-fA-F]+ in (.+?) (\S+?):(\d+)(?::\d+)?\s*$`)
	lfJavaRe    = regexp.MustCompile(`^== Java Exception: ([\w.$]+)(?:: (.*))?$`)
	lfJavaAtRe  = regexp.MustCompile(`^\s+at ([\w.$<>]+)\(([^:()]+)(?::(\d+))?\)`)
	lfArtRe     = regexp.MustCompile(`Test unit written to (\S+)`)
	lfDedupRe   = regexp.MustCompile(`^DEDUP_TOKEN: (.+)$`)
	lfRunningRe = regexp.MustCompile(`^(?:Running|INFO: Running): (\S+)`)
)

type libfuzzerCrash struct {
	Engine    string   `json:"engine"`
	Sanitizer string   `json:"sanitizer"`
	CrashType string   `json:"crash_type"`
	Error     string   `json:"error"`
	Access    string   `json:"access,omitempty"`
	Summary   string   `json:"summary,omitempty"`
	File      string   `json:"file,omitempty"`
	Line      int      `json:"line,omitempty"`
	Function  string   `json:"function,omitempty"`
	Frames    []string `json:"frames,omitempty"`
	Dedup     string   `json:"dedup_token,omitempty"`
	Artifact  string   `json:"artifact,omitempty"`
	Target    string   `json:"target,omitempty"`

	stackDone bool
}

func init() {
	registerImportFormat(ImportFormat{ID: "libfuzzer", Label: "libFuzzer / Jazzer crash log (text)", Tool: "libFuzzer", Category: "other", Media: "text", Order: 379,
		match: func(p *importProbe) bool {
			if p.kind == "object" || p.kind == "array" || p.kind == "jsonl" || p.kind == "xml" {
				return false
			}
			sanitizer := p.headHas("==ERROR: ") && (p.headHas("Sanitizer: ") || p.headHas("ERROR: libFuzzer: "))
			jazzer := p.headHas("== Java Exception: ") && (p.headHas("libFuzzer") || p.headHas("jazzer"))
			return sanitizer || jazzer
		},
		parse: parseLibFuzzer})
}

func parseLibFuzzer(raw []byte) ([]importRecord, error) {
	sc := bufio.NewScanner(bytes.NewReader(bytes.TrimPrefix(raw, utf8BOM)))
	sc.Buffer(make([]byte, 0, 64<<10), 4<<20)
	var crashes []*libfuzzerCrash
	var cur *libfuzzerCrash
	target := ""
	start := func(c *libfuzzerCrash) {
		c.Target = target
		crashes = append(crashes, c)
		cur = c
	}
	for sc.Scan() {
		line := strings.TrimRight(sc.Text(), "\r")
		if m := lfRunningRe.FindStringSubmatch(line); m != nil && target == "" {
			target = m[1]
		}
		switch {
		case lfErrorRe.MatchString(line):
			m := lfErrorRe.FindStringSubmatch(line)
			// LeakSanitizer follows "ERROR: libFuzzer" only for real leaks; a
			// sanitizer report after a libFuzzer deadly-signal line is the
			// same crash.
			if cur != nil && cur.Engine == "libfuzzer" && cur.Sanitizer == "libFuzzer" && cur.Summary == "" && m[1] != "libFuzzer" {
				cur.Sanitizer, cur.Error = m[1], m[2]
				cur.CrashType = lfCrashType(m[2])
				continue
			}
			start(&libfuzzerCrash{Engine: "libfuzzer", Sanitizer: m[1], Error: m[2], CrashType: lfCrashType(m[2])})
		case lfJavaRe.MatchString(line):
			m := lfJavaRe.FindStringSubmatch(line)
			start(&libfuzzerCrash{Engine: "jazzer", Sanitizer: "Jazzer", CrashType: m[1], Error: strings.TrimSpace(m[2])})
		case lfUBSanRe.MatchString(line) && (cur == nil || cur.Summary != ""):
			m := lfUBSanRe.FindStringSubmatch(line)
			start(&libfuzzerCrash{Engine: "libfuzzer", Sanitizer: "UndefinedBehaviorSanitizer", Error: m[3], CrashType: "undefined-behavior",
				File: m[1], Line: atoiLoose(m[2])})
		case cur == nil:
		case lfSummaryRe.MatchString(line):
			m := lfSummaryRe.FindStringSubmatch(line)
			cur.Summary = clipText(line, 500)
			if cur.CrashType == "" || cur.CrashType == "deadly-signal" {
				cur.CrashType = m[2]
			}
			// A symbolised summary names the crashing frame; the stack
			// (first frame outside the runtimes) is preferred.
			if l := lfSumLocRe.FindStringSubmatch(m[3]); l != nil && cur.File == "" {
				cur.File, cur.Line, cur.Function = l[1], atoiLoose(l[2]), l[3]
			}
			cur.stackDone = true
		case lfFrameRe.MatchString(line) && !cur.stackDone:
			// Only the crash stack (the first one) is kept; allocation and
			// free stacks follow a blank line.
			if len(cur.Frames) < 20 {
				cur.Frames = append(cur.Frames, clipText(strings.TrimSpace(line), 300))
			}
			if m := lfFrameLoc.FindStringSubmatch(line); m != nil && cur.File == "" && !lfRuntimeFrame(m[2]) {
				cur.File, cur.Line, cur.Function = m[2], atoiLoose(m[3]), m[1]
			}
		case strings.TrimSpace(line) == "" && len(cur.Frames) > 0:
			cur.stackDone = true
		case lfJavaAtRe.MatchString(line) && cur.Engine == "jazzer":
			m := lfJavaAtRe.FindStringSubmatch(line)
			if len(cur.Frames) < 20 {
				cur.Frames = append(cur.Frames, strings.TrimSpace(line))
			}
			if cur.Function == "" && !strings.HasPrefix(m[1], "com.code_intelligence.jazzer.") && !strings.HasPrefix(m[1], "java.") &&
				!strings.HasPrefix(m[1], "jdk.") && !strings.HasPrefix(m[1], "sun.") {
				cur.Function, cur.File, cur.Line = m[1], m[2], atoiLoose(m[3])
			}
		case lfDedupRe.MatchString(line):
			cur.Dedup = lfDedupRe.FindStringSubmatch(line)[1]
		case lfArtRe.MatchString(line):
			cur.Artifact = lfArtRe.FindStringSubmatch(line)[1]
		case strings.Contains(line, " of size ") && cur.Access == "" && (strings.HasPrefix(line, "READ") || strings.HasPrefix(line, "WRITE")):
			cur.Access = clipText(line, 200)
		}
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("libfuzzer: %w", err)
	}
	var out []importRecord
	for _, c := range crashes {
		out = append(out, libfuzzerFinding(c))
	}
	return out, nil
}

// lfCrashType returns the crash type of a sanitizer or libFuzzer error line
// ("heap-buffer-overflow on address ..." -> heap-buffer-overflow).
func lfCrashType(s string) string {
	s = strings.TrimSpace(s)
	for _, p := range []string{"deadly signal", "timeout", "out-of-memory", "fuzz target exited", "detected memory leaks", "malloc limit"} {
		if strings.HasPrefix(s, p) {
			return strings.ReplaceAll(p, " ", "-")
		}
	}
	if f := strings.Fields(s); len(f) > 0 {
		return strings.TrimSuffix(f[0], ":")
	}
	return "crash"
}

// lfRuntimeFrame reports frames of the sanitizer and fuzzer runtimes.
func lfRuntimeFrame(file string) bool {
	for _, p := range []string{"compiler-rt/", "/libfuzzer/", "FuzzerLoop.cpp", "FuzzerDriver.cpp", "FuzzerMain.cpp", "asan_", "sanitizer_common", "libc-start", "/libc.so"} {
		if strings.Contains(file, p) {
			return true
		}
	}
	return false
}

func libfuzzerSeverity(c *libfuzzerCrash) (string, []string) {
	t := strings.ToLower(c.CrashType)
	if c.Engine == "jazzer" {
		for _, s := range []string{"critical", "high", "medium", "low"} {
			if strings.HasSuffix(t, "fuzzersecurityissue"+s) {
				return s, nil
			}
		}
		return "medium", nil
	}
	switch {
	case strings.Contains(t, "heap-buffer-overflow"):
		return "high", []string{"CWE-122"}
	case strings.Contains(t, "stack-buffer-overflow"):
		return "high", []string{"CWE-121"}
	case strings.Contains(t, "stack-overflow"):
		return "medium", []string{"CWE-674"}
	case strings.Contains(t, "global-buffer-overflow"):
		return "high", []string{"CWE-120"}
	case strings.Contains(t, "use-after-free"):
		return "high", []string{"CWE-416"}
	case strings.Contains(t, "double-free"):
		return "high", []string{"CWE-415"}
	case strings.Contains(t, "use-after-return"), strings.Contains(t, "use-after-scope"):
		return "high", []string{"CWE-562"}
	case strings.Contains(t, "use-of-uninitialized-value"):
		return "medium", []string{"CWE-457"}
	case strings.Contains(t, "data-race"), strings.Contains(t, "data race"):
		return "medium", []string{"CWE-362"}
	case strings.Contains(t, "leak"):
		return "low", []string{"CWE-401"}
	case strings.Contains(t, "out-of-memory"), strings.Contains(t, "malloc-limit"), strings.Contains(t, "allocation-size-too-big"):
		return "low", []string{"CWE-400"}
	case strings.Contains(t, "timeout"):
		return "low", []string{"CWE-834"}
	case strings.Contains(t, "segv"):
		if strings.Contains(c.Error, "address 0x000000000") || strings.Contains(c.Error, "address (nil)") {
			return "medium", []string{"CWE-476"}
		}
		return "high", nil
	case strings.Contains(t, "undefined-behavior"):
		if strings.Contains(c.Error, "overflow") {
			return "medium", []string{"CWE-190"}
		}
		return "medium", nil
	}
	return "medium", nil
}

func libfuzzerFinding(c *libfuzzerCrash) importRecord {
	sev, cwe := libfuzzerSeverity(c)
	file := NormalizePath(c.File)
	if file == "" || file == "." {
		file = NormalizePath(firstNonEmpty(c.Target, "fuzz-target"))
	}
	title := c.Sanitizer + ": " + c.CrashType
	if c.Engine == "jazzer" {
		title = "Jazzer: " + c.CrashType[strings.LastIndex(c.CrashType, ".")+1:]
		if c.Error != "" {
			title += ": " + clipText(c.Error, 150)
		}
	}
	if c.Function != "" {
		title += " in " + c.Function
	}
	f := Finding{Category: "other", RuleID: strings.ToLower(c.Engine) + ":" + c.CrashType, Title: title, Severity: sev, CWE: cwe,
		FilePath: file, StartLine: intPtr(c.Line), Confidence: "high"}
	f.Description = joinText("The fuzzer found an input that crashes the target ("+c.Sanitizer+").",
		labelled("Error", clipText(c.Error, 500)), labelled("Access", c.Access), labelled("Summary", c.Summary),
		labelled("Stack", strings.Join(c.Frames[:min(len(c.Frames), 8)], "\n")),
		labelled("Crash input", c.Artifact), labelled("Fuzz target", c.Target))
	key := c.Dedup
	if key == "" {
		key = c.CrashType + "|" + c.Function
	}
	return importRecord{F: f, SnippetKey: hashOf(key), Raw: rawJSON(c)}
}
