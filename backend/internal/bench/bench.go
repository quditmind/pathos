// Package bench scores PATHOS scanner output against benchmark suites with
// known answers (benchmarks/, docs/BENCHMARKS.md).
//
// The input is what `pathos-worker run-local` writes: each tool's own
// report and results.json with the tool's version, status and manifest
// parser. Reports are parsed exactly as the API parses worker uploads
// (scans.Ingest): with the manifest's parser, or by scanner key for
// built-in tools. Findings of all tools are then merged by fingerprint the
// way the findings table merges them (one finding per fingerprint and
// repository), and every tool and the merged result are scored against
// the suite's labelled cases.
package bench

import (
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"os"
	"path"
	"path/filepath"
	"slices"
	"sort"
	"strings"

	"pathos/internal/scanners"
)

// Match modes: how a finding is matched to a labelled case.
const (
	// MatchOWASP is the OWASP Benchmark rule: a finding in the test case's
	// file (BenchmarkTestNNNNN.*) with the case's CWE.
	MatchOWASP = "owasp"
	// MatchFile: any finding (of the suite's finding categories) in the
	// case's file.
	MatchFile = "file"
	// MatchSCA: a dependency finding for the case's package (any of its
	// names) whose CVE or rule ID is one of the case's vulnerability IDs,
	// in a file under the case's directory.
	MatchSCA = "sca"
)

// Labels is a suite's answer key.
type Labels struct {
	Suite   string `json:"suite"`
	Source  string `json:"source"`
	License string `json:"license"`
	Match   string `json:"match"`
	// Categories restricts MatchFile to findings of these finding
	// categories (empty = all).
	Categories []string `json:"categories,omitempty"`
	Cases      []Case   `json:"cases"`
}

// Case is one labelled test case.
type Case struct {
	ID         string `json:"id"`
	Category   string `json:"category"`
	Vulnerable bool   `json:"vulnerable"`
	// CWE is "CWE-<n>" (MatchOWASP).
	CWE string `json:"cwe,omitempty"`
	// File is the path relative to the scanned directory (MatchFile), or
	// the directory the dependency manifest is in (MatchSCA).
	File string `json:"file,omitempty"`
	// Packages are the names tools use for the dependency (MatchSCA).
	Packages []string `json:"packages,omitempty"`
	Version  string   `json:"version,omitempty"`
	// Vulns are the identifiers of one vulnerability (CVE, GHSA, GO-...).
	Vulns []string `json:"vulns,omitempty"`
}

// LoadLabels reads a labels file.
func LoadLabels(file string) (Labels, error) {
	var l Labels
	// #nosec G304 -- benchmark input chosen by the operator running the harness
	raw, err := os.ReadFile(file)
	if err != nil {
		return l, err
	}
	if err := json.Unmarshal(raw, &l); err != nil {
		return l, fmt.Errorf("%s: %w", file, err)
	}
	switch l.Match {
	case MatchOWASP, MatchFile, MatchSCA:
	default:
		return l, fmt.Errorf("%s: unknown match mode %q", file, l.Match)
	}
	if len(l.Cases) == 0 {
		return l, fmt.Errorf("%s: no cases", file)
	}
	return l, nil
}

// localResult is one entry of results.json (worker.LocalResult).
type localResult struct {
	Scanner    string               `json:"scanner"`
	Version    string               `json:"version"`
	Status     string               `json:"status"`
	Error      string               `json:"error"`
	DurationMS int64                `json:"duration_ms"`
	Output     string               `json:"output"`
	Parser     *scanners.ToolParser `json:"parser"`
}

// ToolRun is one tool's run with its parsed findings.
type ToolRun struct {
	Scanner    string `json:"scanner"`
	Version    string `json:"version"`
	Status     string `json:"status"`
	Error      string `json:"error,omitempty"`
	DurationMS int64  `json:"duration_ms"`
	// Findings as the API would store them (before merging).
	Findings []scanners.Finding `json:"-"`
}

// LoadRuns reads the results.json and reports of one or more run-local
// output directories. A scanner listed twice is an error.
func LoadRuns(dirs ...string) ([]ToolRun, error) {
	var runs []ToolRun
	seen := map[string]bool{}
	for _, dir := range dirs {
		// #nosec G304 -- benchmark output directory chosen by the operator
		raw, err := os.ReadFile(filepath.Join(dir, "results.json"))
		if err != nil {
			return nil, err
		}
		var rs []localResult
		if err := json.Unmarshal(raw, &rs); err != nil {
			return nil, fmt.Errorf("%s/results.json: %w", dir, err)
		}
		for _, r := range rs {
			if seen[r.Scanner] {
				return nil, fmt.Errorf("scanner %s appears in two runs", r.Scanner)
			}
			seen[r.Scanner] = true
			run := ToolRun{Scanner: r.Scanner, Version: r.Version, Status: r.Status, Error: r.Error, DurationMS: r.DurationMS}
			if r.Status == "succeeded" && r.Output != "" && !scanners.IsSBOMTool(r.Scanner) && !scanners.IsReachabilityTool(r.Scanner) {
				if filepath.Base(r.Output) != r.Output {
					return nil, fmt.Errorf("%s: invalid output name %q", r.Scanner, r.Output)
				}
				// #nosec G304 -- file name checked above, in the operator's output directory
				out, err := os.ReadFile(filepath.Join(dir, r.Output))
				if err != nil {
					return nil, err
				}
				fs, err := parse(r, out)
				if err != nil {
					if len(fs) == 0 {
						run.Status, run.Error = "failed", "could not parse output: "+err.Error()
					} else {
						run.Error = err.Error()
					}
				}
				run.Findings = fs
			}
			runs = append(runs, run)
		}
	}
	return runs, nil
}

// parse is the parser selection of scans.Ingest for worker uploads.
func parse(r localResult, raw []byte) ([]scanners.Finding, error) {
	if r.Parser != nil {
		return scanners.ParseToolOutput(r.Scanner, *r.Parser, raw)
	}
	return scanners.Parse(r.Scanner, raw)
}

// Merge merges findings by fingerprint like the findings table does
// (ON CONFLICT (repository_id, fingerprint)): the first finding's fields
// are kept, the CVE is filled in when the first had none, and the scanner
// keys are collected.
func Merge(runs []ToolRun) []Merged {
	idx := map[string]int{}
	var out []Merged
	for _, r := range runs {
		for _, f := range r.Findings {
			if i, ok := idx[f.Fingerprint]; ok {
				if !slices.Contains(out[i].Scanners, f.ScannerKey) {
					out[i].Scanners = append(out[i].Scanners, f.ScannerKey)
					sort.Strings(out[i].Scanners)
				}
				if out[i].CVE == "" {
					out[i].CVE = f.CVE
				}
				continue
			}
			idx[f.Fingerprint] = len(out)
			out = append(out, Merged{Finding: f, Scanners: []string{f.ScannerKey}})
		}
	}
	return out
}

// Merged is one finding after merging, with the tools that reported it.
type Merged struct {
	scanners.Finding
	Scanners []string
}

// Counts are a confusion matrix.
type Counts struct {
	TP int `json:"tp"`
	FP int `json:"fp"`
	TN int `json:"tn"`
	FN int `json:"fn"`
}

// Metrics are the counts and the rates derived from them. Rates whose
// denominator is zero are null.
type Metrics struct {
	Counts
	Precision *float64 `json:"precision"`
	Recall    *float64 `json:"recall"` // true positive rate
	FPR       *float64 `json:"fpr"`
	F1        *float64 `json:"f1"`
	// Score is the OWASP Benchmark score: TPR - FPR.
	Score *float64 `json:"score"`
}

func ratio(a, b int) *float64 {
	if b == 0 {
		return nil
	}
	v := float64(a) / float64(b)
	return &v
}

// Finish computes the rates.
func (c Counts) Finish() Metrics {
	m := Metrics{Counts: c, Precision: ratio(c.TP, c.TP+c.FP), Recall: ratio(c.TP, c.TP+c.FN), FPR: ratio(c.FP, c.FP+c.TN)}
	if m.Precision != nil && m.Recall != nil && *m.Precision+*m.Recall > 0 {
		f := 2 * *m.Precision * *m.Recall / (*m.Precision + *m.Recall)
		m.F1 = &f
	} else if m.Precision != nil && m.Recall != nil {
		z := 0.0
		m.F1 = &z
	}
	if m.Recall != nil && m.FPR != nil {
		s := *m.Recall - *m.FPR
		m.Score = &s
	}
	return m
}

func (c *Counts) add(vulnerable, detected bool) {
	switch {
	case vulnerable && detected:
		c.TP++
	case vulnerable:
		c.FN++
	case detected:
		c.FP++
	default:
		c.TN++
	}
}

// ToolScore is one tool's (or the merged result's) score.
type ToolScore struct {
	Scanner    string `json:"scanner"`
	Version    string `json:"version,omitempty"`
	Status     string `json:"status"`
	Error      string `json:"error,omitempty"`
	DurationMS int64  `json:"duration_ms"`
	// Findings is the number of findings the tool produced on the whole
	// suite (for the merged result: after merging by fingerprint).
	Findings int `json:"findings"`
	// Unrelated counts findings that match no labelled case's file or
	// package (outside the labelled test cases; not scored).
	Unrelated  int                `json:"unrelated"`
	Overall    Metrics            `json:"overall"`
	ByCategory map[string]Metrics `json:"by_category"`
	// CategoryAverage is the mean TPR, FPR and score over the categories
	// that have both positive and negative cases: the OWASP Benchmark
	// scorecard's summary score (each category weighs the same).
	CategoryAverage *Average `json:"category_average,omitempty"`
	// FileOnly is the OWASP score when any finding in the test case's
	// file counts, whatever its CWE (MatchOWASP only; for comparison).
	FileOnly *Metrics `json:"file_only,omitempty"`
}

// Average is a mean over categories.
type Average struct {
	Categories int     `json:"categories"`
	TPR        float64 `json:"tpr"`
	FPR        float64 `json:"fpr"`
	Score      float64 `json:"score"`
}

func categoryAverage(by map[string]Metrics) *Average {
	a := Average{}
	for _, m := range by {
		if m.Score == nil {
			continue
		}
		a.Categories++
		a.TPR += *m.Recall
		a.FPR += *m.FPR
		a.Score += *m.Score
	}
	if a.Categories == 0 {
		return nil
	}
	n := float64(a.Categories)
	a.TPR, a.FPR, a.Score = a.TPR/n, a.FPR/n, a.Score/n
	return &a
}

// Result is a scored suite.
type Result struct {
	Suite    string      `json:"suite"`
	Source   string      `json:"source"`
	License  string      `json:"license"`
	Match    string      `json:"match"`
	Cases    int         `json:"cases"`
	Positive int         `json:"positive"`
	Tools    []ToolScore `json:"tools"`
	// Combined is all tools' findings merged by fingerprint.
	Combined ToolScore `json:"combined"`
}

// Score scores every tool run and the merged result.
func Score(l Labels, runs []ToolRun) Result {
	res := Result{Suite: l.Suite, Source: l.Source, License: l.License, Match: l.Match, Cases: len(l.Cases)}
	for _, c := range l.Cases {
		if c.Vulnerable {
			res.Positive++
		}
	}
	var total int64
	for _, r := range runs {
		fs := make([]Merged, 0, len(r.Findings))
		for _, f := range r.Findings {
			fs = append(fs, Merged{Finding: f, Scanners: []string{f.ScannerKey}})
		}
		ts := score(l, fs)
		ts.Scanner, ts.Version, ts.Status, ts.Error, ts.DurationMS = r.Scanner, r.Version, r.Status, r.Error, r.DurationMS
		if r.Status != "succeeded" {
			// A tool that did not run has no score: its zeros would read
			// as "detects nothing".
			ts.Overall, ts.ByCategory, ts.FileOnly, ts.CategoryAverage = Metrics{}, nil, nil, nil
		}
		total += r.DurationMS
		res.Tools = append(res.Tools, ts)
	}
	ts := score(l, Merge(runs))
	ts.Scanner, ts.Status, ts.DurationMS = "combined", "succeeded", total
	res.Combined = ts
	return res
}

// score matches findings to cases.
func score(l Labels, fs []Merged) ToolScore {
	ts := ToolScore{Findings: len(fs), ByCategory: map[string]Metrics{}}
	cats := map[string]*Counts{}
	var all, loose Counts
	related := make([]bool, len(fs))
	m := newMatcher(l, fs)
	for _, c := range l.Cases {
		hit, fileHit := m.detects(c, related)
		all.add(c.Vulnerable, hit)
		loose.add(c.Vulnerable, fileHit)
		if cats[c.Category] == nil {
			cats[c.Category] = &Counts{}
		}
		cats[c.Category].add(c.Vulnerable, hit)
	}
	for _, r := range related {
		if !r {
			ts.Unrelated++
		}
	}
	ts.Overall = all.Finish()
	for k, c := range cats {
		ts.ByCategory[k] = c.Finish()
	}
	ts.CategoryAverage = categoryAverage(ts.ByCategory)
	if l.Match == MatchOWASP {
		lm := loose.Finish()
		ts.FileOnly = &lm
	}
	return ts
}

type matcher struct {
	l  Labels
	fs []Merged
	// byKey indexes findings by test case name (MatchOWASP), path
	// (MatchFile) or lower-case package name (MatchSCA).
	byKey map[string][]int
}

func newMatcher(l Labels, fs []Merged) *matcher {
	m := &matcher{l: l, fs: fs, byKey: map[string][]int{}}
	for i, f := range fs {
		var k string
		switch l.Match {
		case MatchOWASP:
			b := path.Base(scanners.NormalizePath(f.FilePath))
			k = strings.TrimSuffix(b, path.Ext(b))
		case MatchFile:
			if len(l.Categories) > 0 && !slices.Contains(l.Categories, f.Category) {
				continue
			}
			k = scanners.NormalizePath(f.FilePath)
		case MatchSCA:
			k = normPkg(f.PackageName)
		}
		if k != "" {
			m.byKey[k] = append(m.byKey[k], i)
		}
	}
	return m
}

func normPkg(s string) string {
	return strings.ReplaceAll(strings.ToLower(strings.TrimSpace(s)), "_", "-")
}

// detects reports whether the case is detected (by the suite's rule) and,
// for MatchOWASP, whether any finding is in its file. related marks the
// findings that belong to a labelled case's file or package.
func (m *matcher) detects(c Case, related []bool) (bool, bool) {
	switch m.l.Match {
	case MatchOWASP:
		hit := false
		idx := m.byKey[c.ID]
		for _, i := range idx {
			related[i] = true
			if slices.Contains(m.fs[i].CWE, c.CWE) {
				hit = true
			}
		}
		return hit, len(idx) > 0
	case MatchFile:
		idx := m.byKey[path.Clean(c.File)]
		for _, i := range idx {
			related[i] = true
		}
		return len(idx) > 0, len(idx) > 0
	case MatchSCA:
		hit := false
		dir := path.Clean(c.File)
		for _, p := range c.Packages {
			for _, i := range m.byKey[normPkg(p)] {
				f := m.fs[i]
				fp := scanners.NormalizePath(f.FilePath)
				if dir != "." && fp != dir && !strings.HasPrefix(fp, dir+"/") {
					continue
				}
				related[i] = true
				for _, v := range c.Vulns {
					if strings.EqualFold(f.CVE, v) || strings.EqualFold(f.RuleID, v) {
						hit = true
					}
				}
			}
		}
		return hit, hit
	}
	return false, false
}

// round4 rounds for display.
func round4(v float64) float64 { return math.Round(v*10000) / 10000 }

// ErrNoRuns means no tool output was given.
var ErrNoRuns = errors.New("no tool runs")

// Exclude drops the runs of the given scanners (to score a subset of
// tools, for example without one noisy tool).
func Exclude(runs []ToolRun, keys []string) []ToolRun {
	return slices.DeleteFunc(slices.Clone(runs), func(r ToolRun) bool { return slices.Contains(keys, r.Scanner) })
}
