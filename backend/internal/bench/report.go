package bench

import (
	"fmt"
	"math"
	"sort"
	"strings"
)

func pct(v *float64) string {
	if v == nil {
		return "n/a"
	}
	return fmt.Sprintf("%.1f%%", round4(*v)*100)
}

func signedPct(v *float64) string {
	if v == nil {
		return "n/a"
	}
	r := round4(*v) * 100
	if math.Abs(r) < 0.05 {
		r = 0 // no "-0.0"
	}
	return fmt.Sprintf("%+.1f", r)
}

func secs(ms int64) string { return fmt.Sprintf("%.1f", float64(ms)/1000) }

// Markdown renders scored suites as Markdown tables (docs/BENCHMARKS.md).
func Markdown(results []Result) string {
	var b strings.Builder
	for _, r := range results {
		fmt.Fprintf(&b, "### %s\n\n", r.Suite)
		fmt.Fprintf(&b, "Source: %s. Licence: %s. %d labelled cases (%d positive, %d negative); match rule: %s.\n\n",
			r.Source, r.License, r.Cases, r.Positive, r.Cases-r.Positive, matchText(r.Match))
		b.WriteString("| Tool | Version | Status | Time (s) | Findings | Unrelated | TP | FP | FN | TN | Precision | Recall (TPR) | FPR | F1 | Score (TPR−FPR) |\n")
		b.WriteString("|---|---|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|\n")
		rows := append(append([]ToolScore{}, r.Tools...), r.Combined)
		for _, t := range rows {
			name, ver := t.Scanner, t.Version
			if t.Scanner == "combined" {
				name, ver = "**PATHOS combined (merged by fingerprint)**", "—"
			}
			status := t.Status
			if t.Error != "" && t.Status != "succeeded" {
				status += ": " + strings.ReplaceAll(firstN(t.Error, 80), "|", "/")
			}
			if t.Status != "succeeded" {
				fmt.Fprintf(&b, "| %s | %s | %s | %s | — | — | — | — | — | — | — | — | — | — | — |\n", name, ver, status, secs(t.DurationMS))
				continue
			}
			m := t.Overall
			fmt.Fprintf(&b, "| %s | %s | %s | %s | %d | %d | %d | %d | %d | %d | %s | %s | %s | %s | %s |\n", name, ver, status,
				secs(t.DurationMS), t.Findings, t.Unrelated, m.TP, m.FP, m.FN, m.TN, pct(m.Precision), pct(m.Recall), pct(m.FPR), pct(m.F1), signedPct(m.Score))
		}
		b.WriteString("\n")
		var avg strings.Builder
		for _, t := range rows {
			if a := t.CategoryAverage; a != nil {
				fmt.Fprintf(&avg, "| %s | %d | %s | %s | %s |\n", t.Scanner, a.Categories, pct(&a.TPR), pct(&a.FPR), signedPct(&a.Score))
			}
		}
		if avg.Len() > 0 {
			b.WriteString("Mean over the categories with positive and negative cases (the OWASP Benchmark scorecard's summary; each category weighs the same):\n\n")
			b.WriteString("| Tool | Categories | Mean TPR | Mean FPR | Mean score |\n|---|---:|---:|---:|---:|\n")
			b.WriteString(avg.String() + "\n")
		}
		if r.Match == MatchOWASP {
			b.WriteString("Any finding in the test case's file, whatever its CWE (for comparison; not the OWASP rule):\n\n")
			b.WriteString("| Tool | TP | FP | Recall (TPR) | FPR | Score |\n|---|---:|---:|---:|---:|---:|\n")
			for _, t := range rows {
				if t.FileOnly == nil || t.Status != "succeeded" {
					continue
				}
				fmt.Fprintf(&b, "| %s | %d | %d | %s | %s | %s |\n", t.Scanner, t.FileOnly.TP, t.FileOnly.FP, pct(t.FileOnly.Recall), pct(t.FileOnly.FPR), signedPct(t.FileOnly.Score))
			}
			b.WriteString("\n")
		}
		// Per category: recall and false positive rate of each tool.
		cats := map[string][2]int{}
		for _, t := range rows {
			for c, m := range t.ByCategory {
				cats[c] = [2]int{m.TP + m.FN, m.FP + m.TN}
			}
		}
		names := make([]string, 0, len(cats))
		for c := range cats {
			names = append(names, c)
		}
		sort.Strings(names)
		b.WriteString("Per category, recall (TPR) / false positive rate:\n\n| Category | Positive | Negative |")
		var cols []ToolScore
		for _, t := range rows {
			if t.Status == "succeeded" {
				cols = append(cols, t)
				fmt.Fprintf(&b, " %s |", t.Scanner)
			}
		}
		b.WriteString("\n|---|---:|---:|" + strings.Repeat("---|", len(cols)) + "\n")
		for _, c := range names {
			fmt.Fprintf(&b, "| %s | %d | %d |", c, cats[c][0], cats[c][1])
			for _, t := range cols {
				m := t.ByCategory[c]
				fmt.Fprintf(&b, " %s / %s |", pct(m.Recall), pct(m.FPR))
			}
			b.WriteString("\n")
		}
		b.WriteString("\n")
	}
	return b.String()
}

func matchText(m string) string {
	switch m {
	case MatchOWASP:
		return "a finding in the test case's file with the test case's CWE (OWASP Benchmark rule)"
	case MatchFile:
		return "any secrets finding in the case's file"
	case MatchSCA:
		return "a dependency finding for the case's package, in its directory, with one of the vulnerability's IDs (CVE, GHSA, GO, PYSEC)"
	}
	return m
}

func firstN(s string, n int) string {
	s = strings.TrimSpace(strings.ReplaceAll(s, "\n", " "))
	if len(s) > n {
		return s[:n] + "…"
	}
	return s
}
