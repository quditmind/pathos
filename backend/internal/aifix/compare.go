package aifix

import (
	"fmt"
	"sort"
)

// Result is one scanner result in a changed file, as kept in the evidence.
type Result struct {
	RuleID string `json:"rule_id"`
	File   string `json:"file"`
	Line   int    `json:"line,omitempty"`
	Title  string `json:"title,omitempty"`
}

// Target is the finding a fix must remove.
type Target struct {
	RuleID string
	File   string
	Line   int // 0: unknown
}

// Verdict compares scanner results on the original and the fixed files.
type Verdict struct {
	// Reproduced: the scanner reports the finding on the original file.
	Reproduced bool `json:"reproduced"`
	// Removed: it no longer reports it after the fix.
	Removed bool `json:"removed"`
	// New results in the changed files that were not there before.
	New    []Result `json:"new"`
	Before []Result `json:"before"`
	After  []Result `json:"after"`
	// Reason explains a failure ("" when verified).
	Reason string `json:"reason,omitempty"`
}

// Verified reports whether the scanner evidence shows the fix works.
func (v Verdict) Verified() bool { return v.Reproduced && v.Removed && len(v.New) == 0 }

// Compare decides whether a fix removed the target finding without
// introducing others. Results are compared as multisets per rule and file
// (line numbers move when code changes). The target counts as removed when
// the scanner reports fewer results of its rule in its file after the fix
// and none of them on the lines the original finding line became
// (applied maps lines; nil when the target file was not changed).
func Compare(before, after []Result, target Target, applied *Applied) Verdict {
	v := Verdict{Before: nonNil(before), After: nonNil(after), New: []Result{}}
	key := func(r Result) string { return r.RuleID + "\x00" + r.File }
	tkey := target.RuleID + "\x00" + target.File
	countB, countA := map[string]int{}, map[string]int{}
	for _, r := range before {
		countB[key(r)]++
	}
	for _, r := range after {
		countA[key(r)]++
	}
	v.Reproduced = countB[tkey] > 0
	if !v.Reproduced {
		v.Reason = fmt.Sprintf("the scanner did not report rule %s in %s on the original code, so the fix cannot be verified", target.RuleID, target.File)
		return v
	}
	v.Removed = countA[tkey] < countB[tkey]
	if v.Removed && target.Line > 0 && applied != nil {
		from, to := applied.MapLine(target.Line)
		for _, r := range after {
			if key(r) == tkey && r.Line >= from && r.Line <= to {
				v.Removed = false
			}
		}
	}
	// New results: more of a rule in a file than before.
	extra := map[string]int{}
	for k, n := range countA {
		if n > countB[k] {
			extra[k] = n - countB[k]
		}
	}
	sorted := append([]Result(nil), after...)
	sort.SliceStable(sorted, func(i, j int) bool { return sorted[i].Line > sorted[j].Line })
	for _, r := range sorted {
		if extra[key(r)] > 0 {
			extra[key(r)]--
			v.New = append(v.New, r)
		}
	}
	sort.SliceStable(v.New, func(i, j int) bool {
		return v.New[i].File < v.New[j].File || (v.New[i].File == v.New[j].File && v.New[i].Line < v.New[j].Line)
	})
	switch {
	case !v.Removed:
		v.Reason = fmt.Sprintf("the scanner still reports rule %s in %s after the fix", target.RuleID, target.File)
	case len(v.New) > 0:
		v.Reason = fmt.Sprintf("the fix introduces %d new scanner result(s) in the changed files (first: %s at %s:%d)", len(v.New), v.New[0].RuleID, v.New[0].File, v.New[0].Line)
	}
	return v
}

func nonNil(r []Result) []Result {
	if r == nil {
		return []Result{}
	}
	return r
}
