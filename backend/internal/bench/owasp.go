package bench

import (
	"bufio"
	"fmt"
	"os"
	"regexp"
	"strconv"
	"strings"
)

var owaspTestRe = regexp.MustCompile(`^BenchmarkTest\d{5}$`)

// OWASPLabels reads an OWASP Benchmark expectedresults-*.csv file
// ("# test name, category, real vulnerability, cwe, ..." then one line per
// test case). The same format is used by BenchmarkJava and BenchmarkPython.
func OWASPLabels(csvFile, suite, source, license string) (Labels, error) {
	l := Labels{Suite: suite, Source: source, License: license, Match: MatchOWASP}
	// #nosec G304 -- benchmark input chosen by the operator running the harness
	f, err := os.Open(csvFile)
	if err != nil {
		return l, err
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	n := 0
	for sc.Scan() {
		n++
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		p := strings.Split(line, ",")
		if len(p) < 4 {
			return l, fmt.Errorf("%s:%d: expected 4 fields", csvFile, n)
		}
		id, cat, real, cwe := strings.TrimSpace(p[0]), strings.TrimSpace(p[1]), strings.TrimSpace(p[2]), strings.TrimSpace(p[3])
		if !owaspTestRe.MatchString(id) {
			return l, fmt.Errorf("%s:%d: unexpected test name %q", csvFile, n, id)
		}
		vuln, err := strconv.ParseBool(real)
		if err != nil {
			return l, fmt.Errorf("%s:%d: real vulnerability %q", csvFile, n, real)
		}
		if _, err := strconv.Atoi(cwe); err != nil {
			return l, fmt.Errorf("%s:%d: cwe %q", csvFile, n, cwe)
		}
		l.Cases = append(l.Cases, Case{ID: id, Category: cat, Vulnerable: vuln, CWE: "CWE-" + cwe})
	}
	if err := sc.Err(); err != nil {
		return l, err
	}
	if len(l.Cases) == 0 {
		return l, fmt.Errorf("%s: no test cases", csvFile)
	}
	return l, nil
}
