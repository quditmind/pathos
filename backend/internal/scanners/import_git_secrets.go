package scanners

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"regexp"
	"strconv"
	"strings"
)

// git-secrets output (`git secrets --scan` or `--scan-history`, stderr):
// one line per match, "file:line:text" (history scans prefix the commit:
// "commit:file:line:text"), followed by "[ERROR] Matched one or more
// prohibited patterns" and the mitigation hints. The matched text is the
// secret: it is removed before the report is stored and never kept in a
// finding. Matches are high.

const gitSecretsMarker = "[ERROR] Matched one or more prohibited patterns" // #nosec G101 -- git-secrets output banner, not a credential

var (
	gitSecretsLine = regexp.MustCompile(`^(?:([0-9a-f]{40}):)?(.+?):([0-9]+):`)
	gitSecretsSHA  = regexp.MustCompile(`^[0-9a-f]{40}$`)
)

func init() {
	registerImportFormat(ImportFormat{ID: "git-secrets", Label: "git-secrets scan output (text)", Tool: "git-secrets", Category: "secrets", Media: "text", Order: 707,
		match: func(p *importProbe) bool {
			return (p.kind == "" || p.kind == "csv") && p.headHas(gitSecretsMarker)
		},
		parse: parseGitSecrets, sanitize: sanitizeGitSecrets})
}

// gitSecretsMatches calls fn for every match line before the marker.
func gitSecretsMatches(raw []byte, fn func(line string, m []string)) {
	sc := bufio.NewScanner(bytes.NewReader(bytes.TrimPrefix(raw, utf8BOM)))
	sc.Buffer(make([]byte, 0, 64<<10), 4<<20)
	for sc.Scan() {
		line := sc.Text()
		if strings.HasPrefix(line, gitSecretsMarker) {
			return
		}
		fn(line, gitSecretsLine.FindStringSubmatch(line))
	}
}

func sanitizeGitSecrets(raw []byte) []byte {
	var out bytes.Buffer
	done := false
	sc := bufio.NewScanner(bytes.NewReader(bytes.TrimPrefix(raw, utf8BOM)))
	sc.Buffer(make([]byte, 0, 64<<10), 4<<20)
	for sc.Scan() {
		line := sc.Text()
		if strings.HasPrefix(line, gitSecretsMarker) {
			done = true
		}
		if !done {
			if m := gitSecretsLine.FindStringSubmatch(line); m != nil {
				line = m[0] + "[REDACTED]"
			}
		}
		out.WriteString(line)
		out.WriteByte('\n')
	}
	return out.Bytes()
}

func parseGitSecrets(raw []byte) ([]importRecord, error) {
	if !bytes.Contains(raw, []byte(gitSecretsMarker)) {
		return nil, errors.New("git-secrets: no \"" + gitSecretsMarker + "\" line: not git-secrets output")
	}
	var out []importRecord
	gitSecretsMatches(raw, func(line string, m []string) {
		if m == nil {
			return
		}
		commit, file := m[1], m[2]
		// A history line whose commit was not split off (an abbreviated
		// revision or a ref) keeps it in the file name.
		if c, f, ok := strings.Cut(file, ":"); ok && commit == "" && gitSecretsSHA.MatchString(c) {
			commit, file = c, f
		}
		n, _ := strconv.Atoi(m[3])
		f := Finding{Category: "secrets", RuleID: "git-secrets prohibited pattern", Title: "Prohibited pattern (possible secret) in " + file, Severity: "high",
			FilePath: NormalizePath(file), StartLine: intPtr(n),
			Description: "git-secrets matched a prohibited pattern at " + file + ":" + m[3] + "."}
		rec := map[string]any{"file": file, "line": n}
		if commit != "" {
			f.Description = "git-secrets matched a prohibited pattern at " + file + ":" + m[3] + " in commit " + commit + "."
			rec["commit"] = commit
		}
		f.Description += " The matched text is not kept."
		b, _ := json.Marshal(rec)
		out = append(out, importRecord{F: f, SnippetKey: hashOf(commit), Raw: b})
	})
	return out, nil
}
