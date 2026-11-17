package scans

import (
	"strings"
	"testing"
)

const okRule = `rules:
  - id: acme.java.hardcoded-key
    languages: [java]
    severity: ERROR
    message: Hard-coded crypto key
    pattern: new SecretKeySpec("...".getBytes(), $ALG)
  - id: acme.py.taint
    mode: taint
    languages: [python]
    severity: WARNING
    message: request data reaches os.system
    pattern-sources: [{pattern: request.args.get(...)}]
    pattern-sinks: [{pattern: os.system(...)}]
`

func TestValidateRules(t *testing.T) {
	ids, err := ValidateRules(okRule)
	if err != nil || len(ids) != 2 || ids[0] != "acme.java.hardcoded-key" {
		t.Fatalf("%v %v", ids, err)
	}
	bad := map[string]string{
		"empty":       "",
		"yaml":        "rules: [",
		"no rules":    "foo: bar",
		"no id":       "rules:\n  - languages: [go]\n    severity: ERROR\n    message: x\n    pattern: x",
		"reserved":    strings.Replace(okRule, "acme.java", "pathos.java", 1),
		"duplicate":   strings.Replace(okRule, "acme.py.taint", "acme.java.hardcoded-key", 1),
		"severity":    strings.Replace(okRule, "severity: ERROR", "severity: SEVERE", 1),
		"no pattern":  "rules:\n  - id: a\n    languages: [go]\n    severity: ERROR\n    message: x",
		"no sinks":    strings.Replace(okRule, "    pattern-sinks: [{pattern: os.system(...)}]\n", "", 1),
		"no language": strings.Replace(okRule, "languages: [java]", "languages: []", 1),
	}
	for name, c := range bad {
		if _, err := ValidateRules(c); err == nil {
			t.Errorf("%s: expected an error", name)
		}
	}
}
