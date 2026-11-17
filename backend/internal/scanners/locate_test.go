package scanners

import (
	"strings"
	"testing"
)

const flowSARIF = `{"version":"2.1.0","runs":[{"tool":{"driver":{"name":"opengrep","rules":[
 {"id":"python.sqli","shortDescription":{"text":"SQL injection"},"properties":{"cwe":["CWE-89"]}},
 {"id":"python.weak-hash","shortDescription":{"text":"Weak hash"}}]}},
 "results":[
  {"ruleId":"python.weak-hash","level":"warning","message":{"text":"md5 used"},
   "locations":[{"physicalLocation":{"artifactLocation":{"uri":"app/hash.py"},"region":{"startLine":3}}}]},
  {"ruleId":"python.sqli","level":"error","message":{"text":"user input reaches cursor.execute token=ghp_abcdefghijklmnopqrstuvwxyz0123456789"},
   "locations":[{"physicalLocation":{"artifactLocation":{"uri":"app/db.py"},"region":{"startLine":42,"snippet":{"text":"cursor.execute(q)"}}}}],
   "codeFlows":[{"threadFlows":[{"locations":[
     {"location":{"physicalLocation":{"artifactLocation":{"uri":"app/views.py"},"region":{"startLine":10}},"message":{"text":"request.args['id']"}},"kinds":["source"]},
     {"location":{"physicalLocation":{"artifactLocation":{"uri":"app/service.py"},"region":{"startLine":20}},"logicalLocations":[{"name":"find_user"}]}},
     {"location":{"physicalLocation":{"artifactLocation":{"uri":"app/db.py"},"region":{"startLine":42}}},"kinds":["sink"]}]}]}],
   "relatedLocations":[{"physicalLocation":{"artifactLocation":{"uri":"app/models.py"},"region":{"startLine":5}}}]}
 ]}]}`

func TestLocateSARIFFlows(t *testing.T) {
	fs, err := ParseSARIF("opengrep", []byte(flowSARIF))
	if err != nil || len(fs) != 2 {
		t.Fatalf("parse: %v %d", err, len(fs))
	}
	loc, err := LocateSARIF("opengrep", []byte(flowSARIF), fs[1].Fingerprint)
	if err != nil {
		t.Fatal(err)
	}
	if len(loc.Flows) != 1 || len(loc.Flows[0].Steps) != 3 {
		t.Fatalf("flows: %+v", loc.Flows)
	}
	s := loc.Flows[0].Steps
	if s[0].FilePath != "app/views.py" || s[0].Line != 10 || s[0].Kinds[0] != "source" || s[1].Function != "find_user" || s[2].Line != 42 {
		t.Errorf("steps: %+v", s)
	}
	if len(loc.Related) != 1 || loc.Related[0].FilePath != "app/models.py" {
		t.Errorf("related: %+v", loc.Related)
	}
	if !strings.Contains(string(loc.Rule), "python.sqli") {
		t.Errorf("rule: %s", loc.Rule)
	}
	if strings.Contains(string(loc.Raw), "ghp_abcdefghijklmnopqrstuvwxyz0123456789") {
		t.Error("raw output must be redacted")
	}
	// The first result has no flow; an unknown fingerprint is not located.
	if l, err := LocateSARIF("opengrep", []byte(flowSARIF), fs[0].Fingerprint); err != nil || len(l.Flows) != 0 {
		t.Errorf("no flow: %+v %v", l, err)
	}
	if _, err := LocateSARIF("opengrep", []byte(flowSARIF), "nope"); err != ErrNotLocated {
		t.Errorf("unknown fingerprint: %v", err)
	}
}
