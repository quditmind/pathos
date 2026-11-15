package worker

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestEnrichSARIF(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "src")
	_ = os.MkdirAll(filepath.Join(src, "app"), 0o700)
	var code strings.Builder
	for i := 1; i <= 30; i++ {
		code.WriteString("line ")
		code.WriteString(strings.Repeat("x", i%3))
		code.WriteString("\n")
	}
	_ = os.WriteFile(filepath.Join(src, "app", "a.py"), []byte(code.String()), 0o600)
	_ = os.WriteFile(filepath.Join(dir, "secret.txt"), []byte("TOP SECRET\n"), 0o600)
	sarif := `{"runs":[{"results":[
	  {"ruleId":"r","locations":[{"physicalLocation":{"artifactLocation":{"uri":"app/a.py"},"region":{"startLine":10,"endLine":11}}}]},
	  {"ruleId":"escape","locations":[{"physicalLocation":{"artifactLocation":{"uri":"../secret.txt"},"region":{"startLine":1}}}]},
	  {"ruleId":"abs","locations":[{"physicalLocation":{"artifactLocation":{"uri":"` + filepath.Join(dir, "secret.txt") + `"},"region":{"startLine":1}}}]}
	]}]}`
	out := filepath.Join(dir, "o.sarif")
	_ = os.WriteFile(out, []byte(sarif), 0o600)
	if err := enrichSARIF(out, src); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(out)
	if strings.Contains(string(b), "TOP SECRET") {
		t.Fatal("context must never be read from outside the checkout")
	}
	var doc struct {
		Runs []struct {
			Results []struct {
				Properties map[string]any `json:"properties"`
			} `json:"results"`
		} `json:"runs"`
	}
	_ = json.Unmarshal(b, &doc)
	p := doc.Runs[0].Results[0].Properties
	if p["pathos_context_start"].(float64) != 5 || strings.Count(p["pathos_context"].(string), "\n") != 12 {
		t.Errorf("unexpected context: %v", p)
	}
}
