package scanners

import (
	"os"
	"testing"
)

func TestConfidenceAndCVSSVectors(t *testing.T) {
	raw, _ := os.ReadFile("testdata/trivy-fs.sarif")
	fs, err := ParseSARIF(TrivyFS, raw)
	if err != nil || len(fs) == 0 {
		t.Fatal(err)
	}
	withVector := 0
	for _, f := range fs {
		if f.Confidence != "high" {
			t.Errorf("SCA confidence %q", f.Confidence)
		}
		if f.CVSSVector != "" {
			withVector++
			if f.CVSSVersion == "" {
				t.Errorf("vector without version: %q", f.CVSSVector)
			}
		}
	}
	if withVector == 0 {
		t.Error("Trivy reports CVSS vectors")
	}
	raw, _ = os.ReadFile("testdata/opengrep.sarif")
	if fs, _ := ParseSARIF(Opengrep, raw); len(fs) == 0 || fs[0].Confidence != "medium" {
		t.Errorf("default very-high precision is not a signal: %+v", fs)
	}
	raw, _ = os.ReadFile("testdata/grype.json")
	g, err := ParseGrypeJSON(raw)
	if err != nil || g[0].CVSSVector == "" || g[0].CVSSVersion != "3.1" || g[0].Confidence != "high" {
		t.Errorf("grype: %+v %v", g[0], err)
	}
	if confidenceOf("sast", map[string]any{"precision": "low"}) != "low" || confidenceOf("sast", map[string]any{"confidence": "HIGH"}) != "high" ||
		confidenceOf("sast", map[string]any{"precision": "high"}) != "medium" {
		t.Error("explicit confidence metadata")
	}
	if vectorVersion("CVSS:4.0/AV:N") != "4.0" || vectorVersion("AV:N/AC:L/Au:N") != "2.0" || vectorVersion("x") != "" {
		t.Error("vectorVersion")
	}
}
