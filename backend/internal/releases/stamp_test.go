package releases

import (
	"encoding/json"
	"testing"
	"time"

	"pathos/internal/platform/buildinfo"
)

func TestVEXExportsAreVersionStamped(t *testing.T) {
	now := time.Date(2026, 11, 20, 10, 0, 0, 0, time.UTC)
	st := []Statement{{Vulnerability: "CVE-2024-0001", Status: VEXNotAffected, Justification: "vulnerable_code_not_present", Products: []string{"pkg:npm/a@1.0.0"}}}
	raw, err := CycloneDXVEXDocument("app", "1.0", st, now)
	if err != nil {
		t.Fatal(err)
	}
	var cdx struct {
		Metadata struct {
			Tools struct {
				Components []map[string]string `json:"components"`
			} `json:"tools"`
			Properties []map[string]string `json:"properties"`
		} `json:"metadata"`
	}
	if err := json.Unmarshal(raw, &cdx); err != nil {
		t.Fatal(err)
	}
	c := cdx.Metadata.Tools.Components
	if len(c) != 1 || c[0]["name"] != "PATHOS" || c[0]["publisher"] != "Quditmind" || c[0]["version"] != buildinfo.Version {
		t.Errorf("tools.components: %v", c)
	}
	if len(cdx.Metadata.Properties) == 0 || cdx.Metadata.Properties[0]["value"] != buildinfo.Stamp(now) {
		t.Errorf("stamp property: %v", cdx.Metadata.Properties)
	}
	raw, err = OpenVEXDocument("PATHOS", "https://pathos.local/vex/1", st, now)
	if err != nil {
		t.Fatal(err)
	}
	var ov map[string]any
	_ = json.Unmarshal(raw, &ov)
	if ov["tooling"] != buildinfo.Stamp(now) {
		t.Errorf("OpenVEX tooling: %v", ov["tooling"])
	}
}
