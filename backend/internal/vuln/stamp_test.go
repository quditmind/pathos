package vuln

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"pathos/internal/platform/buildinfo"
)

func TestExportsAreVersionStamped(t *testing.T) {
	now := time.Date(2026, 11, 20, 10, 0, 0, 0, time.UTC)
	comps := []invComponent{{Ref: "a", Name: "lib", Version: "1.0", PURL: "pkg:npm/lib@1.0"}}
	stamp := buildinfo.Stamp(now)
	if !strings.HasPrefix(stamp, "Quditmind PATHOS v") || !strings.Contains(stamp, " · build ") || !strings.HasSuffix(stamp, "generated 2026-11-20T10:00:00Z") {
		t.Fatalf("stamp %q", stamp)
	}

	raw, err := CycloneDXDocument("app", comps, nil, now)
	if err != nil {
		t.Fatal(err)
	}
	var cdx struct {
		Metadata struct {
			Tools      []map[string]string `json:"tools"`
			Properties []map[string]string `json:"properties"`
		} `json:"metadata"`
	}
	if err := json.Unmarshal(raw, &cdx); err != nil {
		t.Fatal(err)
	}
	if len(cdx.Metadata.Tools) != 1 || cdx.Metadata.Tools[0]["vendor"] != "Quditmind" || cdx.Metadata.Tools[0]["name"] != "PATHOS" || cdx.Metadata.Tools[0]["version"] != buildinfo.Version {
		t.Errorf("CycloneDX metadata.tools: %v", cdx.Metadata.Tools)
	}
	if len(cdx.Metadata.Properties) == 0 || cdx.Metadata.Properties[0]["value"] != stamp {
		t.Errorf("CycloneDX stamp property: %v", cdx.Metadata.Properties)
	}

	raw, err = SPDXDocument("app", comps, nil, now)
	if err != nil {
		t.Fatal(err)
	}
	var spdx struct {
		CreationInfo struct {
			Creators []string `json:"creators"`
			Comment  string   `json:"comment"`
		} `json:"creationInfo"`
	}
	if err := json.Unmarshal(raw, &spdx); err != nil {
		t.Fatal(err)
	}
	if len(spdx.CreationInfo.Creators) != 1 || spdx.CreationInfo.Creators[0] != "Tool: PATHOS-"+buildinfo.Version || spdx.CreationInfo.Comment != stamp {
		t.Errorf("SPDX creationInfo: %+v", spdx.CreationInfo)
	}
}
