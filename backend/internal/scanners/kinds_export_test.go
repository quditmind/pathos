package scanners

import (
	"bytes"
	"encoding/json"
	"os"
	"slices"
	"strings"
	"testing"
)

// kindsExportPath is the frontend copy of the kinds of check and of the
// catalogue's tool names: the UI computes kinds and engine counts with it,
// and the tool-name test (frontend/src/test/toolNames.test.tsx) asserts
// that no catalogued tool name appears outside the configuration pages.
const kindsExportPath = "../../../frontend/src/lib/checkKinds.json"

type kindsExport struct {
	Note           string            `json:"_note"`
	Kinds          []exportKind      `json:"kinds"`
	CategoryKinds  map[string]string `json:"category_kinds"`
	Overrides      []kindOverride    `json:"overrides"`
	EngineFamilies []string          `json:"engine_families"`
	EngineAliases  map[string]string `json:"engine_aliases"`
	ImportCategory []string          `json:"import_categories"`
	ScanTypeKinds  map[string]string `json:"scan_type_kinds"`
	ToolKinds      map[string]string `json:"tool_kinds"`
	// Tools are the catalogued tools (key and name), the list the
	// tool-name test enforces.
	Tools []exportTool `json:"tools"`
}

type exportKind struct {
	ID      string `json:"id"`
	Name    string `json:"name"`
	Outside bool   `json:"outside"`
}

type exportTool struct {
	Key  string `json:"key"`
	Name string `json:"name"`
	// FirstParty: a check built into PATHOS (not a third-party tool); its
	// descriptive name is not a tool name.
	FirstParty bool `json:"first_party,omitempty"`
}

// firstParty are PATHOS's own checks.
func firstParty(sc Scanner) bool {
	return strings.HasPrefix(sc.Key, "pathos-") || strings.Contains(sc.Homepage, "quditmind/pathos") ||
		slices.Contains([]string{BinaryHardening, "ai-bom", LicensePolicy}, sc.Key)
}

func buildKindsExport() kindsExport {
	e := kindsExport{Note: "Generated from backend/internal/scanners (scantypes.go, catalog*.go): UPDATE_KINDS=1 go test ./internal/scanners -run TestKindsExport",
		CategoryKinds: categoryKinds, Overrides: kindOverrides, EngineFamilies: engineFamilies, EngineAliases: engineAliases, ImportCategory: ImportCategories,
		ScanTypeKinds: map[string]string{}, ToolKinds: map[string]string{}}
	for _, k := range CheckKinds {
		e.Kinds = append(e.Kinds, exportKind{ID: k.ID, Name: k.Name})
	}
	for _, k := range OutsideKinds {
		e.Kinds = append(e.Kinds, exportKind{ID: k.ID, Name: k.Name, Outside: true})
	}
	for _, st := range ScanTypes {
		e.ScanTypeKinds[st.ID] = KindOfScanType(st.ID)
	}
	for _, sc := range append(append(append([]Scanner{}, Catalog...), Builtins...), SyftUtility) {
		e.Tools = append(e.Tools, exportTool{Key: sc.Key, Name: sc.Name, FirstParty: firstParty(sc)})
		e.ToolKinds[sc.Key] = PrimaryKindOfTool(sc.Key)
	}
	slices.SortFunc(e.Tools, func(a, b exportTool) int {
		if a.Key < b.Key {
			return -1
		}
		if a.Key > b.Key {
			return 1
		}
		return 0
	})
	return e
}

func TestKindsExport(t *testing.T) {
	b, err := json.MarshalIndent(buildKindsExport(), "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	b = append(b, '\n')
	if os.Getenv("UPDATE_KINDS") == "1" {
		if err := os.WriteFile(kindsExportPath, b, 0o644); err != nil { // #nosec G306 -- source file in the repository
			t.Fatal(err)
		}
		return
	}
	cur, err := os.ReadFile(kindsExportPath)
	if err != nil {
		t.Fatalf("%v (run UPDATE_KINDS=1 go test ./internal/scanners -run TestKindsExport)", err)
	}
	if !bytes.Equal(cur, b) {
		t.Fatal("frontend/src/lib/checkKinds.json is out of date: run UPDATE_KINDS=1 go test ./internal/scanners -run TestKindsExport")
	}
}
