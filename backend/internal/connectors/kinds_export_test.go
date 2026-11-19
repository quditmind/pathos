package connectors

import (
	"bytes"
	"encoding/json"
	"os"
	"testing"
)

// connectorKindsPath is the connector kinds catalogue as GET
// /api/v1/connectors/kinds serves it. The frontend tool-name test
// (frontend/src/test/toolNames.test.tsx) renders the Connectors hub with it
// and asserts that no catalogued scanner tool name appears (rule 3).
const connectorKindsPath = "../../../frontend/src/test/fixtures/connectorKinds.json"

func TestConnectorKindsExport(t *testing.T) {
	b, err := json.MarshalIndent(map[string]any{"items": Kinds(), "categories": Categories}, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	b = append(b, '\n')
	if os.Getenv("UPDATE_KINDS") == "1" {
		if err := os.WriteFile(connectorKindsPath, b, 0o644); err != nil { // #nosec G306 -- test fixture in the repository
			t.Fatal(err)
		}
		return
	}
	cur, err := os.ReadFile(connectorKindsPath)
	if err != nil {
		t.Fatalf("%v (run UPDATE_KINDS=1 go test ./internal/connectors -run TestConnectorKindsExport)", err)
	}
	if !bytes.Equal(cur, b) {
		t.Fatal("frontend/src/test/fixtures/connectorKinds.json is out of date: run UPDATE_KINDS=1 go test ./internal/connectors -run TestConnectorKindsExport")
	}
}
