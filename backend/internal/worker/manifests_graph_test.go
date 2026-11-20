package worker

import (
	"encoding/json"
	"os"
	"slices"
	"strings"
	"testing"

	"pathos/internal/scanners"
)

// The worker-graph manifest (workers/graph/tools.d/pathos-graph.yaml): a
// first-party, repository-only, offline tool of the graph family whose
// output is a code graph, not findings. The fixture is the real output of
// the worker-graph image on workers/graph/discover/testdata/fixture-repo
// (backend/internal/codegraph/testdata/fixture-graph.json).
func TestGraphManifest(t *testing.T) {
	d := loadFamilySpec(t, "graph", "pathos-graph.yaml")
	if d.Key() != scanners.PathosGraph || d.Family != "graph" || !d.FirstParty || d.Category != "other" {
		t.Fatalf("manifest: key %s family %s category %s", d.Key(), d.Family, d.Category)
	}
	if !slices.Equal(d.Targets, []string{"repository"}) || d.Network != "none" || d.Intrusive || d.Sandbox || d.DefaultEnabled {
		t.Errorf("targets %v network %s intrusive %v sandbox %v default %v", d.Targets, d.Network, d.Intrusive, d.Sandbox, d.DefaultEnabled)
	}
	if len(d.ScanTypes) != 0 {
		t.Errorf("CodeGraph discovery is not a kind of check: scan types %v", d.ScanTypes)
	}
	if !strings.Contains(strings.Join(d.Args, " "), "{source} {output}") || d.Output != "file" {
		t.Errorf("args %v output %s", d.Args, d.Output)
	}
	sc, ok := scanners.Lookup(scanners.PathosGraph)
	if !ok || sc.Family != "graph" || !scanners.ManifestRouted(sc.Key) || !scanners.IsGraphTool(sc.Key) || sc.License != d.LicenseSPDX {
		t.Errorf("catalog entry: %+v", sc)
	}
	raw, err := os.ReadFile("../codegraph/testdata/fixture-graph.json")
	if err != nil {
		t.Skip("fixture graph not present: ", err)
	}
	var doc struct {
		Schema string            `json:"schema"`
		Nodes  []json.RawMessage `json:"nodes"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil || doc.Schema != "pathos.codegraph/v1" || len(doc.Nodes) == 0 {
		t.Fatalf("fixture graph: %v %q", err, doc.Schema)
	}
	// Should the API ever parse it as findings, the result is empty.
	if fs, _ := scanners.ParseToolOutput(d.Key(), d.ToolParser(), raw); len(fs) != 0 {
		t.Errorf("a graph document produced %d findings", len(fs))
	}
}
