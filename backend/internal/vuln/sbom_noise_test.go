package vuln

import "testing"

// O12: workflow files are not components; GitHub Actions are not libraries.
func TestSBOMNoise(t *testing.T) {
	raw := []byte(`{"bomFormat":"CycloneDX","components":[
		{"bom-ref":"a","type":"library","name":"lodash","version":"4.17.21","purl":"pkg:npm/lodash@4.17.21"},
		{"bom-ref":"b","type":"library","name":"$/.github/workflows/ci.yml","version":"UNKNOWN"},
		{"bom-ref":"c","type":"library","name":"./.github/workflows/reuse.yml","version":""},
		{"bom-ref":"d","type":"library","name":"actions/checkout","version":"v4","purl":"pkg:github/actions/checkout@v4"},
		{"bom-ref":"e","type":"library","name":"tools/pkg","version":"1.0.0","purl":"pkg:golang/tools/pkg@1.0.0"}]}`)
	comps, err := ParseCycloneDX(raw)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]string{}
	for _, c := range comps {
		got[c.Name] = c.Type
	}
	if len(comps) != 3 || got["lodash"] != "library" || got["actions/checkout"] != "github-action" || got["tools/pkg"] != "library" {
		t.Errorf("components: %v", got)
	}
	if !pathLikeComponent("/abs/path.yml", "") || pathLikeComponent("$/x", "1.2.3") {
		t.Error("pathLikeComponent")
	}
}
