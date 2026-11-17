package vuln

import "testing"

func TestParseSPDX(t *testing.T) {
	doc := []byte(`{"spdxVersion":"SPDX-2.3","packages":[
		{"name":"lodash","versionInfo":"4.17.20","licenseConcluded":"MIT","externalRefs":[{"referenceType":"purl","referenceLocator":"pkg:npm/lodash@4.17.20"}]},
		{"name":"lodash","versionInfo":"4.17.20","externalRefs":[{"referenceType":"purl","referenceLocator":"pkg:npm/lodash@4.17.20"}]},
		{"name":"readme","primaryPackagePurpose":"FILE"},
		{"name":"openssl","versionInfo":"3.0.1","licenseDeclared":"Apache-2.0","licenseConcluded":"NOASSERTION"}]}`)
	f, c, err := ParseSBOM(doc)
	if err != nil || f != "spdx" || len(c) != 2 || c[0].PURL != "pkg:npm/lodash@4.17.20" || c[0].Licenses[0] != "MIT" || c[1].Licenses[0] != "Apache-2.0" {
		t.Fatalf("%s %v %+v", f, err, c)
	}
	if f, _, _ := ParseSBOM([]byte(`{"bomFormat":"CycloneDX","components":[]}`)); f != "cyclonedx" {
		t.Error("cyclonedx detection")
	}
	if _, _, err := ParseSBOM([]byte(`{"spdxVersion":"SPDX-3.0"}`)); err == nil {
		t.Error("unsupported versions are rejected")
	}
}
