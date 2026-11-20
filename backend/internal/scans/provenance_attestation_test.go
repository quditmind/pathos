package scans

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
)

func bundleOf(t *testing.T, statement string) string {
	t.Helper()
	b, err := json.Marshal(map[string]any{"mediaType": "application/vnd.dev.sigstore.bundle.v0.3+json",
		"dsseEnvelope": map[string]any{"payloadType": "application/vnd.in-toto+json", "payload": base64.StdEncoding.EncodeToString([]byte(statement))}})
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func TestParseProvenance(t *testing.T) {
	const sha = "4e1f0a6b2c3d4e5f60718293a4b5c6d7e8f90123456789abcdef0123456789ab"
	v1 := `{"_type":"https://in-toto.io/Statement/v1","subject":[{"name":"server","digest":{"sha256":"` + strings.ToUpper(sha) + `"}}],
		"predicateType":"https://slsa.dev/provenance/v1","predicate":{"buildDefinition":{"externalParameters":{"workflow":{"repository":"https://git.example.test/acme/svc"}},
		"resolvedDependencies":[{"uri":"git+https://git.example.test/acme/svc@refs/heads/main","digest":{"gitCommit":"0123456789abcdef0123456789abcdef01234567"}}]},
		"runDetails":{"builder":{"id":"https://ci.example.test/builder"}}}}`
	p, err := ParseProvenance(bundleOf(t, v1))
	if err != nil {
		t.Fatal(err)
	}
	if p.Commit != "0123456789abcdef0123456789abcdef01234567" || p.Builder != "https://ci.example.test/builder" || !p.HasSubject(sha) || p.HasSubject("00") {
		t.Errorf("v1: %+v", p)
	}
	v02 := `{"_type":"https://in-toto.io/Statement/v0.1","subject":[{"name":"x","digest":{"sha256":"` + sha + `"}}],"predicateType":"https://slsa.dev/provenance/v0.2",
		"predicate":{"builder":{"id":"b"},"invocation":{"configSource":{"uri":"git+https://git.example.test/a","digest":{"sha1":"89abcdef0123456789abcdef0123456789abcdef"}}}}}`
	if p, err := ParseProvenance(bundleOf(t, v02)); err != nil || p.Commit != "89abcdef0123456789abcdef0123456789abcdef" {
		t.Errorf("v0.2: %+v %v", p, err)
	}
	for _, bad := range []string{"not json", `{"mediaType":"x"}`, bundleOf(t, `{"_type":"x"}`),
		bundleOf(t, `{"_type":"https://in-toto.io/Statement/v1","predicateType":"https://spdx.dev/Document","subject":[{"name":"x","digest":{"sha256":"`+sha+`"}}]}`),
		bundleOf(t, `{"_type":"https://in-toto.io/Statement/v1","predicateType":"https://slsa.dev/provenance/v1"}`)} {
		if _, err := ParseProvenance(bad); err == nil {
			t.Errorf("accepted %q", bad)
		}
	}
	if ValidProvenanceMaterial("") != nil || ValidProvenanceMaterial(strings.Repeat("x", maxProvenanceMaterial+1)) == nil {
		t.Error("ValidProvenanceMaterial limits")
	}
}
