package scans

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"slices"
	"testing"
)

func TestValidSignatureConfig(t *testing.T) {
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	der, _ := x509.MarshalPKIXPublicKey(&k.PublicKey)
	pub := string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))
	ok := []*SignatureConfig{
		nil,
		{Mode: ""},
		{Mode: "key", PublicKey: pub, Require: true},
		{Mode: "keyless", Identity: "release@acme.example", Issuer: "https://accounts.google.com"},
		{Mode: "keyless", IdentityRegexp: "^https://github.com/acme/", Issuer: "https://token.actions.githubusercontent.com", Attestation: "slsaprovenance"},
	}
	for i, c := range ok {
		if err := validSignatureConfig(c); err != nil {
			t.Errorf("%d: %v", i, err)
		}
	}
	bad := []*SignatureConfig{
		{Mode: "pgp"},
		{Mode: "key", PublicKey: "not a key"},
		{Mode: "key", PublicKey: "-----BEGIN PUBLIC KEY-----\nAAAA\n-----END PUBLIC KEY-----\n"},
		{Mode: "keyless", Identity: "x"},
		{Mode: "keyless", Identity: "x", Issuer: "http://insecure.example"},
		{Mode: "keyless", Identity: "x", IdentityRegexp: "y", Issuer: "https://accounts.google.com"},
		{Mode: "keyless", IdentityRegexp: "(", Issuer: "https://accounts.google.com"},
		{Mode: "keyless", Identity: "x\ny", Issuer: "https://accounts.google.com"},
		{Mode: "key", PublicKey: pub, Attestation: "anything"},
	}
	for i, c := range bad {
		if err := validSignatureConfig(c); err == nil {
			t.Errorf("%d accepted: %+v", i, c)
		}
	}
	// Mode-specific fields are cleared.
	c := &SignatureConfig{Mode: "key", PublicKey: pub, Identity: "x", Issuer: "https://a.example"}
	if err := validSignatureConfig(c); err != nil || c.Identity != "" || c.Issuer != "" {
		t.Errorf("%v %+v", err, c)
	}
}

func TestValidSignatureMaterial(t *testing.T) {
	for _, v := range []string{"", "MEUCIQDx", `{"mediaType":"application/vnd.dev.sigstore.bundle.v0.3+json"}`} {
		if err := validSignatureMaterial(v); err != nil {
			t.Errorf("%q: %v", v, err)
		}
	}
	for _, v := range []string{"not base64 !!", `{"broken"`} {
		if err := validSignatureMaterial(v); err == nil {
			t.Errorf("%q accepted", v)
		}
	}
}

func TestTargetScannerKeys(t *testing.T) {
	if got := targetScannerKeys("image", TargetConfig{}); !slices.Equal(got, []string{"trivy-image"}) {
		t.Errorf("image: %v", got)
	}
	if got := targetScannerKeys("image", TargetConfig{Signature: &SignatureConfig{Mode: "key"}}); !slices.Equal(got, []string{"trivy-image", "cosign"}) {
		t.Errorf("signed image: %v", got)
	}
	if got := targetScannerKeys("endpoints", TargetConfig{}); !slices.Equal(got, []string{"pathos-endpoints"}) {
		t.Errorf("endpoints: %v", got)
	}
	if got := targetScannerKeys("endpoints", TargetConfig{Nuclei: true}); !slices.Equal(got, []string{"pathos-endpoints", "nuclei"}) {
		t.Errorf("endpoints with nuclei: %v", got)
	}
	if got := targetScannerKeys("url", TargetConfig{}); !slices.Equal(got, []string{"nuclei"}) {
		t.Errorf("url: %v", got)
	}
}
