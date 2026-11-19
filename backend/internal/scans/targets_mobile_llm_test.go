package scans

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"testing"
)

func TestLLMEndpointTargetFields(t *testing.T) {
	name, ref := "Support bot", "https://llm.example.com/v1/chat/completions"
	hdr, hname := "header", "Authorization"
	f := targetFields{kind: "llm-endpoint"}
	if err := f.apply(targetRequest{Name: &name, Reference: &ref}); err == nil {
		t.Error("an LLM endpoint needs a model name")
	}
	cfg := TargetConfig{Model: "gpt-4o-mini", Tools: []string{"garak", "promptfoo"}}
	f = targetFields{kind: "llm-endpoint"}
	if err := f.apply(targetRequest{Name: &name, Reference: &ref, Config: &cfg, AuthType: &hdr, AuthHeaderName: &hname}); err != nil ||
		f.egress != "llm.example.com" || f.authHeader != "Authorization" || f.config.Model != "gpt-4o-mini" {
		t.Fatalf("%v %+v", err, f)
	}
	for _, bad := range []string{"model name with spaces", "x\ny"} {
		c := TargetConfig{Model: bad}
		if err := (&targetFields{kind: "llm-endpoint", name: "x", reference: ref}).apply(targetRequest{Config: &c}); err == nil {
			t.Errorf("model %q accepted", bad)
		}
	}
	userinfo := "https://user:pw@llm.example.com/v1"
	if err := (&targetFields{kind: "llm-endpoint", name: "x", config: cfg}).apply(targetRequest{Reference: &userinfo}); err == nil {
		t.Error("credentials in the URL must be rejected")
	}
	// A model name only applies to LLM endpoints.
	if err := (&targetFields{kind: "url", name: "x", reference: "https://x.example"}).apply(targetRequest{Config: &cfg}); err == nil {
		t.Error("model on a url target")
	}
	if !liveKind("llm-endpoint") || !liveKind("url") || liveKind("mobile-app") || !uploadedKind("mobile-app") || !artifactKind("mobile-app") ||
		uploadedKind("llm-endpoint") {
		t.Error("kind helpers")
	}
}

func TestMobileAppTargetFields(t *testing.T) {
	name, ref := "app", "app.apk (0123456789ab)"
	f := targetFields{kind: "mobile-app"}
	if err := f.apply(targetRequest{Name: &name, Reference: &ref}); err != nil || f.egress != "" || f.authType != "none" {
		t.Fatalf("%v %+v", err, f)
	}
	basic, user := "basic", "u"
	if err := (&targetFields{kind: "mobile-app", name: "x"}).apply(targetRequest{AuthType: &basic, AuthUsername: &user}); err == nil {
		t.Error("uploaded targets have no authentication")
	}
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	der, _ := x509.MarshalPKIXPublicKey(&k.PublicKey)
	pub := string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))
	sig := TargetConfig{Signature: &SignatureConfig{Mode: "key", PublicKey: pub}}
	if err := (&targetFields{kind: "mobile-app", name: "x"}).apply(targetRequest{Config: &sig}); err != nil {
		t.Errorf("signature verification of a mobile app: %v", err)
	}
	for name, want := range map[string]bool{"app.apk": true, "App.IPA": true, "bundle.aab": true, "lib.jar": false, "app.zip": false, "apk": false} {
		if MobilePackage(name) != want {
			t.Errorf("MobilePackage(%q)", name)
		}
	}
	h := &headWriter{}
	_, _ = h.Write([]byte("P"))
	_, _ = h.Write([]byte("K\x03\x04 rest"))
	if !bytes.Equal(h.b, []byte("PK\x03\x04")) {
		t.Errorf("head %q", h.b)
	}
}

func TestToolScansNewKinds(t *testing.T) {
	for _, c := range []struct {
		targets []string
		kind    string
		want    bool
	}{
		{[]string{"llm-endpoint"}, "llm-endpoint", true},
		{[]string{"llm-endpoint"}, "url", false},
		{[]string{"url"}, "llm-endpoint", false},
		{[]string{"mobile-app"}, "mobile-app", true},
		{[]string{"mobile-app"}, "artifact", true},
		{[]string{"binary"}, "mobile-app", false},
		{[]string{"model"}, "mobile-app", false},
	} {
		if got := toolScansKind(c.targets, c.kind); got != c.want {
			t.Errorf("%v on %s: %v", c.targets, c.kind, got)
		}
	}
}
