package runtimectx

import (
	"context"
	"encoding/pem"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"pathos/internal/scm"
)

// A registry behind a private CA (VALIDATION_REPORT O3: registry:2 with a
// self-signed certificate failed with "x509: certificate signed by unknown
// authority").
func TestRegistryPrivateCA(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"name":"team/app","tags":["1.0"]}`))
	}))
	defer srv.Close()
	caPEM := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw}))
	s := &Service{}
	loop := func(c *http.Client) *http.Client {
		tr := c.Transport.(*http.Transport)
		tr.DialContext = (&net.Dialer{Timeout: 5 * time.Second}).DialContext
		tr.Proxy = nil
		return c
	}
	base, _ := url.Parse(srv.URL)
	rc := &RegistryClient{Base: base, HTTP: loop(s.client(false, nil)), Auth: "none"}
	if _, _, err := rc.Tags(context.Background(), "team/app", 10); err == nil || !strings.Contains(scm.WithCAHint(err).Error(), "PTH-CONN-1702") {
		t.Fatalf("untrusted private CA: %v", err)
	}
	cfg, err := registryTLS(caPEM)
	if err != nil || cfg == nil || cfg.InsecureSkipVerify || cfg.MinVersion < 0x0303 {
		t.Fatalf("TLS configuration: %+v %v", cfg, err)
	}
	rc.HTTP = loop(s.client(false, cfg))
	tags, _, err := rc.Tags(context.Background(), "team/app", 10)
	if err != nil || len(tags) != 1 {
		t.Fatalf("with the CA bundle: %v %v", tags, err)
	}
	if cfg, err := registryTLS(""); cfg != nil || err != nil {
		t.Errorf("no bundle: %v %v", cfg, err)
	}
	if _, err := registryTLS("-----BEGIN RSA PRIVATE KEY-----\nAA==\n-----END RSA PRIVATE KEY-----\n"); err == nil {
		t.Error("a private key is not a CA bundle")
	}
}
