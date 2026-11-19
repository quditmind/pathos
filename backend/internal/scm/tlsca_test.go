package scm

import (
	"context"
	"crypto/tls"
	"encoding/pem"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// privateCAServer is an httptest TLS server: its certificate is signed by
// httptest's own CA, which is not in any system trust store (a private CA).
func privateCAServer(t *testing.T, h http.HandlerFunc) (*httptest.Server, string) {
	t.Helper()
	srv := httptest.NewTLSServer(h)
	t.Cleanup(srv.Close)
	caPEM := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw}))
	return srv, caPEM
}

// loopback lets a NetPolicy client reach the httptest server (the policy
// always blocks 127.0.0.0/8); only the dialer is replaced, the TLS
// configuration built by ClientWithCA is what is under test.
func loopback(c *http.Client) *http.Client {
	tr := c.Transport.(*http.Transport)
	tr.DialContext = (&net.Dialer{Timeout: 5 * time.Second}).DialContext
	tr.Proxy = nil
	return c
}

func TestParseCABundle(t *testing.T) {
	_, caPEM := privateCAServer(t, func(http.ResponseWriter, *http.Request) {})
	certs, infos, err := ParseCABundle(caPEM+"\n"+caPEM, time.Now())
	if err != nil || len(certs) != 2 || len(infos) != 2 {
		t.Fatalf("parse: %v %d", err, len(certs))
	}
	if !strings.HasPrefix(infos[0].SHA256Fingerprint, "") || len(infos[0].SHA256Fingerprint) != 64 {
		t.Fatalf("fingerprint %q", infos[0].SHA256Fingerprint)
	}
	if c, i, err := ParseCABundle("  ", time.Now()); c != nil || i != nil || err != nil {
		t.Fatal("empty bundle must be nil, nil, nil")
	}
	bad := []string{
		"not pem",
		"-----BEGIN PRIVATE KEY-----\nMIIB\n-----END PRIVATE KEY-----\n",
		caPEM + "trailing garbage",
		"-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n",
		strings.Repeat(caPEM, MaxCABundleCerts+1),
	}
	for i, b := range bad {
		if _, _, err := ParseCABundle(b, time.Now()); err == nil {
			t.Errorf("bad bundle %d accepted", i)
		}
	}
	if _, _, err := ParseCABundle(bad[1], time.Now()); err == nil || !strings.Contains(err.Error(), "private key") {
		t.Errorf("a private key must be refused explicitly: %v", err)
	}
}

// A server behind a private CA: without the bundle the request fails with
// an untrusted certificate; with it, it succeeds. Verification is never
// disabled and TLS 1.2 is the minimum.
func TestClientWithCA(t *testing.T) {
	srv, caPEM := privateCAServer(t, func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("ok")) })
	get := func(c *http.Client) error {
		req, _ := http.NewRequestWithContext(context.Background(), "GET", srv.URL, nil)
		resp, err := c.Do(req)
		if err == nil {
			resp.Body.Close()
		}
		return err
	}
	plain := loopback(NetPolicy{}.Client())
	if err := get(plain); err == nil || !strings.Contains(err.Error(), "certificate") {
		t.Fatalf("a private CA must not be trusted by default: %v", err)
	}
	c, err := NetPolicy{}.ClientWithCA(caPEM)
	if err != nil {
		t.Fatal(err)
	}
	tr := c.Transport.(*http.Transport)
	if tr.TLSClientConfig.InsecureSkipVerify || tr.TLSClientConfig.MinVersion < tls.VersionTLS12 || tr.TLSClientConfig.RootCAs == nil {
		t.Fatalf("TLS configuration: %+v", tr.TLSClientConfig)
	}
	if err := get(loopback(c)); err != nil {
		t.Fatalf("with the CA bundle: %v", err)
	}
	if _, err := (NetPolicy{}).ClientWithCA("-----BEGIN PRIVATE KEY-----\nMIIB\n-----END PRIVATE KEY-----\n"); !errors.Is(err, ErrCABundle) {
		t.Errorf("private key bundle: %v", err)
	}
	// The policy still applies with a bundle (loopback is always blocked).
	c2, _ := NetPolicy{}.ClientWithCA(caPEM)
	if err := get(c2); !errors.Is(err, ErrBlockedAddress) {
		t.Errorf("blocked address with a CA client: %v", err)
	}
}
