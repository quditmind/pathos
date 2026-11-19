package scm

import (
	"context"
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

// A GitHub Enterprise Server behind a private CA: without the bundle the
// connection fails with an untrusted certificate (PTH-CONN-1004); with it,
// the check succeeds and requests go to /api/v3.
func TestPrivateCAGitHubEnterprise(t *testing.T) {
	var paths []string
	srv, caPEM := privateCAServer(t, func(w http.ResponseWriter, r *http.Request) {
		paths = append(paths, r.URL.Path)
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/api/v3/user":
			_, _ = w.Write([]byte(`{"login":"octo"}`))
		case "/api/v3/meta":
			_, _ = w.Write([]byte(`{"installed_version":"3.17.4"}`))
		default:
			w.WriteHeader(404)
		}
	})
	base := NormalizeBaseURL(GitHubEnterprise, srv.URL)
	if !strings.HasSuffix(base, "/api/v3") {
		t.Fatalf("GHES base %q", base)
	}
	ctx := context.Background()

	plain := loopback(NetPolicy{}.Client())
	c, err := New(Config{Provider: GitHubEnterprise, BaseURL: base, AuthType: AuthPAT, Secret: []byte("t"), HTTP: plain})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.Check(ctx); DiagCode(err) != "PTH-CONN-1004" {
		t.Fatalf("without CA: want PTH-CONN-1004, got %q (%v)", DiagCode(err), err)
	}

	withCA, err := NetPolicy{}.ClientWithCA(caPEM)
	if err != nil {
		t.Fatal(err)
	}
	c, _ = New(Config{Provider: GitHubEnterprise, BaseURL: base, AuthType: AuthPAT, Secret: []byte("t"), HTTP: loopback(withCA)})
	msg, err := c.Check(ctx)
	if err != nil || !strings.Contains(msg, "octo") {
		t.Fatalf("with CA: %q %v", msg, err)
	}
	vi, err := c.(VersionChecker).ServerVersion(ctx)
	if !errors.Is(err, ErrVersionUnsupported) || vi.Supported || DiagCode(err) != "PTH-CONN-1105" {
		t.Fatalf("3.17 must be out of support: %+v %v %s", vi, err, DiagCode(err))
	}
	if paths[0] != "/api/v3/user" {
		t.Fatalf("paths %v", paths)
	}
	// The CA is added to, not substituted for, the system pool, and TLS 1.2
	// is the floor.
	tr := withCA.Transport.(*http.Transport)
	if tr.TLSClientConfig == nil || tr.TLSClientConfig.InsecureSkipVerify || tr.TLSClientConfig.MinVersion == 0 {
		t.Fatal("TLS config must verify with a minimum version")
	}
}

// GitLab self-managed behind a private CA, base URL entered with /api/v4.
func TestPrivateCAGitLabSelfManaged(t *testing.T) {
	srv, caPEM := privateCAServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/api/v4/user":
			_, _ = w.Write([]byte(`{"username":"root","name":"Admin"}`))
		case "/api/v4/version":
			_, _ = w.Write([]byte(`{"version":"18.5.1-ee","revision":"abc"}`))
		default:
			w.WriteHeader(404)
		}
	})
	base := NormalizeBaseURL(GitLab, srv.URL+"/api/v4/")
	if base != srv.URL {
		t.Fatalf("GitLab base %q", base)
	}
	hc, err := NetPolicy{}.ClientWithCA(caPEM)
	if err != nil {
		t.Fatal(err)
	}
	c, _ := New(Config{Provider: GitLab, BaseURL: base, AuthType: AuthPAT, Secret: []byte("t"), HTTP: loopback(hc)})
	if _, err := c.Check(context.Background()); err != nil {
		t.Fatal(err)
	}
	vi, err := c.(VersionChecker).ServerVersion(context.Background())
	if err != nil || vi.Version != "18.5.1-ee" {
		t.Fatalf("%+v %v", vi, err)
	}
}

func TestNormalizeBaseURL(t *testing.T) {
	cases := []struct{ p, in, want string }{
		{GitHubEnterprise, "https://ghe.example.com", "https://ghe.example.com/api/v3"},
		{GitHubEnterprise, "https://ghe.example.com/", "https://ghe.example.com/api/v3"},
		{GitHubEnterprise, "https://ghe.example.com/api/v3/", "https://ghe.example.com/api/v3"},
		{GitLab, "https://gitlab.example.com/api/v4", "https://gitlab.example.com"},
		{GitLab, "https://example.com/gitlab", "https://example.com/gitlab"},
		{BitbucketDataCenter, "https://bb.example.com/bitbucket/rest/api/1.0", "https://bb.example.com/bitbucket"},
		{BitbucketDataCenter, "https://bb.example.com/", "https://bb.example.com"},
		{BitbucketDataCenter, "https://bb.example.com/restricted", "https://bb.example.com/restricted"},
		{GitHub, "https://api.github.com/", "https://api.github.com"},
	}
	for _, c := range cases {
		if got := NormalizeBaseURL(c.p, c.in); got != c.want {
			t.Errorf("%s %s: got %s want %s", c.p, c.in, got, c.want)
		}
	}
}

func TestVersionJudge(t *testing.T) {
	now := time.Date(2026, 11, 20, 0, 0, 0, 0, time.UTC)
	if v := judge("GHES", "3.19.2", ghesReleases, now); !v.Supported || v.Minimum != "3.19" {
		t.Errorf("3.19 on 2026-11-20: %+v", v)
	}
	if v := judge("GHES", "3.19.2", ghesReleases, now.AddDate(0, 1, 0)); v.Supported || v.Minimum != "3.20" {
		t.Errorf("3.19 after its end of support: %+v", v)
	}
	if v := judge("BBDC", "10.1.0", bbdcReleases, now); !v.Supported {
		t.Errorf("10.1: %+v", v)
	}
	if v := judge("BBDC", "8.19.5", bbdcReleases, now); v.Supported {
		t.Errorf("8.19: %+v", v)
	}
}

func TestConnectorCatalogCAField(t *testing.T) {
	has := func(ps []ProviderInfo, provider string) bool {
		for _, p := range ps {
			if p.Key != provider {
				continue
			}
			for _, m := range p.AuthMethods {
				for _, f := range m.Fields {
					if f.Name == "ca_bundle_pem" {
						return true
					}
				}
			}
		}
		return false
	}
	if has(Providers(), GitHubEnterprise) || has(Providers(), GitLab) {
		t.Fatal("the classic catalogue must not offer the CA field")
	}
	c := ConnectorCatalog()
	if !has(c, GitHubEnterprise) || !has(c, GitLab) || !has(c, BitbucketDataCenter) || has(c, GitHub) {
		t.Fatal("the connectors catalogue offers the CA field on self-hosted providers only")
	}
	if has(Providers(), GitHubEnterprise) {
		t.Fatal("ConnectorCatalog must not modify the shared catalogue")
	}
}
