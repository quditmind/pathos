package worker

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"pathos/internal/scanners"
)

type endpointFixture struct {
	tlsSrv, httpSrv *httptest.Server
	checker         *endpointChecker
}

// newFixture starts an HTTPS and an HTTP server on 127.0.0.1 and a checker
// that connects to them directly.
func newFixture(t *testing.T, tlsCfg *tls.Config, secure bool) *endpointFixture {
	t.Helper()
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if secure {
			w.Header().Set("Strict-Transport-Security", "max-age=63072000; includeSubDomains")
			w.Header().Set("Content-Security-Policy", "default-src 'self'; frame-ancestors 'none'")
			w.Header().Set("X-Content-Type-Options", "nosniff")
			w.Header().Set("Referrer-Policy", "no-referrer")
		}
		_, _ = w.Write([]byte("<html>ok</html>"))
	})
	ts := httptest.NewUnstartedServer(h)
	if tlsCfg != nil {
		ts.TLS = tlsCfg
	}
	// Probes for legacy protocols fail on purpose; keep the log quiet.
	ts.Config.ErrorLog = log.New(io.Discard, "", 0)
	ts.StartTLS()
	t.Cleanup(ts.Close)
	hs := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if secure {
			http.Redirect(w, r, "https://"+r.Host+r.URL.Path, http.StatusMovedPermanently)
			return
		}
		_, _ = w.Write([]byte("plain"))
	}))
	t.Cleanup(hs.Close)
	_, tlsPort, _ := net.SplitHostPort(strings.TrimPrefix(ts.URL, "https://"))
	_, httpPort, _ := net.SplitHostPort(strings.TrimPrefix(hs.URL, "http://"))
	roots := x509.NewCertPool()
	roots.AddCert(ts.Certificate())
	d := &net.Dialer{Timeout: 5 * time.Second}
	c := &endpointChecker{
		tunnel:    func(ctx context.Context, addr string) (net.Conn, error) { return d.DialContext(ctx, "tcp", addr) },
		roots:     roots,
		now:       time.Now,
		pace:      newPacer(20),
		httpsPort: tlsPort, httpPort: httpPort, timeout: 5 * time.Second,
	}
	return &endpointFixture{tlsSrv: ts, httpSrv: hs, checker: c}
}

func issueIDs(r scanners.EndpointResult) map[string]bool {
	out := map[string]bool{}
	for _, is := range r.Issues {
		out[is.ID] = true
	}
	return out
}

func TestEndpointCheckSecureServer(t *testing.T) {
	f := newFixture(t, nil, true)
	r := f.checker.check(context.Background(), JobEndpoint{Kind: "ip", Value: "127.0.0.1", Authorized: true})
	if r.Status != "verified" {
		t.Fatalf("status %s (%s): %+v", r.Status, r.Detail, r.Checks)
	}
	if len(r.Issues) != 0 {
		t.Fatalf("unexpected issues: %+v", r.Issues)
	}
	tl := r.Checks["tls"].(map[string]any)
	cert := tl["certificate"].(map[string]any)
	if cert["trusted"] != true || cert["hostname_match"] != true || tl["protocol"] != "TLS 1.3" {
		t.Errorf("tls: %+v", tl)
	}
	if len(tl["legacy_protocols"].([]string)) != 0 {
		t.Errorf("legacy protocols reported for a TLS 1.2+ server: %v", tl["legacy_protocols"])
	}
	if hp := r.Checks["http"].(map[string]any); hp["status"] != http.StatusMovedPermanently {
		t.Errorf("http: %+v", hp)
	}
}

func TestEndpointCheckWeakServer(t *testing.T) {
	cfg := &tls.Config{MinVersion: tls.VersionTLS10, CipherSuites: []uint16{ // #nosec G402 -- test server with legacy settings
		tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA, tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256, tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256}}
	f := newFixture(t, cfg, false)
	f.checker.roots = nil // system roots: the test certificate is not trusted
	r := f.checker.check(context.Background(), JobEndpoint{Kind: "ip", Value: "127.0.0.1", Authorized: true})
	if r.Status != "verified" {
		t.Fatalf("status %s (%s)", r.Status, r.Detail)
	}
	ids := issueIDs(r)
	for _, want := range []string{"tls-certificate-untrusted", "hsts-missing", "header-missing-csp", "header-missing-x-content-type-options",
		"header-missing-frame-options", "header-missing-referrer-policy", "http-no-redirect", "tls-weak-protocol", "tls-weak-cipher"} {
		if !ids[want] {
			t.Errorf("missing issue %s (got %v)", want, ids)
		}
	}
	tl := r.Checks["tls"].(map[string]any)
	if lp := tl["legacy_protocols"].([]string); len(lp) != 2 {
		t.Errorf("legacy protocols: %v", lp)
	}
	for _, is := range r.Issues {
		if is.Location == "" || is.Severity == "" || is.Title == "" {
			t.Errorf("incomplete issue %+v", is)
		}
	}
}

func TestEndpointCheckCertificateDates(t *testing.T) {
	f := newFixture(t, nil, true)
	leaf := f.tlsSrv.Certificate()
	f.checker.now = func() time.Time { return leaf.NotAfter.Add(24 * time.Hour) }
	ids := issueIDs(f.checker.check(context.Background(), JobEndpoint{Kind: "ip", Value: "127.0.0.1", Authorized: true}))
	if !ids["tls-certificate-expired"] || ids["tls-certificate-untrusted"] {
		t.Errorf("expired: %v", ids)
	}
	f.checker.now = func() time.Time { return leaf.NotAfter.Add(-10 * 24 * time.Hour) }
	ids = issueIDs(f.checker.check(context.Background(), JobEndpoint{Kind: "ip", Value: "127.0.0.1", Authorized: true}))
	if !ids["tls-certificate-expiring"] || ids["tls-certificate-expired"] {
		t.Errorf("expiring: %v", ids)
	}
}

func TestEndpointCheckHostnameMismatch(t *testing.T) {
	f := newFixture(t, nil, true)
	// A domain endpoint whose certificate does not cover it (the test
	// certificate is for example.com and 127.0.0.1).
	_, port, _ := net.SplitHostPort(strings.TrimPrefix(f.tlsSrv.URL, "https://"))
	info, issues, err := f.checker.checkTLS(context.Background(), "api.acme.test", "127.0.0.1:"+port)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, is := range issues {
		found = found || is.ID == "tls-hostname-mismatch"
	}
	if !found || info["certificate"].(map[string]any)["hostname_match"] != false {
		t.Errorf("mismatch not reported: %+v", issues)
	}
}

func TestEndpointCheckScope(t *testing.T) {
	c := &endpointChecker{httpsPort: "443", httpPort: "80"}
	r := c.check(context.Background(), JobEndpoint{Kind: "domain", Value: "api.acme.test"})
	if r.Status != "skipped" || !strings.Contains(r.Detail, "authorization") {
		t.Errorf("unauthorized endpoint checked: %+v", r)
	}
	r = c.check(context.Background(), JobEndpoint{Kind: "domain", Value: "*.acme.test", Authorized: true})
	if r.Status != "skipped" || !strings.Contains(r.Detail, "wildcard") {
		t.Errorf("wildcard: %+v", r)
	}
	tg, err := c.targetOf(JobEndpoint{Kind: "url", Value: "https://shop.acme.test/app?x=1"})
	if err != nil || tg.https != "https://shop.acme.test/app?x=1" || tg.http != "http://shop.acme.test/app?x=1" || tg.tls != "shop.acme.test:443" {
		t.Errorf("url target: %+v %v", tg, err)
	}
	tg, _ = c.targetOf(JobEndpoint{Kind: "url", Value: "https://shop.acme.test:8443/"})
	if tg.http != "" || tg.tls != "shop.acme.test:8443" {
		t.Errorf("custom port: %+v", tg)
	}
	tg, _ = c.targetOf(JobEndpoint{Kind: "ip", Value: "2001:db8::1"})
	if tg.https != "https://[2001:db8::1]/" || tg.tls != "[2001:db8::1]:443" {
		t.Errorf("ipv6: %+v", tg)
	}
}

// proxyServer answers CONNECT like Squid: denied or DNS failures.
func proxyServer(t *testing.T, squidErr string) *url.URL {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				req, err := http.ReadRequest(bufio.NewReader(c))
				if err != nil {
					return
				}
				status := "403 Forbidden"
				if strings.HasPrefix(squidErr, "ERR_DNS") {
					status = "503 Service Unavailable"
				}
				_, _ = c.Write([]byte("HTTP/1.1 " + status + "\r\nX-Squid-Error: " + squidErr + "\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"))
				_ = req
			}(conn)
		}
	}()
	return &url.URL{Scheme: "http", Host: ln.Addr().String()}
}

func TestEndpointCheckThroughProxy(t *testing.T) {
	for squid, want := range map[string]string{"ERR_ACCESS_DENIED 0": "blocked", "ERR_DNS_FAIL 0": "dns_failed"} {
		pu := proxyServer(t, squid)
		d := &net.Dialer{Timeout: 5 * time.Second}
		c := &endpointChecker{
			tunnel:    func(ctx context.Context, addr string) (net.Conn, error) { return connectTunnel(ctx, d, pu, addr) },
			proxy:     http.ProxyURL(pu),
			now:       time.Now,
			pace:      newPacer(20),
			httpsPort: "443", httpPort: "80", timeout: 5 * time.Second,
		}
		r := c.check(context.Background(), JobEndpoint{Kind: "domain", Value: "shop.acme.test", Authorized: true})
		if r.Status != want {
			t.Errorf("%s: status %s (%s)", squid, r.Status, r.Detail)
		}
		if len(r.Issues) != 0 {
			t.Errorf("%s: issues for an unreachable endpoint: %+v", squid, r.Issues)
		}
	}
}

func TestVerifyEndpointsReportParses(t *testing.T) {
	f := newFixture(t, nil, false)
	out := filepath.Join(t.TempDir(), "report.json")
	eps := []JobEndpoint{{Kind: "ip", Value: "127.0.0.1", Authorized: true}, {Kind: "domain", Value: "other.acme.test"}}
	if err := verifyEndpoints(context.Background(), f.checker, eps, out); err != nil {
		t.Fatal(err)
	}
	raw, _ := os.ReadFile(out)
	fs, err := scanners.Parse(scanners.EndpointCheck, raw)
	if err != nil || len(fs) == 0 {
		t.Fatalf("%v %d", err, len(fs))
	}
	var rep scanners.EndpointReport
	_ = json.Unmarshal(raw, &rep)
	if len(rep.Endpoints) != 2 || rep.Endpoints[1].Status != "skipped" {
		t.Errorf("report: %+v", rep.Endpoints)
	}
	for _, f := range fs {
		if f.Category != "dast" || f.ScannerKey != scanners.EndpointCheck || f.Fingerprint == "" || !strings.HasPrefix(f.RuleID, "endpoint/") {
			t.Errorf("finding %+v", f)
		}
	}
	// The Nuclei URL list holds authorized endpoints only.
	list := filepath.Join(t.TempDir(), "list.txt")
	if err := endpointList(eps, list); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(list)
	if string(b) != "https://127.0.0.1/\n" {
		t.Errorf("list: %q", b)
	}
	if err := endpointList(eps[1:], list); err == nil {
		t.Error("no authorized endpoint accepted")
	}
}

func TestHSTSMaxAge(t *testing.T) {
	for v, want := range map[string]int{"max-age=31536000; includeSubDomains": 31536000, `max-age="600"`: 600, "includeSubDomains": 0} {
		if got := hstsMaxAge(v); got != want {
			t.Errorf("%s: %d", v, got)
		}
	}
}

func TestNucleiArgsEndpoints(t *testing.T) {
	args := strings.Join(nucleiArgs(&JobTarget{Kind: "endpoints", RateLimit: 2}, "out.jsonl", "/work/list.txt"), " ")
	for _, want := range []string{"-l /work/list.txt", "http/exposures", "http/exposed-panels", "http/takeovers", "-etags dos,intrusive,bruteforce,fuzz", "-rl 2"} {
		if !strings.Contains(args, want) {
			t.Errorf("missing %q in %s", want, args)
		}
	}
	if strings.Contains(args, "/dast") {
		t.Error("DAST templates for endpoints")
	}
}
