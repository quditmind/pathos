package worker

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"pathos/internal/scanners"
)

// Verification of a repository's declared public endpoints (opt-in, with a
// recorded authorization statement). Only the declared hosts are contacted,
// at a limited rate and through the egress proxy; nothing intrusive is
// sent: DNS resolution, one HTTPS and one HTTP request per endpoint (plus
// redirects on the same host), and TLS handshakes to observe the
// certificate, the protocol versions and the cipher suites.

// JobEndpoint is a declared endpoint of an endpoints target.
type JobEndpoint struct {
	Kind  string `json:"kind"` // url | domain | ip
	Value string `json:"value"`
	// Authorized: covered by the authorization statement.
	Authorized bool `json:"authorized"`
}

const (
	certExpiryWarnDays = 30
	hstsMinMaxAge      = 15552000 // 180 days
	maxRedirects       = 3
)

// endpointChecker performs the checks. Its network functions are fields so
// that tests can run against local servers.
type endpointChecker struct {
	// tunnel opens a TCP connection to host:port (through the egress proxy
	// with CONNECT when one is configured).
	tunnel func(ctx context.Context, addr string) (net.Conn, error)
	// proxy is the forward proxy for plain HTTP (nil = direct).
	proxy func(*http.Request) (*url.URL, error)
	// lookup resolves a name locally (nil = skip local resolution).
	lookup func(ctx context.Context, host string) ([]string, error)
	roots  *x509.CertPool
	now    func() time.Time
	pace   *pacer
	// httpsPort/httpPort are the ports for domain and IP endpoints.
	httpsPort, httpPort string
	timeout             time.Duration
}

// pacer spaces out new connections (the rate limit).
type pacer struct {
	mu       sync.Mutex
	interval time.Duration
	next     time.Time
}

func newPacer(perSecond int) *pacer {
	if perSecond <= 0 || perSecond > 20 {
		perSecond = 2
	}
	return &pacer{interval: time.Second / time.Duration(perSecond)}
}

func (p *pacer) wait(ctx context.Context) error {
	if p == nil {
		return nil
	}
	p.mu.Lock()
	now := time.Now()
	at := p.next
	if at.Before(now) {
		at = now
	}
	p.next = at.Add(p.interval)
	p.mu.Unlock()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-time.After(time.Until(at)):
		return nil
	}
}

// proxyError is a refusal by the egress proxy.
type proxyError struct {
	status   int
	squidErr string
}

func (e *proxyError) Error() string {
	if e.squidErr != "" {
		return fmt.Sprintf("egress proxy answered %d (%s)", e.status, e.squidErr)
	}
	return fmt.Sprintf("egress proxy answered %d", e.status)
}

func (e *proxyError) outcome() string {
	switch {
	case strings.HasPrefix(e.squidErr, "ERR_DNS_FAIL"):
		return "dns_failed"
	case strings.HasPrefix(e.squidErr, "ERR_ACCESS_DENIED"), e.status == http.StatusForbidden:
		return "blocked"
	}
	return "unreachable"
}

// defaultChecker uses the worker's egress proxy.
func defaultChecker(rate int) *endpointChecker {
	c := &endpointChecker{now: time.Now, pace: newPacer(rate), httpsPort: "443", httpPort: "80", timeout: 15 * time.Second}
	d := &net.Dialer{Timeout: 15 * time.Second}
	if p := proxyURL(); p != "" {
		pu, err := url.Parse(p)
		if err == nil {
			c.tunnel = func(ctx context.Context, addr string) (net.Conn, error) { return connectTunnel(ctx, d, pu, addr) }
			c.proxy = http.ProxyURL(pu)
		}
	}
	if c.tunnel == nil {
		c.tunnel = func(ctx context.Context, addr string) (net.Conn, error) { return d.DialContext(ctx, "tcp", addr) }
	}
	c.lookup = func(ctx context.Context, host string) ([]string, error) {
		ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
		defer cancel()
		return net.DefaultResolver.LookupHost(ctx, host)
	}
	return c
}

// connectTunnel opens an HTTP CONNECT tunnel through the proxy.
func connectTunnel(ctx context.Context, d *net.Dialer, proxy *url.URL, addr string) (net.Conn, error) {
	host := proxy.Host
	if proxy.Port() == "" {
		host = net.JoinHostPort(proxy.Hostname(), "3128")
	}
	conn, err := d.DialContext(ctx, "tcp", host)
	if err != nil {
		return nil, fmt.Errorf("egress proxy unreachable: %w", err)
	}
	if dl, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(dl)
	}
	req := "CONNECT " + addr + " HTTP/1.1\r\nHost: " + addr + "\r\nUser-Agent: PATHOS-endpoint-verification\r\n\r\n"
	if _, err := io.WriteString(conn, req); err != nil {
		_ = conn.Close()
		return nil, err
	}
	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, &http.Request{Method: http.MethodConnect})
	if err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("egress proxy: %w", err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		_ = conn.Close()
		return nil, &proxyError{status: resp.StatusCode, squidErr: resp.Header.Get("X-Squid-Error")}
	}
	_ = conn.SetDeadline(time.Time{})
	if br.Buffered() > 0 {
		return &bufferedConn{Conn: conn, r: br}, nil
	}
	return conn, nil
}

type bufferedConn struct {
	net.Conn
	r *bufio.Reader
}

func (b *bufferedConn) Read(p []byte) (int, error) { return b.r.Read(p) }

// endpointTarget is what is checked for one declared endpoint.
type endpointTarget struct {
	host  string // hostname or IP (no brackets)
	https string // https URL to request ("" = none)
	http  string // http URL to request ("" = none)
	tls   string // host:port of the TLS checks ("" = none)
}

// targetOf derives the URLs and TLS address of a declared endpoint.
func (c *endpointChecker) targetOf(e JobEndpoint) (endpointTarget, error) {
	var t endpointTarget
	switch e.Kind {
	case "url":
		u, err := url.Parse(e.Value)
		if err != nil || u.Host == "" || (u.Scheme != "https" && u.Scheme != "http") {
			return t, errors.New("not an http(s) URL")
		}
		u.Fragment, u.User = "", nil
		t.host = u.Hostname()
		if u.Scheme == "https" {
			t.https = u.String()
			port := u.Port()
			if port == "" {
				port = c.httpsPort
			}
			t.tls = net.JoinHostPort(t.host, port)
			// The plain-HTTP variant of the same host checks the redirect.
			if u.Port() == "" {
				h := *u
				h.Scheme, h.Host = "http", hostPort(t.host, c.httpPort, "80")
				t.http = h.String()
			}
		} else {
			t.http = u.String()
			if u.Port() == "" {
				h := *u
				h.Scheme, h.Host = "https", hostPort(t.host, c.httpsPort, "443")
				t.https = h.String()
				t.tls = net.JoinHostPort(t.host, c.httpsPort)
			}
		}
	case "domain", "ip":
		h := strings.Trim(e.Value, "[]")
		if strings.HasPrefix(h, "*.") {
			return t, errors.New("wildcard domains cannot be checked; declare the concrete host names")
		}
		if h == "" || strings.ContainsAny(h, "/?# ") {
			return t, errors.New("not a host name or IP address")
		}
		t.host = h
		t.https = "https://" + hostPort(h, c.httpsPort, "443") + "/"
		t.http = "http://" + hostPort(h, c.httpPort, "80") + "/"
		t.tls = net.JoinHostPort(h, c.httpsPort)
	default:
		return t, errors.New("unknown endpoint kind")
	}
	return t, nil
}

func hostPort(host, port, def string) string {
	if strings.Contains(host, ":") {
		host = "[" + host + "]"
	}
	if port == def || port == "" {
		return host
	}
	return host + ":" + port
}

// check verifies one endpoint.
func (c *endpointChecker) check(ctx context.Context, e JobEndpoint) scanners.EndpointResult {
	res := scanners.EndpointResult{Kind: e.Kind, Value: e.Value, Checks: map[string]any{}}
	if !e.Authorized {
		res.Status, res.Detail = "skipped", "not covered by the authorization statement; confirm the endpoint list again to include it"
		return res
	}
	t, err := c.targetOf(e)
	if err != nil {
		res.Status, res.Detail = "skipped", err.Error()
		return res
	}
	// DNS: local resolution when the worker has a resolver; otherwise the
	// egress proxy resolves the name (and reports failures).
	if ip := net.ParseIP(t.host); ip == nil && c.lookup != nil {
		addrs, lerr := c.lookup(ctx, t.host)
		dns := map[string]any{"resolver": "worker"}
		if lerr == nil {
			if len(addrs) > 20 {
				addrs = addrs[:20]
			}
			dns["addresses"] = addrs
		} else {
			dns["error"] = lastLine(lerr.Error())
			if c.proxy != nil {
				dns["resolver"] = "egress proxy"
			}
		}
		res.Checks["dns"] = dns
	}
	outcome := ""
	note := func(o string, err error) {
		// The most informative failure wins: blocked > dns > unreachable.
		rank := map[string]int{"": 0, "unreachable": 1, "dns_failed": 2, "blocked": 3}
		if rank[o] > rank[outcome] {
			outcome, res.Detail = o, lastLine(err.Error())
		}
	}
	var issues []scanners.EndpointIssue
	reachable := false
	if t.tls != "" {
		info, tissues, terr := c.checkTLS(ctx, t.host, t.tls)
		if terr != nil {
			note(classify(terr), terr)
			res.Checks["tls"] = map[string]any{"error": lastLine(terr.Error())}
		} else {
			res.Checks["tls"] = info
			issues = append(issues, tissues...)
		}
	}
	if t.https != "" {
		info, hissues, herr := c.checkHTTP(ctx, t.https, t.host)
		if herr != nil {
			note(classify(herr), herr)
			res.Checks["https"] = map[string]any{"url": t.https, "error": lastLine(herr.Error())}
		} else {
			reachable = true
			res.Checks["https"] = info
			issues = append(issues, hissues...)
		}
	}
	if t.http != "" {
		info, perr := c.checkPlainHTTP(ctx, t.http, t.host)
		if perr != nil {
			res.Checks["http"] = map[string]any{"url": t.http, "error": lastLine(perr.Error())}
			if !reachable {
				note(classify(perr), perr)
			}
		} else {
			res.Checks["http"] = info
			loc, _ := info["location"].(string)
			code, _ := info["status"].(int)
			switch {
			case !reachable && code > 0:
				issues = append(issues, scanners.EndpointIssue{ID: "https-unavailable", Severity: "medium", CWE: []string{"CWE-319"},
					Title:       "Endpoint is served over plain HTTP only",
					Description: "The endpoint answered over HTTP but not over HTTPS, so traffic to it is not encrypted.", Location: t.http})
			case code >= 200 && code < 300 && !strings.HasPrefix(strings.ToLower(loc), "https://"):
				issues = append(issues, scanners.EndpointIssue{ID: "http-no-redirect", Severity: "medium", CWE: []string{"CWE-319"},
					Title:       "HTTP is not redirected to HTTPS",
					Description: fmt.Sprintf("The plain-HTTP address answered %d instead of redirecting to HTTPS.", code), Location: t.http})
			}
			reachable = true
		}
	}
	switch {
	case reachable:
		res.Status = "verified"
		res.Detail = ""
	case outcome != "":
		res.Status = outcome
	default:
		res.Status, res.Detail = "unreachable", "no response"
	}
	res.Issues = issues
	return res
}

// classify maps a connection error to an endpoint status.
func classify(err error) string {
	var pe *proxyError
	if errors.As(err, &pe) {
		return pe.outcome()
	}
	var dnsErr *net.DNSError
	if errors.As(err, &dnsErr) && dnsErr.IsNotFound {
		return "dns_failed"
	}
	return "unreachable"
}

var tlsVersionNames = map[uint16]string{tls.VersionTLS10: "TLS 1.0", tls.VersionTLS11: "TLS 1.1", tls.VersionTLS12: "TLS 1.2", tls.VersionTLS13: "TLS 1.3"}

// weakCipherSuites are offered in the weak-cipher probe: RC4, 3DES,
// CBC with SHA-256 and RSA key exchange (no forward secrecy).
func weakCipherSuites() []uint16 {
	var out []uint16
	for _, cs := range tls.InsecureCipherSuites() {
		if slices.Contains(cs.SupportedVersions, tls.VersionTLS12) {
			out = append(out, cs.ID)
		}
	}
	for _, cs := range tls.CipherSuites() {
		if strings.HasPrefix(cs.Name, "TLS_RSA_") && slices.Contains(cs.SupportedVersions, tls.VersionTLS12) {
			out = append(out, cs.ID)
		}
	}
	return out
}

// handshake performs one TLS handshake with cfg (rate limited).
func (c *endpointChecker) handshake(ctx context.Context, addr string, cfg *tls.Config) (tls.ConnectionState, error) {
	if err := c.pace.wait(ctx); err != nil {
		return tls.ConnectionState{}, err
	}
	ctx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()
	raw, err := c.tunnel(ctx, addr)
	if err != nil {
		return tls.ConnectionState{}, err
	}
	defer raw.Close()
	conn := tls.Client(raw, cfg)
	if err := conn.HandshakeContext(ctx); err != nil {
		return tls.ConnectionState{}, err
	}
	return conn.ConnectionState(), nil
}

// checkTLS inspects the certificate and probes for legacy protocols and
// weak cipher suites.
func (c *endpointChecker) checkTLS(ctx context.Context, host, addr string) (map[string]any, []scanners.EndpointIssue, error) {
	sni := host
	if net.ParseIP(host) != nil {
		sni = ""
	}
	loc := "https://" + addr
	if strings.HasSuffix(addr, ":443") {
		loc = "https://" + hostPort(host, "", "")
	}
	// Verification is done below, so that every problem is reported
	// rather than only the first.
	base := &tls.Config{ServerName: sni, InsecureSkipVerify: true, MinVersion: tls.VersionTLS12} // #nosec G402 -- the certificate is verified explicitly below
	st, err := c.handshake(ctx, addr, base)
	if err != nil {
		// No modern handshake: try legacy versions before giving up.
		legacy := base.Clone()
		legacy.MinVersion = tls.VersionTLS10 // #nosec G402 -- probe for legacy protocol support
		st2, err2 := c.handshake(ctx, addr, legacy)
		if err2 != nil {
			return nil, nil, err
		}
		st = st2
	}
	info := map[string]any{"protocol": tlsVersionNames[st.Version], "cipher_suite": tls.CipherSuiteName(st.CipherSuite)}
	var issues []scanners.EndpointIssue
	if len(st.PeerCertificates) > 0 {
		leaf := st.PeerCertificates[0]
		now := c.now()
		days := int(leaf.NotAfter.Sub(now).Hours() / 24)
		cert := map[string]any{"subject": leaf.Subject.CommonName, "issuer": leaf.Issuer.CommonName,
			"not_before": leaf.NotBefore.UTC().Format(time.RFC3339), "not_after": leaf.NotAfter.UTC().Format(time.RFC3339),
			"days_remaining": days, "dns_names": leaf.DNSNames[:min(len(leaf.DNSNames), 20)]}
		inter := x509.NewCertPool()
		for _, ic := range st.PeerCertificates[1:] {
			inter.AddCert(ic)
		}
		_, verr := leaf.Verify(x509.VerifyOptions{Roots: c.roots, Intermediates: inter, CurrentTime: now})
		hostErr := leaf.VerifyHostname(host)
		cert["hostname_match"] = hostErr == nil
		switch {
		case now.After(leaf.NotAfter):
			issues = append(issues, scanners.EndpointIssue{ID: "tls-certificate-expired", Severity: "high", CWE: []string{"CWE-298"},
				Title:       "TLS certificate has expired",
				Description: fmt.Sprintf("The certificate for %s expired on %s.", host, leaf.NotAfter.UTC().Format(time.DateOnly)), Location: loc})
		case now.Before(leaf.NotBefore):
			issues = append(issues, scanners.EndpointIssue{ID: "tls-certificate-not-yet-valid", Severity: "high", CWE: []string{"CWE-298"},
				Title:       "TLS certificate is not yet valid",
				Description: fmt.Sprintf("The certificate for %s is valid from %s.", host, leaf.NotBefore.UTC().Format(time.DateOnly)), Location: loc})
		case days < certExpiryWarnDays:
			sev := "low"
			if days < 7 {
				sev = "medium"
			}
			issues = append(issues, scanners.EndpointIssue{ID: "tls-certificate-expiring", Severity: sev, CWE: []string{"CWE-298"},
				Title:       "TLS certificate expires soon",
				Description: fmt.Sprintf("The certificate for %s expires on %s (%d days).", host, leaf.NotAfter.UTC().Format(time.DateOnly), days), Location: loc})
		}
		// Chain errors other than validity dates (reported above).
		var invalid x509.CertificateInvalidError
		trusted := verr == nil || (errors.As(verr, &invalid) && invalid.Reason == x509.Expired)
		cert["trusted"] = verr == nil
		if !trusted {
			issues = append(issues, scanners.EndpointIssue{ID: "tls-certificate-untrusted", Severity: "medium", CWE: []string{"CWE-295"},
				Title:       "TLS certificate is not trusted",
				Description: "The certificate chain does not verify against public trust roots: " + lastLine(verr.Error()), Location: loc})
		}
		if hostErr != nil {
			issues = append(issues, scanners.EndpointIssue{ID: "tls-hostname-mismatch", Severity: "medium", CWE: []string{"CWE-297"},
				Title:       "TLS certificate does not match the host name",
				Description: fmt.Sprintf("The certificate is not valid for %s (it covers %s).", host, strings.Join(firstN(leaf.DNSNames, 5), ", ")), Location: loc})
		}
		info["certificate"] = cert
	}
	// Legacy protocol versions.
	var weakProtocols []string
	for _, v := range []uint16{tls.VersionTLS10, tls.VersionTLS11} {
		cfg := &tls.Config{ServerName: sni, InsecureSkipVerify: true, MinVersion: v, MaxVersion: v} // #nosec G402 G401 -- probe whether the server accepts a legacy protocol
		if _, err := c.handshake(ctx, addr, cfg); err == nil {
			weakProtocols = append(weakProtocols, tlsVersionNames[v])
		} else if ctx.Err() != nil {
			return info, issues, nil
		}
	}
	info["legacy_protocols"] = nonNilStrs(weakProtocols)
	if len(weakProtocols) > 0 {
		issues = append(issues, scanners.EndpointIssue{ID: "tls-weak-protocol", Severity: "medium", CWE: []string{"CWE-327"},
			Title:       "Legacy TLS protocol versions accepted",
			Description: "The server accepts " + strings.Join(weakProtocols, " and ") + ", which are deprecated (RFC 8996). Require TLS 1.2 or later.", Location: loc})
	}
	// Weak cipher suites (TLS 1.2).
	var weakCiphers []string
	cfg := &tls.Config{ServerName: sni, InsecureSkipVerify: true, MinVersion: tls.VersionTLS12, MaxVersion: tls.VersionTLS12, CipherSuites: weakCipherSuites()} // #nosec G402 -- probe whether the server accepts weak cipher suites
	if st, err := c.handshake(ctx, addr, cfg); err == nil {
		weakCiphers = append(weakCiphers, tls.CipherSuiteName(st.CipherSuite))
	}
	info["weak_cipher_suites"] = nonNilStrs(weakCiphers)
	if len(weakCiphers) > 0 {
		issues = append(issues, scanners.EndpointIssue{ID: "tls-weak-cipher", Severity: "low", CWE: []string{"CWE-327"},
			Title:       "Weak TLS cipher suite accepted",
			Description: "The server negotiated " + strings.Join(weakCiphers, ", ") + " when offered only weak suites (RC4, 3DES, CBC-SHA256 or RSA key exchange without forward secrecy).", Location: loc})
	}
	return info, issues, nil
}

func firstN(v []string, n int) []string { return v[:min(len(v), n)] }

func nonNilStrs(v []string) []string {
	if v == nil {
		return []string{}
	}
	return v
}

func (c *endpointChecker) client(tlsVia bool) *http.Client {
	tr := &http.Transport{
		TLSClientConfig:       &tls.Config{InsecureSkipVerify: true}, // #nosec G402 -- headers are observed; the certificate is verified by checkTLS
		ResponseHeaderTimeout: c.timeout, DisableKeepAlives: true, MaxResponseHeaderBytes: 64 << 10,
	}
	if tlsVia {
		tr.DialContext = func(ctx context.Context, _, addr string) (net.Conn, error) { return c.tunnel(ctx, addr) }
	} else if c.proxy != nil {
		tr.Proxy = c.proxy
	}
	return &http.Client{Transport: tr, Timeout: c.timeout,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
}

// get makes one GET request (rate limited) and reads at most 64 KiB.
func (c *endpointChecker) get(ctx context.Context, cl *http.Client, u string) (*http.Response, error) {
	if err := c.pace.wait(ctx); err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "PATHOS-endpoint-verification")
	resp, err := cl.Do(req)
	if err != nil {
		return nil, err
	}
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10))
	_ = resp.Body.Close()
	if e := resp.Header.Get("X-Squid-Error"); e != "" {
		return nil, &proxyError{status: resp.StatusCode, squidErr: e}
	}
	return resp, nil
}

// checkHTTP requests the HTTPS address (following redirects on the same
// host only) and checks HSTS and the security headers.
func (c *endpointChecker) checkHTTP(ctx context.Context, start, host string) (map[string]any, []scanners.EndpointIssue, error) {
	cl := c.client(true)
	u := start
	var resp *http.Response
	var chain []string
	redirectErr := ""
	for i := 0; ; i++ {
		next, err := c.get(ctx, cl, u)
		if err != nil {
			if resp == nil {
				return nil, nil, err
			}
			// A redirect target that fails: judge the last response.
			redirectErr = lastLine(err.Error())
			u = resp.Request.URL.String()
			break
		}
		resp = next
		loc := resp.Header.Get("Location")
		if resp.StatusCode < 300 || resp.StatusCode >= 400 || loc == "" || i >= maxRedirects {
			break
		}
		nu, err := resp.Request.URL.Parse(loc)
		if err != nil || nu.Scheme != "https" || !strings.EqualFold(nu.Hostname(), host) {
			// Off-host or downgrading redirects are not followed (scope).
			chain = append(chain, loc)
			break
		}
		chain = append(chain, nu.String())
		u = nu.String()
	}
	h := resp.Header
	info := map[string]any{"url": start, "status": resp.StatusCode, "final_url": u}
	if len(chain) > 0 {
		info["redirects"] = chain
	}
	if redirectErr != "" {
		info["redirect_error"] = redirectErr
	}
	headers := map[string]string{}
	for _, k := range []string{"Strict-Transport-Security", "Content-Security-Policy", "X-Content-Type-Options", "X-Frame-Options", "Referrer-Policy", "Permissions-Policy"} {
		if v := h.Get(k); v != "" {
			headers[strings.ToLower(k)] = truncateStr(v, 500)
		}
	}
	info["headers"] = headers
	loc := u
	var issues []scanners.EndpointIssue
	if hsts := h.Get("Strict-Transport-Security"); hsts == "" {
		issues = append(issues, scanners.EndpointIssue{ID: "hsts-missing", Severity: "low", CWE: []string{"CWE-319"},
			Title:       "HTTP Strict Transport Security (HSTS) not set",
			Description: "The HTTPS response has no Strict-Transport-Security header, so browsers may connect over plain HTTP first.", Location: loc})
	} else if age := hstsMaxAge(hsts); age < hstsMinMaxAge {
		issues = append(issues, scanners.EndpointIssue{ID: "hsts-short", Severity: "low", CWE: []string{"CWE-319"},
			Title:       "HSTS max-age is short",
			Description: fmt.Sprintf("Strict-Transport-Security max-age is %d seconds; at least %d (180 days) is recommended.", age, hstsMinMaxAge), Location: loc})
	}
	// Content headers matter for documents, not for redirects or errors.
	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		csp := h.Get("Content-Security-Policy")
		if csp == "" {
			issues = append(issues, scanners.EndpointIssue{ID: "header-missing-csp", Severity: "low", CWE: []string{"CWE-693"},
				Title: "Content-Security-Policy header missing", Description: "The response sets no Content-Security-Policy.", Location: loc})
		}
		if !strings.EqualFold(strings.TrimSpace(h.Get("X-Content-Type-Options")), "nosniff") {
			issues = append(issues, scanners.EndpointIssue{ID: "header-missing-x-content-type-options", Severity: "low", CWE: []string{"CWE-693"},
				Title: "X-Content-Type-Options: nosniff missing", Description: "Without nosniff, browsers may interpret responses as a different content type.", Location: loc})
		}
		if h.Get("X-Frame-Options") == "" && !strings.Contains(strings.ToLower(csp), "frame-ancestors") {
			issues = append(issues, scanners.EndpointIssue{ID: "header-missing-frame-options", Severity: "low", CWE: []string{"CWE-1021"},
				Title: "Clickjacking protection missing", Description: "Neither X-Frame-Options nor a Content-Security-Policy frame-ancestors directive is set.", Location: loc})
		}
		if h.Get("Referrer-Policy") == "" {
			issues = append(issues, scanners.EndpointIssue{ID: "header-missing-referrer-policy", Severity: "info",
				Title: "Referrer-Policy header missing", Description: "The response sets no Referrer-Policy; the browser default applies.", Location: loc})
		}
	}
	return info, issues, nil
}

// checkPlainHTTP requests the HTTP address without following redirects.
func (c *endpointChecker) checkPlainHTTP(ctx context.Context, u, _ string) (map[string]any, error) {
	resp, err := c.get(ctx, c.client(false), u)
	if err != nil {
		return nil, err
	}
	info := map[string]any{"url": u, "status": resp.StatusCode}
	if loc := resp.Header.Get("Location"); loc != "" {
		if next, err := resp.Request.URL.Parse(loc); err == nil {
			info["location"] = truncateStr(next.String(), 1000)
		}
	}
	return info, nil
}

func hstsMaxAge(v string) int {
	for _, part := range strings.Split(v, ";") {
		k, val, ok := strings.Cut(strings.TrimSpace(part), "=")
		if ok && strings.EqualFold(strings.TrimSpace(k), "max-age") {
			n, err := strconv.Atoi(strings.Trim(strings.TrimSpace(val), `"`))
			if err == nil {
				return n
			}
		}
	}
	return 0
}

func truncateStr(s string, n int) string {
	if len(s) > n {
		return s[:n]
	}
	return s
}

// verifyEndpoints checks every declared endpoint and writes the report.
func verifyEndpoints(ctx context.Context, c *endpointChecker, eps []JobEndpoint, out string) error {
	rep := scanners.EndpointReport{Version: 1, Endpoints: []scanners.EndpointResult{}}
	for _, e := range eps {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		rep.Endpoints = append(rep.Endpoints, c.check(ctx, e))
	}
	b, err := json.Marshal(rep)
	if err != nil {
		return err
	}
	return os.WriteFile(out, b, 0o600)
}

// endpointList writes the URLs Nuclei checks (authorized endpoints only).
func endpointList(eps []JobEndpoint, path string) error {
	var lines []string
	c := &endpointChecker{httpsPort: "443", httpPort: "80"}
	for _, e := range eps {
		if !e.Authorized {
			continue
		}
		t, err := c.targetOf(e)
		if err != nil {
			continue
		}
		u := t.https
		if u == "" {
			u = t.http
		}
		if u != "" && !slices.Contains(lines, u) {
			lines = append(lines, u)
		}
	}
	if len(lines) == 0 {
		return errors.New("no authorized endpoint can be checked")
	}
	return os.WriteFile(path, []byte(strings.Join(lines, "\n")+"\n"), 0o600)
}

// endpointsTool is the built-in pathos-endpoints scanner.
type endpointsTool struct{ cfg Config }

func (t endpointsTool) Version(context.Context) (string, error) {
	v := t.cfg.Version
	if v == "" {
		v = "dev"
	}
	return "pathos " + v, nil
}

func (t endpointsTool) Run(ctx context.Context, in RunInput) (string, error) {
	if in.Target == nil || in.Target.Kind != "endpoints" {
		return "only runs for declared public endpoints", nil
	}
	if t.cfg.Offline {
		return "endpoint verification is disabled in offline mode (PATHOS_OFFLINE=true)", nil
	}
	return "", verifyEndpoints(ctx, defaultChecker(in.Target.RateLimit), in.Target.Endpoints, in.Out)
}
