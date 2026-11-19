package scm

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"syscall"
	"time"
)

// ErrBlockedAddress is returned when an SCM URL resolves to a forbidden IP.
var ErrBlockedAddress = errors.New("scm: destination address is not allowed")

// ErrPlainHTTP is an http:// URL while plain HTTP is not allowed.
var ErrPlainHTTP = errors.New("base URL must use https")

// NetPolicy controls which destinations SCM requests may reach. Base URLs
// are administrator input, so outbound requests are checked at connect time
// (after DNS resolution, which also defeats DNS rebinding).
type NetPolicy struct {
	// AllowPrivate permits RFC 1918 / ULA destinations (self-hosted GitHub
	// Enterprise or Azure DevOps Server on an internal network).
	AllowPrivate bool
	// AllowHTTP permits plain-http base URLs (development only).
	AllowHTTP bool
}

var alwaysBlocked = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"),
	netip.MustParsePrefix("127.0.0.0/8"),
	netip.MustParsePrefix("169.254.0.0/16"), // link-local, cloud metadata
	netip.MustParsePrefix("100.64.0.0/10"),  // CGNAT
	netip.MustParsePrefix("192.0.0.0/24"),
	netip.MustParsePrefix("224.0.0.0/4"),
	netip.MustParsePrefix("240.0.0.0/4"),
	netip.MustParsePrefix("::/128"),
	netip.MustParsePrefix("::1/128"),
	netip.MustParsePrefix("fe80::/10"),
	netip.MustParsePrefix("ff00::/8"),
	netip.MustParsePrefix("fd00:ec2::254/128"), // AWS IMDS over IPv6
}

var privateRanges = []netip.Prefix{
	netip.MustParsePrefix("10.0.0.0/8"),
	netip.MustParsePrefix("172.16.0.0/12"),
	netip.MustParsePrefix("192.168.0.0/16"),
	netip.MustParsePrefix("fc00::/7"),
}

// Allowed reports whether ip may be contacted under the policy.
func (p NetPolicy) Allowed(ip netip.Addr) bool {
	ip = ip.Unmap()
	for _, b := range alwaysBlocked {
		if b.Contains(ip) {
			return false
		}
	}
	if !p.AllowPrivate {
		for _, b := range privateRanges {
			if b.Contains(ip) {
				return false
			}
		}
	}
	return true
}

// ValidateBaseURL checks scheme and shape of an administrator-supplied URL.
func (p NetPolicy) ValidateBaseURL(raw string) (*url.URL, error) {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return nil, errors.New("base URL must be an absolute URL without credentials, query or fragment")
	}
	if u.Scheme != "https" && !(p.AllowHTTP && u.Scheme == "http") {
		return nil, ErrPlainHTTP
	}
	if ip, err := netip.ParseAddr(u.Hostname()); err == nil && !p.Allowed(ip) {
		return nil, ErrBlockedAddress
	}
	return u, nil
}

// Client returns an HTTP client that refuses blocked destinations, does not
// follow redirects to other hosts, and has sane timeouts. It trusts the
// system certificate pool.
func (p NetPolicy) Client() *http.Client { return p.client(nil) }

// Dialer returns a dialer that refuses blocked destinations at connect time
// (after DNS resolution). SSH connections (Generic Git) use it too.
func (p NetPolicy) Dialer() *net.Dialer {
	return &net.Dialer{
		Timeout: 10 * time.Second,
		Control: func(_, address string, _ syscall.RawConn) error {
			host, _, err := net.SplitHostPort(address)
			if err != nil {
				return err
			}
			ip, err := netip.ParseAddr(host)
			if err != nil || !p.Allowed(ip) {
				return fmt.Errorf("%w: %s", ErrBlockedAddress, host)
			}
			return nil
		},
	}
}

// client builds the client; roots == nil means the system pool.
func (p NetPolicy) client(roots *x509.CertPool) *http.Client {
	dialer := p.Dialer()
	tr := &http.Transport{
		DialContext:           dialer.DialContext,
		Proxy:                 http.ProxyFromEnvironment,
		TLSHandshakeTimeout:   10 * time.Second,
		ResponseHeaderTimeout: 30 * time.Second,
		MaxIdleConnsPerHost:   4,
		IdleConnTimeout:       60 * time.Second,
		ForceAttemptHTTP2:     true,
	}
	if roots != nil {
		tr.TLSClientConfig = &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12}
	}
	return &http.Client{
		Transport: tr,
		Timeout:   60 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 3 || req.URL.Host != via[0].URL.Host {
				return http.ErrUseLastResponse
			}
			return nil
		},
	}
}
