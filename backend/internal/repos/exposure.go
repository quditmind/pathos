package repos

import (
	"fmt"
	"net/netip"
	"net/url"
	"regexp"
	"strings"

	"golang.org/x/net/idna"
)

// Public exposure answers (repositories.public_exposure).
var publicExposures = []string{"yes", "no", "unknown"}

// maxEndpoints bounds public URLs, domains and IPs per kind.
const maxEndpoints = 50

// normalizeAppURL validates and normalizes an application URL (staging,
// production or public-facing). URLs are metadata: PATHOS never fetches
// them, so no network checks happen here.
func normalizeAppURL(raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", nil
	}
	if len(raw) > 2048 || strings.ContainsAny(raw, " \t\r\n\x00") {
		return "", fmt.Errorf("not a valid URL")
	}
	u, err := url.Parse(raw)
	if err != nil || (u.Scheme != "https" && u.Scheme != "http" && u.Scheme != "HTTPS" && u.Scheme != "HTTP") || u.Host == "" || u.Opaque != "" {
		return "", fmt.Errorf("enter an absolute http:// or https:// URL")
	}
	if u.User != nil {
		return "", fmt.Errorf("URLs must not contain user names or passwords")
	}
	host, err := normalizeHost(u.Hostname())
	if err != nil {
		return "", err
	}
	u.Scheme = strings.ToLower(u.Scheme)
	port := u.Port()
	if (u.Scheme == "https" && port == "443") || (u.Scheme == "http" && port == "80") {
		port = ""
	}
	if strings.Contains(host, ":") {
		host = "[" + host + "]"
	}
	u.Host = host
	if port != "" {
		u.Host += ":" + port
	}
	u.Fragment, u.RawFragment = "", ""
	if u.Path == "/" && u.RawQuery == "" {
		u.Path = ""
	}
	return u.String(), nil
}

var labelRe = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`)

// normalizeHost accepts a DNS name (IDNs are converted to ASCII) or an IP.
func normalizeHost(h string) (string, error) {
	if ip, err := netip.ParseAddr(strings.Trim(h, "[]")); err == nil {
		return ip.Unmap().String(), nil
	}
	return normalizeDomain(h, false)
}

// normalizeDomain validates a domain name; wildcard allows "*.example.com".
func normalizeDomain(raw string, wildcard bool) (string, error) {
	d := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(raw)), ".")
	star := wildcard && strings.HasPrefix(d, "*.")
	if star {
		d = d[2:]
	}
	a, err := idna.Lookup.ToASCII(d)
	if err != nil || len(a) > 253 || !strings.Contains(a, ".") {
		return "", fmt.Errorf("%q is not a valid domain name", raw)
	}
	for _, l := range strings.Split(a, ".") {
		if !labelRe.MatchString(l) {
			return "", fmt.Errorf("%q is not a valid domain name", raw)
		}
	}
	if star {
		a = "*." + a
	}
	return a, nil
}

// normalizePublicIP accepts a public IPv4 or IPv6 address.
func normalizePublicIP(raw string) (string, error) {
	ip, err := netip.ParseAddr(strings.TrimSpace(raw))
	if err != nil {
		return "", fmt.Errorf("%q is not an IP address", raw)
	}
	ip = ip.Unmap()
	if ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsMulticast() || ip.IsUnspecified() ||
		netip.MustParsePrefix("100.64.0.0/10").Contains(ip) || ip.Zone() != "" {
		return "", fmt.Errorf("%s is not a public IP address", ip)
	}
	return ip.String(), nil
}

// normalizeList normalizes and de-duplicates a list with fn.
func normalizeList(in []string, fn func(string) (string, error)) ([]string, error) {
	out := []string{}
	for _, v := range in {
		if strings.TrimSpace(v) == "" {
			continue
		}
		n, err := fn(v)
		if err != nil {
			return out, err
		}
		if !containsStr(out, n) {
			out = append(out, n)
		}
	}
	if len(out) > maxEndpoints {
		return out, fmt.Errorf("at most %d entries", maxEndpoints)
	}
	return out, nil
}
