package repos

import "testing"

func TestNormalizeAppURL(t *testing.T) {
	ok := map[string]string{
		"":                               "",
		"HTTPS://Shop.Example.COM:443/":  "https://shop.example.com",
		"http://x.example:80/a?b=1#frag": "http://x.example/a?b=1",
		"https://bücher.example/":        "https://xn--bcher-kva.example",
		"https://[2001:db8::1]:8443/x":   "https://[2001:db8::1]:8443/x",
		"https://app.example.com/login/": "https://app.example.com/login/",
	}
	for in, want := range ok {
		if got, err := normalizeAppURL(in); err != nil || got != want {
			t.Errorf("normalizeAppURL(%q) = %q, %v; want %q", in, got, err, want)
		}
	}
	for _, bad := range []string{"ftp://x.example", "x.example", "https://user:pw@x.example", "https://", "javascript:alert(1)", "https://bad host.example", "https://-x.example"} {
		if _, err := normalizeAppURL(bad); err == nil {
			t.Errorf("normalizeAppURL(%q) accepted", bad)
		}
	}
}

func TestNormalizeDomainAndIP(t *testing.T) {
	if d, err := normalizeDomain("*.CDN.Example.com.", true); err != nil || d != "*.cdn.example.com" {
		t.Errorf("wildcard domain: %q %v", d, err)
	}
	for _, bad := range []string{"localhost", "a..b.com", "*.x.com.evil/", "under_score.example.com"} {
		if _, err := normalizeDomain(bad, true); err == nil {
			t.Errorf("domain %q accepted", bad)
		}
	}
	if ip, err := normalizePublicIP(" 203.0.113.7 "); err != nil || ip != "203.0.113.7" {
		t.Errorf("public IP: %q %v", ip, err)
	}
	for _, bad := range []string{"10.0.0.1", "192.168.1.1", "127.0.0.1", "169.254.169.254", "100.64.0.1", "::1", "fe80::1", "not-an-ip"} {
		if _, err := normalizePublicIP(bad); err == nil {
			t.Errorf("IP %q accepted as public", bad)
		}
	}
	got, err := normalizeList([]string{"https://A.example.com/", " ", "https://a.example.com"}, normalizeAppURL)
	if err != nil || len(got) != 1 {
		t.Errorf("dedupe: %v %v", got, err)
	}
}
