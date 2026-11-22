package scm

import (
	"errors"
	"net/http"
	"net/netip"
	"net/url"
	"testing"
)

func TestOrgChosenPrivateFollowsTheGate(t *testing.T) {
	t.Cleanup(func() { SetOrgPrivateGate(nil) })
	private := netip.MustParseAddr("10.1.2.3")
	operator := NetPolicy{AllowPrivate: true}
	org := NetPolicy{AllowPrivate: true, OrgChosen: true}

	SetOrgPrivateGate(nil) // single installation
	if !org.Allowed(private) || !operator.Allowed(private) {
		t.Fatal("without a gate, allow_private works as before")
	}
	SetOrgPrivateGate(func() bool { return false }) // multi-tenant, operator did not allow
	if org.Allowed(private) {
		t.Error("an organization-chosen policy reached a private address")
	}
	if !operator.Allowed(private) {
		t.Error("the operator's own policy must not be affected")
	}
	if !org.Allowed(netip.MustParseAddr("140.82.112.3")) {
		t.Error("public addresses stay allowed")
	}
	if (NetPolicy{AllowPrivate: true, OrgChosen: true}).Allowed(netip.MustParseAddr("169.254.169.254")) {
		t.Error("metadata is always blocked")
	}
	SetOrgPrivateGate(func() bool { return true }) // operator allowed it
	if !org.Allowed(private) {
		t.Error("the operator allowed private networks")
	}
}

// Through a proxy the dialer only sees the proxy, so the target is checked
// when the proxy is chosen.
func TestProxyChecksTheDestination(t *testing.T) {
	proxyURL, _ := url.Parse("http://proxy.corp.example:3128")
	viaProxy := func(*http.Request) (*url.URL, error) { return proxyURL, nil }
	noProxy := func(*http.Request) (*url.URL, error) { return nil, nil }
	p := NetPolicy{}
	for _, target := range []string{"http://169.254.169.254/latest/meta-data", "https://127.0.0.1/", "https://10.0.0.5/", "https://localhost/"} {
		req, _ := http.NewRequest(http.MethodGet, target, nil)
		if _, err := p.proxyVia(viaProxy, req); !errors.Is(err, ErrBlockedAddress) {
			t.Errorf("%s through the proxy: want blocked, got %v", target, err)
		}
	}
	req, _ := http.NewRequest(http.MethodGet, "https://140.82.112.3/", nil)
	if u, err := p.proxyVia(viaProxy, req); err != nil || u != proxyURL {
		t.Errorf("public destination through the proxy: %v %v", u, err)
	}
	req, _ = http.NewRequest(http.MethodGet, "https://10.0.0.5/", nil)
	if u, err := p.proxyVia(noProxy, req); err != nil || u != nil {
		t.Errorf("without a proxy the dialer checks; got %v %v", u, err)
	}
}
