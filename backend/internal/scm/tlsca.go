package scm

import (
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// Per-connection private certificate authority (PATHOS 3.0, M2; backported to 2.2.2 for registry
// connections, outbound webhooks and ticket connections).
//
// Self-hosted servers (GitHub Enterprise Server, GitLab self-managed,
// Bitbucket Data Center, Generic Git, Vault) are often served with a
// certificate issued by a private CA. A connection may carry a PEM bundle
// that is ADDED to the system trust store for that connection only; it
// never replaces it and never disables verification.
//
// The bundle is stored as configuration, not as a secret: CA certificates
// are public by construction (every client of the server receives the chain
// in the TLS handshake), administrators must be able to read back what is
// trusted and compare fingerprints, and encrypting them would add no
// confidentiality while hiding a trust decision from review. Private keys
// are refused.

// Limits of a CA bundle.
const (
	MaxCABundleBytes = 64 << 10
	MaxCABundleCerts = 20
)

// ErrCABundle is returned for an unusable CA bundle.
var ErrCABundle = errors.New("CA bundle must be PEM \"CERTIFICATE\" blocks only")

// CACert describes one certificate of a bundle (shown to administrators).
type CACert struct {
	Subject           string    `json:"subject"`
	Issuer            string    `json:"issuer"`
	NotAfter          time.Time `json:"not_after"`
	SHA256Fingerprint string    `json:"sha256_fingerprint"`
	IsCA              bool      `json:"is_ca"`
	Expired           bool      `json:"expired"`
}

// ParseCABundle validates a PEM bundle and returns its certificates. Empty
// input returns (nil, nil).
func ParseCABundle(bundle string, now time.Time) ([]*x509.Certificate, []CACert, error) {
	bundle = strings.TrimSpace(bundle)
	if bundle == "" {
		return nil, nil, nil
	}
	if len(bundle) > MaxCABundleBytes {
		return nil, nil, fmt.Errorf("CA bundle is larger than %d KiB", MaxCABundleBytes>>10)
	}
	rest := []byte(bundle)
	var certs []*x509.Certificate
	var infos []CACert
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			return nil, nil, fmt.Errorf("%w (found %q; never paste a private key)", ErrCABundle, block.Type)
		}
		c, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, nil, fmt.Errorf("CA bundle: certificate %d does not parse: %v", len(certs)+1, err)
		}
		certs = append(certs, c)
		sum := sha256.Sum256(c.Raw)
		infos = append(infos, CACert{
			Subject: c.Subject.String(), Issuer: c.Issuer.String(), NotAfter: c.NotAfter.UTC(),
			SHA256Fingerprint: strings.ToUpper(hex.EncodeToString(sum[:])), IsCA: c.IsCA, Expired: now.After(c.NotAfter),
		})
		if len(certs) > MaxCABundleCerts {
			return nil, nil, fmt.Errorf("CA bundle has more than %d certificates", MaxCABundleCerts)
		}
	}
	if strings.TrimSpace(string(rest)) != "" || len(certs) == 0 {
		return nil, nil, ErrCABundle
	}
	return certs, infos, nil
}

// CAPool returns the system pool plus the bundle's certificates. An empty
// bundle returns nil (use the system pool unchanged).
func CAPool(bundle string) (*x509.CertPool, error) {
	certs, _, err := ParseCABundle(bundle, time.Now())
	if err != nil || certs == nil {
		return nil, err
	}
	pool, err := x509.SystemCertPool()
	if err != nil || pool == nil {
		pool = x509.NewCertPool()
	}
	for _, c := range certs {
		pool.AddCert(c)
	}
	return pool, nil
}

// ClientWithCA is Client with a per-connection CA bundle added to the
// system trust store. An empty bundle returns Client().
func (p NetPolicy) ClientWithCA(bundle string) (*http.Client, error) {
	pool, err := CAPool(bundle)
	if err != nil {
		return nil, err
	}
	return p.client(pool), nil
}

// NormalizeBaseURL applies the vendor's documented API root to a base URL
// an administrator entered:
//
//   - GitHub Enterprise Server: the REST API lives at https://HOST/api/v3
//     (https://docs.github.com/en/enterprise-server@latest/rest/quickstart).
//     A bare host URL gets /api/v3 appended; a URL that already ends in
//     /api/v3 is kept.
//   - GitLab self-managed: the connection stores the instance root; the
//     client appends /api/v4 (https://docs.gitlab.com/api/rest/), so a
//     trailing /api/v4 is removed.
//   - Bitbucket Data Center: the instance root (it may have a context path
//     such as /bitbucket); a trailing /rest or /rest/api/... is removed.
//
// Other providers are returned unchanged (without a trailing slash).
func NormalizeBaseURL(provider, raw string) string {
	raw = strings.TrimRight(strings.TrimSpace(raw), "/")
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return raw
	}
	switch provider {
	case GitHubEnterprise:
		if !strings.HasSuffix(strings.ToLower(u.Path), "/api/v3") {
			u.Path = strings.TrimRight(u.Path, "/") + "/api/v3"
		}
	case GitLab:
		u.Path = strings.TrimSuffix(u.Path, "/api/v4")
	case BitbucketDataCenter:
		if i := strings.Index(strings.ToLower(u.Path), "/rest"); i >= 0 && (len(u.Path) == i+5 || u.Path[i+5] == '/') {
			u.Path = u.Path[:i]
		}
	}
	return strings.TrimRight(u.String(), "/")
}

// Diagnostic codes of private CA bundles (2.2.2): registry connections,
// outbound webhooks and ticket connections (catalogue_conn_ca.go).
const (
	// DiagCABundleInvalid: the ca_bundle_pem given is not a PEM bundle of
	// certificates (or contains a private key).
	DiagCABundleInvalid = "PTH-CONN-1701"
	// DiagCAUntrusted: the server's certificate chain is not trusted; add
	// the issuing private CA to the connection's ca_bundle_pem.
	DiagCAUntrusted = "PTH-CONN-1702"
)

// UntrustedCertificate reports whether err is a TLS verification failure
// caused by an unknown certificate authority.
func UntrustedCertificate(err error) bool {
	var ua x509.UnknownAuthorityError
	var cv *tls.CertificateVerificationError
	if errors.As(err, &cv) {
		return errors.As(cv.Err, &ua) || strings.Contains(cv.Err.Error(), "unknown authority")
	}
	return errors.As(err, &ua) || strings.Contains(err.Error(), "certificate signed by unknown authority")
}

// WithCAHint adds the corrective action to an untrusted-certificate error
// (anything else is returned unchanged).
func WithCAHint(err error) error {
	if err == nil || !UntrustedCertificate(err) {
		return err
	}
	return fmt.Errorf("%s: the server certificate is issued by a CA that is not trusted; add the private CA bundle (PEM) "+
		"to the connection's ca_bundle_pem: %w", DiagCAUntrusted, err)
}
