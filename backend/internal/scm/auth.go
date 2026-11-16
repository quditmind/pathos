package scm

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

// authorizer is the provider-independent token layer. Adapters call
// authorize on every request and never look at the credential themselves;
// the auth type only matters for the git clone username.
type authorizer interface {
	// kind is the auth type (AuthPAT, AuthOAuth, ...).
	kind() string
	// authorize sets the Authorization header, obtaining or refreshing a
	// token first where needed.
	authorize(ctx context.Context, req *http.Request) error
	// unauthorized is called once after a 401 for req. It returns true if
	// a new token was obtained and the request should be retried.
	unauthorized(ctx context.Context, req *http.Request) (bool, error)
	// secret returns the token to use as the git password and its expiry.
	secret(ctx context.Context) (string, *time.Time, error)
}

// bearerAuth is a static bearer token (PATs and access tokens).
type bearerAuth struct {
	tok string
	k   string
}

func (a bearerAuth) kind() string { return a.k }
func (a bearerAuth) authorize(_ context.Context, req *http.Request) error {
	req.Header.Set("Authorization", "Bearer "+a.tok)
	return nil
}
func (bearerAuth) unauthorized(context.Context, *http.Request) (bool, error) { return false, nil }
func (a bearerAuth) secret(context.Context) (string, *time.Time, error)      { return a.tok, nil, nil }

// basicAuth is static HTTP Basic (Azure DevOps PAT with an empty user,
// Bitbucket API token with the account e-mail).
type basicAuth struct {
	user, pass string
	k          string
}

func (a basicAuth) kind() string { return a.k }
func (a basicAuth) authorize(_ context.Context, req *http.Request) error {
	req.SetBasicAuth(a.user, a.pass)
	return nil
}
func (basicAuth) unauthorized(context.Context, *http.Request) (bool, error) { return false, nil }
func (a basicAuth) secret(context.Context) (string, *time.Time, error)      { return a.pass, nil, nil }

// ---------------------------------------------------------------------------
// Process-wide cache for short-lived machine tokens (GitHub App installation
// tokens, Entra ID client-credential tokens). Keys are hashes over the token
// endpoint, the identity and the key material, so a rotated key never reuses
// a token minted with the old one. A token is renewed 5 minutes before it
// expires; fetches for one key are serialized so concurrent requests do not
// stampede the token endpoint.

const tokenRenewBefore = 5 * time.Minute

type cachedToken struct {
	mu      sync.Mutex
	token   string
	expires time.Time
}

type tokenCache struct {
	mu sync.Mutex
	m  map[string]*cachedToken
}

var sharedTokens = &tokenCache{m: map[string]*cachedToken{}}

func cacheKey(parts ...string) string {
	h := sha256.Sum256([]byte(strings.Join(parts, "\x00")))
	return hex.EncodeToString(h[:])
}

func (c *tokenCache) entry(key string) *cachedToken {
	c.mu.Lock()
	defer c.mu.Unlock()
	e := c.m[key]
	if e == nil {
		if len(c.m) >= 1024 {
			now := time.Now()
			for k, old := range c.m {
				if old.mu.TryLock() {
					if old.expires.Before(now) {
						delete(c.m, k)
					}
					old.mu.Unlock()
				}
			}
		}
		e = &cachedToken{}
		c.m[key] = e
	}
	return e
}

func (c *tokenCache) get(ctx context.Context, key string, fetch func(context.Context) (string, time.Time, error)) (string, time.Time, error) {
	e := c.entry(key)
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.token != "" && time.Until(e.expires) > tokenRenewBefore {
		return e.token, e.expires, nil
	}
	tok, exp, err := fetch(ctx)
	if err != nil {
		return "", time.Time{}, err
	}
	e.token, e.expires = tok, exp
	return tok, exp, nil
}

// invalidate drops tok from the cache (after the provider rejected it).
func (c *tokenCache) invalidate(key, tok string) {
	e := c.entry(key)
	e.mu.Lock()
	if e.token == tok {
		e.token = ""
	}
	e.mu.Unlock()
}

func bearerOf(req *http.Request) string {
	return strings.TrimPrefix(req.Header.Get("Authorization"), "Bearer ")
}

// ---------------------------------------------------------------------------
// GitHub App: App JWT → installation access token (1 h).

type githubAppAuth struct {
	base   string
	appID  int64
	instID int64
	key    *rsa.PrivateKey
	hc     *http.Client
	ck     string
}

func newGitHubAppAuth(cfg Config) (*githubAppAuth, error) {
	k, err := ParseRSAPrivateKey(cfg.Secret)
	if err != nil {
		return nil, err
	}
	if cfg.AppID <= 0 || cfg.InstallationID <= 0 {
		return nil, errors.New("scm: GitHub App ID and installation ID are required")
	}
	der := x509.MarshalPKCS1PrivateKey(k)
	return &githubAppAuth{
		base: cfg.BaseURL, appID: cfg.AppID, instID: cfg.InstallationID, key: k, hc: cfg.HTTP,
		ck: cacheKey("github_app", cfg.BaseURL, strconv.FormatInt(cfg.AppID, 10), strconv.FormatInt(cfg.InstallationID, 10), string(der)),
	}, nil
}

func (a *githubAppAuth) kind() string { return AuthGitHubApp }

func (a *githubAppAuth) authorize(ctx context.Context, req *http.Request) error {
	tok, _, err := sharedTokens.get(ctx, a.ck, a.fetch)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+tok)
	return nil
}

func (a *githubAppAuth) unauthorized(_ context.Context, req *http.Request) (bool, error) {
	sharedTokens.invalidate(a.ck, bearerOf(req))
	return true, nil
}

func (a *githubAppAuth) secret(ctx context.Context) (string, *time.Time, error) {
	tok, exp, err := sharedTokens.get(ctx, a.ck, a.fetch)
	if err != nil {
		return "", nil, err
	}
	return tok, &exp, nil
}

func (a *githubAppAuth) fetch(ctx context.Context) (string, time.Time, error) {
	jwt, err := githubAppJWT(a.key, a.appID, time.Now())
	if err != nil {
		return "", time.Time{}, err
	}
	req, err := http.NewRequest(http.MethodPost, fmt.Sprintf("%s/app/installations/%d/access_tokens", a.base, a.instID), nil)
	if err != nil {
		return "", time.Time{}, errors.New("scm: invalid base URL")
	}
	req.Header.Set("Authorization", "Bearer "+jwt)
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	var out struct {
		Token     string    `json:"token"`
		ExpiresAt time.Time `json:"expires_at"`
	}
	if _, err := doJSON(ctx, a.hc, req, &out); err != nil {
		return "", time.Time{}, err
	}
	if out.Token == "" {
		return "", time.Time{}, ErrAuth
	}
	return out.Token, out.ExpiresAt, nil
}

// githubAppJWT builds the short-lived RS256 JWT that authenticates as the App.
func githubAppJWT(key *rsa.PrivateKey, appID int64, now time.Time) (string, error) {
	enc := base64.RawURLEncoding
	header := enc.EncodeToString([]byte(`{"alg":"RS256","typ":"JWT"}`))
	claims, _ := json.Marshal(map[string]any{
		"iat": now.Add(-60 * time.Second).Unix(), // clock skew allowance
		"exp": now.Add(9 * time.Minute).Unix(),
		"iss": strconv.FormatInt(appID, 10),
	})
	signing := header + "." + enc.EncodeToString(claims)
	sum := sha256.Sum256([]byte(signing))
	sig, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, sum[:])
	if err != nil {
		return "", err
	}
	return signing + "." + enc.EncodeToString(sig), nil
}

// ParseRSAPrivateKey parses a PKCS#1 or PKCS#8 PEM RSA key (GitHub App keys).
func ParseRSAPrivateKey(pemBytes []byte) (*rsa.PrivateKey, error) {
	k, err := parseRSAKey(pemBytes)
	if err != nil {
		return nil, errors.New("scm: GitHub App private key must be an RSA key in PEM format")
	}
	return k, nil
}

// parseRSAKey finds the first private key block in pemBytes.
func parseRSAKey(pemBytes []byte) (*rsa.PrivateKey, error) {
	rest := pemBytes
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			return nil, errors.New("no PEM private key")
		}
		if !strings.Contains(block.Type, "PRIVATE KEY") {
			continue
		}
		if k, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil {
			return k, nil
		}
		k, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, err
		}
		rk, ok := k.(*rsa.PrivateKey)
		if !ok {
			return nil, errors.New("not an RSA key")
		}
		return rk, nil
	}
}

// ---------------------------------------------------------------------------
// Microsoft Entra ID service principal (client credentials).

// entraLoginBase is the Microsoft identity platform authority. A variable
// only so tests can point it at a fake token endpoint.
var entraLoginBase = "https://login.microsoftonline.com"

// AzureDevOpsResource is the Entra ID application ID of Azure DevOps.
const AzureDevOpsResource = "499b84ac-1321-427f-aa17-267ca6975798"

var entraIDRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9.-]{0,99}$`)

type servicePrincipalAuth struct {
	cred  ServicePrincipalCredential
	key   *rsa.PrivateKey // certificate credential
	x5t   string          // base64url SHA-256 thumbprint of the certificate
	scope string
	hc    *http.Client
	ck    string
}

// ParseServicePrincipal validates a stored service principal credential:
// tenant and client IDs, and exactly one of a client secret or a
// certificate with its RSA private key (which must match).
func ParseServicePrincipal(secret []byte) (ServicePrincipalCredential, error) {
	var c ServicePrincipalCredential
	if err := json.Unmarshal(secret, &c); err != nil {
		return c, errors.New("scm: invalid service principal credential")
	}
	if !entraIDRe.MatchString(c.TenantID) || !entraIDRe.MatchString(c.ClientID) {
		return c, errors.New("scm: tenant ID and client ID are required")
	}
	hasCert := c.CertificatePEM != "" || c.PrivateKeyPEM != ""
	switch {
	case c.ClientSecret != "" && hasCert:
		return c, errors.New("scm: provide either a client secret or a certificate, not both")
	case c.ClientSecret == "" && !hasCert:
		return c, errors.New("scm: a client secret or a certificate and private key is required")
	}
	if hasCert {
		if _, _, err := parseCertificateCredential(c); err != nil {
			return c, err
		}
	}
	return c, nil
}

func parseCertificateCredential(c ServicePrincipalCredential) (*rsa.PrivateKey, string, error) {
	var cert *x509.Certificate
	rest := []byte(c.CertificatePEM)
	for cert == nil {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			return nil, "", errors.New("scm: certificate must be PEM encoded")
		}
		if block.Type == "CERTIFICATE" {
			parsed, err := x509.ParseCertificate(block.Bytes)
			if err != nil {
				return nil, "", errors.New("scm: invalid certificate")
			}
			cert = parsed
		}
	}
	keyPEM := c.PrivateKeyPEM
	if keyPEM == "" {
		keyPEM = c.CertificatePEM // combined PEM
	}
	key, err := parseRSAKey([]byte(keyPEM))
	if err != nil {
		return nil, "", errors.New("scm: certificate private key must be an RSA key in PEM format")
	}
	pub, ok := cert.PublicKey.(*rsa.PublicKey)
	if !ok || !pub.Equal(&key.PublicKey) {
		return nil, "", errors.New("scm: private key does not match the certificate")
	}
	sum := sha256.Sum256(cert.Raw)
	return key, base64.RawURLEncoding.EncodeToString(sum[:]), nil
}

func newServicePrincipalAuth(cfg Config) (*servicePrincipalAuth, error) {
	c, err := ParseServicePrincipal(cfg.Secret)
	if err != nil {
		return nil, err
	}
	a := &servicePrincipalAuth{cred: c, scope: AzureDevOpsResource + "/.default", hc: cfg.HTTP}
	material := c.ClientSecret
	if c.ClientSecret == "" {
		if a.key, a.x5t, err = parseCertificateCredential(c); err != nil {
			return nil, err
		}
		material = string(x509.MarshalPKCS1PrivateKey(a.key)) + a.x5t
	}
	a.ck = cacheKey("service_principal", entraLoginBase, c.TenantID, c.ClientID, material, a.scope)
	return a, nil
}

func (a *servicePrincipalAuth) kind() string { return AuthServicePrincipal }

func (a *servicePrincipalAuth) authorize(ctx context.Context, req *http.Request) error {
	tok, _, err := sharedTokens.get(ctx, a.ck, a.fetch)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+tok)
	return nil
}

func (a *servicePrincipalAuth) unauthorized(_ context.Context, req *http.Request) (bool, error) {
	sharedTokens.invalidate(a.ck, bearerOf(req))
	return true, nil
}

func (a *servicePrincipalAuth) secret(ctx context.Context) (string, *time.Time, error) {
	tok, exp, err := sharedTokens.get(ctx, a.ck, a.fetch)
	if err != nil {
		return "", nil, err
	}
	return tok, &exp, nil
}

func (a *servicePrincipalAuth) tokenURL() string {
	return entraLoginBase + "/" + url.PathEscape(a.cred.TenantID) + "/oauth2/v2.0/token"
}

func (a *servicePrincipalAuth) fetch(ctx context.Context) (string, time.Time, error) {
	endpoint := a.tokenURL()
	now := time.Now()
	form := url.Values{
		"client_id":  {a.cred.ClientID},
		"scope":      {a.scope},
		"grant_type": {"client_credentials"},
	}
	if a.key != nil {
		assertion, err := a.assertion(endpoint, now)
		if err != nil {
			return "", time.Time{}, err
		}
		form.Set("client_assertion_type", "urn:ietf:params:oauth:client-assertion-type:jwt-bearer")
		form.Set("client_assertion", assertion)
	} else {
		form.Set("client_secret", a.cred.ClientSecret)
	}
	tr, err := postToken(ctx, a.hc, endpoint, form, "", "")
	if err != nil {
		return "", time.Time{}, err
	}
	return tr.AccessToken, now.Add(time.Duration(tr.expiresIn()) * time.Second), nil
}

// assertion builds the RFC 7523 client assertion signed with the
// certificate key (PS256, x5t#S256 header as Entra ID requires).
func (a *servicePrincipalAuth) assertion(aud string, now time.Time) (string, error) {
	enc := base64.RawURLEncoding
	header, _ := json.Marshal(map[string]string{"alg": "PS256", "typ": "JWT", "x5t#S256": a.x5t})
	jti := make([]byte, 16)
	if _, err := rand.Read(jti); err != nil {
		return "", err
	}
	claims, _ := json.Marshal(map[string]any{
		"aud": aud,
		"iss": a.cred.ClientID,
		"sub": a.cred.ClientID,
		"jti": hex.EncodeToString(jti),
		"nbf": now.Add(-time.Minute).Unix(),
		"iat": now.Unix(),
		"exp": now.Add(10 * time.Minute).Unix(),
	})
	signing := enc.EncodeToString(header) + "." + enc.EncodeToString(claims)
	sum := sha256.Sum256([]byte(signing))
	sig, err := rsa.SignPSS(rand.Reader, a.key, crypto.SHA256, sum[:], &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash})
	if err != nil {
		return "", err
	}
	return signing + "." + enc.EncodeToString(sig), nil
}

// ---------------------------------------------------------------------------
// OAuth (authorization code) tokens with refresh through the TokenStore.

// oauthRefreshSkew refreshes tokens that expire within this window.
const oauthRefreshSkew = 2 * time.Minute

type oauthAuth struct {
	hc    *http.Client
	app   *OAuthApp
	ex    OAuthExchange
	store TokenStore

	mu  sync.Mutex
	tok OAuthToken
}

func newOAuthAuth(cfg Config) (*oauthAuth, error) {
	a := &oauthAuth{hc: cfg.HTTP, app: cfg.OAuth, store: cfg.Tokens}
	if len(cfg.Secret) > 0 {
		if err := json.Unmarshal(cfg.Secret, &a.tok); err != nil || a.tok.AccessToken == "" {
			return nil, errors.New("scm: invalid stored OAuth token")
		}
	} else if cfg.Tokens == nil {
		return nil, errors.New("scm: OAuth token required")
	}
	if ex, err := OAuthFor(cfg.Provider); err == nil {
		a.ex = ex
	} else {
		return nil, err
	}
	return a, nil
}

func (a *oauthAuth) kind() string { return AuthOAuth }

func (a *oauthAuth) canRefresh() bool { return a.store != nil && a.app != nil && a.ex != nil }

func (a *oauthAuth) current(ctx context.Context) (OAuthToken, error) {
	a.mu.Lock()
	tok := a.tok
	a.mu.Unlock()
	if tok.AccessToken == "" && a.store != nil {
		t, err := a.store.Current(ctx)
		if err != nil {
			return OAuthToken{}, err
		}
		tok = t
		a.mu.Lock()
		a.tok = t
		a.mu.Unlock()
	}
	if tok.AccessToken == "" {
		return OAuthToken{}, ErrTokenExpired
	}
	now := time.Now()
	if !tok.Expired(now, oauthRefreshSkew) {
		return tok, nil
	}
	if tok.RefreshToken == "" || !a.canRefresh() {
		if tok.Expired(now, 0) && tok.RefreshToken == "" {
			return OAuthToken{}, ErrTokenExpired
		}
		return tok, nil // no store (tests, one-off checks): use as is
	}
	return a.refresh(ctx, tok.AccessToken, false)
}

// refresh renews the token under the store's lock. The callback is
// idempotent: when another process already stored a newer, valid token it
// is returned unchanged, so a TokenStore may always invoke it.
func (a *oauthAuth) refresh(ctx context.Context, used string, force bool) (OAuthToken, error) {
	nt, err := a.store.RefreshLocked(ctx, func(ctx context.Context, cur OAuthToken) (OAuthToken, error) {
		fresh := cur.AccessToken != "" && !cur.Expired(time.Now(), oauthRefreshSkew)
		if fresh && (!force || cur.AccessToken != used) {
			return cur, nil
		}
		if cur.RefreshToken == "" {
			return cur, ErrTokenExpired
		}
		return a.ex.Refresh(ctx, a.hc, *a.app, cur)
	})
	switch {
	case err == nil:
	case errors.Is(err, ErrTokenExpired):
		return OAuthToken{}, err
	case errors.Is(err, ErrAuth):
		return OAuthToken{}, fmt.Errorf("%w (%w)", ErrTokenExpired, err)
	default:
		return OAuthToken{}, err
	}
	if nt.AccessToken == "" {
		return OAuthToken{}, ErrTokenExpired
	}
	a.mu.Lock()
	a.tok = nt
	a.mu.Unlock()
	return nt, nil
}

func (a *oauthAuth) authorize(ctx context.Context, req *http.Request) error {
	tok, err := a.current(ctx)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+tok.AccessToken)
	return nil
}

func (a *oauthAuth) unauthorized(ctx context.Context, req *http.Request) (bool, error) {
	if !a.canRefresh() {
		return false, nil
	}
	if _, err := a.refresh(ctx, bearerOf(req), true); err != nil {
		return false, err
	}
	return true, nil
}

func (a *oauthAuth) secret(ctx context.Context) (string, *time.Time, error) {
	tok, err := a.current(ctx)
	if err != nil {
		return "", nil, err
	}
	return tok.AccessToken, tok.ExpiresAt, nil
}

// accessToken returns the current access token (for revocation).
func (a *oauthAuth) accessToken() string {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.tok.AccessToken
}
