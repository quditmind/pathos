package scm

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// bitbucketWebBase is the Bitbucket Cloud site (OAuth endpoints). A
// variable only so tests can point it at a fake server.
var bitbucketWebBase = "https://bitbucket.org"

// OAuthError is an error response from a provider's OAuth token endpoint.
// It matches ErrAuth. Only the RFC 6749 error code is kept: descriptions
// are free text from the provider and are not echoed.
type OAuthError struct {
	Code   string
	Status int
}

func (e *OAuthError) Error() string {
	return fmt.Sprintf("scm: the OAuth token endpoint rejected the request (%s, HTTP %d)", e.Code, e.Status)
}

// Unwrap makes OAuthError match ErrAuth.
func (e *OAuthError) Unwrap() error { return ErrAuth }

var oauthCodeRe = regexp.MustCompile(`^[a-z_]{1,64}$`)

type tokenResponse struct {
	AccessToken  string          `json:"access_token"`
	RefreshToken string          `json:"refresh_token"`
	TokenType    string          `json:"token_type"`
	Scope        string          `json:"scope"`
	Scopes       string          `json:"scopes"` // Bitbucket
	ExpiresIn    json.RawMessage `json:"expires_in"`
	Error        string          `json:"error"`
}

// expiresIn accepts a JSON number or string (seconds).
func (t tokenResponse) expiresIn() int64 {
	s := strings.Trim(string(t.ExpiresIn), `"`)
	n, err := strconv.ParseInt(s, 10, 64)
	if err != nil || n < 0 {
		return 0
	}
	return n
}

func (t tokenResponse) token(now time.Time) OAuthToken {
	out := OAuthToken{AccessToken: t.AccessToken, RefreshToken: t.RefreshToken, TokenType: t.TokenType, Scope: t.Scope}
	if out.Scope == "" {
		out.Scope = t.Scopes
	}
	if n := t.expiresIn(); n > 0 {
		exp := now.Add(time.Duration(n) * time.Second).UTC()
		out.ExpiresAt = &exp
	}
	return out
}

// postToken POSTs a form to an OAuth token endpoint. basicUser non-empty
// sends client authentication as HTTP Basic.
func postToken(ctx context.Context, hc *http.Client, endpoint string, form url.Values, basicUser, basicPass string) (tokenResponse, error) {
	var tr tokenResponse
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return tr, errors.New("scm: invalid token endpoint")
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "PATHOS-ASPM")
	if basicUser != "" {
		req.SetBasicAuth(basicUser, basicPass)
	}
	host := req.URL.Host
	resp, err := hc.Do(req)
	if err != nil {
		return tr, newTransportError(host, err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	_ = json.Unmarshal(body, &tr)
	switch {
	case resp.StatusCode >= 500:
		return tokenResponse{}, &StatusError{Code: resp.StatusCode, Host: host}
	case resp.StatusCode == http.StatusTooManyRequests:
		return tokenResponse{}, &StatusError{Code: resp.StatusCode, Host: host, kind: ErrRateLimited}
	case tr.Error != "" || resp.StatusCode >= 300:
		code := tr.Error
		if !oauthCodeRe.MatchString(code) {
			code = "invalid_request"
		}
		return tokenResponse{}, &OAuthError{Code: code, Status: resp.StatusCode}
	case tr.AccessToken == "":
		return tokenResponse{}, &OAuthError{Code: "invalid_response", Status: resp.StatusCode}
	}
	return tr, nil
}

// NewPKCE returns a random RFC 7636 code verifier and its S256 challenge.
func NewPKCE() (verifier, challenge string, err error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", "", err
	}
	verifier = base64.RawURLEncoding.EncodeToString(b)
	return verifier, PKCEChallenge(verifier), nil
}

// PKCEChallenge returns the S256 code challenge of verifier.
func PKCEChallenge(verifier string) string {
	sum := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// DefaultScopes returns the OAuth scopes PATHOS requests per provider.
// Bitbucket scopes are configured on the OAuth consumer, so none are sent.
func DefaultScopes(provider string) string {
	switch provider {
	case GitHub, GitHubEnterprise:
		return "repo read:org"
	case GitLab:
		return "read_api read_repository"
	case AzureDevOps:
		return AzureDevOpsResource + "/.default offline_access"
	}
	return ""
}

// OAuthFor returns the OAuth authorization-code flow for provider.
func OAuthFor(provider string) (OAuthExchange, error) {
	switch provider {
	case GitHub, GitHubEnterprise:
		return githubOAuth{provider: provider}, nil
	case GitLab:
		return gitlabOAuth{}, nil
	case Bitbucket:
		return bitbucketOAuth{}, nil
	case AzureDevOps:
		return entraOAuth{}, nil
	}
	return nil, fmt.Errorf("scm: OAuth is not supported for provider %q", provider)
}

func scopesFor(app OAuthApp, provider string) string {
	if strings.TrimSpace(app.Scopes) != "" {
		return strings.TrimSpace(app.Scopes)
	}
	return DefaultScopes(provider)
}

func checkAuthorizeArgs(app OAuthApp, redirectURI, state, challenge string, pkce bool) error {
	if app.ClientID == "" || redirectURI == "" || state == "" {
		return errors.New("scm: client ID, redirect URI and state are required")
	}
	if pkce && challenge == "" {
		return errors.New("scm: PKCE challenge required")
	}
	return nil
}

// webBase validates a self-managed base URL from an OAuth app and returns it
// without a trailing slash.
func webBase(raw, def string, strip ...string) (string, error) {
	if raw == "" {
		return def, nil
	}
	u, err := parseBase(strings.TrimRight(raw, "/"))
	if err != nil || u.RawQuery != "" || u.Fragment != "" {
		return "", errors.New("scm: invalid OAuth base URL")
	}
	s := strings.TrimRight(u.String(), "/")
	for _, suffix := range strip {
		s = strings.TrimSuffix(s, suffix)
	}
	return s, nil
}

func keepRefreshToken(next OAuthToken, cur OAuthToken) OAuthToken {
	if next.RefreshToken == "" {
		next.RefreshToken = cur.RefreshToken
	}
	return next
}

// --- GitHub (OAuth App) ----------------------------------------------------

// githubOAuth: GitHub OAuth Apps do not support PKCE, so the challenge and
// verifier are ignored. Tokens expire only when the app opted into
// expiring user tokens; then a refresh token is returned.
type githubOAuth struct{ provider string }

// githubWebBase maps an API base URL to the web base: api.github.com →
// github.com, GHE https://host/api/v3 → https://host.
func githubWebBase(base string) (string, error) {
	if base == "" || strings.EqualFold(strings.TrimRight(base, "/"), "https://api.github.com") {
		return "https://github.com", nil
	}
	return webBase(base, "https://github.com", "/api/v3")
}

func (g githubOAuth) AuthorizeURL(app OAuthApp, redirectURI, state, _ string) (string, error) {
	if err := checkAuthorizeArgs(app, redirectURI, state, "", false); err != nil {
		return "", err
	}
	base, err := githubWebBase(app.BaseURL)
	if err != nil {
		return "", err
	}
	q := url.Values{
		"client_id":    {app.ClientID},
		"redirect_uri": {redirectURI},
		"scope":        {scopesFor(app, g.provider)},
		"state":        {state},
		"allow_signup": {"false"},
	}
	return base + "/login/oauth/authorize?" + q.Encode(), nil
}

func (githubOAuth) Exchange(ctx context.Context, hc *http.Client, app OAuthApp, redirectURI, code, _ string) (OAuthToken, error) {
	base, err := githubWebBase(app.BaseURL)
	if err != nil {
		return OAuthToken{}, err
	}
	form := url.Values{
		"client_id":     {app.ClientID},
		"client_secret": {string(app.ClientSecret)},
		"code":          {code},
		"redirect_uri":  {redirectURI},
	}
	tr, err := postToken(ctx, hc, base+"/login/oauth/access_token", form, "", "")
	if err != nil {
		return OAuthToken{}, err
	}
	return tr.token(time.Now()), nil
}

func (githubOAuth) Refresh(ctx context.Context, hc *http.Client, app OAuthApp, cur OAuthToken) (OAuthToken, error) {
	base, err := githubWebBase(app.BaseURL)
	if err != nil {
		return OAuthToken{}, err
	}
	form := url.Values{
		"client_id":     {app.ClientID},
		"client_secret": {string(app.ClientSecret)},
		"grant_type":    {"refresh_token"},
		"refresh_token": {cur.RefreshToken},
	}
	tr, err := postToken(ctx, hc, base+"/login/oauth/access_token", form, "", "")
	if err != nil {
		return OAuthToken{}, err
	}
	return keepRefreshToken(tr.token(time.Now()), cur), nil
}

// --- GitLab ----------------------------------------------------------------

// gitlabOAuth: authorization code + PKCE (S256); refresh tokens rotate.
type gitlabOAuth struct{}

func gitlabWebBase(raw string) (string, error) {
	return webBase(raw, "https://gitlab.com", "/api/v4")
}

func (gitlabOAuth) AuthorizeURL(app OAuthApp, redirectURI, state, challenge string) (string, error) {
	if err := checkAuthorizeArgs(app, redirectURI, state, challenge, true); err != nil {
		return "", err
	}
	base, err := gitlabWebBase(app.BaseURL)
	if err != nil {
		return "", err
	}
	q := url.Values{
		"client_id":             {app.ClientID},
		"redirect_uri":          {redirectURI},
		"response_type":         {"code"},
		"state":                 {state},
		"scope":                 {scopesFor(app, GitLab)},
		"code_challenge":        {challenge},
		"code_challenge_method": {"S256"},
	}
	return base + "/oauth/authorize?" + q.Encode(), nil
}

func (gitlabOAuth) Exchange(ctx context.Context, hc *http.Client, app OAuthApp, redirectURI, code, verifier string) (OAuthToken, error) {
	base, err := gitlabWebBase(app.BaseURL)
	if err != nil {
		return OAuthToken{}, err
	}
	form := url.Values{
		"client_id":     {app.ClientID},
		"code":          {code},
		"grant_type":    {"authorization_code"},
		"redirect_uri":  {redirectURI},
		"code_verifier": {verifier},
	}
	if len(app.ClientSecret) > 0 {
		form.Set("client_secret", string(app.ClientSecret))
	}
	tr, err := postToken(ctx, hc, base+"/oauth/token", form, "", "")
	if err != nil {
		return OAuthToken{}, err
	}
	return tr.token(time.Now()), nil
}

func (gitlabOAuth) Refresh(ctx context.Context, hc *http.Client, app OAuthApp, cur OAuthToken) (OAuthToken, error) {
	base, err := gitlabWebBase(app.BaseURL)
	if err != nil {
		return OAuthToken{}, err
	}
	form := url.Values{
		"client_id":     {app.ClientID},
		"grant_type":    {"refresh_token"},
		"refresh_token": {cur.RefreshToken},
	}
	if len(app.ClientSecret) > 0 {
		form.Set("client_secret", string(app.ClientSecret))
	}
	tr, err := postToken(ctx, hc, base+"/oauth/token", form, "", "")
	if err != nil {
		return OAuthToken{}, err
	}
	return keepRefreshToken(tr.token(time.Now()), cur), nil
}

// --- Bitbucket Cloud ---------------------------------------------------------

// bitbucketOAuth: OAuth consumer, client authentication with HTTP Basic.
// Bitbucket does not document PKCE, so it is not used; scopes are set on
// the consumer.
type bitbucketOAuth struct{}

func (bitbucketOAuth) AuthorizeURL(app OAuthApp, redirectURI, state, _ string) (string, error) {
	if err := checkAuthorizeArgs(app, redirectURI, state, "", false); err != nil {
		return "", err
	}
	q := url.Values{
		"client_id":     {app.ClientID},
		"response_type": {"code"},
		"state":         {state},
		"redirect_uri":  {redirectURI},
	}
	if s := scopesFor(app, Bitbucket); s != "" {
		q.Set("scope", s)
	}
	return bitbucketWebBase + "/site/oauth2/authorize?" + q.Encode(), nil
}

func (bitbucketOAuth) Exchange(ctx context.Context, hc *http.Client, app OAuthApp, redirectURI, code, _ string) (OAuthToken, error) {
	form := url.Values{"grant_type": {"authorization_code"}, "code": {code}, "redirect_uri": {redirectURI}}
	tr, err := postToken(ctx, hc, bitbucketWebBase+"/site/oauth2/access_token", form, app.ClientID, string(app.ClientSecret))
	if err != nil {
		return OAuthToken{}, err
	}
	return tr.token(time.Now()), nil
}

func (bitbucketOAuth) Refresh(ctx context.Context, hc *http.Client, app OAuthApp, cur OAuthToken) (OAuthToken, error) {
	form := url.Values{"grant_type": {"refresh_token"}, "refresh_token": {cur.RefreshToken}}
	tr, err := postToken(ctx, hc, bitbucketWebBase+"/site/oauth2/access_token", form, app.ClientID, string(app.ClientSecret))
	if err != nil {
		return OAuthToken{}, err
	}
	return keepRefreshToken(tr.token(time.Now()), cur), nil
}

// --- Microsoft Entra ID (Azure DevOps Services, delegated) ------------------

// entraOAuth: authorization code + PKCE against the Microsoft identity
// platform v2.0 endpoints of the app's tenant ("organizations" if unset).
type entraOAuth struct{}

func entraTenant(app OAuthApp) (string, error) {
	t := app.TenantID
	if t == "" {
		t = "organizations"
	}
	if !entraIDRe.MatchString(t) {
		return "", errors.New("scm: invalid tenant ID")
	}
	return t, nil
}

func (entraOAuth) AuthorizeURL(app OAuthApp, redirectURI, state, challenge string) (string, error) {
	if err := checkAuthorizeArgs(app, redirectURI, state, challenge, true); err != nil {
		return "", err
	}
	tenant, err := entraTenant(app)
	if err != nil {
		return "", err
	}
	q := url.Values{
		"client_id":             {app.ClientID},
		"response_type":         {"code"},
		"redirect_uri":          {redirectURI},
		"response_mode":         {"query"},
		"scope":                 {scopesFor(app, AzureDevOps)},
		"state":                 {state},
		"code_challenge":        {challenge},
		"code_challenge_method": {"S256"},
	}
	return entraLoginBase + "/" + url.PathEscape(tenant) + "/oauth2/v2.0/authorize?" + q.Encode(), nil
}

func (entraOAuth) token(ctx context.Context, hc *http.Client, app OAuthApp, form url.Values) (OAuthToken, error) {
	tenant, err := entraTenant(app)
	if err != nil {
		return OAuthToken{}, err
	}
	form.Set("client_id", app.ClientID)
	form.Set("scope", scopesFor(app, AzureDevOps))
	if len(app.ClientSecret) > 0 {
		form.Set("client_secret", string(app.ClientSecret))
	}
	tr, err := postToken(ctx, hc, entraLoginBase+"/"+url.PathEscape(tenant)+"/oauth2/v2.0/token", form, "", "")
	if err != nil {
		return OAuthToken{}, err
	}
	return tr.token(time.Now()), nil
}

func (e entraOAuth) Exchange(ctx context.Context, hc *http.Client, app OAuthApp, redirectURI, code, verifier string) (OAuthToken, error) {
	return e.token(ctx, hc, app, url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"redirect_uri":  {redirectURI},
		"code_verifier": {verifier},
	})
}

func (e entraOAuth) Refresh(ctx context.Context, hc *http.Client, app OAuthApp, cur OAuthToken) (OAuthToken, error) {
	t, err := e.token(ctx, hc, app, url.Values{"grant_type": {"refresh_token"}, "refresh_token": {cur.RefreshToken}})
	if err != nil {
		return OAuthToken{}, err
	}
	return keepRefreshToken(t, cur), nil
}
