package scm

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"math/big"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"
)

type entraFake struct {
	certKey *rsa.PublicKey
	x5t     string
}

// azureServer serves Azure DevOps (organization-less layout under /, plus
// a Server collection under /tfs/DefaultCollection), the VSSPS profile and
// accounts APIs under /vssps, and an Entra ID token endpoint under /login.
func azureServer(t *testing.T, e *entraFake) *fake {
	repos := []map[string]any{
		{"id": "guid-1", "name": "api", "remoteUrl": "https://dev.azure.com/acme/Shop/_git/api", "webUrl": "https://dev.azure.com/acme/Shop/_git/api",
			"defaultBranch": "refs/heads/main", "size": 1234, "project": map[string]string{"id": "p1", "name": "Shop", "visibility": "private"}},
		{"id": "guid-2", "name": "web", "defaultBranch": "refs/heads/main", "project": map[string]string{"id": "p1", "name": "Shop", "visibility": "public"}},
		{"id": "guid-3", "name": "apidocs", "isDisabled": true, "project": map[string]string{"id": "p2", "name": "Docs"}},
	}
	return newFake(t, func(f *fake, w http.ResponseWriter, r *http.Request) {
		p := r.URL.Path
		if strings.HasPrefix(p, "/login/") {
			_ = r.ParseForm()
			form := r.Form
			if p != "/login/tenant-1/oauth2/v2.0/token" || form.Get("client_id") != "app-1" ||
				form.Get("scope") != AzureDevOpsResource+"/.default" || form.Get("grant_type") != "client_credentials" {
				t.Errorf("token request %s %v", p, form)
				w.WriteHeader(400)
				return
			}
			switch {
			case form.Get("client_secret") == "s3cret":
				jsonResp(w, map[string]any{"access_token": "sp-secret-tok", "expires_in": 3599, "token_type": "Bearer"})
			case form.Get("client_assertion") != "":
				if form.Get("client_assertion_type") != "urn:ietf:params:oauth:client-assertion-type:jwt-bearer" {
					t.Error("assertion type")
				}
				if err := verifyAssertion(e, form.Get("client_assertion"), "http://"+r.Host+p); err != nil {
					t.Errorf("assertion: %v", err)
					w.Header().Set("Content-Type", "application/json")
					w.WriteHeader(401)
					_, _ = w.Write([]byte(`{"error":"invalid_client"}`))
					return
				}
				jsonResp(w, map[string]any{"access_token": "sp-cert-tok", "expires_in": "3599", "token_type": "Bearer"})
			default:
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(401)
				_, _ = w.Write([]byte(`{"error":"invalid_client","error_description":"secret-body-should-not-leak"}`))
			}
			return
		}
		_, pass, _ := r.BasicAuth()
		tok := bearer(r)
		if pass != "adopat" && tok != "ado-oauth" && tok != "sp-secret-tok" && tok != "sp-cert-tok" {
			w.Header().Set("Content-Type", "text/html")
			w.WriteHeader(203)
			return
		}
		q := r.URL.Query()
		if strings.HasPrefix(p, "/vssps/") {
			if q.Get("api-version") != adoVSSPSAPIVersion {
				t.Errorf("vssps api-version: %s", r.URL.RawQuery)
			}
			switch p {
			case "/vssps/_apis/profile/profiles/me":
				jsonResp(w, map[string]string{"id": "member-1", "displayName": "Ada"})
			case "/vssps/_apis/accounts":
				if q.Get("memberId") != "member-1" {
					t.Errorf("memberId: %s", r.URL.RawQuery)
				}
				jsonResp(w, map[string]any{"count": 2, "value": []map[string]string{{"accountId": "a2", "accountName": "beta"}, {"accountId": "a1", "accountName": "acme"}}})
			default:
				status(w, 404)
			}
			return
		}
		if q.Get("api-version") != "7.1" {
			t.Errorf("api-version missing: %s", r.URL.RequestURI())
		}
		p = strings.TrimPrefix(p, "/tfs/DefaultCollection")
		switch p {
		case "/acme/_apis/projects", "/_apis/projects":
			if q.Get("continuationToken") == "" && q.Get("$top") == "100" {
				w.Header().Set("X-Ms-Continuationtoken", "page2")
				jsonResp(w, map[string]any{"value": []map[string]string{{"id": "p1", "name": "Shop"}}})
				return
			}
			jsonResp(w, map[string]any{"value": []map[string]string{{"id": "p2", "name": "Docs", "description": "docs"}}})
		case "/acme/_apis/git/repositories", "/_apis/git/repositories":
			jsonResp(w, map[string]any{"value": repos})
		case "/beta/_apis/git/repositories":
			jsonResp(w, map[string]any{"value": []any{}})
		case "/acme/Shop/_apis/git/repositories":
			jsonResp(w, map[string]any{"value": repos[:2]})
		case "/acme/Shop/_apis/git/repositories/guid-1", "/acme/_apis/git/repositories/guid-1", "/Shop/_apis/git/repositories/guid-1":
			jsonResp(w, repos[0])
		case "/acme/Shop/_apis/git/repositories/guid-404":
			status(w, 404)
		case "/acme/Shop/_apis/git/repositories/guid-1/refs", "/Shop/_apis/git/repositories/guid-1/refs":
			if q.Get("filter") != "heads/" {
				t.Errorf("refs filter: %s", r.URL.RawQuery)
			}
			jsonResp(w, map[string]any{"value": []map[string]string{{"name": "refs/heads/main", "objectId": "c1"}, {"name": "refs/heads/dev", "objectId": "c2"}}})
		case "/acme/Shop/_apis/git/repositories/guid-1/commits":
			if q.Get("searchCriteria.itemVersion.version") != "main" || q.Get("searchCriteria.$top") != "1" {
				t.Errorf("commits query: %s", r.URL.RawQuery)
			}
			jsonResp(w, map[string]any{"value": []map[string]any{{"commitId": "c1", "comment": "Merged PR 5\nbody",
				"author": map[string]string{"name": "Ada", "date": "2026-01-01T00:00:00Z"}}}})
		default:
			status(w, 404)
		}
	})
}

func verifyAssertion(e *entraFake, jwt, aud string) error {
	parts := strings.Split(jwt, ".")
	if len(parts) != 3 {
		return errors.New("not a JWT")
	}
	var header map[string]string
	var claims map[string]any
	hb, _ := base64.RawURLEncoding.DecodeString(parts[0])
	cb, _ := base64.RawURLEncoding.DecodeString(parts[1])
	if json.Unmarshal(hb, &header) != nil || json.Unmarshal(cb, &claims) != nil {
		return errors.New("bad JSON")
	}
	if header["alg"] != "PS256" || header["x5t#S256"] != e.x5t {
		return errors.New("bad header")
	}
	if claims["aud"] != aud || claims["iss"] != "app-1" || claims["sub"] != "app-1" || claims["jti"] == "" {
		return errors.New("bad claims")
	}
	if exp, _ := claims["exp"].(float64); int64(exp) <= time.Now().Unix() {
		return errors.New("expired")
	}
	sig, _ := base64.RawURLEncoding.DecodeString(parts[2])
	sum := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	return rsa.VerifyPSS(e.certKey, crypto.SHA256, sum[:], sig, &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash})
}

func selfSignedCert(t *testing.T) (*rsa.PrivateKey, []byte, []byte) {
	t.Helper()
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	tpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "pathos"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, _ := x509.MarshalPKCS8PrivateKey(key)
	return key, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
}

func withAzureFakes(t *testing.T, srv *fake) {
	u, _ := url.Parse(srv.URL)
	oldHost, oldVSSPS, oldLogin := adoServicesHost, adoVSSPSBase, entraLoginBase
	adoServicesHost, adoVSSPSBase, entraLoginBase = u.Host, srv.URL+"/vssps", srv.URL+"/login"
	t.Cleanup(func() { adoServicesHost, adoVSSPSBase, entraLoginBase = oldHost, oldVSSPS, oldLogin })
}

func TestAzureDevOpsOrganizationless(t *testing.T) {
	key, certPEM, keyPEM := selfSignedCert(t)
	_ = key
	e := &entraFake{certKey: &key.PublicKey}
	blk, _ := pem.Decode(certPEM)
	sum := sha256.Sum256(blk.Bytes)
	e.x5t = base64.RawURLEncoding.EncodeToString(sum[:])
	srv := azureServer(t, e)
	withAzureFakes(t, srv)
	ctx := context.Background()

	spSecret, _ := json.Marshal(ServicePrincipalCredential{TenantID: "tenant-1", ClientID: "app-1", ClientSecret: "s3cret"})
	spCert, _ := json.Marshal(ServicePrincipalCredential{TenantID: "tenant-1", ClientID: "app-1", CertificatePEM: string(certPEM), PrivateKeyPEM: string(keyPEM)})
	spCombined, _ := json.Marshal(ServicePrincipalCredential{TenantID: "tenant-1", ClientID: "app-1", CertificatePEM: string(certPEM) + string(keyPEM)})

	for _, tc := range []struct {
		name  string
		cfg   Config
		token string
	}{
		{name: "pat", cfg: Config{AuthType: AuthPAT, Secret: []byte("adopat")}, token: "adopat"},
		{name: "oauth", cfg: Config{AuthType: AuthOAuth, Secret: tokenJSON(t, OAuthToken{AccessToken: "ado-oauth", ExpiresAt: future(time.Hour)})}, token: "ado-oauth"},
		{name: "sp secret", cfg: Config{AuthType: AuthServicePrincipal, Secret: spSecret, Organizations: []string{"acme"}}, token: "sp-secret-tok"},
		{name: "sp certificate", cfg: Config{AuthType: AuthServicePrincipal, Secret: spCert, Organizations: []string{"acme"}}, token: "sp-cert-tok"},
		{name: "sp combined pem", cfg: Config{AuthType: AuthServicePrincipal, Secret: spCombined, Organizations: []string{"acme"}}, token: "sp-cert-tok"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := tc.cfg
			cfg.Provider, cfg.BaseURL, cfg.HTTP = AzureDevOps, srv.URL, srv.Client()
			c := mustNew(t, cfg)
			if _, err := c.Check(ctx); err != nil {
				t.Fatalf("check: %v", err)
			}
			orgs, err := c.ListOrganizations(ctx)
			if err != nil || len(orgs) == 0 || orgs[0].Name != "acme" {
				t.Fatalf("orgs: %+v %v", orgs, err)
			}
			projects, err := c.ListProjects(ctx, "acme")
			if err != nil || len(projects) != 2 || projects[1].Name != "Docs" {
				t.Fatalf("projects (continuation): %+v %v", projects, err)
			}
			q := RepoQuery{Organization: "acme", Search: "API", PageSize: 1}
			p1, err := c.ListRepositoriesPage(ctx, q)
			if err != nil || len(p1.Items) != 1 || p1.Items[0].Name != "apidocs" || p1.NextPageToken == "" {
				t.Fatalf("page 1: %+v %v", p1, err)
			}
			q.PageToken = p1.NextPageToken
			p2, err := c.ListRepositoriesPage(ctx, q)
			if err != nil || len(p2.Items) != 1 || p2.Items[0].Name != "api" || p2.NextPageToken != "" {
				t.Fatalf("page 2: %+v %v", p2, err)
			}
			r := p2.Items[0]
			if r.Organization != "acme" || r.Project != "Shop" || r.SizeBytes != 1234 || r.DefaultBranch != "main" || r.ExternalID != "guid-1" {
				t.Errorf("mapping: %+v", r)
			}
			assertInvalidTokens(t, c, AzureDevOps, RepoQuery{Organization: "acme", Search: "API", PageSize: 1}, srv.URL)
			bad := q
			bad.PageToken = encodeCursor(AzureDevOps, q, srv.URL+"/acme/_apis/git/repositories", 1)
			if _, err := c.ListRepositoriesPage(ctx, bad); !errors.Is(err, ErrInvalidPageToken) {
				t.Errorf("URL cursor must be rejected for Azure: %v", err)
			}
			if p, err := c.ListRepositoriesPage(ctx, RepoQuery{Organization: "acme", Project: "Shop"}); err != nil || len(p.Items) != 2 {
				t.Fatalf("project filter: %+v %v", p, err)
			}
			if _, err := c.GetRepository(ctx, RepoRef{ExternalID: "guid-404", Organization: "acme", Project: "Shop"}); !errors.Is(err, ErrNotFound) {
				t.Errorf("404: %v", err)
			}
			if _, err := c.GetRepository(ctx, RepoRef{ExternalID: "guid-1", Organization: "../x"}); err == nil {
				t.Error("invalid organization accepted")
			}
			d, err := Details(ctx, c, r.Ref())
			if err != nil || len(d.Branches) != 2 || !d.Branches[0].Default || d.LatestCommit == nil || d.LatestCommit.Message != "Merged PR 5" || d.Permission != "unknown" {
				t.Fatalf("details: %+v %v", d, err)
			}
			cred, err := c.CloneCredential(ctx)
			if err != nil || cred.Username != "pathos" || cred.Token != tc.token {
				t.Errorf("clone: %+v %v", cred, err)
			}
			if err := c.Revoke(ctx); err != nil {
				t.Error(err)
			}
		})
	}
	// Service principal tokens are cached process-wide: one token request
	// per credential although several clients made many API calls.
	if n := srv.count("POST /login/tenant-1/oauth2/v2.0/token"); n != 2 {
		t.Errorf("want 2 token requests (secret + certificate), got %d", n)
	}

	// A service principal without configured organizations cannot discover them.
	c := mustNew(t, Config{Provider: AzureDevOps, BaseURL: srv.URL, AuthType: AuthServicePrincipal, Secret: spSecret, HTTP: srv.Client()})
	if _, err := c.ListOrganizations(ctx); !errors.Is(err, ErrNotSupported) {
		t.Errorf("want ErrNotSupported, got %v", err)
	}
	// Wrong client secret → ErrAuth without the provider's description.
	wrong, _ := json.Marshal(ServicePrincipalCredential{TenantID: "tenant-1", ClientID: "app-1", ClientSecret: "nope"})
	c = mustNew(t, Config{Provider: AzureDevOps, BaseURL: srv.URL, AuthType: AuthServicePrincipal, Secret: wrong, Organizations: []string{"acme"}, HTTP: srv.Client()})
	_, err := c.Check(ctx)
	if !errors.Is(err, ErrAuth) {
		t.Errorf("want ErrAuth, got %v", err)
	}
	assertNoLeak(t, err, "nope")

	// Invalid service principal credentials are rejected up front.
	_, otherCert, _ := selfSignedCert(t)
	for name, sp := range map[string]ServicePrincipalCredential{
		"no secret":    {TenantID: "tenant-1", ClientID: "app-1"},
		"both":         {TenantID: "tenant-1", ClientID: "app-1", ClientSecret: "x", CertificatePEM: string(certPEM), PrivateKeyPEM: string(keyPEM)},
		"bad tenant":   {TenantID: "../evil", ClientID: "app-1", ClientSecret: "x"},
		"key mismatch": {TenantID: "tenant-1", ClientID: "app-1", CertificatePEM: string(otherCert), PrivateKeyPEM: string(keyPEM)},
		"no key":       {TenantID: "tenant-1", ClientID: "app-1", CertificatePEM: string(certPEM)},
		"garbage cert": {TenantID: "tenant-1", ClientID: "app-1", CertificatePEM: "nope", PrivateKeyPEM: string(keyPEM)},
	} {
		b, _ := json.Marshal(sp)
		if _, err := New(Config{Provider: AzureDevOps, BaseURL: srv.URL, AuthType: AuthServicePrincipal, Secret: b, HTTP: srv.Client()}); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestAzureDevOpsLegacyAndServer(t *testing.T) {
	srv := azureServer(t, &entraFake{})
	withAzureFakes(t, srv)
	ctx := context.Background()

	// Legacy: the organization is part of the base URL.
	c := mustNew(t, Config{Provider: AzureDevOps, BaseURL: srv.URL + "/acme", AuthType: AuthPAT, Secret: []byte("adopat"), HTTP: srv.Client()})
	orgs, err := c.ListOrganizations(ctx)
	if err != nil || len(orgs) != 1 || orgs[0].Name != "acme" {
		t.Fatalf("legacy orgs: %+v %v", orgs, err)
	}
	repos, err := c.ListRepositories(ctx)
	if err != nil || len(repos) != 3 || repos[0].Organization != "acme" {
		t.Fatalf("legacy list: %+v %v", repos, err)
	}
	if _, err := c.GetRepository(ctx, RepoRef{ExternalID: "guid-1", FullName: "Shop/api"}); err != nil {
		t.Fatalf("legacy get: %v", err)
	}

	// Organization-less with OAuth: organizations come from the profile API,
	// and ListRepositories walks all of them.
	c = mustNew(t, Config{Provider: AzureDevOps, BaseURL: srv.URL, AuthType: AuthOAuth, Secret: tokenJSON(t, OAuthToken{AccessToken: "ado-oauth"}), HTTP: srv.Client()})
	orgs, err = c.ListOrganizations(ctx)
	if err != nil || len(orgs) != 2 || orgs[0].Name != "acme" || orgs[1].Name != "beta" {
		t.Fatalf("profile orgs: %+v %v", orgs, err)
	}
	if repos, err := c.ListRepositories(ctx); err != nil || len(repos) != 3 {
		t.Fatalf("orgless list: %v %v", repos, err)
	}
	if _, err := c.ListRepositoriesPage(ctx, RepoQuery{}); err == nil {
		t.Error("organization must be required when several are visible")
	}

	// Server: collection in the base URL, PAT only.
	c = mustNew(t, Config{Provider: AzureDevOpsServer, BaseURL: srv.URL + "/tfs/DefaultCollection", AuthType: AuthPAT, Secret: []byte("adopat"), HTTP: srv.Client()})
	orgs, err = c.ListOrganizations(ctx)
	if err != nil || len(orgs) != 1 || orgs[0].Name != "DefaultCollection" || orgs[0].Kind != "collection" {
		t.Fatalf("server orgs: %+v %v", orgs, err)
	}
	if p, err := c.ListRepositoriesPage(ctx, RepoQuery{}); err != nil || len(p.Items) != 3 {
		t.Fatalf("server repos: %+v %v", p, err)
	}
	if projects, err := c.ListProjects(ctx, ""); err != nil || len(projects) != 2 {
		t.Fatalf("server projects: %+v %v", projects, err)
	}
	if _, err := New(Config{Provider: AzureDevOpsServer, BaseURL: srv.URL, AuthType: AuthOAuth, Secret: []byte(`{"access_token":"x"}`), HTTP: srv.Client()}); err == nil {
		t.Error("Azure DevOps Server must be PAT only")
	}
	bad := mustNew(t, Config{Provider: AzureDevOpsServer, BaseURL: srv.URL + "/tfs/DefaultCollection", AuthType: AuthPAT, Secret: []byte("x"), HTTP: srv.Client()})
	if _, err := bad.Check(ctx); !errors.Is(err, ErrAuth) {
		t.Errorf("203 sign-in page must map to ErrAuth: %v", err)
	}
}
