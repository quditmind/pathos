package identity

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/clientcredentials"
)

// Provisioner creates and disables accounts in the identity provider.
type Provisioner interface {
	// EnsureUser creates the IdP account if needed, asks the IdP to email the
	// user a set-password link, and returns the IdP subject.
	EnsureUser(ctx context.Context, email, displayName string) (subject string, created bool, err error)
	SetEnabled(ctx context.Context, subject string, enabled bool) error
	// Logout ends all IdP sessions of the user.
	Logout(ctx context.Context, subject string) error
}

// KeycloakProvisioner uses the Keycloak Admin REST API with a confidential
// service-account client holding realm-management manage-users.
type KeycloakProvisioner struct {
	BaseURL      string // e.g. http://keycloak:8080/auth
	Realm        string
	ClientID     string
	ClientSecret string
	// RedirectURI and ClientIDForActions control where the set-password email
	// sends the user afterwards.
	ActionsClientID    string
	ActionsRedirectURI string
	// RequireMFA adds CONFIGURE_TOTP to new users' required actions. Once a
	// user has an authenticator, Keycloak's browser flow asks for it on
	// every login.
	RequireMFA bool
	HTTP       *http.Client
}

func (k *KeycloakProvisioner) requiredActions() []string {
	a := []string{"UPDATE_PASSWORD", "VERIFY_EMAIL"}
	if k.RequireMFA {
		a = append(a, "CONFIGURE_TOTP")
	}
	return a
}

func (k *KeycloakProvisioner) client(ctx context.Context) *http.Client {
	base := k.HTTP
	if base == nil {
		base = &http.Client{Timeout: 15 * time.Second}
	}
	cc := clientcredentials.Config{
		ClientID:     k.ClientID,
		ClientSecret: k.ClientSecret,
		TokenURL:     fmt.Sprintf("%s/realms/%s/protocol/openid-connect/token", k.BaseURL, url.PathEscape(k.Realm)),
	}
	ctx = context.WithValue(ctx, oauth2.HTTPClient, base)
	return cc.Client(ctx)
}

func (k *KeycloakProvisioner) admin(path string) string {
	return fmt.Sprintf("%s/admin/realms/%s%s", k.BaseURL, url.PathEscape(k.Realm), path)
}

func (k *KeycloakProvisioner) do(ctx context.Context, method, u string, body any, out any) (*http.Response, error) {
	var rd io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return nil, err
		}
		rd = bytes.NewReader(b)
	}
	// #nosec G704 -- URL is built from operator configuration (PATHOS_KEYCLOAK_ADMIN_URL), never from request input
	req, err := http.NewRequestWithContext(ctx, method, u, rd)
	if err != nil {
		return nil, err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	// #nosec G704 -- same request as above; destination is the configured Keycloak
	resp, err := k.client(ctx).Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 && resp.StatusCode != http.StatusConflict {
		msg, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return resp, fmt.Errorf("keycloak %s %s: %d %s", method, req.URL.Path, resp.StatusCode, strings.TrimSpace(string(msg)))
	}
	if out != nil {
		if err := json.NewDecoder(resp.Body).Decode(out); err != nil {
			return resp, err
		}
	}
	return resp, nil
}

func (k *KeycloakProvisioner) findByEmail(ctx context.Context, email string) (string, error) {
	var users []struct {
		ID    string `json:"id"`
		Email string `json:"email"`
	}
	if _, err := k.do(ctx, http.MethodGet, k.admin("/users?exact=true&email="+url.QueryEscape(email)), nil, &users); err != nil {
		return "", err
	}
	for _, u := range users {
		if strings.EqualFold(u.Email, email) {
			return u.ID, nil
		}
	}
	return "", nil
}

// EnsureUser implements Provisioner.
func (k *KeycloakProvisioner) EnsureUser(ctx context.Context, email, displayName string) (string, bool, error) {
	if id, err := k.findByEmail(ctx, email); err != nil || id != "" {
		return id, false, err
	}
	first, last := splitName(displayName)
	resp, err := k.do(ctx, http.MethodPost, k.admin("/users"), map[string]any{
		"username": email, "email": email, "firstName": first, "lastName": last,
		"enabled": true, "emailVerified": false,
		"requiredActions": k.requiredActions(),
	}, nil)
	if err != nil {
		return "", false, err
	}
	var id string
	if resp.StatusCode == http.StatusConflict {
		id, err = k.findByEmail(ctx, email)
	} else if loc := resp.Header.Get("Location"); loc != "" {
		id = loc[strings.LastIndex(loc, "/")+1:]
	}
	if err != nil || id == "" {
		return "", false, errors.Join(err, errors.New("keycloak did not return the new user id"))
	}
	// Send the set-password email. Failure here (e.g. SMTP not configured)
	// is reported but does not undo the account.
	q := url.Values{"lifespan": {"259200"}} // 72h
	if k.ActionsClientID != "" && k.ActionsRedirectURI != "" {
		q.Set("client_id", k.ActionsClientID)
		q.Set("redirect_uri", k.ActionsRedirectURI)
	}
	if _, err := k.do(ctx, http.MethodPut, k.admin("/users/"+url.PathEscape(id)+"/execute-actions-email?"+q.Encode()),
		k.requiredActions(), nil); err != nil {
		return id, true, fmt.Errorf("account created but invitation email failed: %w", err)
	}
	return id, true, nil
}

// SetEnabled implements Provisioner.
func (k *KeycloakProvisioner) SetEnabled(ctx context.Context, subject string, enabled bool) error {
	_, err := k.do(ctx, http.MethodPut, k.admin("/users/"+url.PathEscape(subject)), map[string]any{"enabled": enabled}, nil)
	return err
}

// Logout implements Provisioner.
func (k *KeycloakProvisioner) Logout(ctx context.Context, subject string) error {
	_, err := k.do(ctx, http.MethodPost, k.admin("/users/"+url.PathEscape(subject)+"/logout"), nil, nil)
	return err
}

func splitName(n string) (string, string) {
	n = strings.TrimSpace(n)
	if i := strings.LastIndexByte(n, ' '); i > 0 {
		return n[:i], n[i+1:]
	}
	return n, ""
}
