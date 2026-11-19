package main

import (
	"bytes"
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
	"regexp"
	"strings"
	"time"
)

// Response size limits.
const (
	maxJSONResponse = 8 << 20
	maxSBOMResponse = 64 << 20
)

// client calls the PATHOS REST API with a bearer token.
type client struct {
	base  *url.URL
	token string
	http  *http.Client
}

// apiError is an error response of the API.
type apiError struct {
	Status  int
	Code    string
	Message string
}

func (e *apiError) Error() string {
	hint := ""
	switch {
	case e.Code == "token_read_only":
		hint = " (the token has the api:read scope only; create one with api:write)"
	case e.Code == "invalid_token":
		hint = " (the token is wrong, expired or revoked)"
	case e.Status == http.StatusUnauthorized:
		hint = " (set PATHOS_TOKEN to a valid REST API token)"
	case e.Status == http.StatusForbidden:
		hint = " (the token's owner lacks the permission on this repository)"
	}
	msg := e.Message
	if msg == "" {
		msg = http.StatusText(e.Status)
	}
	if e.Code != "" {
		return fmt.Sprintf("%s: %s%s (HTTP %d)", e.Code, msg, hint, e.Status)
	}
	return fmt.Sprintf("%s%s (HTTP %d)", msg, hint, e.Status)
}

// newClient validates the configuration and builds the client.
func (a *app) newClient() (*client, error) {
	if a.client != nil {
		return a.client, nil
	}
	c := a.cfg
	if strings.TrimSpace(c.URL) == "" {
		return nil, errors.New("the PATHOS URL is not set (PATHOS_URL or --url)")
	}
	u, err := url.Parse(strings.TrimRight(strings.TrimSpace(c.URL), "/"))
	if err != nil || u.Host == "" || (u.Scheme != "https" && u.Scheme != "http") {
		return nil, errors.New("the PATHOS URL must be an absolute http(s) URL, for example https://pathos.example.com")
	}
	if u.User != nil {
		return nil, errors.New("the PATHOS URL must not contain credentials")
	}
	if u.Scheme == "http" {
		if !isLoopback(u.Hostname()) && !c.AllowHTTP {
			return nil, errors.New("refusing to send the API token over plain http:// (use https://, or --allow-http on a trusted network)")
		}
		if !isLoopback(u.Hostname()) {
			a.progress("warning: sending the API token over plain http://")
		}
	}
	token := strings.TrimSpace(c.Token)
	if token == "" && c.TokenFile != "" {
		b, err := os.ReadFile(c.TokenFile)
		if err != nil {
			return nil, fmt.Errorf("cannot read the token file: %w", err)
		}
		token = strings.TrimSpace(string(b))
		a.cfg.Token = token
	}
	if token == "" {
		return nil, errors.New("no API token (set PATHOS_TOKEN, --token or --token-file)")
	}
	if strings.ContainsAny(token, " \r\n\t") {
		return nil, errors.New("the API token contains whitespace")
	}
	tlsCfg := &tls.Config{MinVersion: tls.VersionTLS12}
	if c.CACert != "" {
		pem, err := os.ReadFile(c.CACert)
		if err != nil {
			return nil, fmt.Errorf("cannot read the CA certificate: %w", err)
		}
		pool, err := x509.SystemCertPool()
		if err != nil || pool == nil {
			pool = x509.NewCertPool()
		}
		if !pool.AppendCertsFromPEM(pem) {
			return nil, errors.New("the CA certificate file contains no PEM certificate")
		}
		tlsCfg.RootCAs = pool
	}
	tr := http.DefaultTransport.(*http.Transport).Clone()
	tr.TLSClientConfig = tlsCfg
	timeout := c.Timeout
	if timeout <= 0 {
		timeout = 2 * time.Minute
	}
	a.client = &client{base: u, token: token, http: &http.Client{Transport: tr, Timeout: timeout,
		// Never forward the token to another host on redirect.
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 5 {
				return errors.New("too many redirects")
			}
			if req.URL.Host != u.Host || req.URL.Scheme != u.Scheme {
				return errors.New("refusing to follow a redirect to another host")
			}
			return nil
		}}}
	return a.client, nil
}

func isLoopback(host string) bool {
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// do sends a request and returns the response body (bounded) on 2xx.
func (c *client) do(ctx context.Context, method, path string, q url.Values, body io.Reader, contentType string, limit int64) ([]byte, http.Header, error) {
	u := *c.base
	u.Path = strings.TrimRight(c.base.Path, "/") + path
	if q != nil {
		u.RawQuery = q.Encode()
	}
	req, err := http.NewRequestWithContext(ctx, method, u.String(), body)
	if err != nil {
		return nil, nil, err
	}
	req.Header.Set("Authorization", "Bearer "+c.token)
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "pathos-cli/"+version)
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, nil, fmt.Errorf("request to %s failed: %w", c.base.Host, scrubURLError(err))
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, limit+1))
	if err != nil {
		return nil, nil, fmt.Errorf("reading the response failed: %w", err)
	}
	if int64(len(data)) > limit {
		return nil, nil, fmt.Errorf("the response is larger than %d MiB", limit>>20)
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		ae := &apiError{Status: resp.StatusCode}
		var eb struct {
			Error struct {
				Code    string `json:"code"`
				Message string `json:"message"`
			} `json:"error"`
		}
		if json.Unmarshal(data, &eb) == nil {
			ae.Code, ae.Message = eb.Error.Code, eb.Error.Message
		}
		return data, resp.Header, ae
	}
	return data, resp.Header, nil
}

// scrubURLError drops the URL wrapper (it is in the message already).
func scrubURLError(err error) error {
	var ue *url.Error
	if errors.As(err, &ue) {
		return ue.Err
	}
	return err
}

// getJSON GETs path and decodes the JSON response into out.
func (c *client) getJSON(ctx context.Context, path string, q url.Values, out any) error {
	data, _, err := c.do(ctx, http.MethodGet, path, q, nil, "", maxJSONResponse)
	if err != nil {
		return err
	}
	return decode(data, out)
}

// postJSON POSTs body as JSON and decodes the response into out.
func (c *client) postJSON(ctx context.Context, path string, body, out any) error {
	b, err := json.Marshal(body)
	if err != nil {
		return err
	}
	data, _, err := c.do(ctx, http.MethodPost, path, nil, bytes.NewReader(b), "application/json", maxJSONResponse)
	if err != nil {
		return err
	}
	return decode(data, out)
}

func decode(data []byte, out any) error {
	if out == nil {
		return nil
	}
	if err := json.Unmarshal(data, out); err != nil {
		return fmt.Errorf("unexpected response from the server: %w", err)
	}
	return nil
}

var (
	uuidRe    = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)
	repoKeyRe = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9]*-REPO-\d+$`)
)

// repo is the part of a repository object the CLI uses.
type repo struct {
	ID            string `json:"id"`
	FullName      string `json:"full_name"`
	RepositoryKey string `json:"repository_key"`
}

// resolveRepo returns the UUID of a repository given as UUID, Repository
// ID (QD-REPO-000042) or full name (owner/name).
func (c *client) resolveRepo(ctx context.Context, ref string) (string, error) {
	ref = strings.TrimSpace(ref)
	if ref == "" {
		return "", usagef("--repo is required")
	}
	if uuidRe.MatchString(ref) {
		return strings.ToLower(ref), nil
	}
	q := url.Values{"limit": {"100"}}
	byKey := repoKeyRe.MatchString(strings.ToUpper(ref))
	if byKey {
		q.Set("repository_key", ref)
	} else {
		q.Set("q", ref)
	}
	var page struct {
		Items []repo `json:"items"`
	}
	if err := c.getJSON(ctx, "/api/v1/repositories", q, &page); err != nil {
		return "", err
	}
	var hits []repo
	for _, r := range page.Items {
		if (byKey && strings.EqualFold(r.RepositoryKey, ref)) || (!byKey && strings.EqualFold(r.FullName, ref)) {
			hits = append(hits, r)
		}
	}
	switch len(hits) {
	case 0:
		return "", fmt.Errorf("repository %q not found (or not visible to the token's owner)", ref)
	case 1:
		return hits[0].ID, nil
	}
	return "", fmt.Errorf("%q matches %d repositories; use the repository UUID or Repository ID", ref, len(hits))
}
