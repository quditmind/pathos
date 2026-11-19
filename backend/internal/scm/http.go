package scm

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// StatusError is an unexpected HTTP status from a provider. It wraps one of
// the shared errors (ErrAuth, ErrForbidden, ErrNotFound, ErrRateLimited) when
// the status maps onto one, so errors.Is works. The message names only the
// status and host: never the response body, query string or credentials.
type StatusError struct {
	Code int
	Host string
	kind error
}

func (e *StatusError) Error() string {
	msg := "scm: unexpected response"
	if e.kind != nil {
		msg = e.kind.Error()
	}
	return fmt.Sprintf("%s (HTTP %d from %s)", msg, e.Code, e.Host)
}

// Unwrap returns the shared error the status maps onto (may be nil).
func (e *StatusError) Unwrap() error { return e.kind }

// transportError is a failure to reach the provider (DNS, connect, TLS,
// timeout, reset). The underlying *url.Error is stripped so the request URL
// is not repeated in messages.
type transportError struct {
	host string
	err  error
}

func (e *transportError) Error() string {
	return fmt.Sprintf("scm: request to %s failed: %v", e.host, e.err)
}

func (e *transportError) Unwrap() error { return e.err }

func newTransportError(host string, err error) error {
	var ue *url.Error
	if errors.As(err, &ue) {
		err = ue.Err
	}
	return &transportError{host: host, err: err}
}

// IsTransient reports whether err is worth retrying later: rate limits,
// 5xx responses, timeouts and connection failures. Authentication,
// permission, not-found and SSRF-policy errors are not transient.
func IsTransient(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, ErrBlockedAddress) || errors.Is(err, context.Canceled) {
		return false
	}
	if errors.Is(err, ErrRateLimited) || errors.Is(err, context.DeadlineExceeded) {
		return true
	}
	var se *StatusError
	if errors.As(err, &se) {
		return se.Code >= 500 || se.Code == http.StatusTooManyRequests || se.Code == http.StatusRequestTimeout
	}
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() {
		return true
	}
	if errors.Is(err, io.ErrUnexpectedEOF) || errors.Is(err, syscall.ECONNRESET) || errors.Is(err, syscall.ECONNREFUSED) {
		return true
	}
	var te *transportError
	return errors.As(err, &te)
}

// rateLimited recognizes provider rate-limit signals on a 403 (GitHub
// primary and secondary limits, GitLab).
func rateLimited(h http.Header) bool {
	return h.Get("X-RateLimit-Remaining") == "0" || h.Get("RateLimit-Remaining") == "0" || h.Get("Retry-After") != ""
}

// statusError maps a non-2xx response onto the shared errors.
func statusError(resp *http.Response, host string) error {
	code := resp.StatusCode
	if code < 300 {
		return nil
	}
	e := &StatusError{Code: code, Host: host}
	switch {
	case code == http.StatusUnauthorized:
		e.kind = ErrAuth
	case code == http.StatusForbidden && rateLimited(resp.Header):
		e.kind = ErrRateLimited
	case code == http.StatusForbidden:
		e.kind = ErrForbidden
	case code == http.StatusNotFound:
		e.kind = ErrNotFound
	case code == http.StatusTooManyRequests:
		e.kind = ErrRateLimited
	}
	return e
}

// doJSON performs a request and decodes a JSON response into out. Errors
// wrap the shared errors (errors.Is) and never contain response bodies.
func doJSON(ctx context.Context, c *http.Client, req *http.Request, out any) (*http.Response, error) {
	req = req.WithContext(ctx)
	if req.Header.Get("Accept") == "" {
		req.Header.Set("Accept", "application/json")
	}
	req.Header.Set("User-Agent", "PATHOS-ASPM")
	host := req.URL.Host
	resp, err := c.Do(req)
	if err != nil {
		return nil, newTransportError(host, err)
	}
	defer resp.Body.Close()
	if err := statusError(resp, host); err != nil {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10))
		return resp, err
	}
	// Azure DevOps answers some auth failures with a 203 HTML sign-in page.
	if resp.StatusCode == http.StatusNonAuthoritativeInfo {
		return resp, &StatusError{Code: resp.StatusCode, Host: host, kind: ErrAuth}
	}
	if out == nil {
		return resp, nil
	}
	if ct := resp.Header.Get("Content-Type"); !strings.Contains(ct, "json") {
		return resp, &StatusError{Code: resp.StatusCode, Host: host, kind: ErrAuth}
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 32<<20)).Decode(out); err != nil {
		return resp, fmt.Errorf("scm: invalid response from %s: %w", host, err)
	}
	return resp, nil
}

// api performs authenticated requests for one connection.
type api struct {
	hc      *http.Client
	auth    authorizer
	headers map[string]string
}

// do sends one request. A 401 lets the authorizer refresh its token and the
// request is retried at most once. A 401 on an OAuth connection that could
// not be fixed by a refresh also matches ErrTokenExpired.
func (a *api) do(ctx context.Context, method, rawURL string, body []byte, contentType string, out any) (*http.Response, error) {
	waits := 0
	for attempt := 0; ; attempt++ {
		var rd io.Reader
		if body != nil {
			rd = bytes.NewReader(body)
		}
		req, err := http.NewRequestWithContext(ctx, method, rawURL, rd)
		if err != nil {
			return nil, errors.New("scm: invalid request URL")
		}
		for k, v := range a.headers {
			req.Header.Set(k, v)
		}
		if contentType != "" {
			req.Header.Set("Content-Type", contentType)
		}
		if err := a.auth.authorize(ctx, req); err != nil {
			return nil, err
		}
		resp, err := doJSON(ctx, a.hc, req, out)
		// Listing and other read calls honour the provider's Retry-After
		// on a rate limit (seconds or an HTTP date), never retrying sooner,
		// at most twice and only while the wait fits MaxRetryAfter and the
		// caller's deadline. Writes are not retried here.
		if method == http.MethodGet && errors.Is(err, ErrRateLimited) && resp != nil && waits < 2 {
			if d, ok := RetryAfter(resp.Header, time.Now()); ok && d <= MaxRetryAfter && fitsDeadline(ctx, d) {
				waits++
				attempt--
				t := time.NewTimer(d)
				select {
				case <-ctx.Done():
					t.Stop()
					return resp, err
				case <-t.C:
				}
				continue
			}
		}
		if resp == nil || resp.StatusCode != http.StatusUnauthorized {
			return resp, err
		}
		if attempt == 0 {
			retry, rerr := a.auth.unauthorized(ctx, req)
			if rerr != nil {
				return resp, rerr
			}
			if retry {
				continue
			}
		}
		if a.auth.kind() == AuthOAuth {
			err = fmt.Errorf("%w (%w)", ErrTokenExpired, err)
		}
		return resp, err
	}
}

// MaxRetryAfter is the longest Retry-After a read call waits for before
// giving up with ErrRateLimited (background jobs retry later anyway).
var MaxRetryAfter = 60 * time.Second

// RetryAfter parses a Retry-After header: delay-seconds or an HTTP date
// (RFC 9110 §10.2.3). A date in the past means "now" (0).
func RetryAfter(h http.Header, now time.Time) (time.Duration, bool) {
	v := strings.TrimSpace(h.Get("Retry-After"))
	if v == "" {
		return 0, false
	}
	if n, err := strconv.Atoi(v); err == nil {
		if n < 0 {
			return 0, false
		}
		return time.Duration(n) * time.Second, true
	}
	t, err := http.ParseTime(v)
	if err != nil {
		return 0, false
	}
	if d := t.Sub(now); d > 0 {
		return d, true
	}
	return 0, true
}

func fitsDeadline(ctx context.Context, d time.Duration) bool {
	dl, ok := ctx.Deadline()
	return !ok || time.Until(dl) > d+2*time.Second
}

func (a *api) get(ctx context.Context, rawURL string, out any) (*http.Response, error) {
	return a.do(ctx, http.MethodGet, rawURL, nil, "", out)
}

var linkNext = regexp.MustCompile(`<([^>]+)>;\s*rel="next"`)

// linkHeaderNext returns the rel="next" URL of an RFC 8288 Link header.
func linkHeaderNext(resp *http.Response) string {
	if resp == nil {
		return ""
	}
	m := linkNext.FindStringSubmatch(resp.Header.Get("Link"))
	if m == nil {
		return ""
	}
	return m[1]
}

// sameOrigin reports whether raw is an absolute URL with the scheme and host
// of base and no embedded credentials. Provider-supplied URLs (pagination
// links) are only followed when this holds.
func sameOrigin(base *url.URL, raw string) (*url.URL, bool) {
	u, err := url.Parse(raw)
	if err != nil || u.User != nil || u.Fragment != "" || u.Opaque != "" {
		return nil, false
	}
	if !strings.EqualFold(u.Scheme, base.Scheme) || !strings.EqualFold(u.Host, base.Host) {
		return nil, false
	}
	return u, true
}

// checkNext validates a pagination URL (from a provider response or a page
// token): same origin as the first page and one of the allowed paths. A
// path segment "*" in an allowed URL matches exactly one segment (GitLab
// rewrites group paths to numeric IDs in its Link headers).
func checkNext(next string, allowed ...string) (string, bool) {
	if next == "" {
		return "", false
	}
	for _, a := range allowed {
		first, err := url.Parse(a)
		if err != nil {
			continue
		}
		u, ok := sameOrigin(first, next)
		if ok && pathMatches(first.EscapedPath(), u.EscapedPath()) {
			return u.String(), true
		}
	}
	return "", false
}

func pathMatches(pattern, path string) bool {
	if pattern == path {
		return true
	}
	ps, xs := strings.Split(pattern, "/"), strings.Split(path, "/")
	if len(ps) != len(xs) {
		return false
	}
	for i := range ps {
		if ps[i] != xs[i] && !(ps[i] == "*" && xs[i] != "" && xs[i] != "." && xs[i] != "..") {
			return false
		}
	}
	return true
}

// parseBase parses a configured base URL.
func parseBase(raw string) (*url.URL, error) {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" || (u.Scheme != "https" && u.Scheme != "http") || u.User != nil {
		return nil, errors.New("scm: invalid base URL")
	}
	return u, nil
}

// escapeRef escapes a branch name for use in a URL path, keeping slashes.
func escapeRef(ref string) string {
	parts := strings.Split(ref, "/")
	for i, p := range parts {
		parts[i] = url.PathEscape(p)
	}
	return strings.Join(parts, "/")
}

// splitFullName splits "owner/name" (the last slash separates the name, so
// GitLab subgroups work).
func splitFullName(full string) (string, string, bool) {
	i := strings.LastIndex(full, "/")
	if i <= 0 || i == len(full)-1 {
		return "", "", false
	}
	return full[:i], full[i+1:], true
}

// firstLine returns the first line of a commit message, bounded.
func firstLine(s string) string {
	s, _, _ = strings.Cut(s, "\n")
	s = strings.TrimSpace(s)
	if len(s) > 500 {
		s = s[:500]
	}
	return s
}
