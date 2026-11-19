package connectors

import (
	"context"
	"crypto/x509"
	"errors"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strings"

	"pathos/internal/ai"
	"pathos/internal/platform/crypto"
	"pathos/internal/platform/logging"
	"pathos/internal/runtimectx"
	"pathos/internal/scm"
	"pathos/internal/tickets"
	"pathos/internal/vault"
)

// Classify maps a check failure onto the error catalogue. The mapping is
// deterministic code, never AI (integration spec, "Health and AI
// troubleshooting flow"). Kind-specific codes are chosen by the checkers;
// this covers the shared PTH-CONN-10xx range.
func Classify(err error) string {
	if err == nil {
		return ""
	}
	var (
		he  *tickets.HTTPError
		ke  *runtimectx.APIError
		re  *runtimectx.RegistryError
		ua  x509.UnknownAuthorityError
		ci  x509.CertificateInvalidError
		hn  x509.HostnameError
		sys *x509.SystemRootsError
		ne  net.Error
		dns *net.DNSError
		op  *net.OpError
		pe  *ai.ProviderStatusError
	)
	switch {
	case errors.Is(err, crypto.ErrDecrypt):
		return "PTH-CONN-1016"
	case errors.Is(err, scm.ErrPlainHTTP):
		return "PTH-CONN-1019"
	case errors.Is(err, ErrProxy), strings.Contains(err.Error(), "proxyconnect"):
		return "PTH-CONN-1006"
	}
	if c := vault.DiagCode(err); c != "" && c != "PTH-CONN-1012" && c != "PTH-CONN-1004" {
		return c
	}
	switch {
	case errors.As(err, &ua), errors.As(err, &sys):
		return "PTH-CONN-1004"
	case errors.As(err, &ci), errors.As(err, &hn):
		return "PTH-CONN-1005"
	case errors.As(err, &he):
		if he.Unreadable {
			return "PTH-CONN-1013"
		}
		return CodeForStatus(he.Status)
	case errors.As(err, &ke):
		return CodeForStatus(ke.Status)
	case errors.As(err, &re):
		return CodeForStatus(re.Status)
	case errors.As(err, &pe):
		return CodeForStatus(pe.Status)
	case errors.Is(err, ai.ErrAuth):
		return "PTH-CONN-1007"
	case errors.Is(err, ai.ErrRateLimited):
		return "PTH-CONN-1010"
	case errors.Is(err, context.DeadlineExceeded), errors.As(err, &ne) && ne.Timeout():
		return "PTH-CONN-1002"
	case errors.As(err, &dns), errors.As(err, &op):
		return "PTH-CONN-1001"
	}
	if c := vault.DiagCode(err); c != "" {
		return c
	}
	if errors.Is(err, ErrUnexpectedResponse) {
		return "PTH-CONN-1013"
	}
	return "PTH-CONN-1012"
}

// CodeForStatus maps an HTTP status of the vendor onto a shared code.
func CodeForStatus(status int) string {
	switch {
	case status == http.StatusUnauthorized:
		return "PTH-CONN-1007"
	case status == http.StatusForbidden:
		return "PTH-CONN-1009"
	case status == http.StatusNotFound:
		return "PTH-CONN-1011"
	case status == http.StatusTooManyRequests:
		return "PTH-CONN-1010"
	case status == http.StatusRequestTimeout || status == http.StatusGatewayTimeout:
		return "PTH-CONN-1002"
	case status >= 500:
		return "PTH-CONN-1012"
	case status >= 300 && status < 400:
		return "PTH-CONN-1013"
	}
	return "PTH-CONN-1012"
}

// ErrUnexpectedResponse is a response PATHOS cannot read (wrong content
// type, invalid JSON: often a sign-in page or a wrong base URL).
var ErrUnexpectedResponse = errors.New("unexpected response format")

// ErrProxy is a failure of the HTTP proxy itself (CONNECT refused).
var ErrProxy = errors.New("proxy refused or failed the connection")

var (
	urlRe   = regexp.MustCompile(`(?i)\b(https?|wss?)://[^\s"'<>]+`)
	emailRe = regexp.MustCompile(`[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}`)
)

// Redact prepares a message for storage, display and AI context: URLs are
// reduced to scheme and host (a Slack or Teams URL is a credential, a query
// can carry a token), e-mail addresses removed, secrets stripped by the
// shared log redaction, and the size bounded.
func Redact(s string) string {
	s = urlRe.ReplaceAllStringFunc(s, func(m string) string {
		u, err := url.Parse(strings.TrimRight(m, ".,;:)"))
		if err != nil || u.Host == "" {
			return "[url]"
		}
		return u.Scheme + "://" + u.Host
	})
	s = emailRe.ReplaceAllString(s, "[e-mail]")
	s = logging.RedactString(ai.Redact(s, nil))
	s = strings.TrimSpace(s)
	if len(s) > 1000 {
		s = s[:1000]
	}
	return s
}

// HostOf returns scheme://host of a URL ("" when it does not parse).
func HostOf(raw string) string {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || u.Host == "" {
		return ""
	}
	return u.Scheme + "://" + u.Host
}
