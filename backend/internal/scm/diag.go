package scm

import (
	"context"
	"crypto/x509"
	"errors"
	"net"
)

// DiagCode returns the error catalogue code (backend/internal/platform/diag)
// of a provider error, or "" when err is not a provider error.
func DiagCode(err error) string {
	var (
		se  *StatusError
		te  *transportError
		ua  x509.UnknownAuthorityError
		ci  x509.CertificateInvalidError
		he  x509.HostnameError
		ne  net.Error
		sys *x509.SystemRootsError
	)
	switch {
	case err == nil:
		return ""
	case errors.Is(err, ErrBlockedAddress):
		return "PTH-CONN-1003"
	case errors.Is(err, ErrTokenExpired):
		return "PTH-CONN-1008"
	case errors.Is(err, ErrHostKeyMismatch):
		return "PTH-CONN-1140"
	case errors.Is(err, ErrGitAuth):
		return "PTH-CONN-1141"
	case errors.Is(err, ErrAuth):
		return "PTH-CONN-1007"
	case errors.Is(err, ErrRateLimited):
		return "PTH-CONN-1010"
	case errors.Is(err, ErrTokenPermission):
		return "PTH-CONN-1124"
	case errors.Is(err, ErrVersionUnsupported):
		return versionCode(err)
	case errors.Is(err, ErrForbidden):
		return "PTH-CONN-1009"
	case errors.Is(err, ErrNotFound):
		return "PTH-CONN-1011"
	case errors.Is(err, ErrNotSupported):
		return "PTH-CONN-1020"
	case errors.Is(err, ErrInvalidPageToken):
		return "PTH-SYNC-1003"
	case errors.Is(err, ErrSignature):
		return "PTH-CONN-1017"
	case errors.As(err, &ua), errors.As(err, &ci), errors.As(err, &he), errors.As(err, &sys):
		return "PTH-CONN-1004"
	case errors.Is(err, context.DeadlineExceeded), errors.As(err, &ne) && ne.Timeout():
		return "PTH-CONN-1002"
	case errors.As(err, &te):
		return "PTH-CONN-1001"
	case errors.As(err, &se):
		return "PTH-CONN-1012"
	}
	return ""
}
