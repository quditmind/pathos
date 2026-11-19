package scm

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"testing"

	"pathos/internal/platform/diag"
)

func TestDiagCode(t *testing.T) {
	cases := map[string]error{
		"PTH-CONN-1003": fmt.Errorf("dial: %w", ErrBlockedAddress),
		"PTH-CONN-1008": ErrTokenExpired,
		"PTH-CONN-1007": &StatusError{Code: 401, Host: "h", kind: ErrAuth},
		"PTH-CONN-1010": &StatusError{Code: 429, Host: "h", kind: ErrRateLimited},
		"PTH-CONN-1009": &StatusError{Code: 403, Host: "h", kind: ErrForbidden},
		"PTH-CONN-1011": &StatusError{Code: 404, Host: "h", kind: ErrNotFound},
		"PTH-CONN-1012": &StatusError{Code: 503, Host: "h"},
		"PTH-CONN-1020": ErrNotSupported,
		"PTH-SYNC-1003": ErrInvalidPageToken,
		"PTH-CONN-1004": newTransportError("h", x509.UnknownAuthorityError{}),
		"PTH-CONN-1002": newTransportError("h", context.DeadlineExceeded),
		"PTH-CONN-1001": newTransportError("h", errors.New("connection refused")),
	}
	for want, err := range cases {
		got := DiagCode(err)
		if got != want {
			t.Errorf("%v: got %q, want %q", err, got, want)
		}
		if _, ok := diag.Lookup(got); !ok {
			t.Errorf("%s is not in the catalogue", got)
		}
	}
	if DiagCode(errors.New("other")) != "" || DiagCode(nil) != "" {
		t.Error("non-provider errors have no code")
	}
}
