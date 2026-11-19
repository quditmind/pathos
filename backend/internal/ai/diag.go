package ai

import (
	"errors"
	"fmt"
)

// ErrTooLarge means the redacted payload exceeds what is sent to a model.
type ErrTooLarge struct{ Bytes int }

func (e ErrTooLarge) Error() string {
	return fmt.Sprintf("ai: the request is too large (%d bytes after redaction)", e.Bytes)
}

// DiagCode returns the error catalogue code (backend/internal/platform/diag)
// of an AI error ("" when err is not an AI error).
func DiagCode(err error) string {
	var tl ErrTooLarge
	switch {
	case err == nil:
		return ""
	case errors.Is(err, ErrNotConfigured):
		return "PTH-AI-1001"
	case errors.Is(err, ErrAuth):
		return "PTH-AI-1003"
	case errors.Is(err, ErrRateLimited):
		return "PTH-AI-1004"
	case errors.Is(err, ErrRefused):
		return "PTH-AI-1005"
	case errors.Is(err, ErrTruncated):
		return "PTH-AI-1006"
	case errors.As(err, &tl):
		return "PTH-AI-1011"
	}
	return "PTH-AI-1006"
}
