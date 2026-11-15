// Package logging builds the process-wide slog JSON logger with secret
// redaction. Redaction is defense in depth: code should not log secrets in
// the first place, but if a sensitive key or token-shaped value slips into
// an attribute it is masked before it is written.
package logging

import (
	"io"
	"log/slog"
	"regexp"
	"strings"
)

const Redacted = "[REDACTED]"

// sensitiveKeyParts are matched case-insensitively against attribute keys.
var sensitiveKeyParts = []string{
	"password", "passwd", "secret", "token", "authorization", "cookie",
	"api_key", "apikey", "private_key", "master_key", "credential", "dek",
	"ciphertext",
}

// valuePatterns catch token-shaped values regardless of key.
var valuePatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)bearer\s+[a-z0-9._~+/=-]{8,}`),
	regexp.MustCompile(`eyJ[a-zA-Z0-9_-]{8,}\.[a-zA-Z0-9_-]{8,}\.[a-zA-Z0-9_-]{8,}`), // JWT
	regexp.MustCompile(`gh[pousr]_[A-Za-z0-9]{20,}`),                                 // GitHub tokens
	regexp.MustCompile(`github_pat_[A-Za-z0-9_]{20,}`),
	regexp.MustCompile(`sk-(ant-)?[A-Za-z0-9_-]{20,}`), // Anthropic / OpenAI style keys
	regexp.MustCompile(`xai-[A-Za-z0-9]{20,}`),
	regexp.MustCompile(`AKIA[0-9A-Z]{16}`), // AWS access key id
	regexp.MustCompile(`-----BEGIN [A-Z ]*PRIVATE KEY-----`),
	regexp.MustCompile(`(?i)(postgres(ql)?|redis|rediss|amqp)://[^:/\s]+:[^@\s]+@`), // URL credentials
}

// IsSensitiveKey reports whether an attribute key looks like it holds a secret.
func IsSensitiveKey(key string) bool {
	k := strings.ToLower(key)
	for _, p := range sensitiveKeyParts {
		if strings.Contains(k, p) {
			return true
		}
	}
	return false
}

// RedactString masks token-shaped substrings in s.
func RedactString(s string) string {
	for _, re := range valuePatterns {
		s = re.ReplaceAllString(s, Redacted)
	}
	return s
}

func replaceAttr(_ []string, a slog.Attr) slog.Attr {
	if IsSensitiveKey(a.Key) {
		return slog.String(a.Key, Redacted)
	}
	switch a.Value.Kind() {
	case slog.KindString:
		if s := a.Value.String(); s != "" {
			if r := RedactString(s); r != s {
				return slog.String(a.Key, r)
			}
		}
	case slog.KindAny:
		if err, ok := a.Value.Any().(error); ok && err != nil {
			return slog.String(a.Key, RedactString(err.Error()))
		}
	}
	return a
}

// New returns a JSON logger writing to w at the given level.
func New(w io.Writer, level string) *slog.Logger {
	var l slog.Level
	switch level {
	case "debug":
		l = slog.LevelDebug
	case "warn":
		l = slog.LevelWarn
	case "error":
		l = slog.LevelError
	default:
		l = slog.LevelInfo
	}
	return slog.New(slog.NewJSONHandler(w, &slog.HandlerOptions{Level: l, ReplaceAttr: replaceAttr}))
}
