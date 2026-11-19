// Package httpx contains HTTP helpers: JSON encoding, problem responses and
// common middleware.
package httpx

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"pathos/internal/platform/crypto"
	"pathos/internal/platform/diag"
	"pathos/internal/platform/telemetry"
	"runtime/debug"
	"strings"
	"time"
)

// Error is an API error with an HTTP status and a stable code.
type Error struct {
	Status  int    `json:"-"`
	Code    string `json:"code"`
	Message string `json:"message"`
	Details any    `json:"details,omitempty"`
	// Fields carries per-field validation messages (code validation_failed).
	Fields map[string]string `json:"fields,omitempty"`
	// Diag is the catalogue code (PTH-<AREA>-<NNNN>) set where the error is
	// raised; when empty the code is derived from Code, then from Status
	// (diag.Resolve).
	Diag string `json:"-"`
	// Cause is a cause established where the error was raised; it is
	// reported as confirmed.
	Cause string `json:"-"`
}

func (e *Error) Error() string { return e.Code + ": " + e.Message }

func E(status int, code, msg string) *Error { return &Error{Status: status, Code: code, Message: msg} }

// WithDiag returns a copy of e carrying the catalogue code (the shared
// errors such as ErrNotFound are never modified).
func (e *Error) WithDiag(code string) *Error {
	c := *e
	c.Diag = code
	return &c
}

// WithCause returns a copy of e with a confirmed cause.
func (e *Error) WithCause(cause string) *Error {
	c := *e
	c.Cause = cause
	return &c
}

// DiagCode is the catalogue code of e.
func (e *Error) DiagCode() string { return diag.Resolve(e.Diag, e.Code, e.Status) }

// errorBody is the "error" object of an API error response: the legacy
// fields (code, message, details, fields) unchanged, plus the diagnostic
// fields (error_code, title, cause, probable_causes, impact, actions,
// verify, docs_url, ai_help, request_id).
type errorBody struct {
	Code    string            `json:"code"`
	Message string            `json:"message"`
	Details any               `json:"details,omitempty"`
	Fields  map[string]string `json:"fields,omitempty"`
	diag.Detail
}

// ErrorObject returns the "error" object of e for the response to r. It
// also records the code for the access log line.
func ErrorObject(r *http.Request, e *Error) any {
	code := e.DiagCode()
	noteError(r, code)
	return errorBody{Code: e.Code, Message: e.Message, Details: e.Details, Fields: e.Fields, Detail: diag.DetailFor(code, e.Cause, RequestID(r))}
}

// Body returns the complete JSON body of an error response:
// {"error": {...}, "request_id": "..."}. Handlers that add their own
// top-level fields start from it.
func Body(r *http.Request, e *Error) map[string]any {
	return map[string]any{"error": ErrorObject(r, e), "request_id": RequestID(r)}
}

var (
	ErrUnauthenticated = E(http.StatusUnauthorized, "unauthenticated", "authentication required")
	ErrForbidden       = E(http.StatusForbidden, "forbidden", "you do not have permission to perform this action")
	ErrNotFound        = E(http.StatusNotFound, "not_found", "resource not found")
	ErrCSRF            = E(http.StatusForbidden, "csrf_failed", "missing or invalid CSRF token")
)

// BadRequest returns a 400 validation error.
func BadRequest(msg string) *Error { return E(http.StatusBadRequest, "invalid_request", msg) }

// Conflict returns a 409 error.
func Conflict(msg string) *Error { return E(http.StatusConflict, "conflict", msg) }

// WriteJSON writes v as JSON with status.
func WriteJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// WriteError writes err as a JSON problem. Unknown errors become a 500 and
// are logged; their text is never sent to the client.
func WriteError(w http.ResponseWriter, r *http.Request, log *slog.Logger, err error) {
	var e *Error
	if !errors.As(err, &e) {
		if errors.Is(err, context.Canceled) && r.Context().Err() != nil {
			// The client went away (navigation, aborted fetch); nothing to report.
			log.Debug("request canceled by client", "path", r.URL.Path, "request_id", RequestID(r))
			w.WriteHeader(499)
			return
		}
		e = E(http.StatusInternalServerError, "internal", "internal server error")
		if errors.Is(err, crypto.ErrDecrypt) {
			e.Diag = "PTH-PLAT-1013"
		}
		log.Error("internal error", "err", err, "path", r.URL.Path, "request_id", RequestID(r), "error_code", e.DiagCode())
	} else if e.Status >= 500 {
		log.Warn("request failed", "code", e.Code, "path", r.URL.Path, "request_id", RequestID(r), "error_code", e.DiagCode())
	}
	WriteJSON(w, e.Status, Body(r, e))
}

// DecodeJSON decodes a JSON body strictly (size-limited, no unknown fields).
func DecodeJSON(w http.ResponseWriter, r *http.Request, v any) error {
	if ct := r.Header.Get("Content-Type"); !strings.HasPrefix(ct, "application/json") {
		return E(http.StatusUnsupportedMediaType, "unsupported_media_type", "Content-Type must be application/json")
	}
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return BadRequest(fmt.Sprintf("invalid JSON body: %v", err))
	}
	if dec.More() {
		return BadRequest("request body must contain a single JSON object")
	}
	if _, err := dec.Token(); err != io.EOF {
		return BadRequest("request body must contain a single JSON object")
	}
	return nil
}

type ctxKey int

const (
	requestIDKey ctxKey = 0
	errNoteKey   ctxKey = 1
)

// errNote carries the catalogue code of the error response to the access
// log line of the same request.
type errNote struct{ code string }

func noteError(r *http.Request, code string) {
	if n, ok := r.Context().Value(errNoteKey).(*errNote); ok {
		n.code = code
	}
}

// RequestID returns the request ID set by the RequestID middleware.
func RequestID(r *http.Request) string {
	id, _ := r.Context().Value(requestIDKey).(string)
	return id
}

// idAlphabet has no digits: a hex ID can contain a long run of digits that
// data-leak detectors (ZAP 10062 "PII Disclosure") mistake for a payment
// card number in error responses. 24 letters carry about 112 bits.
const idAlphabet = "abcdefghijklmnopqrstuvwxyz"

func newID() string {
	const n = 24
	out := make([]byte, 0, n)
	buf := make([]byte, 32)
	for len(out) < n {
		_, _ = rand.Read(buf)
		for _, b := range buf {
			// Rejection sampling keeps every letter equally likely.
			if b < 26*9 && len(out) < n {
				out = append(out, idAlphabet[b%26])
			}
		}
	}
	return string(out)
}

func validRequestID(s string) bool {
	if len(s) == 0 || len(s) > 64 {
		return false
	}
	for _, c := range s {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-' || c == '_') {
			return false
		}
	}
	return true
}

type statusRecorder struct {
	http.ResponseWriter
	status int
	bytes  int
}

func (s *statusRecorder) WriteHeader(code int) { s.status = code; s.ResponseWriter.WriteHeader(code) }
func (s *statusRecorder) Write(b []byte) (int, error) {
	if s.status == 0 {
		s.status = http.StatusOK
	}
	n, err := s.ResponseWriter.Write(b)
	s.bytes += n
	return n, err
}

// Middleware wraps every request with request ID, panic recovery, access
// logging and security headers.
func Middleware(log *slog.Logger, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		id := r.Header.Get("X-Request-Id")
		if !validRequestID(id) {
			id = newID()
		}
		note := &errNote{}
		ctx := context.WithValue(r.Context(), errNoteKey, note)
		r = r.WithContext(contextWithRequestID(ctx, id))
		w.Header().Set("X-Request-Id", id)

		h := w.Header()
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		// API responses are only for this origin's own pages (ZAP 90004).
		h.Set("Cross-Origin-Resource-Policy", "same-origin")
		h.Set("Referrer-Policy", "strict-origin-when-cross-origin")
		h.Set("Cache-Control", "no-store")
		h.Set("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'")

		rec := &statusRecorder{ResponseWriter: w}
		defer func() {
			if p := recover(); p != nil {
				log.Error("panic", "panic", fmt.Sprint(p), "stack", string(debug.Stack()), "request_id", id, "error_code", diag.Fallback)
				if rec.status == 0 {
					WriteJSON(rec, http.StatusInternalServerError, Body(r, E(500, "internal", "internal server error")))
				}
			}
			if r.URL.Path == "/healthz" || r.URL.Path == "/readyz" {
				return
			}
			attrs := []any{"method", r.Method, "path", r.URL.Path, "status", rec.status, "bytes", rec.bytes,
				"duration_ms", time.Since(start).Milliseconds(), "ip", ClientIP(r), "request_id", id}
			if rec.status >= 400 {
				code := note.code
				if code == "" {
					code = diag.ForStatus(rec.status)
				}
				attrs = append(attrs, "error_code", code)
			}
			if tid := telemetry.TraceID(r.Context()); tid != "" {
				attrs = append(attrs, "trace_id", tid)
			}
			log.Info("http", attrs...)
		}()
		next.ServeHTTP(rec, r)
	})
}

// ClientIP returns the client address. The API is only reachable through
// the edge proxy, which sets X-Forwarded-For; the rightmost entry is the
// one appended by the proxy and the only one that can be trusted.
func ClientIP(r *http.Request) string {
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		parts := strings.Split(xff, ",")
		if ip := net.ParseIP(strings.TrimSpace(parts[len(parts)-1])); ip != nil {
			return ip.String()
		}
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}
