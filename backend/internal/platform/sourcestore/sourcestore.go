// Package sourcestore keeps uploaded source archives and normalized source
// snapshots encrypted at rest.
//
// Every object is encrypted with its own random 256-bit data encryption key
// (DEK) in 64 KiB AES-256-GCM chunks (see format.go). The DEK is sealed with
// the platform master keyring and bound to the object key, so ciphertexts
// cannot be truncated, reordered or moved to another key without detection.
// Callers only ever see plaintext: Put encrypts, Open decrypts.
package sourcestore

import (
	"context"
	"errors"
	"io"
	"strings"
	"unicode/utf8"
)

// Store is an encrypted blob store.
type Store interface {
	// Put encrypts r and stores it under key, replacing any existing
	// object. It returns the number of plaintext bytes written.
	Put(ctx context.Context, key string, r io.Reader) (written int64, err error)
	// Open returns a reader of the decrypted object. Integrity errors
	// (ErrCorrupt) can surface from any Read, including at the very end
	// (truncation), so callers must read to io.EOF and check the error
	// before trusting the content.
	Open(ctx context.Context, key string) (io.ReadCloser, error)
	// Delete removes objects; missing keys are not errors.
	Delete(ctx context.Context, keys ...string) error
	// Exists reports whether an object exists.
	Exists(ctx context.Context, key string) (bool, error)
}

var (
	// ErrNotFound means the object does not exist.
	ErrNotFound = errors.New("sourcestore: object not found")
	// ErrCorrupt means the object failed authentication (tampered,
	// truncated, moved or encrypted under an unknown key).
	ErrCorrupt = errors.New("sourcestore: object failed integrity check")
	// ErrInvalidKey means the object key is not acceptable.
	ErrInvalidKey = errors.New("sourcestore: invalid object key")
)

// MaxKeyLen bounds object keys.
const MaxKeyLen = 512

// ValidateKey accepts slash-separated relative keys made of non-empty
// components, without "." or "..", backslashes, NUL or other control
// characters.
func ValidateKey(key string) error {
	if key == "" || len(key) > MaxKeyLen || !utf8.ValidString(key) {
		return ErrInvalidKey
	}
	if strings.HasPrefix(key, "/") || strings.ContainsRune(key, '\\') {
		return ErrInvalidKey
	}
	for _, r := range key {
		if r < 0x20 || r == 0x7f {
			return ErrInvalidKey
		}
	}
	if len(key) >= 2 && key[1] == ':' {
		return ErrInvalidKey // drive letter
	}
	for _, c := range strings.Split(key, "/") {
		if c == "" || c == "." || c == ".." {
			return ErrInvalidKey
		}
	}
	return nil
}

// ctxReader stops a copy when the context is cancelled.
type ctxReader struct {
	ctx context.Context
	r   io.Reader
}

func (c ctxReader) Read(p []byte) (int, error) {
	if err := c.ctx.Err(); err != nil {
		return 0, err
	}
	return c.r.Read(p)
}
