// Package crypto implements envelope encryption for secrets at rest.
//
// Each secret is encrypted with a fresh random 256-bit data encryption key
// (DEK) using AES-256-GCM. The DEK is then wrapped (encrypted) with the
// versioned master key, also with AES-256-GCM. Both layers authenticate the
// caller-supplied associated data, so a ciphertext cannot be moved to a
// different row or secret kind without detection.
package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"fmt"
	"sort"
)

var (
	ErrUnknownKeyVersion = errors.New("crypto: unknown master key version")
	ErrDecrypt           = errors.New("crypto: decryption failed")
)

// Sealed is the stored form of an encrypted secret.
type Sealed struct {
	Ciphertext []byte // nonce || AES-GCM(DEK, plaintext, aad)
	WrappedDEK []byte // nonce || AES-GCM(master[KeyVersion], DEK, aad)
	KeyVersion int
}

// Keyring holds the versioned master keys.
type Keyring struct {
	keys    map[int][]byte
	current int
}

// NewKeyring copies keys. Every key must be 32 bytes. The highest version
// becomes the current key for new encryptions.
func NewKeyring(keys map[int][]byte) (*Keyring, error) {
	if len(keys) == 0 {
		return nil, errors.New("crypto: at least one master key is required")
	}
	kr := &Keyring{keys: make(map[int][]byte, len(keys))}
	for v, k := range keys {
		if len(k) != 32 {
			return nil, fmt.Errorf("crypto: master key v%d must be 32 bytes", v)
		}
		kr.keys[v] = append([]byte(nil), k...)
		if v > kr.current {
			kr.current = v
		}
	}
	return kr, nil
}

// CurrentVersion returns the version used for new encryptions.
func (kr *Keyring) CurrentVersion() int { return kr.current }

// Versions returns all available key versions in ascending order.
func (kr *Keyring) Versions() []int {
	out := make([]int, 0, len(kr.keys))
	for v := range kr.keys {
		out = append(out, v)
	}
	sort.Ints(out)
	return out
}

// Seal encrypts plaintext under a new DEK wrapped by the current master key.
func (kr *Keyring) Seal(plaintext, aad []byte) (Sealed, error) {
	dek := make([]byte, 32)
	if _, err := rand.Read(dek); err != nil {
		return Sealed{}, err
	}
	defer clear(dek)

	ct, err := gcmSeal(dek, plaintext, aad)
	if err != nil {
		return Sealed{}, err
	}
	wrapped, err := gcmSeal(kr.keys[kr.current], dek, aad)
	if err != nil {
		return Sealed{}, err
	}
	return Sealed{Ciphertext: ct, WrappedDEK: wrapped, KeyVersion: kr.current}, nil
}

// Open decrypts a Sealed value. aad must match what was passed to Seal.
func (kr *Keyring) Open(s Sealed, aad []byte) ([]byte, error) {
	mk, ok := kr.keys[s.KeyVersion]
	if !ok {
		return nil, ErrUnknownKeyVersion
	}
	dek, err := gcmOpen(mk, s.WrappedDEK, aad)
	if err != nil {
		return nil, ErrDecrypt
	}
	defer clear(dek)
	pt, err := gcmOpen(dek, s.Ciphertext, aad)
	if err != nil {
		return nil, ErrDecrypt
	}
	return pt, nil
}

// Rewrap re-encrypts only the DEK under the current master key. The secret
// ciphertext is unchanged, which makes master key rotation cheap.
func (kr *Keyring) Rewrap(s Sealed, aad []byte) (Sealed, error) {
	if s.KeyVersion == kr.current {
		return s, nil
	}
	mk, ok := kr.keys[s.KeyVersion]
	if !ok {
		return Sealed{}, ErrUnknownKeyVersion
	}
	dek, err := gcmOpen(mk, s.WrappedDEK, aad)
	if err != nil {
		return Sealed{}, ErrDecrypt
	}
	defer clear(dek)
	wrapped, err := gcmSeal(kr.keys[kr.current], dek, aad)
	if err != nil {
		return Sealed{}, err
	}
	return Sealed{Ciphertext: s.Ciphertext, WrappedDEK: wrapped, KeyVersion: kr.current}, nil
}

func gcmSeal(key, plaintext, aad []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	return gcm.Seal(nonce, nonce, plaintext, aad), nil
}

func gcmOpen(key, data, aad []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	if len(data) < gcm.NonceSize() {
		return nil, ErrDecrypt
	}
	return gcm.Open(nil, data[:gcm.NonceSize()], data[gcm.NonceSize():], aad)
}
