package crypto

import (
	"bytes"
	"crypto/rand"
	"errors"
	"testing"
)

func key(t *testing.T) []byte {
	t.Helper()
	k := make([]byte, 32)
	if _, err := rand.Read(k); err != nil {
		t.Fatal(err)
	}
	return k
}

func TestSealOpenRoundTrip(t *testing.T) {
	kr, err := NewKeyring(map[int][]byte{1: key(t)})
	if err != nil {
		t.Fatal(err)
	}
	pt := []byte("ghp_supersecrettoken")
	aad := []byte("scm:secret-id-1")
	s, err := kr.Seal(pt, aad)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(s.Ciphertext, pt) {
		t.Fatal("ciphertext contains plaintext")
	}
	got, err := kr.Open(s, aad)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, pt) {
		t.Fatalf("round trip mismatch")
	}
}

func TestSealIsRandomized(t *testing.T) {
	kr, _ := NewKeyring(map[int][]byte{1: key(t)})
	a, _ := kr.Seal([]byte("x"), nil)
	b, _ := kr.Seal([]byte("x"), nil)
	if bytes.Equal(a.Ciphertext, b.Ciphertext) || bytes.Equal(a.WrappedDEK, b.WrappedDEK) {
		t.Fatal("two seals of the same plaintext must differ")
	}
}

func TestAADIsBound(t *testing.T) {
	kr, _ := NewKeyring(map[int][]byte{1: key(t)})
	s, _ := kr.Seal([]byte("x"), []byte("ai:1"))
	if _, err := kr.Open(s, []byte("scm:1")); !errors.Is(err, ErrDecrypt) {
		t.Fatalf("want ErrDecrypt for wrong aad, got %v", err)
	}
}

func TestTamperDetected(t *testing.T) {
	kr, _ := NewKeyring(map[int][]byte{1: key(t)})
	s, _ := kr.Seal([]byte("secret"), nil)
	s.Ciphertext[len(s.Ciphertext)-1] ^= 1
	if _, err := kr.Open(s, nil); !errors.Is(err, ErrDecrypt) {
		t.Fatalf("want ErrDecrypt for tampered ciphertext, got %v", err)
	}
}

func TestRotation(t *testing.T) {
	k1, k2 := key(t), key(t)
	old, _ := NewKeyring(map[int][]byte{1: k1})
	s, _ := old.Seal([]byte("secret"), []byte("aad"))

	kr, _ := NewKeyring(map[int][]byte{1: k1, 2: k2})
	if kr.CurrentVersion() != 2 {
		t.Fatalf("current version should be 2")
	}
	// Old ciphertext still opens with the combined keyring.
	if _, err := kr.Open(s, []byte("aad")); err != nil {
		t.Fatal(err)
	}
	r, err := kr.Rewrap(s, []byte("aad"))
	if err != nil {
		t.Fatal(err)
	}
	if r.KeyVersion != 2 || !bytes.Equal(r.Ciphertext, s.Ciphertext) {
		t.Fatal("rewrap should change only the wrapped DEK and version")
	}
	// After rotation the old key can be retired.
	onlyNew, _ := NewKeyring(map[int][]byte{2: k2})
	got, err := onlyNew.Open(r, []byte("aad"))
	if err != nil || string(got) != "secret" {
		t.Fatalf("rewrapped secret should open with new key only: %v", err)
	}
	if _, err := onlyNew.Open(s, []byte("aad")); !errors.Is(err, ErrUnknownKeyVersion) {
		t.Fatalf("want ErrUnknownKeyVersion, got %v", err)
	}
}

func TestRejectsBadKeys(t *testing.T) {
	if _, err := NewKeyring(nil); err == nil {
		t.Fatal("empty keyring must fail")
	}
	if _, err := NewKeyring(map[int][]byte{1: make([]byte, 16)}); err == nil {
		t.Fatal("short key must fail")
	}
}
