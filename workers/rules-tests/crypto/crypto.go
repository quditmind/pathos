// Test fixture for workers/rules/pathos-crypto.yml (Go). Not compiled.
package fixture

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/des"
	"crypto/hmac"
	"crypto/md5"
	crand "crypto/rand"
	"crypto/rc4"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/tls"
	"math/rand"
	"os"
)

func hashing(data []byte) {
	// ruleid: pathos.crypto.go.weak-hash
	a := md5.Sum(data)
	// ruleid: pathos.crypto.go.weak-hash
	b := sha1.New()
	// ruleid: pathos.crypto.go.weak-hash
	m := hmac.New(sha1.New, []byte(os.Getenv("MAC_KEY")))
	// ok: pathos.crypto.go.weak-hash
	c := sha256.Sum256(data)
	_, _, _, _ = a, b, m, c
}

func ciphers(key, data []byte) {
	// ruleid: pathos.crypto.go.weak-cipher
	d, _ := des.NewTripleDESCipher(key)
	// ruleid: pathos.crypto.go.weak-cipher
	r, _ := rc4.NewCipher(key)
	// ok: pathos.crypto.go.weak-cipher
	block, err := aes.NewCipher(key)
	if err != nil {
		return
	}
	out := make([]byte, len(data))
	for i := 0; i < len(data); i += aes.BlockSize {
		// ruleid: pathos.crypto.go.ecb-mode
		block.Encrypt(out[i:], data[i:])
	}
	// ok: pathos.crypto.go.ecb-mode
	block.Encrypt(out, data)
	// ruleid: pathos.crypto.go.static-iv
	cbc := cipher.NewCBCEncrypter(block, []byte("0000000000000000"))
	gcm, _ := cipher.NewGCM(block)
	// ruleid: pathos.crypto.go.static-iv
	sealed := gcm.Seal(nil, []byte("fixednonce12"), data, nil)
	nonce := make([]byte, gcm.NonceSize())
	_, _ = crand.Read(nonce)
	// ok: pathos.crypto.go.static-iv
	sealed2 := gcm.Seal(nil, nonce, data, nil)
	_, _, _, _, _ = d, r, cbc, sealed, sealed2
}

func keys() {
	// ruleid: pathos.crypto.go.small-rsa-key
	k1, _ := rsa.GenerateKey(crand.Reader, 1024)
	// ok: pathos.crypto.go.small-rsa-key
	k2, _ := rsa.GenerateKey(crand.Reader, 3072)
	_, _ = k1, k2
}

func tokens() {
	// ruleid: pathos.crypto.go.insecure-random-secret
	sessionID := rand.Int63()
	// ok: pathos.crypto.go.insecure-random-secret
	backoff := rand.Intn(100)
	// ok: pathos.crypto.go.insecure-random-secret
	resetToken := crand.Text()
	_, _, _ = sessionID, backoff, resetToken
}

func tlsConfig() {
	// ruleid: pathos.crypto.go.weak-tls-version
	old := &tls.Config{MinVersion: tls.VersionTLS10}
	// ok: pathos.crypto.go.weak-tls-version
	cur := &tls.Config{MinVersion: tls.VersionTLS12}
	_, _ = old, cur
}

func hardcoded(data []byte) {
	// ruleid: pathos.crypto.go.hardcoded-key
	b, _ := aes.NewCipher([]byte("0123456789abcdef"))
	// ruleid: pathos.crypto.go.hardcoded-key
	m := hmac.New(sha256.New, []byte("fixture-mac-key"))
	// ok: pathos.crypto.go.hardcoded-key
	m2 := hmac.New(sha256.New, []byte(os.Getenv("MAC_KEY")))
	_, _, _ = b, m, m2
}
