package sourcestore

import (
	"bufio"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"

	"pathos/internal/platform/crypto"
)

// On-disk / in-bucket format (all integers big-endian):
//
//	header:
//	  "PSRC1"                      5 bytes magic
//	  key version                  uint32  master key version that sealed the DEK
//	  len(wrapped) | wrapped       uint16 + bytes  crypto.Sealed.WrappedDEK
//	  len(sealedDEK) | sealedDEK   uint16 + bytes  crypto.Sealed.Ciphertext (the object DEK)
//	chunks (at least one; the last one carries the final flag):
//	  AES-256-GCM(DEK, nonce, plaintext[<=64 KiB], aad) = ciphertext || 16-byte tag
//
// The object DEK is sealed with Keyring.Seal(dek, "pathos/sourcestore/v1\x00"+key),
// so the header only opens for the object key it was written for. Every
// chunk except the last holds exactly 64 KiB of plaintext; the last holds
// 0..64 KiB and is the only one sealed with the final flag, so truncation at
// a chunk boundary is detected. Chunk nonce = 4 zero bytes || uint64 chunk
// index; chunk AAD = "pathos/sourcestore/chunk\x00" || key || 0x00 ||
// uint64 index || final (0 or 1).
const (
	magic     = "PSRC1"
	chunkSize = 64 << 10
	tagSize   = 16
	maxField  = 1024
)

func headerAAD(key string) []byte { return []byte("pathos/sourcestore/v1\x00" + key) }

func chunkAAD(key string, index uint64, final bool) []byte {
	aad := make([]byte, 0, 32+len(key))
	aad = append(aad, "pathos/sourcestore/chunk\x00"...)
	aad = append(aad, key...)
	aad = append(aad, 0)
	aad = binary.BigEndian.AppendUint64(aad, index)
	if final {
		return append(aad, 1)
	}
	return append(aad, 0)
}

func chunkNonce(index uint64) []byte {
	n := make([]byte, 12)
	binary.BigEndian.PutUint64(n[4:], index)
	return n
}

func newGCM(dek []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(dek)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

// encrypt streams r into w in the store format and returns the number of
// plaintext bytes consumed.
func encrypt(w io.Writer, key string, r io.Reader, keys *crypto.Keyring) (int64, error) {
	dek := make([]byte, 32)
	if _, err := rand.Read(dek); err != nil {
		return 0, err
	}
	defer clear(dek)
	sealed, err := keys.Seal(dek, headerAAD(key))
	if err != nil {
		return 0, err
	}
	if len(sealed.WrappedDEK) > maxField || len(sealed.Ciphertext) > maxField || sealed.KeyVersion < 0 {
		return 0, errors.New("sourcestore: unexpected sealed key size")
	}
	hdr := make([]byte, 0, len(magic)+8+len(sealed.WrappedDEK)+len(sealed.Ciphertext))
	hdr = append(hdr, magic...)
	hdr = binary.BigEndian.AppendUint32(hdr, uint32(sealed.KeyVersion))      // #nosec G115 -- checked non-negative above
	hdr = binary.BigEndian.AppendUint16(hdr, uint16(len(sealed.WrappedDEK))) // #nosec G115 -- bounded by maxField above
	hdr = append(hdr, sealed.WrappedDEK...)
	hdr = binary.BigEndian.AppendUint16(hdr, uint16(len(sealed.Ciphertext))) // #nosec G115 -- bounded by maxField above
	hdr = append(hdr, sealed.Ciphertext...)
	if _, err := w.Write(hdr); err != nil {
		return 0, err
	}
	gcm, err := newGCM(dek)
	if err != nil {
		return 0, err
	}

	cur := make([]byte, chunkSize)
	next := make([]byte, chunkSize)
	out := make([]byte, 0, chunkSize+tagSize)
	var total int64
	n, rerr := io.ReadFull(r, cur)
	for index := uint64(0); ; index++ {
		final := false
		var m int
		var nerr error
		switch {
		case rerr == io.EOF || rerr == io.ErrUnexpectedEOF:
			final = true
		case rerr != nil:
			return total, rerr
		default:
			// A full chunk: it is final only if nothing follows.
			m, nerr = io.ReadFull(r, next)
			if nerr == io.EOF {
				final = true
			}
		}
		out = gcm.Seal(out[:0], chunkNonce(index), cur[:n], chunkAAD(key, index, final))
		if _, err := w.Write(out); err != nil {
			return total, err
		}
		total += int64(n)
		if final {
			return total, nil
		}
		cur, next = next, cur
		n, rerr = m, nerr
	}
}

// decrypter streams plaintext out of a store-format reader.
type decrypter struct {
	key   string
	r     *bufio.Reader
	gcm   cipher.AEAD
	index uint64
	buf   []byte // ciphertext scratch
	plain []byte // pending plaintext
	done  bool
	err   error
}

// newDecrypter reads and opens the header; chunk errors surface from Read.
func newDecrypter(key string, r io.Reader, keys *crypto.Keyring) (io.Reader, error) {
	br := bufio.NewReaderSize(r, chunkSize+tagSize+1)
	fixed := make([]byte, len(magic)+4)
	if _, err := io.ReadFull(br, fixed); err != nil {
		return nil, corruptOr(err)
	}
	if string(fixed[:len(magic)]) != magic {
		return nil, fmt.Errorf("%w: bad magic", ErrCorrupt)
	}
	version := binary.BigEndian.Uint32(fixed[len(magic):])
	wrapped, err := readField(br)
	if err != nil {
		return nil, err
	}
	sealedDEK, err := readField(br)
	if err != nil {
		return nil, err
	}
	if version > 1<<30 {
		return nil, fmt.Errorf("%w: bad key version", ErrCorrupt)
	}
	dek, err := keys.Open(crypto.Sealed{Ciphertext: sealedDEK, WrappedDEK: wrapped, KeyVersion: int(version)}, headerAAD(key))
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrCorrupt, err)
	}
	defer clear(dek)
	gcm, err := newGCM(dek)
	if err != nil {
		return nil, err
	}
	return &decrypter{key: key, r: br, gcm: gcm, buf: make([]byte, chunkSize+tagSize)}, nil
}

func readField(r io.Reader) ([]byte, error) {
	var l [2]byte
	if _, err := io.ReadFull(r, l[:]); err != nil {
		return nil, corruptOr(err)
	}
	n := binary.BigEndian.Uint16(l[:])
	if n == 0 || n > maxField {
		return nil, fmt.Errorf("%w: bad header field", ErrCorrupt)
	}
	b := make([]byte, n)
	if _, err := io.ReadFull(r, b); err != nil {
		return nil, corruptOr(err)
	}
	return b, nil
}

// corruptOr maps short reads to ErrCorrupt and keeps I/O errors.
func corruptOr(err error) error {
	if err == io.EOF || err == io.ErrUnexpectedEOF {
		return fmt.Errorf("%w: truncated", ErrCorrupt)
	}
	return err
}

func (d *decrypter) Read(p []byte) (int, error) {
	for len(d.plain) == 0 {
		if d.err != nil {
			return 0, d.err
		}
		if d.done {
			return 0, io.EOF
		}
		d.err = d.nextChunk()
	}
	n := copy(p, d.plain)
	d.plain = d.plain[n:]
	return n, nil
}

func (d *decrypter) nextChunk() error {
	n, err := io.ReadFull(d.r, d.buf)
	final := false
	switch {
	case err == io.EOF:
		return fmt.Errorf("%w: missing final chunk", ErrCorrupt)
	case err == io.ErrUnexpectedEOF:
		final = true
	case err != nil:
		return err
	default:
		if _, perr := d.r.Peek(1); perr == io.EOF {
			final = true
		} else if perr != nil {
			return perr
		}
	}
	if n < tagSize {
		return fmt.Errorf("%w: truncated chunk", ErrCorrupt)
	}
	pt, oerr := d.gcm.Open(d.buf[:0], chunkNonce(d.index), d.buf[:n], chunkAAD(d.key, d.index, final))
	if oerr != nil {
		return fmt.Errorf("%w: chunk %d", ErrCorrupt, d.index)
	}
	d.index++
	d.plain = pt
	d.done = final
	return nil
}
