package sourcestore

import (
	"context"
	"errors"
	"io"
	"os"
	"strings"

	"pathos/internal/platform/crypto"
	"pathos/internal/platform/objstore"
)

// blobAPI is the subset of objstore.S3 used here (a fake in tests).
type blobAPI interface {
	PutStream(ctx context.Context, key string, body io.ReadSeeker, size int64, contentType string) error
	GetStream(ctx context.Context, key string) (io.ReadCloser, error)
	Exists(ctx context.Context, key string) (bool, error)
	Delete(ctx context.Context, keys []string) error
}

// S3 stores encrypted objects in an S3-compatible bucket under a prefix.
type S3 struct {
	api    blobAPI
	prefix string
	keys   *crypto.Keyring
	// TempDir holds the encrypted spool file during Put (S3 needs a
	// seekable body of known length). Empty means os.TempDir().
	TempDir string
}

// NewS3 builds an S3-backed store. It does not contact the server; the
// bucket is shared with objstore and created by its EnsureBucket.
func NewS3(cfg objstore.Config, prefix string, keys *crypto.Keyring) (*S3, error) {
	if keys == nil {
		return nil, errors.New("sourcestore: keyring is required")
	}
	c, err := objstore.NewS3(cfg)
	if err != nil {
		return nil, err
	}
	return newS3(c, prefix, keys), nil
}

func newS3(api blobAPI, prefix string, keys *crypto.Keyring) *S3 {
	if prefix != "" && !strings.HasSuffix(prefix, "/") {
		prefix += "/"
	}
	return &S3{api: api, prefix: prefix, keys: keys}
}

// objectKey returns the bucket key. The authenticated data binds the store
// key (without prefix), so changing the prefix does not invalidate objects.
func (s *S3) objectKey(key string) (string, error) {
	if err := ValidateKey(key); err != nil {
		return "", err
	}
	return s.prefix + key, nil
}

// Put implements Store.
func (s *S3) Put(ctx context.Context, key string, r io.Reader) (int64, error) {
	ok, err := s.objectKey(key)
	if err != nil {
		return 0, err
	}
	tmp, err := os.CreateTemp(s.TempDir, "pathos-source-*") // mode 0600
	if err != nil {
		return 0, err
	}
	defer func() {
		_ = tmp.Close()
		_ = os.Remove(tmp.Name())
	}()
	n, err := encrypt(tmp, key, ctxReader{ctx, r}, s.keys)
	if err != nil {
		return n, err
	}
	size, err := tmp.Seek(0, io.SeekCurrent)
	if err != nil {
		return n, err
	}
	if _, err := tmp.Seek(0, io.SeekStart); err != nil {
		return n, err
	}
	if err := s.api.PutStream(ctx, ok, tmp, size, "application/octet-stream"); err != nil {
		return n, err
	}
	return n, nil
}

// Open implements Store.
func (s *S3) Open(ctx context.Context, key string) (io.ReadCloser, error) {
	ok, err := s.objectKey(key)
	if err != nil {
		return nil, err
	}
	body, err := s.api.GetStream(ctx, ok)
	if errors.Is(err, objstore.ErrNotFound) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	d, err := newDecrypter(key, body, s.keys)
	if err != nil {
		_ = body.Close()
		return nil, err
	}
	return readCloser{d, body}, nil
}

// Delete implements Store.
func (s *S3) Delete(ctx context.Context, keys ...string) error {
	full := make([]string, 0, len(keys))
	for _, k := range keys {
		ok, err := s.objectKey(k)
		if err != nil {
			return err
		}
		full = append(full, ok)
	}
	if len(full) == 0 {
		return nil
	}
	return s.api.Delete(ctx, full)
}

// Exists implements Store.
func (s *S3) Exists(ctx context.Context, key string) (bool, error) {
	ok, err := s.objectKey(key)
	if err != nil {
		return false, err
	}
	return s.api.Exists(ctx, ok)
}
