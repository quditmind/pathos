package sourcestore

import (
	"context"
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"

	"pathos/internal/platform/crypto"
)

// FS stores encrypted objects as files below a directory.
type FS struct {
	dir  string
	keys *crypto.Keyring
}

// NewFS returns a file-system store rooted at dir (created 0700 if
// missing).
func NewFS(dir string, keys *crypto.Keyring) (*FS, error) {
	if dir == "" || keys == nil {
		return nil, errors.New("sourcestore: directory and keyring are required")
	}
	abs, err := filepath.Abs(dir)
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(abs, 0o700); err != nil {
		return nil, err
	}
	return &FS{dir: abs, keys: keys}, nil
}

// path maps a validated key to a file below the root.
func (s *FS) path(key string) (string, error) {
	if err := ValidateKey(key); err != nil {
		return "", err
	}
	p := filepath.Join(s.dir, filepath.FromSlash(key))
	rel, err := filepath.Rel(s.dir, p)
	if err != nil || !filepath.IsLocal(rel) {
		return "", ErrInvalidKey
	}
	return p, nil
}

// Put implements Store. The object is written to a temporary file in the
// destination directory and renamed into place, so readers never see a
// partial object.
func (s *FS) Put(ctx context.Context, key string, r io.Reader) (int64, error) {
	p, err := s.path(key)
	if err != nil {
		return 0, err
	}
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		return 0, err
	}
	tmp, err := os.CreateTemp(filepath.Dir(p), ".put-*") // mode 0600
	if err != nil {
		return 0, err
	}
	committed := false
	defer func() {
		if !committed {
			_ = tmp.Close()
			_ = os.Remove(tmp.Name())
		}
	}()
	n, err := encrypt(tmp, key, ctxReader{ctx, r}, s.keys)
	if err != nil {
		return n, err
	}
	if err := tmp.Sync(); err != nil {
		return n, err
	}
	if err := tmp.Close(); err != nil {
		return n, err
	}
	if err := os.Rename(tmp.Name(), p); err != nil {
		return n, err
	}
	committed = true
	return n, nil
}

// Open implements Store.
func (s *FS) Open(_ context.Context, key string) (io.ReadCloser, error) {
	p, err := s.path(key)
	if err != nil {
		return nil, err
	}
	// #nosec G304 -- p is a validated key below the store root
	f, err := os.Open(p)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	if st, err := f.Stat(); err != nil || !st.Mode().IsRegular() {
		_ = f.Close()
		return nil, ErrNotFound
	}
	d, err := newDecrypter(key, f, s.keys)
	if err != nil {
		_ = f.Close()
		return nil, err
	}
	return readCloser{d, f}, nil
}

// Delete implements Store.
func (s *FS) Delete(_ context.Context, keys ...string) error {
	for _, k := range keys {
		p, err := s.path(k)
		if err != nil {
			return err
		}
		if err := os.Remove(p); err != nil && !errors.Is(err, fs.ErrNotExist) {
			return err
		}
	}
	return nil
}

// Exists implements Store.
func (s *FS) Exists(_ context.Context, key string) (bool, error) {
	p, err := s.path(key)
	if err != nil {
		return false, err
	}
	st, err := os.Lstat(p)
	if errors.Is(err, fs.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return st.Mode().IsRegular(), nil
}

type readCloser struct {
	io.Reader
	io.Closer
}
