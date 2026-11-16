package sourcestore

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"pathos/internal/platform/crypto"
	"pathos/internal/platform/objstore"
)

func keyring(t *testing.T, versions ...int) *crypto.Keyring {
	t.Helper()
	m := map[int][]byte{}
	for _, v := range versions {
		k := bytes.Repeat([]byte{byte(v)}, 32)
		m[v] = k
	}
	kr, err := crypto.NewKeyring(m)
	if err != nil {
		t.Fatal(err)
	}
	return kr
}

func random(t *testing.T, n int) []byte {
	t.Helper()
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	return b
}

func readAll(s Store, key string) ([]byte, error) {
	rc, err := s.Open(context.Background(), key)
	if err != nil {
		return nil, err
	}
	defer rc.Close()
	return io.ReadAll(rc)
}

// memBlobs is an in-memory blobAPI for the S3 backend.
type memBlobs struct{ m map[string][]byte }

func (b *memBlobs) PutStream(_ context.Context, key string, body io.ReadSeeker, size int64, _ string) error {
	data, err := io.ReadAll(body)
	if err != nil {
		return err
	}
	if int64(len(data)) != size {
		return errors.New("size mismatch")
	}
	b.m[key] = data
	return nil
}

func (b *memBlobs) GetStream(_ context.Context, key string) (io.ReadCloser, error) {
	d, ok := b.m[key]
	if !ok {
		return nil, objstore.ErrNotFound
	}
	return io.NopCloser(bytes.NewReader(d)), nil
}

func (b *memBlobs) Exists(_ context.Context, key string) (bool, error) {
	_, ok := b.m[key]
	return ok, nil
}

func (b *memBlobs) Delete(_ context.Context, keys []string) error {
	for _, k := range keys {
		delete(b.m, k)
	}
	return nil
}

func backends(t *testing.T, kr *crypto.Keyring) map[string]Store {
	fsStore, err := NewFS(t.TempDir(), kr)
	if err != nil {
		t.Fatal(err)
	}
	s3 := newS3(&memBlobs{m: map[string][]byte{}}, "sources", kr)
	s3.TempDir = t.TempDir()
	return map[string]Store{"fs": fsStore, "s3": s3}
}

func TestRoundTrip(t *testing.T) {
	kr := keyring(t, 1)
	sizes := []int{0, 1, chunkSize - 1, chunkSize, chunkSize + 1, 2 * chunkSize, 3*chunkSize + 17, 5 << 20}
	for name, s := range backends(t, kr) {
		for _, n := range sizes {
			data := random(t, n)
			key := "uploads/u1/part-" + strings.Repeat("x", n%7)
			w, err := s.Put(context.Background(), key, bytes.NewReader(data))
			if err != nil || w != int64(n) {
				t.Fatalf("%s put %d: written=%d err=%v", name, n, w, err)
			}
			got, err := readAll(s, key)
			if err != nil || !bytes.Equal(got, data) {
				t.Fatalf("%s round trip %d: len=%d err=%v", name, n, len(got), err)
			}
		}
		ok, err := s.Exists(context.Background(), "uploads/u1/part-")
		if err != nil || !ok {
			t.Fatalf("%s exists: %v %v", name, ok, err)
		}
		if err := s.Delete(context.Background(), "uploads/u1/part-", "missing/key"); err != nil {
			t.Fatalf("%s delete: %v", name, err)
		}
		if ok, _ := s.Exists(context.Background(), "uploads/u1/part-"); ok {
			t.Fatalf("%s: object still exists after delete", name)
		}
		if _, err := s.Open(context.Background(), "uploads/u1/part-"); !errors.Is(err, ErrNotFound) {
			t.Fatalf("%s: open missing: %v", name, err)
		}
	}
}

func TestCiphertextIsNotPlaintext(t *testing.T) {
	kr := keyring(t, 1)
	dir := t.TempDir()
	s, _ := NewFS(dir, kr)
	secret := bytes.Repeat([]byte("AKIA-SECRET-VALUE "), 10000)
	if _, err := s.Put(context.Background(), "a/b", bytes.NewReader(secret)); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(filepath.Join(dir, "a", "b"))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(raw, []byte("AKIA-SECRET")) || !bytes.HasPrefix(raw, []byte(magic)) {
		t.Fatal("stored object is not encrypted in the expected format")
	}
	st, _ := os.Stat(filepath.Join(dir, "a", "b"))
	if st.Mode().Perm() != 0o600 {
		t.Fatalf("file mode %v", st.Mode().Perm())
	}
	dst, _ := os.Stat(filepath.Join(dir, "a"))
	if dst.Mode().Perm() != 0o700 {
		t.Fatalf("dir mode %v", dst.Mode().Perm())
	}
}

// headerLen returns the header size of a stored object with n plaintext bytes.
func headerLen(total, n int) int {
	chunks := max(1, (n+chunkSize-1)/chunkSize)
	return total - n - chunks*tagSize
}

func TestTamperDetected(t *testing.T) {
	kr := keyring(t, 1)
	dir := t.TempDir()
	s, _ := NewFS(dir, kr)
	ctx := context.Background()
	data := random(t, 3*chunkSize+100) // 4 chunks
	for _, k := range []string{"x/a", "x/b"} {
		if _, err := s.Put(ctx, k, bytes.NewReader(data)); err != nil {
			t.Fatal(err)
		}
	}
	pathA := filepath.Join(dir, "x", "a")
	orig, _ := os.ReadFile(pathA)
	origB, _ := os.ReadFile(filepath.Join(dir, "x", "b"))
	hl := headerLen(len(orig), len(data))
	if hl != len(magic)+4+2+60+2+60 {
		t.Fatalf("unexpected header length %d", hl)
	}
	full := chunkSize + tagSize

	cases := map[string]func([]byte) []byte{
		"bit flip in chunk": func(b []byte) []byte { b[hl+10] ^= 1; return b },
		"bit flip in tag":   func(b []byte) []byte { b[len(b)-1] ^= 0x80; return b },
		"bit flip in header": func(b []byte) []byte {
			b[len(magic)+4+2+5] ^= 1
			return b
		},
		"truncate inside chunk":      func(b []byte) []byte { return b[:len(b)-5] },
		"truncate at chunk boundary": func(b []byte) []byte { return b[:hl+3*full] },
		"drop everything after header": func(b []byte) []byte {
			return b[:hl]
		},
		"swap chunks": func(b []byte) []byte {
			c0 := bytes.Clone(b[hl : hl+full])
			copy(b[hl:hl+full], b[hl+full:hl+2*full])
			copy(b[hl+full:hl+2*full], c0)
			return b
		},
		"header from another key": func(b []byte) []byte {
			copy(b[:hl], origB[:hl])
			return b
		},
		"whole object from another key": func([]byte) []byte { return bytes.Clone(origB) },
		"appended chunk": func(b []byte) []byte {
			return append(b, b[hl:hl+full]...)
		},
		"key version changed": func(b []byte) []byte { b[len(magic)+3] = 2; return b },
		"bad magic":           func(b []byte) []byte { b[0] = 'X'; return b },
	}
	for name, mutate := range cases {
		if err := os.WriteFile(pathA, mutate(bytes.Clone(orig)), 0o600); err != nil {
			t.Fatal(err)
		}
		_, err := readAll(s, "x/a")
		if !errors.Is(err, ErrCorrupt) {
			t.Errorf("%s: expected ErrCorrupt, got %v", name, err)
		}
	}
	// Sanity: the untouched object still opens.
	_ = os.WriteFile(pathA, orig, 0o600)
	if got, err := readAll(s, "x/a"); err != nil || !bytes.Equal(got, data) {
		t.Fatalf("restored object: %v", err)
	}
}

func TestKeyRotation(t *testing.T) {
	dir := t.TempDir()
	ctx := context.Background()
	v1, _ := NewFS(dir, keyring(t, 1))
	data := random(t, 200000)
	if _, err := v1.Put(ctx, "old", bytes.NewReader(data)); err != nil {
		t.Fatal(err)
	}
	both, _ := NewFS(dir, keyring(t, 1, 2))
	got, err := readAll(both, "old")
	if err != nil || !bytes.Equal(got, data) {
		t.Fatalf("open v1 object with {v1,v2}: %v", err)
	}
	if _, err := both.Put(ctx, "new", bytes.NewReader(data)); err != nil {
		t.Fatal(err)
	}
	raw, _ := os.ReadFile(filepath.Join(dir, "new"))
	if raw[len(magic)+3] != 2 {
		t.Fatalf("new object sealed with version %d, want 2", raw[len(magic)+3])
	}
	if _, err := readAll(v1, "new"); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("v2 object opened without v2 key: %v", err)
	}
}

func TestFSPathSafety(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, "store")
	s, _ := NewFS(dir, keyring(t, 1))
	bad := []string{"", "/etc/passwd", "../x", "a/../../x", "a/..", "./a", "a//b", "a/", "a\\b", "C:x", "a\x00b",
		"a\nb", ".", "..", strings.Repeat("a", MaxKeyLen+1), "\xff\xfe"}
	for _, k := range bad {
		if _, err := s.Put(context.Background(), k, strings.NewReader("x")); !errors.Is(err, ErrInvalidKey) {
			t.Errorf("Put(%q): expected ErrInvalidKey, got %v", k, err)
		}
		if _, err := s.Open(context.Background(), k); !errors.Is(err, ErrInvalidKey) {
			t.Errorf("Open(%q): expected ErrInvalidKey, got %v", k, err)
		}
		if err := s.Delete(context.Background(), k); !errors.Is(err, ErrInvalidKey) {
			t.Errorf("Delete(%q): expected ErrInvalidKey, got %v", k, err)
		}
	}
	entries, _ := os.ReadDir(root)
	if len(entries) != 1 {
		t.Fatalf("files escaped the store directory: %v", entries)
	}
	// No temporary files are left behind after a failed Put.
	if _, err := s.Put(context.Background(), "k", errReader{}); err == nil {
		t.Fatal("expected read error")
	}
	left, _ := os.ReadDir(dir)
	if len(left) != 0 {
		t.Fatalf("temporary files left: %v", left)
	}
}

func TestPutHonoursContext(t *testing.T) {
	s, _ := NewFS(t.TempDir(), keyring(t, 1))
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := s.Put(ctx, "k", bytes.NewReader(make([]byte, 1<<20))); !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context.Canceled, got %v", err)
	}
}

type errReader struct{}

func (errReader) Read([]byte) (int, error) { return 0, errors.New("boom") }
