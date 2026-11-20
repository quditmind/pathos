package sourcestore

import (
	"bytes"
	"context"
	"errors"
	"testing"
)

// Enabling S3 after objects were written to the directory store must not
// make them unreadable (every earlier repository failed to scan).
func TestFallbackKeepsDiskObjectsReadable(t *testing.T) {
	ctx := context.Background()
	kr := keyring(t, 1)
	disk, err := NewFS(t.TempDir(), kr)
	if err != nil {
		t.Fatal(err)
	}
	old := random(t, 70_000)
	if _, err := disk.Put(ctx, "snapshots/repo-1/a.tar", bytes.NewReader(old)); err != nil {
		t.Fatal(err)
	}
	s3 := newS3(&memBlobs{m: map[string][]byte{}}, "sources", kr)
	st := Fallback{Primary: s3, Secondary: disk}

	got, err := readAll(st, "snapshots/repo-1/a.tar")
	if err != nil || !bytes.Equal(got, old) {
		t.Fatalf("object written before the switch: %v", err)
	}
	if ok, err := st.Exists(ctx, "snapshots/repo-1/a.tar"); !ok || err != nil {
		t.Fatalf("exists: %v %v", ok, err)
	}

	// New objects go to S3 only, and S3 wins over the disk.
	fresh := random(t, 1000)
	if _, err := st.Put(ctx, "snapshots/repo-1/a.tar", bytes.NewReader(fresh)); err != nil {
		t.Fatal(err)
	}
	if got, _ := readAll(st, "snapshots/repo-1/a.tar"); !bytes.Equal(got, fresh) {
		t.Fatal("the primary store's object must be read first")
	}
	if _, err := st.Put(ctx, "uploads/u-2", bytes.NewReader(fresh)); err != nil {
		t.Fatal(err)
	}
	if ok, _ := disk.Exists(ctx, "uploads/u-2"); ok {
		t.Fatal("new objects must not be written to the directory store")
	}

	// Delete removes the object from both stores.
	if err := st.Delete(ctx, "snapshots/repo-1/a.tar"); err != nil {
		t.Fatal(err)
	}
	if _, err := st.Open(ctx, "snapshots/repo-1/a.tar"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("after delete: %v", err)
	}
	if ok, _ := st.Exists(ctx, "missing"); ok {
		t.Fatal("missing object exists")
	}
}
