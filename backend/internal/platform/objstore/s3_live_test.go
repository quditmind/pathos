package objstore

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"testing"
	"time"
)

// TestS3Live exercises a real S3-compatible server (SeaweedFS in CI/dev).
// Set PATHOS_TEST_S3_ENDPOINT, PATHOS_TEST_S3_ACCESS_KEY and
// PATHOS_TEST_S3_SECRET_KEY to run it.
func TestS3Live(t *testing.T) {
	ep := os.Getenv("PATHOS_TEST_S3_ENDPOINT")
	if ep == "" {
		t.Skip("PATHOS_TEST_S3_ENDPOINT not set")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	st, err := NewS3(Config{Endpoint: ep, Bucket: fmt.Sprintf("pathos-test-%d", time.Now().UnixNano()),
		AccessKey: os.Getenv("PATHOS_TEST_S3_ACCESS_KEY"), SecretKey: os.Getenv("PATHOS_TEST_S3_SECRET_KEY"), PathStyle: true})
	if err != nil {
		t.Fatal(err)
	}
	var lastErr error
	for range 20 {
		if lastErr = st.EnsureBucket(ctx); lastErr == nil {
			break
		}
		time.Sleep(time.Second)
	}
	if lastErr != nil {
		t.Fatal(lastErr)
	}
	if err := st.EnsureBucket(ctx); err != nil {
		t.Fatalf("EnsureBucket must be idempotent: %v", err)
	}
	big := bytes.Repeat([]byte("pathos-artifact-"), 1<<16) // 1 MiB
	keys := []string{}
	for i := range 5 {
		k := fmt.Sprintf("artifacts/org/%d.gz", i)
		if err := st.Put(ctx, k, big[:len(big)-i], "application/gzip"); err != nil {
			t.Fatalf("put %s: %v", k, err)
		}
		keys = append(keys, k)
	}
	got, err := st.Get(ctx, keys[2])
	if err != nil || !bytes.Equal(got, big[:len(big)-2]) {
		t.Fatalf("get: %v (len %d)", err, len(got))
	}
	if err := st.Delete(ctx, append(keys, "artifacts/org/never-existed.gz")); err != nil {
		t.Fatalf("batch delete: %v", err)
	}
	if _, err := st.Get(ctx, keys[0]); !errors.Is(err, ErrNotFound) {
		t.Fatalf("deleted object: want ErrNotFound, got %v", err)
	}
	// Wrong credentials are rejected by the server.
	bad, _ := NewS3(Config{Endpoint: ep, Bucket: "pathos-test-denied", AccessKey: "nope", SecretKey: "wrong", PathStyle: true})
	if err := bad.Put(ctx, "x", []byte("x"), "text/plain"); err == nil {
		t.Error("server accepted invalid credentials")
	}
}
