package worker

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"sync"
	"testing"
	"time"
)

func stubTrivyUpdate(t *testing.T, fn func(ctx context.Context, bin, cacheDir string) error) {
	t.Helper()
	old, oldPoll := trivyDBUpdate, trivyDBLockPoll
	trivyDBUpdate, trivyDBLockPoll = fn, 5*time.Millisecond
	t.Cleanup(func() { trivyDBUpdate, trivyDBLockPoll = old, oldPoll })
}

// A worker must not replace the shared database while another worker's
// scan is reading it (that crashed Trivy with SIGBUS in bbolt).
func TestTrivyDBUpdateWaitsForRunningScans(t *testing.T) {
	dir := t.TempDir()
	var mu sync.Mutex
	var events []string
	record := func(e string) { mu.Lock(); events = append(events, e); mu.Unlock() }
	stubTrivyUpdate(t, func(context.Context, string, string) error { record("update"); return nil })

	scanning, release := make(chan struct{}), make(chan struct{})
	done := make(chan error, 1)
	go func() {
		done <- withTrivyDB(context.Background(), "trivy", dir, false, func(extra []string) error {
			if !slices.Contains(extra, "--skip-db-update") {
				t.Errorf("scan must not update the database itself: %v", extra)
			}
			record("scan A start")
			close(scanning)
			<-release
			record("scan A end")
			return nil
		})
	}()
	<-scanning

	second := make(chan error, 1)
	go func() {
		second <- withTrivyDB(context.Background(), "trivy", dir, false, func([]string) error { record("scan B"); return nil })
	}()
	time.Sleep(50 * time.Millisecond)
	close(release)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if err := <-second; err != nil {
		t.Fatal(err)
	}
	want := []string{"update", "scan A start", "scan A end", "update", "scan B"}
	if !slices.Equal(events, want) {
		t.Fatalf("events %v, want %v", events, want)
	}
}

func writeTrivyDB(t *testing.T, dir string, age time.Duration) {
	t.Helper()
	_ = os.MkdirAll(filepath.Join(dir, "db"), 0o700)
	for _, f := range []string{"trivy.db", "metadata.json"} {
		p := filepath.Join(dir, "db", f)
		if err := os.WriteFile(p, []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
		at := time.Now().Add(-age)
		_ = os.Chtimes(p, at, at)
	}
}

// Concurrent scans may read a fresh database at the same time; a worker
// that cannot take the exclusive lock does not wait to update it.
func TestTrivyDBScansShareTheLock(t *testing.T) {
	dir := t.TempDir()
	writeTrivyDB(t, dir, time.Hour)
	var n int
	var mu sync.Mutex
	stubTrivyUpdate(t, func(context.Context, string, string) error { mu.Lock(); n++; mu.Unlock(); return nil })
	inA, inB := make(chan struct{}), make(chan struct{})
	errs := make(chan error, 2)
	go func() {
		errs <- withTrivyDB(context.Background(), "trivy", dir, false, func([]string) error {
			close(inA)
			select {
			case <-inB:
				return nil
			case <-time.After(5 * time.Second):
				return errors.New("second scan did not start while the first was running")
			}
		})
	}()
	<-inA
	go func() {
		errs <- withTrivyDB(context.Background(), "trivy", dir, false, func([]string) error { close(inB); return nil })
	}()
	for range 2 {
		if err := <-errs; err != nil {
			t.Fatal(err)
		}
	}
	if n != 1 {
		t.Fatalf("updates: %d, want 1 (the second scan skips the update while the first is reading)", n)
	}
}

// A missing or old database is stale: the worker then waits for the
// exclusive lock to update it.
func TestTrivyDBStale(t *testing.T) {
	dir := t.TempDir()
	writeTrivyDB(t, dir, 48*time.Hour)
	if !trivyDBStale(dir) {
		t.Fatal("48h old database must be stale")
	}
	writeTrivyDB(t, dir, time.Hour)
	if trivyDBStale(dir) {
		t.Fatal("1h old database must be fresh")
	}
	if !trivyDBStale(t.TempDir()) {
		t.Fatal("missing database must be stale")
	}
}

func TestTrivyDBUpdateFailure(t *testing.T) {
	dir := t.TempDir()
	stubTrivyUpdate(t, func(context.Context, string, string) error { return errors.New("Forbidden") })
	ran := false
	err := withTrivyDB(context.Background(), "trivy", dir, false, func([]string) error { ran = true; return nil })
	if err == nil || ran {
		t.Fatalf("no database and no download: want an error without scanning, got %v (scanned %v)", err, ran)
	}
	// With a cached database the scan goes ahead.
	_ = os.MkdirAll(filepath.Join(dir, "db"), 0o700)
	_ = os.WriteFile(filepath.Join(dir, "db", "trivy.db"), []byte("x"), 0o600)
	if err := withTrivyDB(context.Background(), "trivy", dir, false, func([]string) error { ran = true; return nil }); err != nil || !ran {
		t.Fatalf("cached database: err %v, scanned %v", err, ran)
	}
}

func TestTrivyDBOfflineAndCancel(t *testing.T) {
	dir := t.TempDir()
	stubTrivyUpdate(t, func(context.Context, string, string) error { t.Error("offline must not update"); return nil })
	if err := withTrivyDB(context.Background(), "trivy", dir, true, func(extra []string) error {
		if extra != nil {
			t.Errorf("offline extra flags: %v", extra)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}

	// A worker waiting for the lock gives up when its job is cancelled.
	stubTrivyUpdate(t, func(context.Context, string, string) error { return nil })
	hold, release := make(chan struct{}), make(chan struct{})
	go func() {
		_ = withTrivyDB(context.Background(), "trivy", dir, false, func([]string) error { close(hold); <-release; return nil })
	}()
	<-hold
	defer close(release)
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	if err := withTrivyDB(ctx, "trivy", dir, false, func([]string) error { return nil }); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("want deadline exceeded, got %v", err)
	}
}

// Concurrent Trivy runs of several workers must not share the file-based
// scan cache (its lock made all but one fail).
func TestTrivyCacheArgs(t *testing.T) {
	args := trivyCacheArgs("/cache/trivy")
	if !slices.Equal(args, []string{"--cache-dir", "/cache/trivy", "--cache-backend", "memory"}) {
		t.Errorf("trivy cache flags: %v", args)
	}
}
