package worker

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"syscall"
	"time"
)

// Workers share the scanner cache volume, and Trivy keeps its vulnerability
// database there as one bbolt file that it memory-maps while scanning. When
// the database is due for an update, Trivy replaces the file in place, so a
// worker that updates it while another worker is scanning crashes the
// scanning process (SIGBUS in bbolt) and fails that scan. withTrivyDB
// serializes the update between workers with a file lock on the shared
// volume: the update (a no-op while the database is fresh) runs under an
// exclusive lock, the scan under a shared lock with --skip-db-update.
//
// Scans of different workers still overlap: a worker that finds the lock
// held by running scans skips the update and scans with the cached database,
// unless that database is missing or older than trivyDBMaxAge; then it waits
// for the exclusive lock (and so do the scans that start after it).

// trivyDBLockPoll is how often a waiting worker retries the lock.
var trivyDBLockPoll = 250 * time.Millisecond

// trivyDBMaxAge is the age after which a worker waits to update the
// database instead of scanning with it (Trivy publishes it every 6 hours).
const trivyDBMaxAge = 24 * time.Hour

// trivyDBStale reports whether the cached database is missing or old.
func trivyDBStale(cacheDir string) bool {
	st, err := os.Stat(filepath.Join(cacheDir, "db", "metadata.json"))
	if err != nil {
		return true
	}
	if _, err := os.Stat(filepath.Join(cacheDir, "db", "trivy.db")); err != nil {
		return true
	}
	return time.Since(st.ModTime()) > trivyDBMaxAge
}

// trivyDBUpdate downloads the database when it is due (Trivy decides).
var trivyDBUpdate = func(ctx context.Context, bin, cacheDir string) error {
	_, err := command(ctx, nil, []int{0}, bin, "image", "--download-db-only", "--cache-dir", cacheDir,
		"--quiet", "--skip-version-check", "--no-progress", "--timeout", "20m")
	return err
}

// withTrivyDB runs scan with the extra Trivy flags it must add. Offline the
// database is never updated, so no lock is taken.
func withTrivyDB(ctx context.Context, bin, cacheDir string, offline bool, scan func(extra []string) error) error {
	if offline {
		return scan(nil)
	}
	if err := os.MkdirAll(cacheDir, 0o750); err != nil {
		return fmt.Errorf("trivy cache: %w", err)
	}
	// #nosec G304 -- fixed name in the worker's own cache directory
	f, err := os.OpenFile(filepath.Join(cacheDir, ".pathos-db.lock"), os.O_CREATE|os.O_RDWR|syscall.O_NOFOLLOW, 0o600)
	if err != nil {
		return fmt.Errorf("trivy cache lock: %w", err)
	}
	defer f.Close()
	fd := int(f.Fd())
	var updateErr error
	locked := syscall.Flock(fd, syscall.LOCK_EX|syscall.LOCK_NB) == nil
	if !locked && trivyDBStale(cacheDir) {
		if err := flockWait(ctx, fd, syscall.LOCK_EX); err != nil {
			return err
		}
		locked = true
	}
	if locked {
		updateErr = trivyDBUpdate(ctx, bin, cacheDir)
	}
	// Downgrade: other workers may scan with the database now, but none may
	// replace it until this scan is finished.
	if err := flockWait(ctx, fd, syscall.LOCK_SH); err != nil {
		_ = syscall.Flock(fd, syscall.LOCK_UN)
		return err
	}
	defer func() { _ = syscall.Flock(fd, syscall.LOCK_UN) }()
	if updateErr != nil {
		if _, err := os.Stat(filepath.Join(cacheDir, "db", "trivy.db")); err != nil {
			return fmt.Errorf("trivy vulnerability database download failed: %w", updateErr)
		}
		// A database is present: scan with it rather than fail the scan.
		slog.Warn("trivy database update failed; scanning with the cached database", "error", updateErr)
	}
	return scan([]string{"--skip-db-update"})
}

// flockWait takes the lock, retrying until ctx ends.
func flockWait(ctx context.Context, fd, how int) error {
	for {
		err := syscall.Flock(fd, how|syscall.LOCK_NB)
		if err == nil {
			return nil
		}
		if err != syscall.EWOULDBLOCK && err != syscall.EINTR {
			return fmt.Errorf("trivy cache lock: %w", err)
		}
		select {
		case <-ctx.Done():
			return fmt.Errorf("waiting for the trivy database lock: %w", ctx.Err())
		case <-time.After(trivyDBLockPoll):
		}
	}
}
