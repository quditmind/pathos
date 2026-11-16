package worker

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"hash"
	"io"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"

	"pathos/internal/ingest"
)

var sha256Re = regexp.MustCompile(`^[0-9a-f]{64}$`)

// fetchSnapshot downloads the job's source snapshot from the worker API
// (GET /internal/worker/v1/jobs/{id}/source; the API decrypts it, workers
// hold no storage credentials), extracts it into dst with the ingest path
// rules and verifies its SHA-256 and size. The digest is computed over the
// bytes as received while extracting; on any mismatch or error dst is
// removed before returning, so no scanner ever sees unverified content.
func (a *Agent) fetchSnapshot(ctx context.Context, job Job, dst string) (err error) {
	want := strings.ToLower(job.Source.SHA256)
	if !sha256Re.MatchString(want) {
		return errors.New("job has no valid snapshot SHA-256")
	}
	if job.Source.Size < 0 {
		return errors.New("job has an invalid snapshot size")
	}
	defer func() {
		if err != nil {
			_ = os.RemoveAll(dst)
		}
	}()
	u := strings.TrimRight(a.cfg.APIURL, "/") + "/internal/worker/v1/jobs/" + url.PathEscape(job.JobID) + "/source"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+a.token)
	// Large snapshots can take longer than the API client's overall
	// timeout; the job context bounds the download instead.
	client := *a.http
	client.Timeout = 0
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		msg, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return &apiError{Status: resp.StatusCode, Body: strings.TrimSpace(string(msg))}
	}

	// A snapshot is gzip-compressed, so it is never meaningfully larger than
	// its content; bound the download as well as the extraction.
	maxDownload := a.cfg.MaxRepoBytes + 1<<20
	if job.Source.Size > 0 {
		maxDownload = min(maxDownload, job.Source.Size)
	}
	h := sha256.New()
	body := &hashingReader{r: io.LimitReader(resp.Body, maxDownload+1), h: h}

	lim := ingest.DefaultLimits()
	lim.MaxTotalBytes = a.cfg.MaxRepoBytes
	lim.MaxFileBytes = min(lim.MaxFileBytes, a.cfg.MaxRepoBytes)
	if err := ingest.ExtractSnapshot(ctx, body, dst, lim); err != nil {
		if body.n > maxDownload {
			return fmt.Errorf("snapshot exceeds the %d MB size limit", maxDownload>>20)
		}
		return fmt.Errorf("extracting snapshot: %w", err)
	}
	// Hash whatever follows the archive end (gzip trailer, padding).
	if _, err := io.Copy(io.Discard, body); err != nil {
		return fmt.Errorf("downloading snapshot: %w", err)
	}
	if body.n > maxDownload {
		return fmt.Errorf("snapshot exceeds the %d MB size limit", maxDownload>>20)
	}
	if job.Source.Size > 0 && body.n != job.Source.Size {
		return fmt.Errorf("snapshot size mismatch: got %d bytes, expected %d", body.n, job.Source.Size)
	}
	got := hex.EncodeToString(h.Sum(nil))
	if subtle.ConstantTimeCompare([]byte(got), []byte(want)) != 1 {
		return errors.New("snapshot SHA-256 mismatch")
	}
	return nil
}

type hashingReader struct {
	r io.Reader
	h hash.Hash
	n int64
}

func (r *hashingReader) Read(p []byte) (int, error) {
	k, err := r.r.Read(p)
	r.h.Write(p[:k])
	r.n += int64(k)
	return k, err
}
