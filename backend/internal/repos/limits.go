package repos

import (
	"context"
	"io"
	"os"
	"time"
)

// SourceStore is the encrypted blob store for uploads and snapshots
// (implemented by internal/platform/sourcestore).
type SourceStore interface {
	Put(ctx context.Context, key string, r io.Reader) (int64, error)
	Open(ctx context.Context, key string) (io.ReadCloser, error)
	Delete(ctx context.Context, keys ...string) error
}

// Limits bounds uploads and import processing (PATHOS_UPLOAD_* and
// PATHOS_IMPORT_* settings).
type Limits struct {
	UploadMaxBytes    int64
	MaxFiles          int
	MaxExtractedBytes int64
	MaxFileBytes      int64
	// ImportTimeout bounds one import item.
	ImportTimeout time.Duration
	// ClamAVAddress enables malware scanning of uploads (host:port).
	ClamAVAddress  string
	ClamAVRequired bool
	// WorkDir holds temporary archive files during processing.
	WorkDir string
}

// DefaultLimits are used when configuration leaves a value at zero.
func DefaultLimits() Limits {
	return Limits{UploadMaxBytes: 2 << 30, MaxFiles: 200_000, MaxExtractedBytes: 8 << 30, MaxFileBytes: 1 << 30,
		ImportTimeout: 30 * time.Minute, WorkDir: os.TempDir()}
}

// uploadChunkSize is the part size browsers upload (8 MiB).
const uploadChunkSize = 8 << 20
