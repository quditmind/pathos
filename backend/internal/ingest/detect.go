package ingest

import (
	"bytes"
	"compress/gzip"
	"io"
	"strings"
)

// DetectFormat identifies an archive by its first bytes (at least 262 for
// an uncompressed tar; 512 is plenty) and cross-checks the file name
// extension when one is given. It returns "zip", "tar" or "tar.gz".
func DetectFormat(head []byte, filename string) (string, error) {
	var magicFormat string
	switch {
	case bytes.HasPrefix(head, []byte("PK\x03\x04")), bytes.HasPrefix(head, []byte("PK\x05\x06")):
		magicFormat = "zip"
	case bytes.HasPrefix(head, []byte{0x1f, 0x8b}):
		magicFormat = "tar.gz"
		// If enough of the stream is present, the inflated start must be a
		// tar header (a gzipped single file is not an archive).
		if zr, err := gzip.NewReader(bytes.NewReader(head)); err == nil {
			inner := make([]byte, 263)
			k, _ := io.ReadFull(zr, inner)
			if k >= 262 && !isTar(inner[:k]) {
				return "", reject(CodeUnsupportedFormat, filename, "gzip file does not contain a tar archive")
			}
		}
	case isTar(head):
		magicFormat = "tar"
	default:
		return "", reject(CodeUnsupportedFormat, filename, "not a ZIP, tar or tar.gz archive")
	}
	if filename == "" {
		return magicFormat, nil
	}
	lower := strings.ToLower(filename)
	var extFormat string
	switch {
	case strings.HasSuffix(lower, ".zip"):
		extFormat = "zip"
	case strings.HasSuffix(lower, ".tar.gz"), strings.HasSuffix(lower, ".tgz"):
		extFormat = "tar.gz"
	case strings.HasSuffix(lower, ".tar"):
		extFormat = "tar"
	default:
		return "", reject(CodeUnsupportedFormat, filename, "unsupported file extension")
	}
	if extFormat != magicFormat {
		return "", reject(CodeUnsupportedFormat, filename, "file content does not match its extension")
	}
	return magicFormat, nil
}

// isTar checks the POSIX/GNU "ustar" magic at offset 257.
func isTar(b []byte) bool {
	return len(b) >= 262 && string(b[257:262]) == "ustar"
}
