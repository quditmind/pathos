package ingest

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"errors"
	"io"
	"os"
	"path"
)

// maxTrailer bounds data accepted after the tar end marker (block padding).
const maxTrailer = 1 << 20

// ExtractSnapshot unpacks a snapshot produced by Normalize (gzip tar) into
// dst, which is created if needed and should be empty. It applies the same
// path validation and limits as Normalize and accepts only regular files
// and directories; anything else rejects the snapshot. All file system
// operations go through an os.Root confined to dst, files are created with
// O_CREATE|O_EXCL (never through an existing name or symlink), and modes are
// reduced to 0644/0755. On error dst may contain a partial extraction that
// the caller must remove.
func ExtractSnapshot(ctx context.Context, r io.Reader, dst string, lim Limits) error {
	lim = lim.withDefaults()
	if err := os.MkdirAll(dst, 0o700); err != nil {
		return err
	}
	root, err := os.OpenRoot(dst)
	if err != nil {
		return err
	}
	defer root.Close()

	zr, err := gzip.NewReader(r)
	if err != nil {
		return corrupt(err, "")
	}
	zr.Multistream(false)
	tr := tar.NewReader(zr)
	paths := newPathSet()
	count := 0
	var total int64
	buf := make([]byte, 32<<10)
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		h, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil && !(errors.Is(err, tar.ErrInsecurePath) && h != nil) {
			return corrupt(err, "")
		}
		count++
		if count > lim.MaxFiles {
			return reject(CodeTooManyFiles, "", "snapshot has too many entries")
		}
		p, err := cleanPath(h.Name, lim)
		if err != nil {
			return err
		}
		switch h.Typeflag {
		case tar.TypeDir:
			if p == "" {
				continue
			}
			if err := paths.add(p, true); err != nil {
				return err
			}
			if err := root.MkdirAll(p, 0o755); err != nil {
				return err
			}
		case tar.TypeReg:
			if p == "" {
				return reject(CodeInvalidPath, h.Name, "file without a name")
			}
			if err := paths.add(p, false); err != nil {
				return err
			}
			if h.Size < 0 || h.Size > lim.MaxFileBytes {
				return reject(CodeFileTooLarge, p, "file exceeds the size limit")
			}
			if total+h.Size > lim.MaxTotalBytes {
				return reject(CodeTooLarge, "", "snapshot exceeds the size limit")
			}
			if dir := path.Dir(p); dir != "." {
				if err := root.MkdirAll(dir, 0o755); err != nil {
					return err
				}
			}
			mode := os.FileMode(0o644)
			if h.Mode&0o111 != 0 {
				mode = 0o755
			}
			f, err := root.OpenFile(p, os.O_WRONLY|os.O_CREATE|os.O_EXCL|oNoFollow, mode)
			if err != nil {
				return err
			}
			n, err := copyLimited(ctx, f, tr, buf, lim.MaxFileBytes, lim.MaxTotalBytes-total, p)
			total += n
			if cerr := f.Close(); err == nil {
				err = cerr
			}
			if err != nil {
				return err
			}
			if n != h.Size {
				return reject(CodeCorruptArchive, p, "entry is shorter than its header declares")
			}
			mt := normTime(h.ModTime)
			if err := root.Chtimes(p, mt, mt); err != nil {
				return err
			}
		default:
			return reject(CodeUnsupportedEntry, h.Name, "snapshot contains an entry that is not a regular file or directory")
		}
	}
	// Consume the end-of-archive padding so the gzip checksum is verified.
	k, err := io.Copy(io.Discard, io.LimitReader(zr, maxTrailer+1))
	if err != nil {
		return corrupt(err, "")
	}
	if k > maxTrailer {
		return reject(CodeCorruptArchive, "", "unexpected data after the end of the snapshot")
	}
	return nil
}

func copyLimited(ctx context.Context, dst io.Writer, src io.Reader, buf []byte, maxFile, remaining int64, p string) (int64, error) {
	var n int64
	for {
		if err := ctx.Err(); err != nil {
			return n, err
		}
		k, rerr := src.Read(buf)
		if k > 0 {
			n += int64(k)
			if n > maxFile {
				return n, reject(CodeFileTooLarge, p, "file exceeds the size limit")
			}
			if n > remaining {
				return n, reject(CodeTooLarge, "", "snapshot exceeds the size limit")
			}
			if _, err := dst.Write(buf[:k]); err != nil {
				return n, err
			}
		}
		if rerr == io.EOF {
			return n, nil
		}
		if rerr != nil {
			return n, corrupt(rerr, p)
		}
	}
}
