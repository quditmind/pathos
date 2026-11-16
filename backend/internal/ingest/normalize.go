package ingest

import (
	"archive/tar"
	"archive/zip"
	"compress/gzip"
	"context"
	"errors"
	"io"
	"io/fs"
	"strings"
	"time"
)

// Result describes a normalized snapshot.
type Result struct {
	Files             int              `json:"files"`
	UncompressedBytes int64            `json:"uncompressed_bytes"`
	Languages         map[string]int64 `json:"languages"` // bytes per language
	Manifests         []string         `json:"manifests"` // relative paths, at most MaxManifests
	Skipped           map[string]int   `json:"skipped"`   // symlink, hardlink, device, fifo, other
	StrippedPrefix    string           `json:"stripped_prefix,omitempty"`
}

// Skip reasons in Result.Skipped.
const (
	SkipSymlink  = "symlink"
	SkipHardlink = "hardlink"
	SkipDevice   = "device"
	SkipFifo     = "fifo"
	SkipOther    = "other"
)

type kind int

const (
	kindFile kind = iota
	kindDir
	kindSkip
	kindIgnore // tar global headers: metadata only, not counted
)

// entry is one archive member as seen by the validation pass.
type entry struct {
	path  string // cleaned
	kind  kind
	skip  string
	size  int64
	exec  bool
	mtime time.Time
	zf    *zip.File
}

// Normalize reads an archive of the given format ("zip", "tar" or
// "tar.gz"/"tgz") from src (size bytes; typically a temporary file),
// validates every entry and writes a gzip-compressed tar snapshot to out
// that contains only regular files and directories with normalized
// relative paths, modes 0644/0755, uid/gid 0 and no owner names. Nothing is
// written to the file system.
//
// Tar archives are read twice (headers first, then content), so the whole
// archive is validated and the common top-level directory known before
// output starts. Limits are enforced on header values first and again on
// the bytes actually read. Any violation rejects the whole archive with an
// *Error; out must then be discarded.
func Normalize(ctx context.Context, src io.ReaderAt, format string, size int64, out io.Writer, lim Limits) (Result, error) {
	lim = lim.withDefaults()
	var n normalizer
	n.ctx, n.lim = ctx, lim
	n.res = Result{Languages: map[string]int64{}, Skipped: map[string]int{}, Manifests: []string{}}
	switch format {
	case "zip":
		return n.zip(src, size, out)
	case "tar", "tar.gz", "tgz":
		return n.tar(src, size, format != "tar", out)
	}
	return Result{}, reject(CodeUnsupportedFormat, "", "unsupported archive format")
}

type normalizer struct {
	ctx      context.Context
	lim      Limits
	res      Result
	entries  []entry
	declared int64 // sum of declared file sizes
	count    int   // archive entries seen
	paths    *pathSet
}

// add validates one entry's metadata and records it.
func (n *normalizer) add(name string, e entry) error {
	if err := n.ctx.Err(); err != nil {
		return err
	}
	if e.kind == kindIgnore {
		n.entries = append(n.entries, e)
		return nil
	}
	n.count++
	if n.count > n.lim.MaxFiles {
		return reject(CodeTooManyFiles, "", "archive has too many entries")
	}
	p, err := cleanPath(name, n.lim)
	if err != nil {
		return err
	}
	e.path = p
	switch e.kind {
	case kindSkip:
		n.res.Skipped[e.skip]++
	case kindDir:
		if p != "" {
			if err := n.paths.add(p, true); err != nil {
				return err
			}
		}
	case kindFile:
		if p == "" {
			return reject(CodeInvalidPath, name, "file without a name")
		}
		if e.size < 0 || e.size > n.lim.MaxFileBytes {
			return reject(CodeFileTooLarge, p, "file exceeds the size limit")
		}
		n.declared += e.size
		if n.declared > n.lim.MaxTotalBytes {
			return reject(CodeTooLarge, "", "archive exceeds the uncompressed size limit")
		}
		if err := n.paths.add(p, false); err != nil {
			return err
		}
	}
	n.entries = append(n.entries, e)
	return nil
}

// stripPrefix returns the single top-level directory shared by every kept
// entry, or "".
func (n *normalizer) stripPrefix() string {
	top := ""
	deeper := false
	for _, e := range n.entries {
		if (e.kind != kindFile && e.kind != kindDir) || e.path == "" {
			continue
		}
		first, rest, hasRest := strings.Cut(e.path, "/")
		if top == "" {
			top = first
		} else if first != top {
			return ""
		}
		if !hasRest {
			if e.kind == kindFile {
				return ""
			}
			continue
		}
		if rest != "" {
			deeper = true
		}
	}
	if !deeper {
		return ""
	}
	return top
}

// outPath applies the stripped prefix ("" means drop the entry).
func outPath(p, prefix string) string {
	if prefix == "" {
		return p
	}
	if p == prefix {
		return ""
	}
	return strings.TrimPrefix(p, prefix+"/")
}

// snapshotWriter writes the normalized tar.gz.
type snapshotWriter struct {
	gz *gzip.Writer
	tw *tar.Writer
}

func newSnapshotWriter(out io.Writer) *snapshotWriter {
	gz, _ := gzip.NewWriterLevel(out, gzip.DefaultCompression)
	return &snapshotWriter{gz: gz, tw: tar.NewWriter(gz)}
}

func normTime(t time.Time) time.Time {
	if t.IsZero() || t.Before(time.Unix(0, 0)) {
		return time.Unix(0, 0).UTC()
	}
	return t.UTC().Truncate(time.Second)
}

func (w *snapshotWriter) dir(p string, mtime time.Time) error {
	return w.tw.WriteHeader(&tar.Header{Typeflag: tar.TypeDir, Name: p + "/", Mode: 0o755, ModTime: normTime(mtime)})
}

func (w *snapshotWriter) fileHeader(p string, size int64, exec bool, mtime time.Time) error {
	mode := int64(0o644)
	if exec {
		mode = 0o755
	}
	return w.tw.WriteHeader(&tar.Header{Typeflag: tar.TypeReg, Name: p, Size: size, Mode: mode, ModTime: normTime(mtime)})
}

func (w *snapshotWriter) close() error {
	if err := w.tw.Close(); err != nil {
		return err
	}
	return w.gz.Close()
}

// copyFile copies one file's content with limits on the actual bytes.
// ratio, when non-nil, is consulted after every read.
func (n *normalizer) copyFile(dst io.Writer, src io.Reader, e entry, ratio func(read int64) error) (int64, error) {
	buf := make([]byte, 32<<10)
	var read int64
	for {
		if err := n.ctx.Err(); err != nil {
			return read, err
		}
		k, rerr := src.Read(buf)
		if k > 0 {
			read += int64(k)
			if read > n.lim.MaxFileBytes {
				return read, reject(CodeFileTooLarge, e.path, "file exceeds the size limit")
			}
			if n.res.UncompressedBytes+read > n.lim.MaxTotalBytes {
				return read, reject(CodeTooLarge, "", "archive exceeds the uncompressed size limit")
			}
			if read > e.size {
				return read, reject(CodeCorruptArchive, e.path, "entry is larger than its header declares")
			}
			if ratio != nil {
				if err := ratio(read); err != nil {
					return read, err
				}
			}
			if _, err := dst.Write(buf[:k]); err != nil {
				return read, err
			}
		}
		if rerr == io.EOF {
			break
		}
		if rerr != nil {
			return read, corrupt(rerr, e.path)
		}
	}
	if read != e.size {
		return read, reject(CodeCorruptArchive, e.path, "entry is shorter than its header declares")
	}
	return read, nil
}

// corrupt maps archive decoding errors to CodeCorruptArchive, keeping
// rejections and context errors as they are.
func corrupt(err error, p string) error {
	var e *Error
	if errors.As(err, &e) || errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return err
	}
	if errors.Is(err, zip.ErrAlgorithm) {
		return reject(CodeUnsupportedFormat, p, "unsupported compression method")
	}
	return reject(CodeCorruptArchive, p, "archive is corrupt: "+err.Error())
}

func (n *normalizer) record(p string, size int64) {
	n.res.Files++
	n.res.UncompressedBytes += size
	if lang := languageOf(p); lang != "" {
		n.res.Languages[lang] += size
	}
	if isManifest(p) && len(n.res.Manifests) < MaxManifests {
		n.res.Manifests = append(n.res.Manifests, p)
	}
}

// --- ZIP ---

func (n *normalizer) zip(src io.ReaderAt, size int64, out io.Writer) (Result, error) {
	zr, err := zip.NewReader(src, size)
	if err != nil && !(errors.Is(err, zip.ErrInsecurePath) && zr != nil) {
		return Result{}, corrupt(err, "")
	}
	n.paths = newPathSet()
	for _, f := range zr.File {
		mode := f.Mode()
		e := entry{size: int64(f.UncompressedSize64), exec: mode&0o111 != 0, mtime: f.Modified, zf: f} // #nosec G115 -- checked against MaxFileBytes in add
		if f.UncompressedSize64 > uint64(n.lim.MaxFileBytes) {                                         // #nosec G115 -- MaxFileBytes is positive after withDefaults
			e.size = -1
		}
		switch {
		case mode.IsDir() || strings.HasSuffix(f.Name, "/"):
			e.kind = kindDir
		case mode&fs.ModeSymlink != 0:
			e.kind, e.skip = kindSkip, SkipSymlink
		case mode&fs.ModeDevice != 0 || mode&fs.ModeCharDevice != 0:
			e.kind, e.skip = kindSkip, SkipDevice
		case mode&fs.ModeNamedPipe != 0:
			e.kind, e.skip = kindSkip, SkipFifo
		case !mode.IsRegular():
			e.kind, e.skip = kindSkip, SkipOther
		default:
			e.kind = kindFile
		}
		if f.Flags&0x1 != 0 {
			return Result{}, reject(CodeEncryptedEntry, f.Name, "encrypted ZIP entries are not supported")
		}
		if err := n.add(f.Name, e); err != nil {
			return Result{}, err
		}
		if e.kind == kindFile && f.UncompressedSize64 > ratioMinBytes &&
			float64(f.UncompressedSize64) > n.lim.MaxRatio*float64(f.CompressedSize64) {
			return Result{}, reject(CodeCompressionRatio, f.Name, "compression ratio exceeds the limit")
		}
	}
	prefix := n.stripPrefix()
	n.res.StrippedPrefix = prefix
	w := newSnapshotWriter(out)
	for _, e := range n.entries {
		p := outPath(e.path, prefix)
		if p == "" {
			continue
		}
		switch e.kind {
		case kindDir:
			if err := w.dir(p, e.mtime); err != nil {
				return Result{}, err
			}
		case kindFile:
			if err := w.fileHeader(p, e.size, e.exec, e.mtime); err != nil {
				return Result{}, err
			}
			rc, err := e.zf.Open()
			if err != nil {
				return Result{}, corrupt(err, e.path)
			}
			compressed := float64(e.zf.CompressedSize64)
			got, err := n.copyFile(w.tw, rc, e, func(read int64) error {
				if read > ratioMinBytes && float64(read) > n.lim.MaxRatio*compressed {
					return reject(CodeCompressionRatio, e.path, "compression ratio exceeds the limit")
				}
				return nil
			})
			_ = rc.Close()
			if err != nil {
				return Result{}, err
			}
			n.record(p, got)
		}
	}
	return n.res, w.close()
}

// --- TAR ---

// countingReader counts bytes consumed from the compressed stream.
type countingReader struct {
	r io.Reader
	n int64
}

func (c *countingReader) Read(p []byte) (int, error) {
	k, err := c.r.Read(p)
	c.n += int64(k)
	return k, err
}

// tarStream opens a fresh pass over the archive.
func tarStream(src io.ReaderAt, size int64, gz bool) (*tar.Reader, *countingReader, error) {
	cr := &countingReader{r: io.NewSectionReader(src, 0, size)}
	if !gz {
		return tar.NewReader(cr), cr, nil
	}
	zr, err := gzip.NewReader(cr)
	if err != nil {
		return nil, nil, reject(CodeCorruptArchive, "", "not a gzip stream")
	}
	return tar.NewReader(zr), cr, nil
}

func tarKind(h *tar.Header) (kind, string) {
	switch h.Typeflag {
	case tar.TypeReg, '\x00': // '\x00' is the legacy TypeRegA
		return kindFile, ""
	case tar.TypeDir:
		return kindDir, ""
	case tar.TypeSymlink:
		return kindSkip, SkipSymlink
	case tar.TypeLink:
		return kindSkip, SkipHardlink
	case tar.TypeChar, tar.TypeBlock:
		return kindSkip, SkipDevice
	case tar.TypeFifo:
		return kindSkip, SkipFifo
	case tar.TypeXGlobalHeader:
		return kindIgnore, ""
	}
	return kindSkip, SkipOther
}

func (n *normalizer) tar(src io.ReaderAt, size int64, gz bool, out io.Writer) (Result, error) {
	ratio := func(cr *countingReader, uncompressed int64) error {
		if gz && uncompressed > ratioMinBytes && float64(uncompressed) > n.lim.MaxRatio*float64(max(cr.n, 1)) {
			return reject(CodeCompressionRatio, "", "compression ratio exceeds the limit")
		}
		return nil
	}

	// Pass 1: headers. Declared sizes are bounded by the limits before the
	// reader skips over (and, for gzip, inflates) their content.
	tr, cr, err := tarStream(src, size, gz)
	if err != nil {
		return Result{}, err
	}
	n.paths = newPathSet()
	for {
		h, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil && !(errors.Is(err, tar.ErrInsecurePath) && h != nil) {
			return Result{}, corrupt(err, "")
		}
		k, skip := tarKind(h)
		e := entry{kind: k, skip: skip, size: h.Size, exec: h.Mode&0o111 != 0, mtime: h.ModTime}
		// The content of every earlier entry has been consumed by now.
		if err := ratio(cr, n.declared); err != nil {
			return Result{}, err
		}
		if err := n.add(h.Name, e); err != nil {
			return Result{}, err
		}
	}
	if err := ratio(cr, n.declared); err != nil {
		return Result{}, err
	}
	if len(n.entries) == 0 && cr.n == 0 {
		return Result{}, reject(CodeCorruptArchive, "", "empty archive")
	}
	prefix := n.stripPrefix()
	n.res.StrippedPrefix = prefix

	// Pass 2: content, in the same order.
	tr, cr, err = tarStream(src, size, gz)
	if err != nil {
		return Result{}, err
	}
	w := newSnapshotWriter(out)
	for i := 0; ; i++ {
		h, err := tr.Next()
		if err == io.EOF {
			if i != len(n.entries) {
				return Result{}, reject(CodeCorruptArchive, "", "archive changed between passes")
			}
			break
		}
		if err != nil && !(errors.Is(err, tar.ErrInsecurePath) && h != nil) {
			return Result{}, corrupt(err, "")
		}
		if i >= len(n.entries) {
			return Result{}, reject(CodeCorruptArchive, "", "archive changed between passes")
		}
		e := n.entries[i]
		p := outPath(e.path, prefix)
		if p == "" {
			continue
		}
		switch e.kind {
		case kindDir:
			if err := w.dir(p, e.mtime); err != nil {
				return Result{}, err
			}
		case kindFile:
			if h.Size != e.size {
				return Result{}, reject(CodeCorruptArchive, e.path, "archive changed between passes")
			}
			if err := w.fileHeader(p, e.size, e.exec, e.mtime); err != nil {
				return Result{}, err
			}
			base := n.res.UncompressedBytes
			got, err := n.copyFile(w.tw, tr, e, func(read int64) error { return ratio(cr, base+read) })
			if err != nil {
				return Result{}, err
			}
			n.record(p, got)
		}
	}
	return n.res, w.close()
}
