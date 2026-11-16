// Package ingest validates and normalizes uploaded source archives.
//
// It is pure Go: archives are only parsed, never extracted by an external
// tool, and nothing in them is executed. Normalize rewrites an upload into a
// canonical gzip tar "snapshot" (regular files and directories only);
// ExtractSnapshot unpacks such a snapshot in a scan worker with the same
// path rules (defense in depth).
package ingest

import (
	"errors"
	"fmt"
	"strings"
	"unicode/utf8"
)

// Code classifies why an archive was rejected.
type Code string

const (
	CodePathTraversal     Code = "path_traversal"
	CodeAbsolutePath      Code = "absolute_path"
	CodeInvalidPath       Code = "invalid_path"
	CodeDuplicatePath     Code = "duplicate_path"
	CodeTooManyFiles      Code = "too_many_files"
	CodeTooLarge          Code = "too_large"
	CodeFileTooLarge      Code = "file_too_large"
	CodeCompressionRatio  Code = "compression_ratio"
	CodeEncryptedEntry    Code = "encrypted_entry"
	CodeUnsupportedFormat Code = "unsupported_format"
	CodeCorruptArchive    Code = "corrupt_archive"
	// CodeUnsupportedEntry is used only by ExtractSnapshot: a snapshot
	// contains something other than a regular file or directory.
	CodeUnsupportedEntry Code = "unsupported_entry"
)

// Error is an archive rejection.
type Error struct {
	Code Code
	Path string // offending entry (may be empty); never contains file content
	Msg  string
}

func (e *Error) Error() string {
	if e.Path != "" {
		return fmt.Sprintf("%s: %s (%q)", e.Code, e.Msg, e.Path)
	}
	return fmt.Sprintf("%s: %s", e.Code, e.Msg)
}

// CodeOf returns the rejection code of err, or "" if err is not an *Error.
func CodeOf(err error) Code {
	var e *Error
	if errors.As(err, &e) {
		return e.Code
	}
	return ""
}

func reject(code Code, path, msg string) *Error {
	if len(path) > 256 {
		path = path[:256] + "..."
	}
	if !utf8.ValidString(path) {
		path = strings.ToValidUTF8(path, "?")
	}
	return &Error{Code: code, Path: path, Msg: msg}
}

// Limits bound the work an archive can cause. Zero fields take the
// DefaultLimits value.
type Limits struct {
	MaxFiles      int     // archive entries (all kinds)
	MaxTotalBytes int64   // total uncompressed file bytes
	MaxFileBytes  int64   // single file
	MaxRatio      float64 // uncompressed/compressed, checked once more than 1 MiB has been inflated
	MaxPathLen    int     // bytes of a normalized path
	MaxDepth      int     // path components
}

// ratioMinBytes is the uncompressed size from which MaxRatio applies.
const ratioMinBytes = 1 << 20

// DefaultLimits mirrors the PATHOS_IMPORT_* defaults.
func DefaultLimits() Limits {
	return Limits{
		MaxFiles:      200000,
		MaxTotalBytes: 8 << 30,
		MaxFileBytes:  1 << 30,
		MaxRatio:      200,
		MaxPathLen:    1024,
		MaxDepth:      64,
	}
}

func (l Limits) withDefaults() Limits {
	d := DefaultLimits()
	if l.MaxFiles <= 0 {
		l.MaxFiles = d.MaxFiles
	}
	if l.MaxTotalBytes <= 0 {
		l.MaxTotalBytes = d.MaxTotalBytes
	}
	if l.MaxFileBytes <= 0 {
		l.MaxFileBytes = d.MaxFileBytes
	}
	if l.MaxRatio <= 0 {
		l.MaxRatio = d.MaxRatio
	}
	if l.MaxPathLen <= 0 {
		l.MaxPathLen = d.MaxPathLen
	}
	if l.MaxDepth <= 0 {
		l.MaxDepth = d.MaxDepth
	}
	return l
}

// cleanPath validates an archive entry name and returns its normalized
// slash-separated relative form. "" means the entry is the archive root
// (for example "./"). Empty and "." components are dropped; everything that
// could address a location outside the root is rejected.
func cleanPath(name string, lim Limits) (string, error) {
	if name == "" {
		return "", reject(CodeInvalidPath, name, "empty name")
	}
	if len(name) > 4*lim.MaxPathLen {
		return "", reject(CodeInvalidPath, name, "path too long")
	}
	if !utf8.ValidString(name) {
		return "", reject(CodeInvalidPath, name, "name is not valid UTF-8")
	}
	for _, r := range name {
		if r < 0x20 || r == 0x7f {
			return "", reject(CodeInvalidPath, name, "name contains NUL or control characters")
		}
	}
	isDrive := len(name) >= 2 && name[1] == ':' && ((name[0] >= 'a' && name[0] <= 'z') || (name[0] >= 'A' && name[0] <= 'Z'))
	switch {
	case strings.HasPrefix(name, `\\`) || strings.HasPrefix(name, "//") || isDrive:
		return "", reject(CodeAbsolutePath, name, "UNC or drive-letter path")
	case strings.HasPrefix(name, "/"):
		return "", reject(CodeAbsolutePath, name, "absolute path")
	case strings.ContainsRune(name, '\\'):
		for _, c := range strings.FieldsFunc(name, func(r rune) bool { return r == '\\' || r == '/' }) {
			if c == ".." {
				return "", reject(CodePathTraversal, name, "path traversal")
			}
		}
		return "", reject(CodeInvalidPath, name, "backslash in path")
	}
	parts := make([]string, 0, 8)
	for _, c := range strings.Split(name, "/") {
		switch c {
		case "", ".":
			continue
		case "..":
			return "", reject(CodePathTraversal, name, "path traversal")
		}
		parts = append(parts, c)
	}
	p := strings.Join(parts, "/")
	if len(p) > lim.MaxPathLen {
		return "", reject(CodeInvalidPath, name, "path too long")
	}
	if len(parts) > lim.MaxDepth {
		return "", reject(CodeInvalidPath, name, "path too deep")
	}
	return p, nil
}

// pathSet detects duplicates and file/directory conflicts.
type pathSet struct {
	files map[string]bool
	dirs  map[string]bool // explicit and implied parents
}

func newPathSet() *pathSet { return &pathSet{files: map[string]bool{}, dirs: map[string]bool{}} }

func (s *pathSet) add(p string, isDir bool) error {
	if s.files[p] {
		return reject(CodeDuplicatePath, p, "duplicate path")
	}
	if isDir {
		s.dirs[p] = true
	} else {
		if s.dirs[p] {
			return reject(CodeDuplicatePath, p, "path is both a file and a directory")
		}
		s.files[p] = true
	}
	for i := strings.LastIndexByte(p, '/'); i > 0; i = strings.LastIndexByte(p[:i], '/') {
		parent := p[:i]
		if s.files[parent] {
			return reject(CodeDuplicatePath, p, "parent path is a file")
		}
		s.dirs[parent] = true
	}
	return nil
}
