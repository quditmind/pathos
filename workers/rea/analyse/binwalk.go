package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// binwalk (MIT) finds embedded file signatures in firmware images and
// extracts them (built-in extractors, recursively) into the job's temporary
// directory. Extracted files are listed (never executed, never followed
// through symbolic links).

type bwAnalysis struct {
	Analysis struct {
		FilePath string `json:"file_path"`
		FileMap  []struct {
			Offset      int64  `json:"offset"`
			ID          string `json:"id"`
			Size        int64  `json:"size"`
			Name        string `json:"name"`
			Description string `json:"description"`
		} `json:"file_map"`
		Extractions map[string]struct {
			Success bool `json:"success"`
		} `json:"extractions"`
	} `json:"Analysis"`
}

func binwalkVersion(ctx context.Context) string {
	out, _, err := runTool(ctx, runOpts{timeout: 20 * time.Second}, "binwalk", "-V")
	if err != nil {
		return ""
	}
	return strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(string(out)), "binwalk"))
}

const maxFirmwareBytes = 2 << 30

func runBinwalk(ctx context.Context, file, tmp string, memMB int, budget time.Duration) (*Firmware, error) {
	root := filepath.Join(tmp, "binwalk")
	// #nosec G703 -- under the job's temporary directory (pathos-rea's argument)
	if err := os.MkdirAll(root, 0o700); err != nil {
		return nil, err
	}
	logf := filepath.Join(tmp, "binwalk.json")
	_, _, err := runTool(ctx, runOpts{timeout: budget, memoryMB: memMB, dir: tmp}, "binwalk", "-q", "-e", "-M", "-C", root, "-l", logf, file)
	if err != nil && err != errTimeout {
		return nil, err
	}
	fw := &Firmware{Entries: []FirmwareEntry{}, Files: []FirmwareFile{}}
	// #nosec G304 G703 -- binwalk's log in the job's temporary directory
	raw, rerr := os.ReadFile(logf)
	if rerr == nil {
		as := parseBinwalkLog(raw)
		if len(as) > 0 {
			// The first analysis is the input file; the others (-M) are
			// extracted files.
			top := as[0].Analysis
			for _, e := range top.FileMap {
				if len(fw.Entries) >= maxFwEntries {
					break
				}
				ex := top.Extractions[e.ID]
				fw.Entries = append(fw.Entries, FirmwareEntry{Offset: e.Offset, Type: clip(e.Name, 100), Description: clip(e.Description, 500),
					Size: e.Size, Extracted: ex.Success})
			}
		}
	}
	var total int64
	rt, rerr2 := os.OpenRoot(root)
	if rerr2 != nil {
		return fw, nil
	}
	defer rt.Close()
	// #nosec G703 -- the extraction directory under the job's temporary directory
	_ = fs.WalkDir(rt.FS(), ".", func(rel string, d fs.DirEntry, werr error) error {
		if werr != nil || len(fw.Files) >= maxFwFiles {
			return nil
		}
		if !d.Type().IsRegular() {
			return nil // directories, and symbolic links (never followed)
		}
		info, ierr := d.Info()
		if ierr != nil {
			return nil
		}
		if !strings.Contains(rel, "/") {
			return nil // the input's link or copy at the top
		}
		ff := FirmwareFile{Path: clip(rel, 1000), Size: info.Size()}
		total += info.Size()
		if total < maxFirmwareBytes {
			ff.SHA256, ff.Type = hashAndSniff(rt, rel)
		}
		fw.Files = append(fw.Files, ff)
		return nil
	})
	if err == errTimeout {
		return fw, err
	}
	return fw, nil
}

func hashAndSniff(rt *os.Root, rel string) (string, string) {
	// Opened inside the extraction root: a symbolic link cannot lead out.
	f, err := rt.Open(rel)
	if err != nil {
		return "", ""
	}
	defer f.Close()
	head := make([]byte, 512)
	n, _ := io.ReadFull(f, head)
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		return "", ""
	}
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", ""
	}
	t := sniff(head[:n])
	if t == "unknown" && isText(head[:n]) {
		t = "text"
	}
	return hex.EncodeToString(h.Sum(nil)), t
}

func isText(b []byte) bool {
	for _, c := range b {
		if c < 9 || (c > 13 && c < 32) {
			return false
		}
	}
	return len(b) > 0
}

// parseBinwalkLog reads binwalk's JSON log: an array of analyses, which
// binwalk 3.1.0 writes without separators between the entries of a
// recursive (-M) run; the entries are read one by one.
func parseBinwalkLog(raw []byte) []bwAnalysis {
	var out []bwAnalysis
	rest := bytes.TrimSpace(raw)
	rest = bytes.TrimPrefix(rest, []byte("["))
	for len(out) < 10000 {
		rest = bytes.TrimLeft(rest, " \t\r\n,")
		if len(rest) == 0 || rest[0] != '{' {
			break
		}
		dec := json.NewDecoder(bytes.NewReader(rest))
		var a bwAnalysis
		if err := dec.Decode(&a); err != nil {
			break
		}
		out = append(out, a)
		rest = rest[dec.InputOffset():]
	}
	return out
}
