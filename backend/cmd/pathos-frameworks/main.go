// Command pathos-frameworks updates the bundled threat-modelling reference
// data (MITRE ATT&CK, CAPEC, CWE, D3FEND) from pinned, checksum-verified
// releases (internal/threatmodel/frameworks/sources.json).
//
//	make threat-frameworks                       # download, verify, extract
//	go run ./cmd/pathos-frameworks -pin attack   # after editing a release URL: record its SHA-256
//
// Downloads are cached in ~/.cache/pathos-frameworks (or -cache). A file
// whose SHA-256 differs from the pin is refused. The extracted files
// (frameworks/data/<framework>.json) are committed and embedded in the
// build, so installations never fetch them.
package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"strings"
	"time"

	"pathos/internal/threatmodel/frameworks"
)

func main() {
	dir := flag.String("dir", "internal/threatmodel/frameworks", "the frameworks package directory")
	home, _ := os.UserHomeDir()
	cache := flag.String("cache", filepath.Join(home, ".cache", "pathos-frameworks"), "download cache")
	pin := flag.String("pin", "", "record the SHA-256 of this framework's current URL in sources.json instead of extracting")
	only := flag.String("only", "", "extract only this framework")
	flag.Parse()
	if err := run(*dir, *cache, *pin, *only); err != nil {
		fmt.Fprintln(os.Stderr, "pathos-frameworks:", err)
		os.Exit(1)
	}
}

func run(dir, cache, pin, only string) error {
	srcPath := filepath.Join(dir, frameworks.SourcesFile)
	raw, err := os.ReadFile(srcPath) // #nosec G304 -- a path given by the maintainer
	if err != nil {
		return err
	}
	var sources []frameworks.Source
	if err := json.Unmarshal(raw, &sources); err != nil {
		return fmt.Errorf("%s: %w", srcPath, err)
	}
	if err := os.MkdirAll(cache, 0o750); err != nil {
		return err
	}
	for i, s := range sources {
		if only != "" && s.Framework != only {
			continue
		}
		if pin != "" {
			if s.Framework != pin {
				continue
			}
			data, err := fetch(cache, s.URL)
			if err != nil {
				return err
			}
			sum := sha256.Sum256(data)
			sources[i].SHA256 = hex.EncodeToString(sum[:])
			out, _ := json.MarshalIndent(sources, "", "  ")
			if err := os.WriteFile(srcPath, append(out, '\n'), 0o600); err != nil {
				return err
			}
			fmt.Printf("%s %s pinned: sha256 %s (review the diff of %s)\n", s.Framework, s.Release, sources[i].SHA256, srcPath)
			return nil
		}
		data, err := fetch(cache, s.URL)
		if err != nil {
			return err
		}
		sum := sha256.Sum256(data)
		if got := hex.EncodeToString(sum[:]); got != s.SHA256 {
			return fmt.Errorf("%s %s: SHA-256 %s does not match the pin %s; refusing the file", s.Framework, s.Release, got, s.SHA256)
		}
		var d *frameworks.Dataset
		switch s.Framework {
		case frameworks.ATTACK:
			d, err = frameworks.ExtractATTACK(s, strings.NewReader(string(data)))
		case frameworks.CAPEC:
			d, err = frameworks.ExtractCAPEC(s, strings.NewReader(string(data)))
		case frameworks.CWE:
			d, err = frameworks.ExtractCWE(s, data)
		case frameworks.D3FEND:
			d, err = frameworks.ExtractD3FEND(s, strings.NewReader(string(data)))
		default:
			err = fmt.Errorf("unknown framework %q", s.Framework)
		}
		if err != nil {
			return err
		}
		out, err := json.MarshalIndent(d, "", " ")
		if err != nil {
			return err
		}
		target := filepath.Join(dir, "data", s.Framework+".json")
		if err := os.WriteFile(target, append(out, '\n'), 0o600); err != nil {
			return err
		}
		fmt.Printf("%s %s: %d entries, %d relations -> %s\n", s.Framework, s.Release, len(d.Entries), len(d.Relations), target)
	}
	if pin != "" {
		return fmt.Errorf("no framework %q in %s", pin, srcPath)
	}
	return nil
}

// fetch returns the cached download of url, downloading it once.
func fetch(cache, url string) ([]byte, error) {
	if !strings.HasPrefix(url, "https://") {
		return nil, fmt.Errorf("%s: only https downloads are allowed", url)
	}
	file := filepath.Join(cache, path.Base(url))
	if b, err := os.ReadFile(file); err == nil { // #nosec G304 -- the cache directory
		return b, nil
	}
	c := &http.Client{Timeout: 10 * time.Minute}
	resp, err := c.Get(url) // #nosec G107 -- pinned release URLs from sources.json
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%s: HTTP %d", url, resp.StatusCode)
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, 512<<20))
	if err != nil {
		return nil, err
	}
	if err := os.WriteFile(file, b, 0o600); err != nil {
		return nil, err
	}
	return b, nil
}
