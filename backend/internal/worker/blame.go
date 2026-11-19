package worker

import (
	"bufio"
	"bytes"
	"context"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"pathos/internal/scanners"
)

// Introducing commits: for code findings (SAST, secrets, IaC) with a file
// and line, git blame of the scanned commit names the commit that last
// changed that line, its author's name and date. Author e-mail addresses
// are never collected. A shallow clone has no history, so the commit is
// reported as unknown instead of guessed.

// BlameReport is uploaded to the worker API.
type BlameReport struct {
	Version int `json:"version"`
	// Mode: full (history available) or shallow.
	Mode    string       `json:"mode"`
	Entries []BlameEntry `json:"entries"`
	// Missing lists locations that are not in the scanned commit.
	Missing []BlameLocation `json:"missing,omitempty"`
}

// BlameLocation is a file and line.
type BlameLocation struct {
	File string `json:"file"`
	Line int    `json:"line"`
}

// BlameEntry is the blame of one location.
type BlameEntry struct {
	File   string    `json:"file"`
	Line   int       `json:"line"`
	Commit string    `json:"commit"`
	Author string    `json:"author"`
	Time   time.Time `json:"time"`
}

const (
	maxBlameLocations = 2000
	maxBlameFiles     = 300
)

// blameCategories are the finding categories with code locations.
var blameCategories = map[string]bool{"sast": true, "secrets": true, "iac": true}

// blameLocations reads the reports of code scanners in outDir and returns
// the distinct file:line locations of their findings.
func blameLocations(outDir string, keys []string) map[string][]int {
	locs := map[string]map[int]bool{}
	n := 0
	for _, key := range keys {
		if !blameCategories[categoryOf(key)] {
			continue
		}
		// #nosec G304 -- report path is created by the worker in its job directory
		raw, err := os.ReadFile(filepath.Join(outDir, key+".out"))
		if err != nil || len(raw) == 0 {
			continue
		}
		fs, _ := scanners.Parse(key, raw)
		for _, f := range fs {
			if f.StartLine == nil || *f.StartLine <= 0 || f.FilePath == "" || n >= maxBlameLocations {
				continue
			}
			p := scanners.NormalizePath(f.FilePath)
			if p == "" || strings.HasPrefix(p, "..") || strings.Contains(p, "://") {
				continue
			}
			if locs[p] == nil {
				if len(locs) >= maxBlameFiles {
					continue
				}
				locs[p] = map[int]bool{}
			}
			if !locs[p][*f.StartLine] {
				locs[p][*f.StartLine] = true
				n++
			}
		}
	}
	out := map[string][]int{}
	for p, lines := range locs {
		for l := range lines {
			out[p] = append(out[p], l)
		}
		sort.Ints(out[p])
	}
	return out
}

// categoryOf is the finding category of a scanner (plugins carry it in
// their key: plugin-<category>-<name>).
func categoryOf(key string) string {
	if sc, ok := scanners.Lookup(key); ok {
		return sc.FindingCategory()
	}
	if parts := strings.SplitN(key, "-", 3); len(parts) == 3 && parts[0] == "plugin" {
		return parts[1]
	}
	return ""
}

// blame runs git blame for each file's lines in a full-history checkout.
func blame(ctx context.Context, src string, locs map[string][]int) BlameReport {
	rep := BlameReport{Version: 1, Mode: "full", Entries: []BlameEntry{}}
	files := make([]string, 0, len(locs))
	for f := range locs {
		files = append(files, f)
	}
	sort.Strings(files)
	for _, file := range files {
		if ctx.Err() != nil {
			break
		}
		lines := locs[file]
		// Only regular files inside the checkout (no symlinks).
		st, err := os.Lstat(filepath.Join(src, filepath.FromSlash(file)))
		if err != nil || !st.Mode().IsRegular() {
			for _, l := range lines {
				rep.Missing = append(rep.Missing, BlameLocation{File: file, Line: l})
			}
			continue
		}
		base := []string{"-C", src, "-c", "core.hooksPath=/dev/null", "-c", "core.fsmonitor=false", "blame", "--line-porcelain", "-w", "--root"}
		args := append([]string{}, base...)
		for _, l := range lines {
			args = append(args, "-L", strconv.Itoa(l)+",+1")
		}
		args = append(args, "HEAD", "--", file)
		fctx, cancel := context.WithTimeout(ctx, 60*time.Second)
		var out bytes.Buffer
		_, err = commandTo(fctx, &limitedWriter{buf: &out, max: 8 << 20}, []string{"GIT_CONFIG_NOSYSTEM=1", "GIT_CONFIG_GLOBAL=/dev/null"}, []int{0}, "git", args...)
		cancel()
		if err != nil {
			// A line past the end of the file (the finding is in an
			// older revision) fails the whole call: blame line by line.
			for _, l := range lines {
				one := append(append([]string{}, base...), "-L", strconv.Itoa(l)+",+1", "HEAD", "--", file)
				var o bytes.Buffer
				lctx, cancel := context.WithTimeout(ctx, 30*time.Second)
				_, lerr := commandTo(lctx, &limitedWriter{buf: &o, max: 1 << 20}, []string{"GIT_CONFIG_NOSYSTEM=1", "GIT_CONFIG_GLOBAL=/dev/null"}, []int{0}, "git", one...)
				cancel()
				es := parseLinePorcelain(o.Bytes(), file)
				if lerr != nil || len(es) == 0 {
					rep.Missing = append(rep.Missing, BlameLocation{File: file, Line: l})
					continue
				}
				rep.Entries = append(rep.Entries, es...)
			}
			continue
		}
		rep.Entries = append(rep.Entries, parseLinePorcelain(out.Bytes(), file)...)
	}
	return rep
}

// parseLinePorcelain reads `git blame --line-porcelain` output. Author
// e-mail lines are ignored.
func parseLinePorcelain(out []byte, file string) []BlameEntry {
	var res []BlameEntry
	var cur *BlameEntry
	var tz string
	var unix int64
	sc := bufio.NewScanner(bytes.NewReader(out))
	sc.Buffer(make([]byte, 0, 64<<10), 4<<20)
	for sc.Scan() {
		line := sc.Text()
		if strings.HasPrefix(line, "\t") {
			// The content line ends a record.
			if cur != nil && cur.Commit != "" {
				t := time.Unix(unix, 0).UTC()
				if loc, ok := parseTZ(tz); ok {
					t = t.In(loc)
				}
				cur.Time = t
				res = append(res, *cur)
			}
			cur, tz, unix = nil, "", 0
			continue
		}
		if cur == nil {
			f := strings.Fields(line)
			if len(f) >= 3 && fullSHARe.MatchString(f[0]) {
				n, err := strconv.Atoi(f[2])
				if err == nil {
					cur = &BlameEntry{File: file, Line: n, Commit: f[0]}
				}
			}
			continue
		}
		switch {
		case strings.HasPrefix(line, "author "):
			cur.Author = truncateStr(strings.TrimSpace(strings.TrimPrefix(line, "author ")), 200)
		case strings.HasPrefix(line, "author-time "):
			unix, _ = strconv.ParseInt(strings.TrimSpace(strings.TrimPrefix(line, "author-time ")), 10, 64)
		case strings.HasPrefix(line, "author-tz "):
			tz = strings.TrimSpace(strings.TrimPrefix(line, "author-tz "))
		}
	}
	return res
}

// parseTZ reads a git time zone offset such as +0200.
func parseTZ(s string) (*time.Location, bool) {
	if len(s) != 5 || (s[0] != '+' && s[0] != '-') {
		return nil, false
	}
	h, err1 := strconv.Atoi(s[1:3])
	m, err2 := strconv.Atoi(s[3:5])
	if err1 != nil || err2 != nil {
		return nil, false
	}
	off := h*3600 + m*60
	if s[0] == '-' {
		off = -off
	}
	return time.FixedZone(s, off), true
}
