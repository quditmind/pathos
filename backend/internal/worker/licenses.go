package worker

import (
	"bytes"
	"context"
	"io"
	"os"
	"path"
	"regexp"
	"strings"

	"github.com/google/licensecheck"

	"pathos/internal/scanners"
)

const (
	headerBytes      = 16 << 10 // SPDX tags are in file headers
	noticeBytes      = 4 << 10  // licence notices are matched in the first 4 KiB
	maxLicenseFile   = 1 << 20  // licence files are read whole up to this size
	maxLicenseFiles  = 200000
	maxLicenseBytes  = 1 << 30
	maxLicenseReport = 100000
)

var (
	spdxTagRe   = regexp.MustCompile(`SPDX-License-Identifier:\s*([^\r\n]+)`)
	spdxTokenRe = regexp.MustCompile(`[()]|[^\s()]+`)
	spdxIDRe    = regexp.MustCompile(`^(?:LicenseRef-)?[A-Za-z0-9][A-Za-z0-9.+-]{0,99}$`)
	noticeRe    = regexp.MustCompile(`(?i)licen[cs]e|copyright|gnu|public domain`)
	// Comment closers and trailing punctuation after an SPDX expression.
	tagTrimRe = regexp.MustCompile(`\s*(\*/|-->|#\}|%>|\*\)|"|'|;|,)\s*$`)
)

// licenseFile reports whether a file name looks like a licence text.
func licenseFile(rel string) bool {
	base := strings.ToUpper(path.Base(rel))
	for _, p := range []string{"LICENSE", "LICENCE", "COPYING", "COPYRIGHT", "NOTICE", "UNLICENSE", "PATENTS"} {
		if strings.HasPrefix(base, p) {
			return true
		}
	}
	if strings.HasSuffix(base, ".LICENSE") || strings.HasSuffix(base, ".LICENCE") {
		return true
	}
	return strings.HasPrefix(strings.ToUpper(rel), "LICENSES/")
}

// normalizeSPDX maps deprecated "X+" identifiers to "X-or-later".
func normalizeSPDX(id string) string {
	if strings.HasSuffix(id, "+") {
		return strings.TrimSuffix(id, "+") + "-or-later"
	}
	return id
}

// spdxExpression returns the licence identifiers of an SPDX expression and
// whether the expression offers a choice (OR): with a choice, the
// identifiers are alternatives of each other. Exceptions after WITH are
// dropped.
func spdxExpression(expr string) (ids []string, choice bool) {
	expr = tagTrimRe.ReplaceAllString(strings.TrimSpace(expr), "")
	toks := spdxTokenRe.FindAllString(expr, 64)
	skip := false
	operand := true // an identifier is expected next
	for _, t := range toks {
		switch u := strings.ToUpper(t); {
		case t == "(" || t == ")":
		case u == "AND" || u == "OR":
			if operand {
				return nil, false
			}
			choice = choice || u == "OR"
			operand = true
		case u == "WITH":
			if operand {
				return nil, false
			}
			skip = true
		case skip:
			skip = false
		case operand && spdxIDRe.MatchString(t) && (t[0] < 'a' || t[0] > 'z'):
			operand = false
			id := normalizeSPDX(t)
			dup := false
			for _, x := range ids {
				dup = dup || x == id
			}
			if !dup {
				ids = append(ids, id)
			}
		default:
			return nil, false // not an SPDX expression (prose, templates)
		}
	}
	if operand {
		return nil, false
	}
	return ids, choice
}

// lineAt returns the 1-based line number of byte offset off.
func lineAt(text []byte, off int) int {
	if off > len(text) {
		off = len(text)
	}
	return bytes.Count(text[:max(off, 0)], []byte{'\n'}) + 1
}

// detectLicenses finds licences in one file: SPDX-License-Identifier tags
// in the header and licence texts or notices (licensecheck). licenseText
// marks licence files, which are scanned whole.
func detectLicenses(rel string, text []byte, licenseText bool) []scanners.FileLicense {
	var out []scanners.FileLicense
	seen := map[string]bool{}
	add := func(l scanners.FileLicense) {
		if !seen[l.SPDX] {
			seen[l.SPDX] = true
			out = append(out, l)
		}
	}
	for _, m := range spdxTagRe.FindAllSubmatchIndex(text, 20) {
		ids, choice := spdxExpression(string(text[m[2]:m[3]]))
		for _, id := range ids {
			l := scanners.FileLicense{Path: rel, SPDX: id, Method: "spdx-tag", Line: lineAt(text, m[0])}
			if choice {
				for _, a := range ids {
					if a != id {
						l.Alternatives = append(l.Alternatives, a)
					}
				}
			}
			add(l)
		}
	}
	if !licenseText && !noticeRe.Match(text) {
		return out
	}
	if !licenseText {
		// Notices in source files sit in the header comment.
		text = text[:min(len(text), noticeBytes)]
	}
	cov := licensecheck.Scan(text)
	if licenseText && cov.Percent < 10 {
		return out // a NOTICE or COPYRIGHT file without licence text
	}
	for _, m := range cov.Match {
		if !spdxIDRe.MatchString(m.ID) {
			continue
		}
		add(scanners.FileLicense{Path: rel, SPDX: normalizeSPDX(m.ID), Method: "license-text", Line: lineAt(text, m.Start), Percent: cov.Percent})
	}
	return out
}

// binaryContent reports whether data looks binary (a NUL byte early on).
func binaryContent(data []byte) bool {
	return bytes.IndexByte(data[:min(len(data), 8000)], 0) >= 0
}

// runLicenseCheck detects file-level licences in src. The report lists
// every detection; the API turns those the licence policy denies or flags
// for review into findings.
func runLicenseCheck(ctx context.Context, src, out, version string) error {
	root, err := os.OpenRoot(src)
	if err != nil {
		return err
	}
	defer root.Close()
	rep := scanners.NativeReport{Tool: scanners.LicenseCheck, Version: version}
	files, read, skipped := 0, int64(0), 0
	links, err := walkFiles(ctx, src, func(rel string, size int64) error {
		if files >= maxLicenseFiles || read >= maxLicenseBytes || len(rep.Licenses) >= maxLicenseReport {
			skipped++
			return nil
		}
		files++
		whole := licenseFile(rel) && size <= maxLicenseFile
		limit := int64(headerBytes)
		if whole {
			limit = maxLicenseFile
		}
		f, err := openIn(root, rel)
		if err != nil {
			skipped++
			return nil
		}
		data, err := io.ReadAll(io.LimitReader(f, limit))
		_ = f.Close()
		if err != nil {
			skipped++
			return nil
		}
		read += int64(len(data))
		if len(data) == 0 || binaryContent(data) {
			return nil
		}
		rep.Licenses = append(rep.Licenses, detectLicenses(rel, data, whole)...)
		return nil
	})
	if err != nil {
		return err
	}
	rep.Stats = map[string]int{"files_scanned": files, "files_skipped": skipped, "licenses": len(rep.Licenses), "links_skipped": links}
	toolLog(ctx, "checked %d files for licences: %d detections, %d files skipped (limits or unreadable), %d links not followed",
		files, len(rep.Licenses), skipped, links)
	return writeNative(out, rep)
}
