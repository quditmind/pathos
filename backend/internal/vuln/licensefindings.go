package vuln

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"pathos/internal/platform/db"
	"pathos/internal/scanners"
)

// Licence policy violations as findings.
//
// The licence policy (license_policies: deny or review per SPDX id) is
// evaluated against two inventories of a repository: the SBOM components
// (Syft or an imported SBOM) and the licences found in its files
// (licensecheck). Each violation is one finding in the "license" category
// with the normal lifecycle and SLA. Findings are de-duplicated by
// fingerprint (component and licence, or file and licence), re-opened when
// a violation returns, and set to fixed, never deleted, when the component
// or file disappears or the policy no longer denies or flags the licence.

// StoreFileLicenses replaces a repository's file-level licence inventory
// with the result of a licensecheck run.
func StoreFileLicenses(ctx context.Context, tx pgx.Tx, orgID, repoID, jobID uuid.UUID, ls []scanners.FileLicense) error {
	if _, err := tx.Exec(ctx, `DELETE FROM repository_file_licenses WHERE repository_id = $1`, repoID); err != nil {
		return err
	}
	rows := make([][]any, 0, len(ls))
	for _, l := range ls {
		var line *int
		if l.Line > 0 {
			n := l.Line
			line = &n
		}
		alts := l.Alternatives
		if alts == nil {
			alts = []string{}
		}
		rows = append(rows, []any{orgID, repoID, jobID, l.Path, l.SPDX, l.Method, line, alts})
	}
	_, err := tx.CopyFrom(ctx, pgx.Identifier{"repository_file_licenses"},
		[]string{"organization_id", "repository_id", "scan_job_id", "file_path", "spdx_id", "method", "line", "alternatives"}, pgx.CopyFromRows(rows))
	return err
}

// licenseViolation is one policy violation.
type licenseViolation struct {
	RepoID   uuid.UUID
	Source   string // component | file
	Name     string
	Version  string
	PURL     string
	Path     string
	Line     *int
	SPDX     string
	Decision string // deny | review
	Method   string // file: spdx-tag | license-text
}

func (v licenseViolation) scannerKey() string {
	if v.Source == "file" {
		return scanners.LicenseCheck
	}
	return scanners.LicensePolicy
}

func (v licenseViolation) fingerprint() string {
	var parts []string
	if v.Source == "file" {
		parts = []string{scanners.LicenseCheck, "file", v.Path, v.SPDX}
	} else {
		parts = []string{scanners.LicensePolicy, "component", v.Name, v.Version, v.SPDX}
	}
	h := sha256.New()
	for _, p := range parts {
		h.Write([]byte(p))
		h.Write([]byte{0})
	}
	return hex.EncodeToString(h.Sum(nil))
}

func (v licenseViolation) finding() (title, description, severity, confidence string) {
	verdict, severity := "requires review under the licence policy", "medium"
	if v.Decision == "deny" {
		verdict, severity = "is denied by the licence policy", "high"
	}
	confidence = "high"
	if v.Source == "file" {
		how := "an SPDX-License-Identifier tag"
		if v.Method == "license-text" {
			how, confidence = "licence text matching", "medium"
		}
		title = fmt.Sprintf("File licence %s %s", v.SPDX, verdict)
		description = fmt.Sprintf("%s is licensed under %s (found by %s). The organization's licence policy marks %s as %q.\n\n"+
			"Remove or replace the file, obtain the code under a licence the policy allows, or ask a licence policy administrator "+
			"to review the decision. Accepting the risk or marking the finding a false positive records the decision with its reason.",
			v.Path, v.SPDX, how, v.SPDX, v.Decision)
		return
	}
	comp := v.Name
	if v.Version != "" {
		comp += " " + v.Version
	}
	title = fmt.Sprintf("Licence %s of %s %s", v.SPDX, comp, verdict)
	description = fmt.Sprintf("The dependency %s (%s) is licensed under %s. The organization's licence policy marks %s as %q.\n\n"+
		"Replace the dependency with one under an allowed licence, check whether a differently licensed version exists, or ask a "+
		"licence policy administrator to review the decision.", comp, firstNonEmpty(v.PURL, "no package URL"), v.SPDX, v.SPDX, v.Decision)
	return
}

// LicenseRun attributes a licence policy evaluation to a scan result.
type LicenseRun struct {
	JobID, ResultID uuid.UUID
	// Source is the inventory the result produced: "component" (Syft) or
	// "file" (licensecheck); its violations get an occurrence.
	Source string
}

// SyncLicenseFindings evaluates the licence policy for one repository
// (repoID set) or the whole organization (repoID nil). With run (during
// scan ingestion of one repository), the findings are attributed to that
// scan and the violations of the run's inventory get an occurrence. It
// returns the number of violations and of findings resolved.
func SyncLicenseFindings(ctx context.Context, tx pgx.Tx, orgID uuid.UUID, repoID *uuid.UUID, run *LicenseRun) (violations, resolved int, err error) {
	var jobID *uuid.UUID
	if run != nil {
		jobID = &run.JobID
	}
	rows, err := tx.Query(ctx, `
		SELECT c.repository_id, 'component', c.name, c.version, max(c.purl), '', NULL::int, c.spdx, min(c.decision), ''
		FROM (SELECT sc.repository_id, sc.name, sc.version, sc.purl, l.spdx, pathos_license_decision(sc.organization_id, l.spdx) AS decision
		      FROM sbom_components sc CROSS JOIN LATERAL unnest(sc.licenses) AS l(spdx)
		      WHERE sc.organization_id = $1 AND ($2::uuid IS NULL OR sc.repository_id = $2)) c
		WHERE c.decision IS NOT NULL
		GROUP BY c.repository_id, c.name, c.version, c.spdx
		UNION ALL
		SELECT f.repository_id, 'file', '', '', '', f.file_path, f.line, f.spdx_id, f.decision, f.method
		FROM (SELECT fl.*, pathos_license_decision(fl.organization_id, fl.spdx_id) AS decision
		      FROM repository_file_licenses fl WHERE fl.organization_id = $1 AND ($2::uuid IS NULL OR fl.repository_id = $2)) f
		WHERE f.decision IS NOT NULL
		  -- an "OR" choice conflicts only if no alternative is allowed
		  AND NOT EXISTS (SELECT 1 FROM unnest(f.alternatives) a WHERE pathos_license_decision($1, a) IS NULL)
		`, orgID, repoID)
	if err != nil {
		return 0, 0, err
	}
	vs, err := pgx.CollectRows(rows, func(r pgx.CollectableRow) (licenseViolation, error) {
		var v licenseViolation
		err := r.Scan(&v.RepoID, &v.Source, &v.Name, &v.Version, &v.PURL, &v.Path, &v.Line, &v.SPDX, &v.Decision, &v.Method)
		return v, err
	})
	if err != nil {
		return 0, 0, err
	}
	if err := db.SetChangeContext(ctx, tx, nil, "scanner", "licence policy evaluation"); err != nil {
		return 0, 0, err
	}
	const upsert = `
		INSERT INTO findings (id, organization_id, repository_id, fingerprint, category, scanner_keys, rule_id, title, description,
		  severity, package_name, package_version, file_path, start_line, end_line, first_scan_job_id, last_scan_job_id, confidence)
		VALUES ($1, $2, $3, $4, 'license', ARRAY[$5], $6, $7, $8, $9, $10, $11, $12, $13, $13, $14, $14, $15)
		ON CONFLICT (repository_id, fingerprint) DO UPDATE SET
		  last_seen_at = now(), last_scan_job_id = COALESCE(EXCLUDED.last_scan_job_id, findings.last_scan_job_id),
		  -- the policy decides the severity, in both directions
		  severity = EXCLUDED.severity, title = EXCLUDED.title, description = EXCLUDED.description,
		  start_line = EXCLUDED.start_line, end_line = EXCLUDED.end_line,
		  status = CASE WHEN findings.status = 'fixed' THEN 'open' ELSE findings.status END,
		  updated_at = now()
		RETURNING id`
	repos := make([]uuid.UUID, 0, len(vs))
	fps := make([]string, 0, len(vs))
	ids := make([]uuid.UUID, 0, len(vs))
	for start := 0; start < len(vs); start += 500 {
		chunk := vs[start:min(start+500, len(vs))]
		b := &pgx.Batch{}
		for _, v := range chunk {
			title, desc, sev, conf := v.finding()
			b.Queue(upsert, uuid.Must(uuid.NewV7()), orgID, v.RepoID, v.fingerprint(), v.scannerKey(), "license/"+v.SPDX,
				clip(title, 300), desc, sev, clip(v.Name, 300), clip(v.Version, 100), clip(v.Path, 1000), v.Line, jobID, conf)
			repos, fps = append(repos, v.RepoID), append(fps, v.fingerprint())
		}
		br := tx.SendBatch(ctx, b)
		for range chunk {
			var id uuid.UUID
			if err := br.QueryRow().Scan(&id); err != nil {
				_ = br.Close()
				return 0, 0, err
			}
			ids = append(ids, id)
		}
		if err := br.Close(); err != nil {
			return 0, 0, err
		}
	}
	if run != nil && repoID != nil {
		occ := &pgx.Batch{}
		for i, v := range vs {
			if v.Source != run.Source {
				continue
			}
			occ.Queue(`INSERT INTO finding_occurrences (id, organization_id, finding_id, scan_result_id, file_path, start_line, end_line)
				VALUES ($1, $2, $3, $4, $5, $6, $6)`, uuid.Must(uuid.NewV7()), orgID, ids[i], run.ResultID, clip(v.Path, 1000), v.Line)
		}
		if err := tx.SendBatch(ctx, occ).Close(); err != nil {
			return 0, 0, err
		}
	}
	if err := db.SetChangeContext(ctx, tx, nil, "scanner", "licence policy no longer violated (component or file removed, or policy changed)"); err != nil {
		return 0, 0, err
	}
	tag, err := tx.Exec(ctx, `
		UPDATE findings f SET status = 'fixed', resolved_at = now(), updated_at = now()
		WHERE f.organization_id = $1 AND ($2::uuid IS NULL OR f.repository_id = $2) AND f.category = 'license'
		  AND f.scanner_keys && ARRAY[$3, $4]::text[] AND f.status IN ('open', 'in_progress', 'needs_review')
		  AND f.scan_target_id IS NULL
		  AND NOT EXISTS (SELECT 1 FROM unnest($5::uuid[], $6::text[]) AS k(repo, fp) WHERE k.repo = f.repository_id AND k.fp = f.fingerprint)`,
		orgID, repoID, scanners.LicensePolicy, scanners.LicenseCheck, repos, fps)
	if err != nil {
		return 0, 0, err
	}
	return len(vs), int(tag.RowsAffected()), nil
}
