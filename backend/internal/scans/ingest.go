package scans

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"pathos/internal/platform/objstore"
	"slices"
	"strings"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"pathos/internal/platform/db"
	"pathos/internal/platform/httpx"
	"pathos/internal/platform/logging"
	"pathos/internal/scanners"
	"pathos/internal/vuln"
)

// maxRawReport caps a decompressed report.
const maxRawReport = 256 << 20

// Ingest stores one scanner result (and its raw artifact) and, for
// successful finding scanners, upserts normalized findings. It returns the
// number of findings recorded.
func (s *Service) Ingest(ctx context.Context, orgID, jobID uuid.UUID, up ResultUpload, gz []byte) (int, error) {
	var raw []byte
	if len(gz) > 0 {
		var err error
		if raw, err = gunzipLimited(gz, maxRawReport); err != nil {
			return 0, err
		}
	}
	var repoID uuid.UUID
	var threshold, commit string
	var exclusions []string
	if err := s.DB.QueryRow(ctx, `SELECT j.repository_id, j.commit_sha, v.severity_threshold, v.exclusions
		FROM scan_jobs j JOIN scan_profile_versions v ON v.id = j.profile_version_id WHERE j.id = $1`, jobID).
		Scan(&repoID, &commit, &threshold, &exclusions); err != nil {
		return 0, err
	}

	var findings []scanners.Finding
	parseErr := ""
	if up.Status == "succeeded" && up.Scanner != scanners.Syft && len(raw) > 0 {
		fs, err := scanners.Parse(up.Scanner, raw)
		if err != nil {
			if len(fs) == 0 {
				up.Status, parseErr = "failed", "could not parse output: "+safeErr(err)
			} else {
				parseErr = err.Error() // truncated, keep what was parsed
			}
		}
		for _, f := range fs {
			if scanners.SeverityRank(f.Severity) < scanners.SeverityRank(threshold) || scanners.Excluded(f.FilePath, exclusions) {
				continue
			}
			findings = append(findings, f)
		}
	}
	errText := logging.RedactString(firstNonEmpty(parseErr, up.Error))
	if len(errText) > 2000 {
		errText = errText[:2000]
	}

	var written []string // objects to remove if the transaction fails
	err := db.InTx(ctx, s.DB, func(tx pgx.Tx) error {
		if err := db.SetChangeContext(ctx, tx, nil, "scanner", "detected again by "+up.Scanner); err != nil {
			return err
		}
		resultID := uuid.Must(uuid.NewV7())
		if _, err := tx.Exec(ctx, `INSERT INTO scan_results (id, organization_id, scan_job_id, scanner_key, scanner_version, status,
			duration_ms, findings_count, error) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`,
			resultID, orgID, jobID, up.Scanner, truncate(up.Version, 100), up.Status, max(up.DurationMS, 0), len(findings), errText); err != nil {
			if db.IsUniqueViolation(err) {
				return httpx.Conflict("result for this scanner was already uploaded")
			}
			return err
		}
		if len(raw) > 0 {
			kind, ct := "raw", "application/sarif+json"
			switch up.Scanner {
			case scanners.Syft:
				kind, ct = "sbom", "application/vnd.cyclonedx+json"
			case scanners.Grype:
				ct = "application/json"
			}
			sum := sha256.Sum256(raw)
			artID := uuid.Must(uuid.NewV7())
			key, inline, err := putArtifact(ctx, s.Artifacts, orgID, artID, recompress(gz, raw))
			if err != nil {
				return err
			}
			if key != nil {
				written = append(written, *key)
			}
			if _, err := tx.Exec(ctx, `INSERT INTO scan_artifacts (id, organization_id, scan_result_id, kind, content_type, sha256, size_bytes, data_gzip, object_key)
				VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`, artID, orgID, resultID, kind, ct,
				hex.EncodeToString(sum[:]), len(raw), inline, key); err != nil {
				return err
			}
		}
		if up.Scanner == scanners.Syft && up.Status == "succeeded" && len(raw) > 0 {
			if _, err := vuln.StoreSBOM(ctx, tx, orgID, repoID, jobID, raw); err != nil {
				s.Log.Warn("SBOM inventory not updated", "job_id", jobID, "err", err)
			}
		}
		return upsertFindings(ctx, tx, orgID, repoID, jobID, resultID, commit, findings)
	})
	if err != nil && len(written) > 0 {
		if derr := s.Artifacts.Delete(context.WithoutCancel(ctx), written); derr != nil {
			s.Log.Warn("orphaned artifact objects after a failed ingest", "keys", written, "err", derr)
		}
	}
	return len(findings), err
}

// recompress keeps the worker's gzip unless it was not a single stream.
func recompress(gz, raw []byte) []byte {
	if len(gz) > 0 {
		return gz
	}
	var b bytes.Buffer
	zw := gzip.NewWriter(&b)
	_, _ = zw.Write(raw)
	_ = zw.Close()
	return b.Bytes()
}

func truncate(s string, n int) string {
	if len(s) > n {
		return s[:n]
	}
	return s
}

// upsertFindings merges findings by (repository, fingerprint). Findings
// seen again are refreshed and re-opened if previously fixed; the
// detecting scanner is added to scanner_keys.
func upsertFindings(ctx context.Context, tx pgx.Tx, orgID, repoID, jobID, resultID uuid.UUID, commit string, fs []scanners.Finding) error {
	if len(fs) == 0 {
		return nil
	}
	const q = `
		INSERT INTO findings (id, organization_id, repository_id, fingerprint, category, scanner_keys, rule_id, title, description,
		  severity, cwe, cve, cvss, package_name, package_version, fixed_version, file_path, start_line, end_line,
		  first_scan_job_id, last_scan_job_id, snippet, snippet_start_line)
		VALUES ($1, $2, $3, $4, $5, ARRAY[$6], $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, $20, $20, $21, $22)
		ON CONFLICT (repository_id, fingerprint) DO UPDATE SET
		  last_seen_at = now(), last_scan_job_id = EXCLUDED.last_scan_job_id,
		  scanner_keys = (SELECT array_agg(DISTINCT k ORDER BY k) FROM unnest(findings.scanner_keys || EXCLUDED.scanner_keys) k),
		  severity = CASE WHEN array_position(ARRAY['info','low','medium','high','critical'], EXCLUDED.severity)
		                     > array_position(ARRAY['info','low','medium','high','critical'], findings.severity)
		                  THEN EXCLUDED.severity ELSE findings.severity END,
		  cvss = COALESCE(EXCLUDED.cvss, findings.cvss),
		  cve = CASE WHEN findings.cve = '' THEN EXCLUDED.cve ELSE findings.cve END,
		  fixed_version = CASE WHEN EXCLUDED.fixed_version <> '' THEN EXCLUDED.fixed_version ELSE findings.fixed_version END,
		  file_path = EXCLUDED.file_path, start_line = EXCLUDED.start_line, end_line = EXCLUDED.end_line,
		  snippet = CASE WHEN EXCLUDED.snippet <> '' THEN EXCLUDED.snippet ELSE findings.snippet END,
		  snippet_start_line = CASE WHEN EXCLUDED.snippet <> '' THEN EXCLUDED.snippet_start_line ELSE findings.snippet_start_line END,
		  status = CASE WHEN findings.status = 'fixed' THEN 'open' ELSE findings.status END,
		  resolved_at = CASE WHEN findings.status = 'fixed' THEN NULL ELSE findings.resolved_at END,
		  updated_at = now()
		RETURNING id`
	ids := make([]uuid.UUID, 0, len(fs))
	for start := 0; start < len(fs); start += 500 {
		end := min(start+500, len(fs))
		b := &pgx.Batch{}
		for _, f := range fs[start:end] {
			cwe := f.CWE
			if cwe == nil {
				cwe = []string{}
			}
			b.Queue(q, uuid.Must(uuid.NewV7()), orgID, repoID, f.Fingerprint, f.Category, f.ScannerKey, truncate(f.RuleID, 300),
				truncate(f.Title, 300), f.Description, f.Severity, cwe, f.CVE, f.CVSS, truncate(f.PackageName, 300),
				truncate(f.PackageVersion, 100), truncate(f.FixedVersion, 100), truncate(f.FilePath, 1000), f.StartLine, f.EndLine, jobID,
				f.Snippet, f.SnippetStart)
		}
		br := tx.SendBatch(ctx, b)
		for range fs[start:end] {
			var id uuid.UUID
			if err := br.QueryRow().Scan(&id); err != nil {
				_ = br.Close()
				return err
			}
			ids = append(ids, id)
		}
		if err := br.Close(); err != nil {
			return err
		}
	}
	occ := &pgx.Batch{}
	for i, f := range fs {
		occ.Queue(`INSERT INTO finding_occurrences (id, organization_id, finding_id, scan_result_id, commit_sha, file_path, start_line, end_line)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`, uuid.Must(uuid.NewV7()), orgID, ids[i], resultID, commit, truncate(f.FilePath, 1000), f.StartLine, f.EndLine)
	}
	return tx.SendBatch(ctx, occ).Close()
}

// Finalize completes a job: final status, auto-resolution of findings no
// longer detected, counts and the critical gate.
func (s *Service) Finalize(ctx context.Context, jobID uuid.UUID, workerFailed bool, workerErr string) (Job, error) {
	var job Job
	err := db.InTx(ctx, s.DB, func(tx pgx.Tx) error {
		if err := db.SetChangeContext(ctx, tx, nil, "scanner", "no longer detected by a successful scan"); err != nil {
			return err
		}
		var repoID uuid.UUID
		var failOnCritical bool
		if err := tx.QueryRow(ctx, `SELECT j.repository_id, v.fail_on_critical FROM scan_jobs j
			JOIN scan_profile_versions v ON v.id = j.profile_version_id WHERE j.id = $1 FOR UPDATE OF j`, jobID).
			Scan(&repoID, &failOnCritical); err != nil {
			return err
		}
		rows, err := tx.Query(ctx, `SELECT scanner_key, status FROM scan_results WHERE scan_job_id = $1`, jobID)
		if err != nil {
			return err
		}
		var ok, bad []string
		for rows.Next() {
			var k, st string
			if err := rows.Scan(&k, &st); err != nil {
				rows.Close()
				return err
			}
			switch st {
			case "succeeded":
				ok = append(ok, k)
			case "failed", "timed_out":
				bad = append(bad, k)
			}
		}
		rows.Close()

		status := "succeeded"
		switch {
		case workerFailed && len(ok) == 0:
			status = "failed"
		case workerFailed || len(bad) > 0:
			status = "partial"
		}
		if len(ok) == 0 && len(bad) > 0 {
			status = "failed"
		}

		// Auto-resolve: open findings that a scanner which succeeded in this
		// run no longer reports, unless a scanner that failed also covers it.
		fixed := int64(0)
		if len(ok) > 0 {
			tag, err := tx.Exec(ctx, `UPDATE findings SET status = 'fixed', resolved_at = now(), updated_at = now()
				WHERE repository_id = $1 AND status IN ('open', 'in_progress', 'needs_review')
				  AND (last_scan_job_id IS DISTINCT FROM $2)
				  AND scanner_keys && $3::text[] AND NOT (scanner_keys && $4::text[])`,
				repoID, jobID, ok, nonNilStrings(bad))
			if err != nil {
				return err
			}
			fixed = tag.RowsAffected()
		}
		var newCount, newCritical int
		if err := tx.QueryRow(ctx, `SELECT count(*), count(*) FILTER (WHERE severity = 'critical')
			FROM findings WHERE repository_id = $1 AND first_scan_job_id = $2`, repoID, jobID).Scan(&newCount, &newCritical); err != nil {
			return err
		}
		gate := failOnCritical && newCritical > 0
		errText := logging.RedactString(truncate(workerErr, 2000))
		if errText == "" && len(bad) > 0 {
			errText = "scanners failed: " + joinSorted(bad)
		}
		if _, err := tx.Exec(ctx, `UPDATE scan_jobs SET status = $2, finished_at = now(), lease_expires_at = NULL,
			findings_new = $3, findings_fixed = $4, gate_failed = $5, error = $6 WHERE id = $1`,
			jobID, status, newCount, fixed, gate, errText); err != nil {
			return err
		}
		job.Status, job.FindingsNew, job.FindingsFixed, job.GateFailed = status, newCount, int(fixed), gate
		return nil
	})
	return job, err
}

func joinSorted(v []string) string {
	c := slices.Clone(v)
	slices.Sort(c)
	return strings.Join(c, ", ")
}

// PruneArtifacts deletes raw reports and SBOMs older than the retention
// configured on the profile version that produced them. Findings, results
// and the audit log are kept.
func PruneArtifacts(ctx context.Context, q db.Querier, store objstore.Store) (int64, error) {
	rows, err := q.Query(ctx, `
		DELETE FROM scan_artifacts a USING scan_results sr, scan_jobs j, scan_profile_versions v
		WHERE a.scan_result_id = sr.id AND sr.scan_job_id = j.id AND v.id = j.profile_version_id
		  AND a.created_at < now() - make_interval(days => v.retention_days)
		RETURNING a.object_key`)
	if err != nil {
		return 0, err
	}
	var n int64
	var keys []string
	for rows.Next() {
		var k *string
		if err := rows.Scan(&k); err != nil {
			rows.Close()
			return n, err
		}
		n++
		if k != nil {
			keys = append(keys, *k)
		}
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return n, err
	}
	// Rows are gone first: a failed object delete leaves an unreferenced
	// object (harmless) rather than a row pointing at nothing.
	if len(keys) > 0 && store != nil {
		if err := store.Delete(ctx, keys); err != nil {
			return n, fmt.Errorf("delete %d expired objects: %w", len(keys), err)
		}
	}
	return n, nil
}
