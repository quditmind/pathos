package scans

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"pathos/internal/platform/objstore"
	"slices"
	"strings"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"pathos/internal/platform/db"
	"pathos/internal/platform/httpx"
	"pathos/internal/platform/logging"
	"pathos/internal/policy"
	"pathos/internal/reach"
	"pathos/internal/runtimectx"
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
	var targetID *uuid.UUID
	var threshold, commit string
	var exclusions, secretExclusions []string
	var secretDefaults bool
	var pr *int
	if err := s.DB.QueryRow(ctx, `SELECT j.repository_id, j.commit_sha, v.severity_threshold, v.exclusions, j.target_id, j.pull_request,
		v.secret_default_exclusions, v.secret_exclusions
		FROM scan_jobs j JOIN scan_profile_versions v ON v.id = j.profile_version_id WHERE j.id = $1`, jobID).
		Scan(&repoID, &commit, &threshold, &exclusions, &targetID, &pr, &secretDefaults, &secretExclusions); err != nil {
		return 0, err
	}

	var findings []scanners.Finding
	parseErr := ""
	secretDropped := 0
	// SBOM generators (Syft, cdxgen, the AI-BOM) produce the component inventory, not
	// findings.
	sbomTool := scanners.IsSBOMTool(up.Scanner)
	// pathos-reach reports are reachability evidence, not findings.
	reachTool := scanners.IsReachabilityTool(up.Scanner)
	// A tool that failed or timed out may still have written a usable
	// report (a stopped Nuclei run, Dependency-Check on cached NVD data, a
	// wrapper where one of several runs failed): its findings are kept.
	// The result stays failed / timed out, so the execution is partial and
	// nothing the tool covers is auto-resolved.
	partial := up.Status == "failed" || up.Status == "timed_out"
	if (up.Status == "succeeded" || partial) && !sbomTool && !reachTool && len(raw) > 0 {
		var fs []scanners.Finding
		var err error
		switch {
		case scanners.IsImportKey(up.Scanner):
			fs, err = scanners.ParseImport(up.Scanner, up.Format, raw)
		case up.Parser != nil:
			fs, err = scanners.ParseToolOutput(up.Scanner, *up.Parser, raw)
		default:
			fs, err = scanners.Parse(up.Scanner, raw)
		}
		switch {
		case err != nil && partial:
			// The tool's own error explains the result; an unreadable
			// partial report adds nothing.
		case err != nil && len(fs) == 0:
			up.Status, parseErr = "failed", "could not parse output: "+safeErr(err)
		case err != nil:
			parseErr = err.Error() // truncated, keep what was parsed
		}
		if partial && len(fs) > 0 {
			up.Error = strings.TrimSpace(up.Error + fmt.Sprintf(" (%d findings from the partial report kept)", len(fs)))
		}
		for _, f := range fs {
			if scanners.SeverityRank(f.Severity) < scanners.SeverityRank(threshold) || scanners.Excluded(f.FilePath, exclusions) {
				continue
			}
			// Secret findings in vendored code, fixtures, lockfiles and
			// minified files (the profile's secret exclusions). Target
			// scans (images, artifacts) keep theirs.
			if f.Category == "secrets" && targetID == nil && scanners.SecretExcluded(f.FilePath, secretDefaults, secretExclusions) {
				secretDropped++
				continue
			}
			if targetID != nil {
				// A target's findings are its own: the same CVE in an image
				// and in the repository's manifests are separate findings.
				f.Fingerprint = targetFingerprint(*targetID, f.Fingerprint)
				if f.LegacyFingerprint != "" {
					f.LegacyFingerprint = targetFingerprint(*targetID, f.LegacyFingerprint)
				}
			}
			findings = append(findings, f)
		}
	}
	if secretDropped > 0 {
		s.Log.Info("secret findings dropped by the profile's secret exclusions", "job_id", jobID, "scanner", up.Scanner, "dropped", secretDropped)
	}
	if up.Parser != nil && up.Parser.Kind == "import" && len(raw) > 0 {
		// A manifest tool parsed with an import parser (TruffleHog,
		// Kingfisher, detect-secrets, Talisman, ...): its report is stored
		// like an imported one, without the secret values the format
		// carries. Identities do not depend on them, so findings are
		// located in the stored copy as well.
		if clean := scanners.SanitizeImport(up.Parser.Format, raw); !bytes.Equal(clean, raw) {
			raw, gz = clean, nil
		}
	}
	errText := logging.RedactString(firstNonEmpty(parseErr, up.Error))
	if len(errText) > 2000 {
		errText = errText[:2000]
	}

	var written []string // objects to remove if the transaction fails
	licenseFindings := 0 // licence policy violations in files (licensecheck)
	err := db.InTx(ctx, s.DB, func(tx pgx.Tx) error {
		if err := lockRepositoryFindings(ctx, tx, repoID); err != nil {
			return err
		}
		if pr == nil {
			// Stored findings under a legacy fingerprint keep their rows.
			if err := rekeyFindings(ctx, tx, repoID, findings); err != nil {
				return err
			}
		}
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
			case scanners.Grype:
				ct = "application/json"
			case scanners.ClamAV, scanners.LicenseCheck, scanners.BinaryHardening, scanners.Actionlint, scanners.PathosReach:
				ct = "application/json"
			}
			if sbomTool {
				kind, ct = "sbom", "application/vnd.cyclonedx+json"
			}
			if scanners.IsImportKey(up.Scanner) {
				// The content type records the format for evidence capture.
				ct = scanners.ImportContentType(firstNonEmpty(up.Format, scanners.DetectImportFormat(raw)))
			}
			// Manifest tools with another parser: the parser is kept with
			// the tool's original output.
			var parser []byte
			if up.Parser != nil {
				ct = scanners.ToolContentType(*up.Parser)
				parser, _ = json.Marshal(up.Parser)
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
			if _, err := tx.Exec(ctx, `INSERT INTO scan_artifacts (id, organization_id, scan_result_id, kind, content_type, sha256, size_bytes, data_gzip, object_key, parser)
				VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)`, artID, orgID, resultID, kind, ct,
				hex.EncodeToString(sum[:]), len(raw), inline, key, parser); err != nil {
				return err
			}
		}
		if pr != nil {
			// A pull request's results never change the repository's
			// findings or inventory.
			return insertPRFindings(ctx, tx, jobID, findings)
		}
		licenses := false
		if sbomTool && up.Scanner != scanners.AIBOM && up.Status == "succeeded" && len(raw) > 0 && targetID == nil {
			if _, err := vuln.StoreSBOM(ctx, tx, orgID, repoID, jobID, raw); err != nil {
				s.Log.Warn("SBOM inventory not updated", "job_id", jobID, "err", err)
			} else {
				licenses = true
			}
		}
		// The AI-BOM adds the repository's AI frameworks, models and LLM
		// APIs to its component inventory (beside Syft's components).
		if up.Scanner == scanners.AIBOM && up.Status == "succeeded" && len(raw) > 0 && targetID == nil {
			if _, err := vuln.StoreAIBOM(ctx, tx, orgID, repoID, jobID, raw); err != nil {
				s.Log.Warn("AI-BOM inventory not updated", "job_id", jobID, "err", err)
			}
		}
		// Evidence kept besides findings: per-endpoint verification status
		// and signature verification results.
		if up.Status == "succeeded" && len(raw) > 0 {
			switch up.Scanner {
			case scanners.EndpointCheck:
				if err := recordEndpoints(ctx, tx, orgID, repoID, jobID, raw); err != nil {
					return err
				}
			case scanners.Cosign:
				if err := recordSignature(ctx, tx, orgID, jobID, targetID, raw); err != nil {
					return err
				}
			case scanners.TrivyImage:
				// The digests the image reference resolved to: running
				// images are linked to this scan by digest.
				if targetID != nil && pr == nil {
					for _, d := range runtimectx.TrivyRepoDigests(raw) {
						if _, err := tx.Exec(ctx, `INSERT INTO image_scan_digests (organization_id, scan_target_id, digest, reference, scan_job_id)
							VALUES ($1, $2, $3, $4, $5) ON CONFLICT (scan_target_id, digest) DO UPDATE SET reference = EXCLUDED.reference,
							scan_job_id = EXCLUDED.scan_job_id, scanned_at = now()`, orgID, *targetID, d.Digest, d.Reference, jobID); err != nil {
							return err
						}
					}
				}
			}
		}
		// Reachability reports of the repository's code: pathos-reach, and
		// the depth of each vulnerability in govulncheck output (run by the
		// worker or imported). Applied to findings when the job finishes.
		if up.Status == "succeeded" && len(raw) > 0 && targetID == nil {
			if err := s.storeReachReport(ctx, tx, orgID, repoID, jobID, up, raw); err != nil {
				return err
			}
		}
		if up.Scanner == scanners.LicenseCheck && up.Status == "succeeded" && len(raw) > 0 && targetID == nil {
			ls, err := scanners.ParseFileLicenses(raw)
			if err != nil {
				return err
			}
			if err := vuln.StoreFileLicenses(ctx, tx, orgID, repoID, jobID, ls); err != nil {
				return err
			}
			licenses = true
		}
		if err := upsertFindings(ctx, tx, orgID, repoID, jobID, resultID, commit, targetID, findings); err != nil {
			return err
		}
		if licenses {
			// The licence policy against the updated inventory: violations
			// become (or stay) findings, resolved ones are fixed.
			run := &vuln.LicenseRun{JobID: jobID, ResultID: resultID, Source: "component"}
			if up.Scanner == scanners.LicenseCheck {
				run.Source = "file"
			}
			n, _, err := vuln.SyncLicenseFindings(ctx, tx, orgID, &repoID, run)
			if err != nil {
				return err
			}
			if up.Scanner == scanners.LicenseCheck {
				licenseFindings = n
				_, err = tx.Exec(ctx, `UPDATE scan_results SET findings_count = $2 WHERE id = $1`, resultID, n)
				return err
			}
		}
		return nil
	})
	if err != nil && len(written) > 0 {
		if derr := s.Artifacts.Delete(context.WithoutCancel(ctx), written); derr != nil {
			s.Log.Warn("orphaned artifact objects after a failed ingest", "keys", written, "err", derr)
		}
	}
	return len(findings) + licenseFindings, err
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
func upsertFindings(ctx context.Context, tx pgx.Tx, orgID, repoID, jobID, resultID uuid.UUID, commit string, targetID *uuid.UUID, fs []scanners.Finding) error {
	if len(fs) == 0 {
		return nil
	}
	const q = `
		INSERT INTO findings (id, organization_id, repository_id, fingerprint, category, scanner_keys, rule_id, title, description,
		  severity, cwe, cve, cvss, package_name, package_version, fixed_version, file_path, start_line, end_line,
		  first_scan_job_id, last_scan_job_id, snippet, snippet_start_line, confidence, cvss_vector, cvss_version, scan_target_id)
		VALUES ($1, $2, $3, $4, $5, ARRAY[$6], $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, $20, $20, $21, $22, $23, $24, $25, $26)
		ON CONFLICT (repository_id, fingerprint) DO UPDATE SET
		  last_seen_at = now(), last_scan_job_id = EXCLUDED.last_scan_job_id,
		  scanner_keys = (SELECT array_agg(DISTINCT k ORDER BY k) FROM unnest(findings.scanner_keys || EXCLUDED.scanner_keys) k),
		  severity = CASE WHEN array_position(ARRAY['info','low','medium','high','critical'], EXCLUDED.severity)
		                     > array_position(ARRAY['info','low','medium','high','critical'], findings.severity)
		                  THEN EXCLUDED.severity ELSE findings.severity END,
		  cvss = COALESCE(EXCLUDED.cvss, findings.cvss),
		  cvss_vector = CASE WHEN EXCLUDED.cvss_vector <> '' THEN EXCLUDED.cvss_vector ELSE findings.cvss_vector END,
		  cvss_version = CASE WHEN EXCLUDED.cvss_vector <> '' THEN EXCLUDED.cvss_version ELSE findings.cvss_version END,
		  -- several tools agreeing never lowers confidence
		  confidence = CASE WHEN array_position(ARRAY['unknown','low','medium','high'], EXCLUDED.confidence)
		                       > array_position(ARRAY['unknown','low','medium','high'], findings.confidence)
		                    THEN EXCLUDED.confidence ELSE findings.confidence END,
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
				f.Snippet, f.SnippetStart, confidenceOrUnknown(f.Confidence), f.CVSSVector, f.CVSSVersion, targetID)
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

// rekeyFindings moves stored findings from their legacy fingerprint to the
// current one (fingerprint version 2 normalizes dependency package
// identity), so a finding keeps its row: status, triage, comments,
// occurrences and history. When two legacy findings map to the same
// fingerprint (tools that named the package differently), the first is
// re-keyed; the other is no longer reported under its fingerprint and is
// resolved by the scan like any finding no longer detected (unless it was
// triaged), so nothing is deleted.
func rekeyFindings(ctx context.Context, tx pgx.Tx, repoID uuid.UUID, fs []scanners.Finding) error {
	seen := map[string]bool{}
	b := &pgx.Batch{}
	for _, f := range fs {
		if f.LegacyFingerprint == "" || f.LegacyFingerprint == f.Fingerprint || seen[f.LegacyFingerprint] {
			continue
		}
		seen[f.LegacyFingerprint] = true
		b.Queue(`UPDATE findings SET fingerprint = $3, updated_at = now()
			WHERE repository_id = $1 AND fingerprint = $2
			  AND NOT EXISTS (SELECT 1 FROM findings WHERE repository_id = $1 AND fingerprint = $3)`, repoID, f.LegacyFingerprint, f.Fingerprint)
	}
	if b.Len() == 0 {
		return nil
	}
	return tx.SendBatch(ctx, b).Close()
}

// Finalize completes a job: final status, auto-resolution of findings no
// longer detected, counts and the critical gate.
func (s *Service) Finalize(ctx context.Context, jobID uuid.UUID, workerFailed bool, workerErr string) (Job, error) {
	return s.FinalizeWith(ctx, jobID, workerFailed, workerErr, FinalizeOpts{})
}

// FinalizeOpts adjusts Finalize.
type FinalizeOpts struct {
	// NoAutoResolve keeps findings the results no longer report open (a
	// partial import is not evidence that anything was fixed).
	NoAutoResolve bool
}

// FinalizeWith is Finalize with options.
func (s *Service) FinalizeWith(ctx context.Context, jobID uuid.UUID, workerFailed bool, workerErr string, opts FinalizeOpts) (Job, error) {
	var job Job
	err := db.InTx(ctx, s.DB, func(tx pgx.Tx) error {
		if err := db.SetChangeContext(ctx, tx, nil, "scanner", "no longer detected by a successful scan"); err != nil {
			return err
		}
		var repoID, orgID uuid.UUID
		// The repository lock comes before the job's row lock, in the same
		// order as Ingest (which locks the job row through its results).
		if err := tx.QueryRow(ctx, `SELECT repository_id FROM scan_jobs WHERE id = $1`, jobID).Scan(&repoID); err != nil {
			return err
		}
		if err := lockRepositoryFindings(ctx, tx, repoID); err != nil {
			return err
		}
		var targetID *uuid.UUID
		var failOnCritical bool
		var pr *int
		var trigger, commit, targetKind string
		if err := tx.QueryRow(ctx, `SELECT j.repository_id, v.fail_on_critical, j.target_id, j.organization_id, j.pull_request, j.trigger,
			j.commit_sha, j.target_kind FROM scan_jobs j
			JOIN scan_profile_versions v ON v.id = j.profile_version_id WHERE j.id = $1 FOR UPDATE OF j`, jobID).
			Scan(&repoID, &failOnCritical, &targetID, &orgID, &pr, &trigger, &commit, &targetKind); err != nil {
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

		if pr != nil {
			return finalizePR(ctx, tx, orgID, jobID, repoID, status, workerErr, bad, &job)
		}
		// Auto-resolve: open findings that a scanner which succeeded in this
		// run no longer reports, unless a scanner that failed also covers it.
		fixed := int64(0)
		fixedBySeverity := map[string]int{}
		if len(ok) > 0 && !opts.NoAutoResolve {
			rows, err := tx.Query(ctx, `UPDATE findings SET status = 'fixed', resolved_at = now(), updated_at = now()
				WHERE repository_id = $1 AND status IN ('open', 'in_progress', 'needs_review')
				  AND (last_scan_job_id IS DISTINCT FROM $2)
				  AND scanner_keys && $3::text[] AND NOT (scanner_keys && $4::text[])
				  AND scan_target_id IS NOT DISTINCT FROM $5
				RETURNING severity`,
				repoID, jobID, ok, nonNilStrings(bad), targetID)
			if err != nil {
				return err
			}
			for rows.Next() {
				var sev string
				if err := rows.Scan(&sev); err != nil {
					rows.Close()
					return err
				}
				fixedBySeverity[sev]++
				fixed++
			}
			rows.Close()
			if err := rows.Err(); err != nil {
				return err
			}
		}
		// End-of-life status of the components, runtimes and images this
		// scan (re)discovered; new end-of-life findings count as found by it.
		if status != "failed" && (targetID == nil || targetKind == "image") {
			if err := s.syncEOL(ctx, tx, orgID, repoID, jobID); err != nil {
				return err
			}
		}
		if targetID == nil {
			// Dependency findings added by this execution get their
			// reachability from the latest code inventory and SBOM.
			if _, err := reach.Update(ctx, tx, repoID); err != nil {
				return err
			}
		}
		// Approved suppression rules apply to findings detected now too.
		if _, err := vuln.ApplyActiveRules(ctx, tx, orgID, repoID); err != nil {
			return err
		}
		// Security policies: violations of the repository's findings, and
		// whether a new finding violates a blocking policy.
		if _, err := policy.Evaluate(ctx, tx, orgID, &repoID); err != nil {
			return err
		}
		blocking, err := policy.Blocking(ctx, tx, jobID)
		if err != nil {
			return err
		}
		var newCount, newCritical int
		if err := tx.QueryRow(ctx, `SELECT count(*), count(*) FILTER (WHERE severity = 'critical')
			FROM findings WHERE repository_id = $1 AND first_scan_job_id = $2`, repoID, jobID).Scan(&newCount, &newCritical); err != nil {
			return err
		}
		gate := (failOnCritical && newCritical > 0) || len(blocking) > 0
		if len(blocking) > 0 {
			if err := AddEvent(ctx, tx, orgID, jobID, "finalize", "", "info", "security gate failed: blocked by security policy "+strings.Join(blocking, ", ")); err != nil {
				return err
			}
		}
		if targetID != nil {
			unsigned, err := signatureGateFailed(ctx, tx, jobID)
			if err != nil {
				return err
			}
			if unsigned {
				gate = true
				if err := AddEvent(ctx, tx, orgID, jobID, "finalize", "", "info", "security gate failed: the target requires a verified signature"); err != nil {
					return err
				}
			}
		}
		var change []byte
		if targetID == nil && (trigger == "push" || trigger == "merge") {
			cs, err := changeSummary(ctx, tx, jobID, repoID, commit, fixedBySeverity)
			if err != nil {
				return err
			}
			change, _ = json.Marshal(cs)
			job.ChangeSummary = cs
		}
		errText := logging.RedactString(truncate(workerErr, 2000))
		if errText == "" && len(bad) > 0 {
			errText = "scanners failed: " + joinSorted(bad)
		}
		if _, err := tx.Exec(ctx, `UPDATE scan_jobs SET status = $2, finished_at = now(), lease_expires_at = NULL,
			findings_new = $3, findings_fixed = $4, gate_failed = $5, error = $6, change_summary = $7 WHERE id = $1`,
			jobID, status, newCount, fixed, gate, errText, change); err != nil {
			return err
		}
		job.Status, job.FindingsNew, job.FindingsFixed, job.GateFailed = status, newCount, int(fixed), gate
		return nil
	})
	return job, err
}

// lockRepositoryFindings serializes the writes of results and the
// finalization of executions of one repository for the rest of tx. A
// repository scan, target scans and result imports of the same repository
// may run at the same time (migration 00043); their findings upserts,
// auto-resolution, reachability and policy evaluation then never
// interleave or deadlock.
func lockRepositoryFindings(ctx context.Context, tx pgx.Tx, repoID uuid.UUID) error {
	_, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtext('pathos-repo-findings'), hashtext($1::text))`, repoID)
	return err
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

func confidenceOrUnknown(c string) string {
	switch c {
	case "high", "medium", "low":
		return c
	}
	return "unknown"
}

// targetFingerprint namespaces a finding fingerprint by scan target.
func targetFingerprint(targetID uuid.UUID, fp string) string {
	sum := sha256.Sum256([]byte("target:" + targetID.String() + ":" + fp))
	return hex.EncodeToString(sum[:])
}

// storeReachReport keeps a pathos-reach report, or the reachability depths
// of a govulncheck run, as the repository's latest. A report that cannot be
// read is logged and skipped: the result itself is stored either way.
func (s *Service) storeReachReport(ctx context.Context, tx pgx.Tx, orgID, repoID, jobID uuid.UUID, up ResultUpload, raw []byte) error {
	switch {
	case up.Scanner == scanners.PathosReach:
		r, err := reach.ParseReachReport(raw)
		if err != nil {
			s.Log.Warn("pathos-reach report not stored", "job_id", jobID, "err", err)
			return nil
		}
		return reach.StoreReport(ctx, tx, orgID, repoID, jobID, reach.ToolPathosReach, r)
	case up.Scanner == "govulncheck" || scanners.IsImportKey(up.Scanner) && firstNonEmpty(up.Format, scanners.DetectImportFormat(raw)) == "govulncheck":
		res, err := scanners.GovulncheckResults(raw)
		if err != nil {
			s.Log.Warn("govulncheck reachability not stored", "job_id", jobID, "err", err)
			return nil
		}
		return reach.StoreReport(ctx, tx, orgID, repoID, jobID, reach.ToolGovulncheck, map[string]any{"results": res})
	}
	return nil
}
