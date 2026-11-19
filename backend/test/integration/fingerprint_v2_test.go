//go:build integration

package integration

import (
	"net/http"
	"testing"

	"github.com/google/uuid"

	"pathos/internal/auth"
	"pathos/internal/authz"
	"pathos/internal/org"
	"pathos/internal/scanners"
	"pathos/internal/scans"
)

// Fingerprint version 2 (normalized package identity) keeps stored
// findings: a dependency finding stored under its version 1 fingerprint is
// re-keyed when a scan reports it again, with its status, its id and its
// history, and findings of other tools for the same package merge into it.
func TestFingerprintV2KeepsStoredFindings(t *testing.T) {
	ctx := t.Context()
	az := &authz.Authorizer{H: &org.Hierarchy{DB: appPool, OrgID: orgID}}
	scanSvc := &scans.Service{DB: appPool, Authz: az, Log: log, Principal: auth.PrincipalFrom, BootstrapToken: bootstrap, OrgID: orgID}
	h := &scanHarness{t: t, api: newMux(func(m *http.ServeMux) { scanSvc.Register(m) }), internal: scanSvc.InternalHandler()}
	admin := reviewUser(t, "platform_admin")
	repo := createRepo(t, "fpv2-"+uuid.NewString()[:6])
	_, q := h.user(admin, "POST", "/api/v1/repositories/"+repo.String()+"/scan", nil)
	job := uuid.MustParse(q["job_id"].(string))

	// What PATHOS 2.0 stored for a Grype match on a Maven package: the
	// artifact name only, fingerprint version 1, triaged as accepted risk.
	old := scanners.Finding{ScannerKey: scanners.Grype, Category: "sca", RuleID: "GHSA-jfh8-c2jp-5v3q", CVE: "CVE-2021-44228",
		PackageName: "log4j-core", PackageVersion: "2.14.1", FilePath: "svc/pom.xml"}
	legacy := scanners.LegacyFingerprint(old, "")
	id := uuid.Must(uuid.NewV7())
	if _, err := appPool.Exec(ctx, `INSERT INTO findings (id, organization_id, repository_id, fingerprint, category, scanner_keys, rule_id,
		title, description, severity, file_path, package_name, package_version, cve, status)
		VALUES ($1, $2, $3, $4, 'sca', '{grype}', $5, 'log4shell', '', 'critical', 'svc/pom.xml', 'log4j-core', '2.14.1', $6, 'accepted_risk')`,
		id, orgID, repo, legacy, old.RuleID, old.CVE); err != nil {
		t.Fatal(err)
	}

	grype := []byte(`{"matches":[{"vulnerability":{"id":"GHSA-jfh8-c2jp-5v3q","severity":"Critical"},
	  "relatedVulnerabilities":[{"id":"CVE-2021-44228"}],
	  "artifact":{"name":"log4j-core","version":"2.14.1","type":"java-archive","locations":[{"path":"/work/j/src/svc/pom.xml"}],
	    "purl":"pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1"}}]}`)
	if _, err := scanSvc.Ingest(ctx, orgID, job, scans.ResultUpload{Scanner: scanners.Grype, Version: "0.121.3", Status: "succeeded"}, gzipBytes(grype)); err != nil {
		t.Fatal(err)
	}
	trivy := []byte(`{"version":"2.1.0","runs":[{"tool":{"driver":{"name":"Trivy","rules":[{"id":"CVE-2021-44228","shortDescription":{"text":"log4j"},
	  "properties":{"tags":["vulnerability"]}}]}},"results":[{"ruleId":"CVE-2021-44228","level":"error",
	  "message":{"text":"Package: org.apache.logging.log4j:log4j-core\nInstalled Version: 2.14.1\nVulnerability CVE-2021-44228\nSeverity: CRITICAL\nFixed Version: 2.15.0"},
	  "locations":[{"physicalLocation":{"artifactLocation":{"uri":"svc/pom.xml"},"region":{"startLine":1}}}]}]}]}`)
	if _, err := scanSvc.Ingest(ctx, orgID, job, scans.ResultUpload{Scanner: "trivy-fs", Version: "0.76.2", Status: "succeeded"}, gzipBytes(trivy)); err != nil {
		t.Fatal(err)
	}

	type row struct {
		id          uuid.UUID
		fingerprint string
		status      string
		pkg         string
		keys        []string
	}
	rows, err := appPool.Query(ctx, `SELECT id, fingerprint, status, package_name, scanner_keys FROM findings WHERE repository_id = $1 AND category = 'sca'`, repo)
	if err != nil {
		t.Fatal(err)
	}
	var got []row
	for rows.Next() {
		var r row
		if err := rows.Scan(&r.id, &r.fingerprint, &r.status, &r.pkg, &r.keys); err != nil {
			t.Fatal(err)
		}
		got = append(got, r)
	}
	rows.Close()
	cur := old
	cur.PackageName = "org.apache.logging.log4j:log4j-core"
	if len(got) != 1 {
		t.Fatalf("one finding for one package and vulnerability, got %+v", got)
	}
	r := got[0]
	if r.id != id || r.fingerprint != scanners.Fingerprint(cur, "") || r.status != "accepted_risk" || r.pkg != "log4j-core" {
		t.Errorf("the stored finding is re-keyed and keeps its id, status and fields: %+v", r)
	}
	if !contains(r.keys, "grype") || !contains(r.keys, "trivy-fs") {
		t.Errorf("Trivy's finding merged into it: %v", r.keys)
	}
	var occ int
	_ = appPool.QueryRow(ctx, `SELECT count(*) FROM finding_occurrences WHERE finding_id = $1`, id).Scan(&occ)
	if occ != 2 {
		t.Errorf("occurrences of both tools on the same finding: %d", occ)
	}
}
