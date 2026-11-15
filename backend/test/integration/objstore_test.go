//go:build integration

package integration

import (
	"bytes"
	"compress/gzip"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/google/uuid"

	"pathos/internal/auth"
	"pathos/internal/authz"
	"pathos/internal/org"
	"pathos/internal/platform/objstore"
	"pathos/internal/scans"
)

func gz(t *testing.T, b []byte) []byte {
	var buf bytes.Buffer
	w := gzip.NewWriter(&buf)
	_, _ = w.Write(b)
	_ = w.Close()
	return buf.Bytes()
}

// Artifacts land in object storage when configured: the row keeps only the
// key, downloads read through, retention deletes the object, and inline
// rows from before can be migrated.
func TestArtifactsInObjectStorage(t *testing.T) {
	ctx := t.Context()
	mem := objstore.NewMemory()
	az := &authz.Authorizer{H: &org.Hierarchy{DB: appPool, OrgID: orgID}}
	withStore := &scans.Service{DB: appPool, Authz: az, Log: log, Principal: auth.PrincipalFrom, OrgID: orgID, Artifacts: mem}
	inline := &scans.Service{DB: appPool, Authz: az, Log: log, Principal: auth.PrincipalFrom, OrgID: orgID}

	repo := createRepo(t, "obj-"+uuid.NewString()[:6])
	newJob := func() uuid.UUID {
		id := uuid.Must(uuid.NewV7())
		var pv uuid.UUID
		_ = appPool.QueryRow(ctx, `SELECT current_version_id FROM scan_profiles WHERE organization_id = $1 AND is_default`, orgID).Scan(&pv)
		if _, err := appPool.Exec(ctx, `INSERT INTO scan_jobs (id, organization_id, repository_id, profile_version_id, trigger, ref, status)
			VALUES ($1, $2, $3, $4, 'manual', 'main', 'running')`, id, orgID, repo, pv); err != nil {
			t.Fatal(err)
		}
		return id
	}
	raw, err := os.ReadFile("../../internal/scanners/testdata/grype.json")
	if err != nil {
		t.Fatal(err)
	}

	job := newJob()
	if _, err := withStore.Ingest(ctx, orgID, job, scans.ResultUpload{Scanner: "grype", Version: "0.121.3", Status: "succeeded"}, gz(t, raw)); err != nil {
		t.Fatal(err)
	}
	var key *string
	var inlineBytes []byte
	if err := appPool.QueryRow(ctx, `SELECT a.object_key, a.data_gzip FROM scan_artifacts a JOIN scan_results r ON r.id = a.scan_result_id
		WHERE r.scan_job_id = $1`, job).Scan(&key, &inlineBytes); err != nil {
		t.Fatal(err)
	}
	if key == nil || inlineBytes != nil || len(mem.M[*key]) == 0 {
		t.Fatalf("artifact should be in the object store only: key=%v inline=%d", key, len(inlineBytes))
	}

	// Download reads through the object store.
	mux := newMux(withStore.Register)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/api/v1/scans/"+job.String()+"/results/grype/artifact", nil)
	mux.ServeHTTP(rec, req.WithContext(auth.WithPrincipal(ctx, principalWithRole(t, authz.RoleSuperAdmin))))
	if rec.Code != 200 || !bytes.Equal(rec.Body.Bytes(), raw) {
		t.Fatalf("download through object store: %d (%d bytes, want %d)", rec.Code, rec.Body.Len(), len(raw))
	}

	// Retention removes both the row and the object.
	_, _ = ownerPool.Exec(ctx, `UPDATE scan_artifacts SET created_at = now() - interval '10 years' WHERE object_key = $1`, *key)
	if n, err := scans.PruneArtifacts(ctx, appPool, mem); err != nil || n < 1 {
		t.Fatalf("prune: %d %v", n, err)
	}
	if _, ok := mem.M[*key]; ok {
		t.Error("expired object should be deleted")
	}

	// Inline artifacts (stored before object storage was enabled) migrate.
	_, _ = appPool.Exec(ctx, `UPDATE scan_jobs SET status = 'succeeded', finished_at = now() WHERE id = $1`, job)
	job2 := newJob()
	if _, err := inline.Ingest(ctx, orgID, job2, scans.ResultUpload{Scanner: "grype", Version: "0.121.3", Status: "succeeded"}, gz(t, raw)); err != nil {
		t.Fatal(err)
	}
	moved, err := scans.MigrateArtifacts(ctx, appPool, mem, 50)
	if err != nil || moved < 1 {
		t.Fatalf("migrate: %d %v", moved, err)
	}
	var left int
	_ = appPool.QueryRow(ctx, `SELECT count(*) FROM scan_artifacts WHERE object_key IS NULL`).Scan(&left)
	if left != 0 {
		t.Errorf("%d artifacts still inline after migration", left)
	}
	rec = httptest.NewRecorder()
	req = httptest.NewRequest("GET", "/api/v1/scans/"+job2.String()+"/results/grype/artifact", nil)
	mux.ServeHTTP(rec, req.WithContext(auth.WithPrincipal(ctx, principalWithRole(t, authz.RoleSuperAdmin))))
	if rec.Code != 200 || !bytes.Equal(rec.Body.Bytes(), raw) {
		t.Errorf("download after migration: %d", rec.Code)
	}
	// A row can never point both ways or nowhere.
	if _, err := ownerPool.Exec(ctx, `UPDATE scan_artifacts SET data_gzip = '\x00' WHERE object_key IS NOT NULL`); err == nil {
		t.Error("location constraint should reject inline data plus an object key")
	}
}
