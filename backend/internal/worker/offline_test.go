package worker

import (
	"errors"
	"os"
	"path/filepath"
	"slices"
	"testing"
)

func TestOfflineMode(t *testing.T) {
	dir := t.TempDir()
	for _, sc := range []string{"trivy", "grype", "osv-scanner"} {
		if err := offlineReady(dir, sc); !errors.Is(err, ErrNoOfflineDB) {
			t.Errorf("%s without a database: %v", sc, err)
		}
	}
	_ = os.MkdirAll(filepath.Join(dir, "trivy", "db"), 0o700)
	_ = os.WriteFile(filepath.Join(dir, "trivy", "db", "trivy.db"), []byte("x"), 0o600)
	_ = os.MkdirAll(filepath.Join(dir, "grype", "6"), 0o700)
	_ = os.MkdirAll(filepath.Join(dir, "osv", "osv-scalibr"), 0o700)
	for _, sc := range []string{"trivy", "grype"} {
		if err := offlineReady(dir, sc); err != nil {
			t.Errorf("%s with a database: %v", sc, err)
		}
	}
	if err := offlineReady(dir, "osv-scanner"); err == nil {
		t.Error("an empty OSV directory is not a database")
	}
	if offlineReady(dir, "gitleaks") != nil {
		t.Error("scanners without databases are always ready")
	}
	if !slices.Contains(trivyOffline(true), "--skip-db-update") || trivyOffline(false) != nil {
		t.Error("trivy flags")
	}
	if env := grypeEnv(dir, true); !slices.Contains(env, "GRYPE_DB_AUTO_UPDATE=false") {
		t.Errorf("grype env: %v", env)
	}
	if env := grypeEnv(dir, false); slices.Contains(env, "GRYPE_DB_AUTO_UPDATE=false") {
		t.Error("online grype updates its database")
	}
	if f, e := osvArgs(dir, true); f[0] != "--offline-vulnerabilities" || e[0] != "OSV_SCANNER_LOCAL_DB_CACHE_DIRECTORY="+filepath.Join(dir, "osv") {
		t.Errorf("osv: %v %v", f, e)
	}
}
