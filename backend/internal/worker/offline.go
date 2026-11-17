package worker

import (
	"errors"
	"os"
	"path/filepath"
)

// Offline mode (PATHOS_OFFLINE=true): scanners use only the vulnerability
// databases already in the cache (imported from an offline bundle with
// scripts/offline-bundle.sh) and never download anything.

// ErrNoOfflineDB means a scanner's database is missing in offline mode.
var ErrNoOfflineDB = errors.New("offline mode: vulnerability database missing; import an offline bundle (scripts/offline-bundle.sh import)")

// offlineDBs maps scanners to the cache path that must exist offline.
var offlineDBs = map[string]string{
	"trivy":       filepath.Join("trivy", "db", "trivy.db"),
	"grype":       "grype",
	"osv-scanner": filepath.Join("osv", "osv-scalibr"),
}

// offlineReady checks that a scanner's database is present.
func offlineReady(cacheDir, scanner string) error {
	p, ok := offlineDBs[scanner]
	if !ok {
		return nil
	}
	st, err := os.Stat(filepath.Join(cacheDir, p))
	if err != nil {
		return ErrNoOfflineDB
	}
	if st.IsDir() {
		entries, err := os.ReadDir(filepath.Join(cacheDir, p))
		if err != nil || len(entries) == 0 {
			return ErrNoOfflineDB
		}
	}
	return nil
}

// trivyOffline returns Trivy's offline flags.
func trivyOffline(offline bool) []string {
	if !offline {
		return nil
	}
	return []string{"--skip-db-update", "--skip-java-db-update", "--offline-scan"}
}

// grypeEnv returns Grype's database settings.
func grypeEnv(cacheDir string, offline bool) []string {
	env := []string{"GRYPE_CHECK_FOR_APP_UPDATE=false", "GRYPE_DB_CACHE_DIR=" + filepath.Join(cacheDir, "grype")}
	if offline {
		// An imported database may be older than Grype's default age
		// limit; the bundle's age is shown by offline-bundle.sh status.
		env = append(env, "GRYPE_DB_AUTO_UPDATE=false", "GRYPE_DB_VALIDATE_AGE=false")
	}
	return env
}

// osvArgs returns OSV-Scanner's offline flags and environment.
func osvArgs(cacheDir string, offline bool) ([]string, []string) {
	if !offline {
		return nil, nil
	}
	return []string{"--offline-vulnerabilities"}, []string{"OSV_SCANNER_LOCAL_DB_CACHE_DIRECTORY=" + filepath.Join(cacheDir, "osv")}
}
