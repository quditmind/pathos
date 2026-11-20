package scans

import (
	"context"
	"encoding/json"
	"net/http"

	"github.com/google/uuid"
)

// Hooks for the remediation module (internal/remediation, PATHOS 3.0 M8),
// which reuses the verified-AI-fix machinery: the same choice of scanner,
// the same scanner configuration and the same authenticated worker API.

// VerifyScanner is the scanner a worker re-runs for a finding: the first
// of its scanners a worker can run (imported reports cannot be re-run).
func VerifyScanner(keys []string) string { return verifyScanner(keys) }

// ScannerConfigFor returns a scanner's configuration in the profile of a
// scan execution (custom rules included), as AI fix verification uses it.
func (s *Service) ScannerConfigFor(ctx context.Context, jobID *uuid.UUID, key string) json.RawMessage {
	return s.scannerConfig(ctx, jobID, key)
}

// WorkerIdentity is the authenticated worker of an internal API request.
type WorkerIdentity struct {
	ID             uuid.UUID
	OrganizationID uuid.UUID
	Name           string
	Family         string
	Scanners       map[string]string
}

// WorkerFrom returns the worker of an internal API request (nil outside
// the authenticated worker API).
func WorkerFrom(ctx context.Context) *WorkerIdentity {
	w := workerFrom(ctx)
	if w == nil {
		return nil
	}
	return &WorkerIdentity{ID: w.ID, OrganizationID: w.orgID, Name: w.Name, Family: w.Family, Scanners: w.Scanners}
}

// mountWorkerRoutes adds the routes of other modules to the authenticated
// worker API.
func (s *Service) mountWorkerRoutes(mux *http.ServeMux) {
	for _, f := range s.WorkerRoutes {
		f(mux)
	}
}
