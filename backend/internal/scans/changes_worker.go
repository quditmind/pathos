package scans

import (
	"encoding/json"
	"net/http"

	"pathos/internal/insights"
	"pathos/internal/platform/httpx"
)

// jobChanges stores the material change report of the worker holding the
// job (POST /internal/worker/v1/jobs/{id}/changes). It runs after the
// scanners, so the scan's SBOM is available for the dependency comparison.
func (s *Service) jobChanges(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	wk := workerFrom(ctx)
	id, err := pathID(r, "id")
	if err != nil {
		httpx.WriteError(w, r, s.Log, httpx.ErrNotFound)
		return
	}
	if status, err := s.ownedJob(ctx, wk, id); err != nil || status != "running" {
		if err == nil {
			err = httpx.Conflict("job is " + status)
		}
		httpx.WriteError(w, r, s.Log, err)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 16<<20)
	var rep insights.ChangeReport
	if err := json.NewDecoder(r.Body).Decode(&rep); err != nil {
		httpx.WriteError(w, r, s.Log, httpx.BadRequest("invalid change report"))
		return
	}
	n, err := insights.StoreChanges(ctx, s.DB, wk.orgID, id, rep)
	if err != nil {
		if err.Error() == "invalid change report" {
			httpx.WriteError(w, r, s.Log, httpx.BadRequest(err.Error()))
			return
		}
		httpx.WriteError(w, r, s.Log, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]int{"material_changes": n})
}
