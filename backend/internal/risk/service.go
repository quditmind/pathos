package risk

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"pathos/internal/audit"
	"pathos/internal/authz"
	"pathos/internal/platform/db"
	"pathos/internal/platform/httpx"
)

// Service recomputes scores and exposes the risk model.
type Service struct {
	DB        *pgxpool.Pool
	Authz     *authz.Authorizer
	Log       *slog.Logger
	Principal func(context.Context) *authz.Principal
}

// Model is a stored risk model version (version 0 = built-in default).
type Model struct {
	Version    int       `json:"version"`
	Weights    Weights   `json:"weights"`
	ChangeNote string    `json:"change_note"`
	CreatedBy  *string   `json:"created_by"`
	CreatedAt  time.Time `json:"created_at"`
	Default    bool      `json:"is_default"`
}

// CurrentModel returns the organization's latest model.
func CurrentModel(ctx context.Context, q db.Querier, orgID uuid.UUID) (Model, error) {
	var m Model
	var raw []byte
	err := q.QueryRow(ctx, `SELECT m.version, m.weights, m.change_note, COALESCE(NULLIF(u.display_name, ''), u.email), m.created_at
		FROM risk_models m LEFT JOIN users u ON u.id = m.created_by WHERE m.organization_id = $1 ORDER BY m.version DESC LIMIT 1`, orgID).
		Scan(&m.Version, &raw, &m.ChangeNote, &m.CreatedBy, &m.CreatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return Model{Weights: Default(), Default: true}, nil
	}
	if err != nil {
		return m, err
	}
	w := Default()
	if err := json.Unmarshal(raw, &w); err != nil {
		return m, err
	}
	if err := w.Validate(); err != nil {
		return m, err
	}
	m.Weights = w
	return m, nil
}

// Register mounts the API.
func (s *Service) Register(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/v1/risk-model", s.getModel)
	mux.HandleFunc("PUT /api/v1/risk-model", s.putModel)
	mux.HandleFunc("GET /api/v1/risk-model/history", s.modelHistory)
	mux.HandleFunc("GET /api/v1/findings/{id}/risk", s.findingRisk)
}

func (s *Service) fail(w http.ResponseWriter, r *http.Request, err error) {
	switch {
	case errors.Is(err, authz.ErrForbidden):
		err = httpx.ErrForbidden
	case errors.Is(err, pgx.ErrNoRows):
		err = httpx.ErrNotFound
	}
	httpx.WriteError(w, r, s.Log, err)
}

func (s *Service) getModel(w http.ResponseWriter, r *http.Request) {
	p := s.Principal(r.Context())
	if !p.HasAnywhere(authz.PermFindingsRead) {
		s.fail(w, r, authz.ErrForbidden)
		return
	}
	m, err := CurrentModel(r.Context(), s.DB, p.OrganizationID)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	var pending int
	_ = s.DB.QueryRow(r.Context(), `SELECT count(*) FROM findings WHERE organization_id = $1 AND risk_dirty`, p.OrganizationID).Scan(&pending)
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"model": m, "defaults": Default(), "pending_recompute": pending})
}

type modelRequest struct {
	Weights    Weights `json:"weights"`
	ChangeNote string  `json:"change_note"`
}

// putModel stores a new model version and schedules re-scoring.
func (s *Service) putModel(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	p := s.Principal(ctx)
	if !p.HasOrgWide(authz.PermSettingsManage) {
		s.fail(w, r, authz.ErrForbidden)
		return
	}
	var req modelRequest
	if err := httpx.DecodeJSON(w, r, &req); err != nil {
		s.fail(w, r, err)
		return
	}
	if err := req.Weights.Validate(); err != nil {
		s.fail(w, r, httpx.BadRequest(err.Error()))
		return
	}
	note := strings.TrimSpace(req.ChangeNote)
	if len(note) > 2000 {
		s.fail(w, r, httpx.BadRequest("change_note is too long"))
		return
	}
	raw, _ := json.Marshal(req.Weights)
	var version int
	err := db.InTx(ctx, s.DB, func(tx pgx.Tx) error {
		if err := tx.QueryRow(ctx, `INSERT INTO risk_models (id, organization_id, version, weights, change_note, created_by)
			SELECT $1, $2, COALESCE(max(version), 0) + 1, $3, $4, $5 FROM risk_models WHERE organization_id = $2 RETURNING version`,
			uuid.Must(uuid.NewV7()), p.OrganizationID, raw, note, p.UserID).Scan(&version); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `UPDATE findings SET risk_dirty = true WHERE organization_id = $1 AND NOT risk_dirty`, p.OrganizationID); err != nil {
			return err
		}
		return audit.Write(ctx, tx, audit.Entry{OrganizationID: p.OrganizationID, ActorID: &p.UserID, ActorEmail: p.Email,
			Action: "risk_model.update", TargetType: "risk_model", TargetID: p.OrganizationID.String(),
			Metadata: map[string]any{"version": version, "weights": req.Weights, "change_note": note}})
	})
	if err != nil {
		s.fail(w, r, err)
		return
	}
	s.getModel(w, r)
}

func (s *Service) modelHistory(w http.ResponseWriter, r *http.Request) {
	p := s.Principal(r.Context())
	if !p.HasAnywhere(authz.PermFindingsRead) {
		s.fail(w, r, authz.ErrForbidden)
		return
	}
	rows, err := s.DB.Query(r.Context(), `SELECT m.version, m.weights, m.change_note, COALESCE(NULLIF(u.display_name, ''), u.email), m.created_at
		FROM risk_models m LEFT JOIN users u ON u.id = m.created_by WHERE m.organization_id = $1 ORDER BY m.version DESC LIMIT 50`, p.OrganizationID)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	out, err := pgx.CollectRows(rows, func(row pgx.CollectableRow) (Model, error) {
		var m Model
		var raw []byte
		err := row.Scan(&m.Version, &raw, &m.ChangeNote, &m.CreatedBy, &m.CreatedAt)
		m.Weights = Default()
		_ = json.Unmarshal(raw, &m.Weights)
		return m, err
	})
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if out == nil {
		out = []Model{}
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"items": out})
}

// FindingRisk is the score of one finding with its explanation.
type FindingRisk struct {
	Score          *float64        `json:"risk_score"`
	Band           string          `json:"band"`
	Explanation    json.RawMessage `json:"explanation"`
	ScoredAt       *time.Time      `json:"scored_at"`
	Pending        bool            `json:"pending"`
	CVE            string          `json:"cve"`
	EPSS           *float64        `json:"epss"`
	EPSSPercentile *float64        `json:"epss_percentile"`
	KEV            bool            `json:"kev"`
	KEVDueDate     *time.Time      `json:"kev_due_date"`
	Confidence     string          `json:"confidence"`
	Reachability   string          `json:"reachability"`
	CVSSVersion    string          `json:"cvss_version"`
	CVSSVector     string          `json:"cvss_vector"`
}

func (s *Service) findingRisk(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	p := s.Principal(ctx)
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		s.fail(w, r, httpx.ErrNotFound)
		return
	}
	var repo uuid.UUID
	var out FindingRisk
	var factors []byte
	err = s.DB.QueryRow(ctx, `SELECT repository_id, risk_score::float8, risk_factors, risk_scored_at, risk_dirty, cve, epss_score::float8,
		epss_percentile::float8, kev, kev_due_date, confidence, reachability, cvss_version, cvss_vector
		FROM findings WHERE organization_id = $1 AND id = $2`, p.OrganizationID, id).
		Scan(&repo, &out.Score, &factors, &out.ScoredAt, &out.Pending, &out.CVE, &out.EPSS, &out.EPSSPercentile, &out.KEV, &out.KEVDueDate,
			&out.Confidence, &out.Reachability, &out.CVSSVersion, &out.CVSSVector)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if ok, _ := s.Authz.Can(ctx, p, authz.PermFindingsRead, authz.Scope{Type: authz.ScopeRepository, ID: repo}); !ok {
		s.fail(w, r, httpx.ErrNotFound)
		return
	}
	out.Explanation = factors
	if out.Explanation == nil {
		out.Explanation = json.RawMessage("null")
	}
	if out.Score != nil {
		out.Band = Band(*out.Score)
	}
	httpx.WriteJSON(w, http.StatusOK, out)
}

// --- recomputation -----------------------------------------------------------

var critRank = []string{"low", "medium", "high", "critical"}

func higher(a, b string) string {
	if slices.Index(critRank, b) > slices.Index(critRank, a) {
		return b
	}
	return a
}

// Recompute scores up to limit dirty findings of an organization and
// returns how many were scored. EPSS and KEV values are copied from the
// intelligence tables at the same time.
func Recompute(ctx context.Context, pool *pgxpool.Pool, orgID uuid.UUID, limit int) (int, error) {
	m, err := CurrentModel(ctx, pool, orgID)
	if err != nil {
		return 0, err
	}
	n := 0
	err = db.InTx(ctx, pool, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `
			SELECT f.id, f.status, f.severity, COALESCE(f.human_severity, ''), f.cvss::float8, e.score::float8, e.percentile::float8,
			       k.cve_id IS NOT NULL, k.due_date, f.exploit_available, r.criticality, COALESCE(a.criticality, ''), r.public_exposure,
			       f.reachability, f.confidence, COALESCE(f.human_disposition, ''), f.fixed_version <> '',
			       EXISTS (SELECT 1 FROM human_reviews h JOIN human_review_assessments ha ON ha.review_id = h.id AND ha.round = h.round
			               WHERE h.finding_id = f.id AND ha.answers->>'compensating_controls_present' = 'yes'),
			       -- public exploit or proof of concept referenced by the OSV record
			       f.cve <> '' AND EXISTS (SELECT 1 FROM intel_vulns v WHERE v.found AND v.exploit_refs > 0
			               AND (v.id = f.cve OR f.cve = ANY(v.aliases))),
			       `+MaliciousExpr+`
			FROM findings f
			JOIN repositories r ON r.id = f.repository_id
			LEFT JOIN applications a ON a.id = r.application_id
			LEFT JOIN intel_epss e ON e.cve_id = f.cve
			LEFT JOIN intel_kev k ON k.cve_id = f.cve
			WHERE f.organization_id = $1 AND f.risk_dirty
			LIMIT $2 FOR UPDATE OF f SKIP LOCKED`, orgID, limit)
		if err != nil {
			return err
		}
		type upd struct {
			id            uuid.UUID
			res           Result
			epss, epssPct *float64
			kev           bool
			kevDue        *time.Time
			exploit       bool
			osvExploit    bool
			malicious     bool
		}
		var list []upd
		for rows.Next() {
			var u upd
			var in Input
			var repoCrit, appCrit string
			if err := rows.Scan(&u.id, &in.Status, &in.Severity, &in.HumanSeverity, &in.CVSS, &u.epss, &u.epssPct, &u.kev, &u.kevDue,
				&in.ExploitAvailable, &repoCrit, &appCrit, &in.Exposure, &in.Reachability, &in.Confidence, &in.HumanDisposition,
				&in.FixAvailable, &in.Compensating, &u.osvExploit, &in.Malicious); err != nil {
				rows.Close()
				return err
			}
			in.Criticality = higher(repoCrit, appCrit)
			in.EPSSPercentile, in.KEV = u.epssPct, u.kev
			// KEV entries are exploited in the wild.
			in.ExploitAvailable = in.ExploitAvailable || u.kev || u.osvExploit
			u.exploit = in.ExploitAvailable
			u.malicious = in.Malicious
			u.res = Compute(in, m.Weights)
			u.res.Version = m.Version
			list = append(list, u)
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			return err
		}
		b := &pgx.Batch{}
		for _, u := range list {
			raw, _ := json.Marshal(u.res)
			b.Queue(`UPDATE findings SET risk_score = $2, risk_factors = $3, risk_scored_at = now(), risk_dirty = false,
				epss_score = $4, epss_percentile = $5, kev = $6, kev_due_date = $7, exploit_available = $8, malicious = $9 WHERE id = $1`,
				u.id, u.res.Score, raw, u.epss, u.epssPct, u.kev, u.kevDue, u.exploit, u.malicious)
		}
		n = len(list)
		if n == 0 {
			return nil
		}
		return tx.SendBatch(ctx, b).Close()
	})
	return n, err
}

// RunBackground re-scores dirty findings (jobs role).
func RunBackground(ctx context.Context, pool *pgxpool.Pool, log *slog.Logger) {
	t := time.NewTicker(30 * time.Second)
	defer t.Stop()
	for {
		rows, err := pool.Query(ctx, `SELECT DISTINCT organization_id FROM findings WHERE risk_dirty`)
		if err == nil {
			orgs, _ := pgx.CollectRows(rows, pgx.RowTo[uuid.UUID])
			for _, o := range orgs {
				total := 0
				for ctx.Err() == nil {
					n, err := Recompute(ctx, pool, o, 2000)
					if err != nil {
						log.Warn("risk recompute failed", "err", err)
						break
					}
					total += n
					if n < 2000 {
						break
					}
				}
				if total > 0 {
					log.Info("risk scores updated", "findings", total)
				}
			}
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

// MaliciousExpr (alias f) is true for findings about malicious packages:
// OSV MAL-* advisories (directly or through an alias of the advisory) and
// GitHub "Malicious code in" / "Malware in" advisories.
const MaliciousExpr = `(f.rule_id LIKE 'MAL-%' OR f.cve LIKE 'MAL-%'
	OR f.title ~* '^(malicious code in|malware in|embedded malicious code)'
	OR EXISTS (SELECT 1 FROM intel_vulns v WHERE v.found AND (v.id IN (f.cve, f.rule_id) OR f.cve = ANY(v.aliases) OR f.rule_id = ANY(v.aliases))
	           AND (v.id LIKE 'MAL-%' OR EXISTS (SELECT 1 FROM unnest(v.aliases) a WHERE a LIKE 'MAL-%'))))`
