package scans

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"slices"
	"strings"
	"time"
	"unicode"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"pathos/internal/audit"
	"pathos/internal/authz"
	"pathos/internal/platform/db"
	"pathos/internal/platform/httpx"
	"pathos/internal/scanners"
)

// Live secret validation (off by default). Administrators enable
// providers; the lease then tells the worker which providers it may ask
// whether a detected credential is still active. The worker reads the
// secret from its checkout, checks it and uploads only the verdict, the
// HTTP status and a non-secret identity. An active verdict raises the
// finding to critical (the previous severity is kept as evidence) and
// raises its contextual risk; an inactive one restores the severity.

func (s *Service) registerSecretValidation(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/v1/settings/secret-validation", s.getSecretValidationSettings)
	mux.HandleFunc("PUT /api/v1/settings/secret-validation", s.putSecretValidationSettings)
	mux.HandleFunc("POST /api/v1/findings/{id}/secret-validation/recheck", s.recheckSecret)
}

// SecretValidationLease is the job's setting (worker.SecretValidationConfig).
type SecretValidationLease struct {
	Providers     []string `json:"providers"`
	RatePerSecond int      `json:"rate_per_second"`
	MaxChecks     int      `json:"max_checks"`
}

// SecretValidationView is a secret finding's verdict.
type SecretValidationView struct {
	Status       string          `json:"status"`
	Provider     string          `json:"provider"`
	ProviderName string          `json:"provider_name"`
	Identity     string          `json:"identity"`
	CheckedAt    *time.Time      `json:"checked_at"`
	Evidence     json.RawMessage `json:"evidence"`
}

func newSecretValidationView(status, provider, identity string, at *time.Time, evidence []byte) *SecretValidationView {
	v := &SecretValidationView{Status: status, Provider: provider, Identity: identity, CheckedAt: at, Evidence: evidence}
	if p, ok := scanners.LookupSecretProvider(provider); ok {
		v.ProviderName = p.Name
	}
	if len(v.Evidence) == 0 {
		v.Evidence = json.RawMessage("null")
	}
	return v
}

// --- settings ------------------------------------------------------------------

type secretProviderSetting struct {
	scanners.SecretProvider
	Enabled bool `json:"enabled"`
}

// SecretValidationSettings is the settings API representation.
type SecretValidationSettings struct {
	Providers     []secretProviderSetting `json:"providers"`
	RatePerSecond int                     `json:"rate_per_second"`
	MaxChecks     int                     `json:"max_checks_per_scan"`
	UpdatedAt     *time.Time              `json:"updated_at"`
	CanManage     bool                    `json:"can_manage"`
	// Offline: the platform runs with PATHOS_OFFLINE=true; nothing is checked.
	Offline bool `json:"offline"`
}

type secretValidationConfig struct {
	providers []string
	rate, max int
	updatedAt *time.Time
}

func loadSecretValidation(ctx context.Context, q db.Querier, orgID uuid.UUID) (secretValidationConfig, error) {
	c := secretValidationConfig{rate: 1, max: 50}
	err := q.QueryRow(ctx, `SELECT providers, rate_per_second, max_checks_per_scan, updated_at FROM secret_validation_settings WHERE organization_id = $1`, orgID).
		Scan(&c.providers, &c.rate, &c.max, &c.updatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		err = nil
	}
	// Only known providers that can be checked count.
	c.providers = slices.DeleteFunc(c.providers, func(id string) bool {
		p, ok := scanners.LookupSecretProvider(id)
		return !ok || !p.Checkable
	})
	return c, err
}

func (s *Service) secretValidationSettings(ctx context.Context, p *authz.Principal) (SecretValidationSettings, error) {
	c, err := loadSecretValidation(ctx, s.DB, p.OrganizationID)
	if err != nil {
		return SecretValidationSettings{}, err
	}
	out := SecretValidationSettings{RatePerSecond: c.rate, MaxChecks: c.max, UpdatedAt: c.updatedAt, Offline: s.Offline,
		CanManage: p.HasOrgWide(authz.PermSettingsManage)}
	for _, sp := range scanners.SecretProviders {
		out.Providers = append(out.Providers, secretProviderSetting{SecretProvider: sp, Enabled: slices.Contains(c.providers, sp.ID)})
	}
	return out, nil
}

func (s *Service) getSecretValidationSettings(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	p := s.Principal(ctx)
	if !p.HasOrgWide(authz.PermSettingsManage) {
		s.fail(w, r, authz.ErrForbidden)
		return
	}
	out, err := s.secretValidationSettings(ctx, p)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, out)
}

// validateSecretSettings checks a settings update.
func validateSecretSettings(providers []string, rate, max int) ([]string, error) {
	if rate < 1 || rate > 10 {
		return nil, httpx.BadRequest("rate_per_second must be between 1 and 10")
	}
	if max < 1 || max > 500 {
		return nil, httpx.BadRequest("max_checks_per_scan must be between 1 and 500")
	}
	out := []string{}
	for _, id := range providers {
		p, ok := scanners.LookupSecretProvider(id)
		switch {
		case !ok:
			return nil, httpx.BadRequest("unknown provider " + id)
		case !p.Checkable:
			return nil, httpx.BadRequest(p.Name + " cannot be checked without side effects")
		}
		if !slices.Contains(out, id) {
			out = append(out, id)
		}
	}
	slices.Sort(out)
	return out, nil
}

func (s *Service) putSecretValidationSettings(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	p := s.Principal(ctx)
	if err := s.Authz.Require(ctx, p, authz.PermSettingsManage, authz.Scope{Type: authz.ScopeOrganization, ID: p.OrganizationID}); err != nil {
		s.fail(w, r, err)
		return
	}
	var in struct {
		Providers     []string `json:"providers"`
		RatePerSecond *int     `json:"rate_per_second"`
		MaxChecks     *int     `json:"max_checks_per_scan"`
	}
	if err := httpx.DecodeJSON(w, r, &in); err != nil {
		s.fail(w, r, err)
		return
	}
	if in.Providers == nil || in.RatePerSecond == nil || in.MaxChecks == nil {
		s.fail(w, r, httpx.BadRequest("providers, rate_per_second and max_checks_per_scan are required"))
		return
	}
	providers, err := validateSecretSettings(in.Providers, *in.RatePerSecond, *in.MaxChecks)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	err = db.InTx(ctx, s.DB, func(tx pgx.Tx) error {
		before, err := loadSecretValidation(ctx, tx, p.OrganizationID)
		if err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `INSERT INTO secret_validation_settings (organization_id, providers, rate_per_second, max_checks_per_scan, updated_by, updated_at)
			VALUES ($1, $2, $3, $4, $5, now()) ON CONFLICT (organization_id) DO UPDATE SET providers = EXCLUDED.providers,
			rate_per_second = EXCLUDED.rate_per_second, max_checks_per_scan = EXCLUDED.max_checks_per_scan,
			updated_by = EXCLUDED.updated_by, updated_at = now()`, p.OrganizationID, providers, *in.RatePerSecond, *in.MaxChecks, p.UserID); err != nil {
			return err
		}
		return audit.Write(ctx, tx, audit.Entry{OrganizationID: p.OrganizationID, ActorID: &p.UserID, ActorEmail: p.Email,
			Action: "secret_validation.settings.update", TargetType: "organization", TargetID: p.OrganizationID.String(),
			Metadata: map[string]any{"providers": providers, "previous_providers": nonNilStrings(before.providers),
				"rate_per_second": *in.RatePerSecond, "max_checks_per_scan": *in.MaxChecks}})
	})
	if err != nil {
		s.fail(w, r, err)
		return
	}
	out, err := s.secretValidationSettings(ctx, p)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, out)
}

// leaseSecretValidation returns the validation setting of a repository
// branch scan (nil: off). Pull request scans, scan targets and offline
// platforms never validate.
func (s *Service) leaseSecretValidation(ctx context.Context, orgID, jobID uuid.UUID) *SecretValidationLease {
	if s.Offline {
		return nil
	}
	var pr *int
	if err := s.DB.QueryRow(ctx, `SELECT pull_request FROM scan_jobs WHERE id = $1`, jobID).Scan(&pr); err != nil || pr != nil {
		return nil
	}
	c, err := loadSecretValidation(ctx, s.DB, orgID)
	if err != nil || len(c.providers) == 0 {
		return nil
	}
	return &SecretValidationLease{Providers: c.providers, RatePerSecond: c.rate, MaxChecks: c.max}
}

// --- worker upload ---------------------------------------------------------------

// SecretValidationUpload mirrors worker.SecretValidationReport.
type SecretValidationUpload struct {
	Version   int                  `json:"version"`
	Providers []string             `json:"providers"`
	Results   []SecretVerdictInput `json:"results"`
}

// SecretVerdictInput is one location's verdict.
type SecretVerdictInput struct {
	Fingerprints []string  `json:"fingerprints"`
	File         string    `json:"file"`
	Line         int       `json:"line"`
	Provider     string    `json:"provider"`
	Status       string    `json:"status"`
	Identity     string    `json:"identity"`
	Endpoint     string    `json:"endpoint"`
	HTTPStatus   int       `json:"http_status"`
	Detail       string    `json:"detail"`
	CheckedAt    time.Time `json:"checked_at"`
}

func plainText(s string, max int) string {
	s = strings.Map(func(r rune) rune {
		if unicode.IsControl(r) {
			return -1
		}
		return r
	}, strings.TrimSpace(s))
	return truncate(s, max)
}

// normalizeVerdict validates one verdict. ok=false drops it; a verdict
// for a provider that is not enabled is kept only as not_checked.
func normalizeVerdict(v SecretVerdictInput, enabled []string, now time.Time) (SecretVerdictInput, bool) {
	if !slices.Contains(scanners.SecretValidationStatuses, v.Status) || len(v.Fingerprints) == 0 || len(v.Fingerprints) > 20 {
		return v, false
	}
	for _, fp := range v.Fingerprints {
		if fp == "" || len(fp) > 128 || !printable(fp) {
			return v, false
		}
	}
	if v.Provider != "" {
		if _, ok := scanners.LookupSecretProvider(v.Provider); !ok {
			return v, false
		}
	}
	if v.HTTPStatus < 0 || v.HTTPStatus > 599 {
		v.HTTPStatus = 0
	}
	v.Identity, v.Detail, v.Endpoint = plainText(v.Identity, 200), plainText(v.Detail, 500), plainText(v.Endpoint, 200)
	v.File = plainText(v.File, 1000)
	if v.CheckedAt.IsZero() || v.CheckedAt.After(now.Add(time.Hour)) || v.CheckedAt.Before(now.Add(-48*time.Hour)) {
		v.CheckedAt = now
	}
	if v.Status != "not_checked" && !slices.Contains(enabled, v.Provider) {
		// Fail closed: only enabled providers may produce a verdict.
		v.Status, v.Identity, v.HTTPStatus = "not_checked", "", 0
		v.Detail = "discarded: the provider is not enabled for secret validation"
	}
	if v.Status != "active" {
		v.Identity = ""
	}
	return v, true
}

// secretVerdictSQL applies a verdict to the job's secret findings. An
// inconclusive verdict (error, not_checked) never replaces an earlier
// active or inactive one; it is kept as the last attempt.
const secretVerdictSQL = `
	UPDATE findings f SET
	  secret_validation_status = CASE WHEN ` + keepVerdict + ` THEN f.secret_validation_status ELSE $4 END,
	  secret_validation_provider = CASE WHEN ` + keepVerdict + ` THEN f.secret_validation_provider ELSE $5 END,
	  secret_validation_identity = CASE WHEN ` + keepVerdict + ` THEN f.secret_validation_identity ELSE $6 END,
	  secret_validation_checked_at = CASE WHEN ` + keepVerdict + ` THEN f.secret_validation_checked_at ELSE $7 END,
	  secret_validation_evidence = CASE WHEN ` + keepVerdict + `
	      THEN COALESCE(f.secret_validation_evidence, '{}'::jsonb) || jsonb_build_object('last_attempt', $8::jsonb)
	    WHEN $4 = 'active' AND (f.severity <> 'critical' OR f.secret_validation_severity_before IS NOT NULL)
	      THEN $8::jsonb || jsonb_build_object('severity_raised_from', COALESCE(f.secret_validation_severity_before, f.severity))
	    WHEN $4 = 'inactive' AND f.secret_validation_severity_before IS NOT NULL
	      THEN $8::jsonb || jsonb_build_object('severity_restored_to', f.secret_validation_severity_before)
	    ELSE $8::jsonb END,
	  secret_validation_severity_before = CASE WHEN ` + keepVerdict + ` THEN f.secret_validation_severity_before
	    WHEN $4 = 'active' AND f.severity <> 'critical' THEN COALESCE(f.secret_validation_severity_before, f.severity)
	    WHEN $4 = 'inactive' THEN NULL ELSE f.secret_validation_severity_before END,
	  severity = CASE WHEN ` + keepVerdict + ` THEN f.severity
	    WHEN $4 = 'active' THEN 'critical'
	    WHEN $4 = 'inactive' AND f.secret_validation_severity_before IS NOT NULL THEN f.secret_validation_severity_before
	    ELSE f.severity END,
	  risk_dirty = true, updated_at = now()
	WHERE f.repository_id = $1 AND f.last_scan_job_id = $2 AND f.category = 'secrets' AND f.fingerprint = ANY($3)`

const keepVerdict = `($4 NOT IN ('active', 'inactive') AND f.secret_validation_status IN ('active', 'inactive'))`

func (s *Service) registerWorkerSecretValidation(mux *http.ServeMux) {
	mux.HandleFunc("POST /internal/worker/v1/jobs/{id}/secret-validation", s.jobSecretValidation)
}

// jobSecretValidation stores the verdicts of a job and audits the batch.
func (s *Service) jobSecretValidation(w http.ResponseWriter, r *http.Request) {
	orgID, jobID, repoID, skip, ok := s.repoJob(w, r)
	if !ok {
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 2<<20)
	var up SecretValidationUpload
	if err := json.NewDecoder(r.Body).Decode(&up); err != nil || up.Version != 1 || len(up.Results) > 1000 {
		httpx.WriteError(w, r, s.Log, httpx.BadRequest("invalid secret validation report"))
		return
	}
	if skip {
		httpx.WriteJSON(w, http.StatusOK, map[string]int64{"findings_updated": 0})
		return
	}
	ctx := r.Context()
	wk := workerFrom(ctx)
	now := time.Now().UTC()
	var updated int64
	counts := map[string]int{}
	providers := map[string]map[string]int{}
	dropped := 0
	err := db.InTx(ctx, s.DB, func(tx pgx.Tx) error {
		cfg, err := loadSecretValidation(ctx, tx, orgID)
		if err != nil {
			return err
		}
		if s.Offline {
			cfg.providers = nil
		}
		if err := db.SetChangeContext(ctx, tx, nil, "secret_validation", "live secret validation"); err != nil {
			return err
		}
		b := &pgx.Batch{}
		for _, in := range up.Results {
			v, ok := normalizeVerdict(in, cfg.providers, now)
			if !ok {
				dropped++
				continue
			}
			counts[v.Status]++
			if v.Provider != "" {
				if providers[v.Provider] == nil {
					providers[v.Provider] = map[string]int{}
				}
				providers[v.Provider][v.Status]++
			}
			ev := map[string]any{"status": v.Status, "detail": v.Detail, "checked_at": v.CheckedAt, "scan_job_id": jobID, "worker": wk.Name}
			if v.Endpoint != "" {
				ev["endpoint"] = v.Endpoint
			}
			if v.HTTPStatus > 0 {
				ev["http_status"] = v.HTTPStatus
			}
			raw, _ := json.Marshal(ev)
			var at *time.Time
			if v.Status != "not_checked" {
				t := v.CheckedAt
				at = &t
			}
			b.Queue(secretVerdictSQL, repoID, jobID, v.Fingerprints, v.Status, v.Provider, v.Identity, at, string(raw))
		}
		if len(b.QueuedQueries) > 0 {
			br := tx.SendBatch(ctx, b)
			for range b.QueuedQueries {
				tag, err := br.Exec()
				if err != nil {
					_ = br.Close()
					return err
				}
				updated += tag.RowsAffected()
			}
			if err := br.Close(); err != nil {
				return err
			}
		}
		// Every batch is audited, without secret values (the worker never
		// sends them) and without identities.
		return audit.Write(ctx, tx, audit.Entry{OrganizationID: orgID, Action: "secret_validation.batch", TargetType: "scan_job",
			TargetID: jobID.String(), Metadata: map[string]any{"repository_id": repoID, "worker": wk.Name, "locations": len(up.Results),
				"verdicts": counts, "providers": providers, "dropped": dropped, "findings_updated": updated,
				"enabled_providers": nonNilStrings(cfg.providers)}})
	})
	if err != nil {
		httpx.WriteError(w, r, s.Log, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"findings_updated": updated, "dropped": dropped})
}

// --- re-check --------------------------------------------------------------------

// recheckSecret queues a scan of the finding's repository: the secret is
// read again from the checkout and validated by the worker (PATHOS does
// not keep secrets, so it cannot check one without the source).
func (s *Service) recheckSecret(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	p := s.Principal(ctx)
	id, err := pathID(r, "id")
	if err != nil {
		s.fail(w, r, errNotFound)
		return
	}
	var repoID uuid.UUID
	var category string
	var target *uuid.UUID
	if err := s.DB.QueryRow(ctx, `SELECT repository_id, category, scan_target_id FROM findings WHERE organization_id = $1 AND id = $2`,
		p.OrganizationID, id).Scan(&repoID, &category, &target); err != nil {
		s.fail(w, r, errNotFound)
		return
	}
	if err := s.requireRepo(ctx, p, authz.PermFindingsRead, repoID); err != nil {
		s.fail(w, r, err)
		return
	}
	switch {
	case category != "secrets":
		s.fail(w, r, httpx.BadRequest("only secret findings can be re-checked"))
		return
	case target != nil:
		s.fail(w, r, httpx.Conflict("findings of scan targets are not validated"))
		return
	case s.Offline:
		s.fail(w, r, httpx.Conflict("secret validation is disabled in offline mode"))
		return
	}
	cfg, err := loadSecretValidation(ctx, s.DB, p.OrganizationID)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if len(cfg.providers) == 0 {
		s.fail(w, r, httpx.Conflict("live secret validation is off: an administrator enables providers in Administration → Secret validation"))
		return
	}
	res, err := s.enqueueAs(ctx, p, repoID, "manual")
	if errors.Is(err, ErrNotScannable) || errors.Is(err, ErrScanPrerequisite) {
		err = httpx.Conflict(err.Error())
	}
	if err != nil {
		s.fail(w, r, err)
		return
	}
	err = db.InTx(ctx, s.DB, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `UPDATE findings SET secret_validation_evidence = COALESCE(secret_validation_evidence, '{}'::jsonb)
			|| jsonb_build_object('recheck_job_id', $2::text, 'recheck_requested_at', now()) WHERE id = $1`, id, res.JobID.String()); err != nil {
			return err
		}
		return audit.Write(ctx, tx, audit.Entry{OrganizationID: p.OrganizationID, ActorID: &p.UserID, ActorEmail: p.Email,
			Action: "secret_validation.recheck", TargetType: "finding", TargetID: id.String(),
			Metadata: map[string]any{"repository_id": repoID, "job_id": res.JobID, "coalesced": res.Coalesced}})
	})
	if err != nil {
		s.fail(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusAccepted, res)
}
