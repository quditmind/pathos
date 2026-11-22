package runtimectx

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"pathos/internal/audit"
	"pathos/internal/authz"
	"pathos/internal/platform/db"
	"pathos/internal/platform/httpx"
	"pathos/internal/scm"
	"pathos/internal/secrets"
)

// Register mounts the API. Nothing here contacts a cluster or a registry:
// "sync" only records a request that the jobs service carries out.
func (s *Service) Register(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/v1/runtime/summary", s.summary)
	mux.HandleFunc("GET /api/v1/runtime/clusters", s.listClusters)
	mux.HandleFunc("POST /api/v1/runtime/clusters", s.createCluster)
	mux.HandleFunc("PUT /api/v1/runtime/clusters/{id}", s.updateCluster)
	mux.HandleFunc("DELETE /api/v1/runtime/clusters/{id}", s.deleteCluster)
	mux.HandleFunc("POST /api/v1/runtime/clusters/{id}/sync", s.requestSync("runtime_clusters", "runtime_cluster"))
	mux.HandleFunc("GET /api/v1/runtime/clusters/{id}/runs", s.runs("cluster_id"))
	mux.HandleFunc("GET /api/v1/runtime/registries", s.listRegistries)
	mux.HandleFunc("POST /api/v1/runtime/registries", s.createRegistry)
	mux.HandleFunc("PUT /api/v1/runtime/registries/{id}", s.updateRegistry)
	mux.HandleFunc("DELETE /api/v1/runtime/registries/{id}", s.deleteRegistry)
	mux.HandleFunc("POST /api/v1/runtime/registries/{id}/sync", s.requestSync("registry_connections", "registry_connection"))
	mux.HandleFunc("GET /api/v1/runtime/registries/{id}/runs", s.runs("registry_id"))
	mux.HandleFunc("GET /api/v1/runtime/registries/{id}/images", s.registryImages)
	mux.HandleFunc("GET /api/v1/runtime/workloads", s.listWorkloads)
	mux.HandleFunc("GET /api/v1/runtime/workloads/{id}", s.getWorkload)
	mux.HandleFunc("GET /api/v1/runtime/mappings", s.listMappings)
	mux.HandleFunc("POST /api/v1/runtime/mappings", s.createMapping)
	mux.HandleFunc("DELETE /api/v1/runtime/mappings/{id}", s.deleteMapping)
	mux.HandleFunc("GET /api/v1/findings/{id}/runtime", s.findingRuntime)
}

func (s *Service) fail(w http.ResponseWriter, r *http.Request, err error) {
	switch {
	case errors.Is(err, authz.ErrForbidden):
		err = httpx.ErrForbidden
	case errors.Is(err, pgx.ErrNoRows):
		err = httpx.ErrNotFound
	case db.IsUniqueViolation(err):
		err = httpx.Conflict("a connection with this name already exists")
	}
	httpx.WriteError(w, r, s.Log, err)
}

// manage requires settings.manage organization-wide (connections hold
// credentials and see every cluster).
func (s *Service) manage(r *http.Request) (*authz.Principal, error) {
	p := s.Principal(r.Context())
	if p == nil || !p.HasOrgWide(authz.PermSettingsManage) {
		return nil, authz.ErrForbidden
	}
	return p, nil
}

// reader requires organization-wide findings.read: the inventory spans
// every application and is not scoped by business unit.
func (s *Service) reader(r *http.Request) (*authz.Principal, error) {
	p := s.Principal(r.Context())
	if p == nil || (!p.HasOrgWide(authz.PermFindingsRead) && !p.HasOrgWide(authz.PermSettingsManage)) {
		return nil, authz.ErrForbidden
	}
	return p, nil
}

func pathUUID(r *http.Request) (uuid.UUID, error) {
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		return id, pgx.ErrNoRows
	}
	return id, nil
}

// --- clusters -------------------------------------------------------------------

// Cluster as returned by the API (never the credential).
type Cluster struct {
	ID              uuid.UUID  `json:"id"`
	Name            string     `json:"name"`
	APIServer       string     `json:"api_server"`
	AuthType        string     `json:"auth_type"`
	HasCACert       bool       `json:"has_ca_cert"`
	Namespaces      []string   `json:"namespaces"`
	AllowPrivate    bool       `json:"allow_private"`
	Enabled         bool       `json:"enabled"`
	IntervalMinutes int        `json:"sync_interval_minutes"`
	SyncRequestedAt *time.Time `json:"sync_requested_at"`
	LastSyncAt      *time.Time `json:"last_sync_at"`
	LastStatus      string     `json:"last_status"`
	LastError       string     `json:"last_error"`
	Workloads       int        `json:"workloads"`
	Exposed         int        `json:"internet_exposed_workloads"`
	Privileged      int        `json:"privileged_workloads"`
	NamespaceCount  int        `json:"namespace_count"`
	CreatedAt       time.Time  `json:"created_at"`
}

const clusterSelect = `SELECT c.id, c.name, c.api_server, c.auth_type, c.ca_cert <> '', c.namespaces, c.allow_private, c.enabled,
	c.sync_interval_minutes, c.sync_requested_at, c.last_sync_at, c.last_status, c.last_error,
	(SELECT count(*) FROM runtime_workloads w WHERE w.cluster_id = c.id),
	(SELECT count(*) FROM runtime_workloads w WHERE w.cluster_id = c.id AND w.internet_exposed),
	(SELECT count(*) FROM runtime_workloads w WHERE w.cluster_id = c.id AND (w.privileged OR w.host_network OR w.host_pid)),
	(SELECT count(*) FROM runtime_namespaces n WHERE n.cluster_id = c.id), c.created_at
	FROM runtime_clusters c`

func scanCluster(r pgx.Row) (Cluster, error) {
	var c Cluster
	err := r.Scan(&c.ID, &c.Name, &c.APIServer, &c.AuthType, &c.HasCACert, &c.Namespaces, &c.AllowPrivate, &c.Enabled, &c.IntervalMinutes,
		&c.SyncRequestedAt, &c.LastSyncAt, &c.LastStatus, &c.LastError, &c.Workloads, &c.Exposed, &c.Privileged, &c.NamespaceCount, &c.CreatedAt)
	return c, err
}

func (s *Service) listClusters(w http.ResponseWriter, r *http.Request) {
	p, err := s.reader(r)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	rows, err := s.DB.Query(r.Context(), clusterSelect+` WHERE c.organization_id = $1 ORDER BY lower(c.name)`, p.OrganizationID)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	items, err := pgx.CollectRows(rows, func(r pgx.CollectableRow) (Cluster, error) { return scanCluster(r) })
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if items == nil {
		items = []Cluster{}
	}
	if !p.HasOrgWide(authz.PermSettingsManage) {
		for i := range items {
			items[i].APIServer, items[i].LastError = "", ""
		}
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"items": items, "can_manage": p.HasOrgWide(authz.PermSettingsManage)})
}

type clusterInput struct {
	Name            string   `json:"name"`
	AuthType        string   `json:"auth_type"`
	APIServer       string   `json:"api_server"`
	Token           string   `json:"token"`
	CACert          string   `json:"ca_cert"`
	Kubeconfig      string   `json:"kubeconfig"`
	Context         string   `json:"context"`
	Namespaces      []string `json:"namespaces"`
	AllowPrivate    bool     `json:"allow_private"`
	Enabled         *bool    `json:"enabled"`
	IntervalMinutes int      `json:"sync_interval_minutes"`
}

var dns1123Label = regexp.MustCompile(`^[a-z0-9]([-a-z0-9]{0,61}[a-z0-9])?$`)

// validate checks the input; secret is the JSON credential to store (nil:
// keep the stored one on update).
func (in *clusterInput) validate(update bool) (secret []byte, err error) {
	in.Name = strings.TrimSpace(in.Name)
	if in.Name == "" || len(in.Name) > 120 {
		return nil, httpx.BadRequest("name is required (at most 120 characters)")
	}
	if in.IntervalMinutes == 0 {
		in.IntervalMinutes = 60
	}
	if in.IntervalMinutes < 15 || in.IntervalMinutes > 1440 {
		return nil, httpx.BadRequest("sync_interval_minutes must be between 15 and 1440")
	}
	if len(in.Namespaces) > 200 {
		return nil, httpx.BadRequest("at most 200 namespaces")
	}
	seen := map[string]bool{}
	ns := []string{}
	for _, n := range in.Namespaces {
		n = strings.TrimSpace(n)
		if n == "" || seen[n] {
			continue
		}
		if !dns1123Label.MatchString(n) {
			return nil, httpx.BadRequest("namespace " + strconv.Quote(n) + " is not a valid namespace name")
		}
		seen[n] = true
		ns = append(ns, n)
	}
	in.Namespaces = ns
	policy := scm.NetPolicy{AllowPrivate: in.AllowPrivate, OrgChosen: true}
	switch in.AuthType {
	case "token":
		in.APIServer = strings.TrimRight(strings.TrimSpace(in.APIServer), "/")
		if _, err := policy.ValidateBaseURL(in.APIServer); err != nil {
			return nil, httpx.BadRequest("api_server: " + err.Error())
		}
		in.CACert = strings.TrimSpace(in.CACert)
		if in.CACert != "" {
			if len(in.CACert) > 65536 {
				return nil, httpx.BadRequest("ca_cert is too long")
			}
			blk, _ := pem.Decode([]byte(in.CACert))
			if blk == nil || blk.Type != "CERTIFICATE" {
				return nil, httpx.BadRequest("ca_cert must be a PEM certificate")
			}
			if _, err := x509.ParseCertificate(blk.Bytes); err != nil {
				return nil, httpx.BadRequest("ca_cert: " + err.Error())
			}
		}
		tok := strings.TrimSpace(in.Token)
		if len(tok) > 16384 {
			return nil, httpx.BadRequest("token is too long")
		}
		if tok == "" {
			if !update {
				return nil, httpx.BadRequest("token (a service-account token) is required")
			}
			return nil, nil
		}
		// #nosec G117 -- serialized only to be envelope-encrypted into the secrets store
		raw, _ := json.Marshal(Credentials{Token: tok})
		return raw, nil
	case "kubeconfig":
		if strings.TrimSpace(in.Kubeconfig) == "" {
			if !update {
				return nil, httpx.BadRequest("kubeconfig is required")
			}
			return nil, nil
		}
		c, err := ParseKubeconfig([]byte(in.Kubeconfig), in.Context)
		if err != nil {
			return nil, httpx.BadRequest(err.Error())
		}
		if _, err := policy.ValidateBaseURL(c.Server); err != nil {
			return nil, httpx.BadRequest("kubeconfig server: " + err.Error())
		}
		in.APIServer, in.CACert = c.Server, ""
		// #nosec G117 -- serialized only to be envelope-encrypted into the secrets store
		raw, _ := json.Marshal(c)
		return raw, nil
	}
	return nil, httpx.BadRequest("auth_type must be token or kubeconfig")
}

func (s *Service) createCluster(w http.ResponseWriter, r *http.Request) {
	p, err := s.manage(r)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	var in clusterInput
	if err := httpx.DecodeJSON(w, r, &in); err != nil {
		s.fail(w, r, err)
		return
	}
	secret, err := in.validate(false)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	id := uuid.Must(uuid.NewV7())
	enabled := in.Enabled == nil || *in.Enabled
	err = db.InTx(r.Context(), s.DB, func(tx pgx.Tx) error {
		sid, err := s.Secrets.Create(r.Context(), tx, p.OrganizationID, secrets.KindIntegration, "kubernetes: "+in.Name, secret, &p.UserID)
		if err != nil {
			return err
		}
		if _, err := tx.Exec(r.Context(), `INSERT INTO runtime_clusters (id, organization_id, name, api_server, auth_type, secret_id, ca_cert, namespaces,
			allow_private, enabled, sync_interval_minutes, sync_requested_at, created_by)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, now(), $12)`,
			id, p.OrganizationID, in.Name, in.APIServer, in.AuthType, sid, in.CACert, in.Namespaces, in.AllowPrivate, enabled, in.IntervalMinutes, p.UserID); err != nil {
			return err
		}
		return audit.Write(r.Context(), tx, audit.Entry{OrganizationID: p.OrganizationID, ActorID: &p.UserID, ActorEmail: p.Email,
			Action: "runtime_cluster.create", TargetType: "runtime_cluster", TargetID: id.String(),
			Metadata: map[string]any{"name": in.Name, "api_server": in.APIServer, "auth_type": in.AuthType, "namespaces": in.Namespaces}})
	})
	if err != nil {
		s.fail(w, r, err)
		return
	}
	c, err := scanCluster(s.DB.QueryRow(r.Context(), clusterSelect+` WHERE c.id = $1`, id))
	if err != nil {
		s.fail(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusCreated, c)
}

func (s *Service) updateCluster(w http.ResponseWriter, r *http.Request) {
	p, err := s.manage(r)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	id, err := pathUUID(r)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	var in clusterInput
	if err := httpx.DecodeJSON(w, r, &in); err != nil {
		s.fail(w, r, err)
		return
	}
	var curAuth, curServer, curCA string
	var sid uuid.UUID
	if err := s.DB.QueryRow(r.Context(), `SELECT auth_type, api_server, ca_cert, secret_id FROM runtime_clusters WHERE organization_id = $1 AND id = $2`,
		p.OrganizationID, id).Scan(&curAuth, &curServer, &curCA, &sid); err != nil {
		s.fail(w, r, err)
		return
	}
	if in.AuthType == "" {
		in.AuthType = curAuth
	}
	if in.AuthType == "kubeconfig" && strings.TrimSpace(in.Kubeconfig) == "" {
		if curAuth != "kubeconfig" {
			s.fail(w, r, httpx.BadRequest("kubeconfig is required when switching to kubeconfig credentials"))
			return
		}
		in.APIServer = curServer
	}
	if in.AuthType == "token" && curAuth != "token" && strings.TrimSpace(in.Token) == "" {
		s.fail(w, r, httpx.BadRequest("token is required when switching to token credentials"))
		return
	}
	secret, err := in.validate(true)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if in.AuthType == "kubeconfig" && secret == nil {
		// Kept kubeconfig: re-check the stored server against the policy.
		if _, err := (scm.NetPolicy{AllowPrivate: in.AllowPrivate, OrgChosen: true}).ValidateBaseURL(curServer); err != nil {
			s.fail(w, r, httpx.BadRequest("kubeconfig server: "+err.Error()))
			return
		}
	}
	if in.AuthType == "token" && curAuth == "token" && in.CACert == "" {
		// Like the token, a stored CA certificate is kept unless a new one
		// is sent (the edit form leaves it empty: "paste to replace").
		// Dropping it made the next synchronisation fail with "x509:
		// certificate signed by unknown authority".
		in.CACert = curCA
	}
	enabled := in.Enabled == nil || *in.Enabled
	err = db.InTx(r.Context(), s.DB, func(tx pgx.Tx) error {
		if secret != nil {
			if err := s.Secrets.Update(r.Context(), tx, p.OrganizationID, sid, secrets.KindIntegration, secret); err != nil {
				return err
			}
		}
		if _, err := tx.Exec(r.Context(), `UPDATE runtime_clusters SET name = $3, api_server = $4, auth_type = $5, ca_cert = $6, namespaces = $7,
			allow_private = $8, enabled = $9, sync_interval_minutes = $10, updated_at = now() WHERE organization_id = $1 AND id = $2`,
			p.OrganizationID, id, in.Name, in.APIServer, in.AuthType, in.CACert, in.Namespaces, in.AllowPrivate, enabled, in.IntervalMinutes); err != nil {
			return err
		}
		return audit.Write(r.Context(), tx, audit.Entry{OrganizationID: p.OrganizationID, ActorID: &p.UserID, ActorEmail: p.Email,
			Action: "runtime_cluster.update", TargetType: "runtime_cluster", TargetID: id.String(),
			Metadata: map[string]any{"name": in.Name, "api_server": in.APIServer, "auth_type": in.AuthType, "credential_replaced": secret != nil,
				"namespaces": in.Namespaces, "enabled": enabled}})
	})
	if err != nil {
		s.fail(w, r, err)
		return
	}
	c, err := scanCluster(s.DB.QueryRow(r.Context(), clusterSelect+` WHERE c.id = $1`, id))
	if err != nil {
		s.fail(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, c)
}

func (s *Service) deleteCluster(w http.ResponseWriter, r *http.Request) {
	s.deleteConn(w, r, "runtime_clusters", "runtime_cluster")
}

func (s *Service) deleteConn(w http.ResponseWriter, r *http.Request, table, kind string) {
	p, err := s.manage(r)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	id, err := pathUUID(r)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	err = db.InTx(r.Context(), s.DB, func(tx pgx.Tx) error {
		var name string
		var sid *uuid.UUID
		// table is one of two constants.
		if err := tx.QueryRow(r.Context(), `DELETE FROM `+table+` WHERE organization_id = $1 AND id = $2 RETURNING name, secret_id`,
			p.OrganizationID, id).Scan(&name, &sid); err != nil {
			return err
		}
		if sid != nil {
			if err := s.Secrets.Delete(r.Context(), tx, p.OrganizationID, *sid); err != nil {
				return err
			}
		}
		return audit.Write(r.Context(), tx, audit.Entry{OrganizationID: p.OrganizationID, ActorID: &p.UserID, ActorEmail: p.Email,
			Action: kind + ".delete", TargetType: kind, TargetID: id.String(), Metadata: map[string]any{"name": name}})
	})
	if err != nil {
		s.fail(w, r, err)
		return
	}
	// The inventory went with the connection: relink (database only).
	if err := Link(r.Context(), s.DB, p.OrganizationID); err != nil {
		s.Log.Warn("runtime linking failed", "err", err)
	}
	w.WriteHeader(http.StatusNoContent)
}

// requestSync records a synchronisation request; the jobs service runs it
// within a minute.
// exists reports whether the connection id exists in the organization
// (table is one of the two connection tables), so that another
// organization's id is answered like a missing one (404).
func (s *Service) exists(ctx context.Context, table string, orgID, id uuid.UUID) bool {
	var ok bool
	_ = s.DB.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM `+table+` WHERE organization_id = $1 AND id = $2)`, orgID, id).Scan(&ok)
	return ok
}

func (s *Service) requestSync(table, kind string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		p, err := s.manage(r)
		if err != nil {
			s.fail(w, r, err)
			return
		}
		id, err := pathUUID(r)
		if err != nil {
			s.fail(w, r, err)
			return
		}
		var at time.Time
		// table is one of two constants.
		if err := s.DB.QueryRow(r.Context(), `UPDATE `+table+` SET sync_requested_at = now() WHERE organization_id = $1 AND id = $2 AND enabled
			RETURNING sync_requested_at`, p.OrganizationID, id).Scan(&at); err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				err = httpx.ErrNotFound
				if s.exists(r.Context(), table, p.OrganizationID, id) {
					err = httpx.Conflict("the connection is disabled")
				}
			}
			s.fail(w, r, err)
			return
		}
		_ = audit.Write(r.Context(), s.DB, audit.Entry{OrganizationID: p.OrganizationID, ActorID: &p.UserID, ActorEmail: p.Email,
			Action: kind + ".sync_request", TargetType: kind, TargetID: id.String()})
		httpx.WriteJSON(w, http.StatusAccepted, map[string]any{"sync_requested_at": at,
			"message": "The jobs service synchronises within a minute; refresh to see the result."})
	}
}

// SyncRun is one synchronisation.
type SyncRun struct {
	ID         uuid.UUID       `json:"id"`
	StartedAt  time.Time       `json:"started_at"`
	FinishedAt *time.Time      `json:"finished_at"`
	Status     string          `json:"status"`
	Stats      json.RawMessage `json:"stats"`
	Error      string          `json:"error"`
}

func (s *Service) runs(column string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		p, err := s.manage(r)
		if err != nil {
			s.fail(w, r, err)
			return
		}
		id, err := pathUUID(r)
		if err != nil {
			s.fail(w, r, err)
			return
		}
		parent := map[string]string{"cluster_id": "runtime_clusters", "registry_id": "registry_connections"}[column]
		if !s.exists(r.Context(), parent, p.OrganizationID, id) {
			s.fail(w, r, httpx.ErrNotFound)
			return
		}
		// column is one of two constants.
		rows, err := s.DB.Query(r.Context(), `SELECT id, started_at, finished_at, status, stats, error FROM runtime_sync_runs
			WHERE organization_id = $1 AND `+column+` = $2 ORDER BY started_at DESC LIMIT 30`, p.OrganizationID, id)
		if err != nil {
			s.fail(w, r, err)
			return
		}
		items, err := pgx.CollectRows(rows, func(r pgx.CollectableRow) (SyncRun, error) {
			var x SyncRun
			err := r.Scan(&x.ID, &x.StartedAt, &x.FinishedAt, &x.Status, &x.Stats, &x.Error)
			return x, err
		})
		if err != nil {
			s.fail(w, r, err)
			return
		}
		if items == nil {
			items = []SyncRun{}
		}
		httpx.WriteJSON(w, http.StatusOK, map[string]any{"items": items})
	}
}

// --- registries ---------------------------------------------------------------

// Registry as returned by the API (never the credential).
type Registry struct {
	ID           uuid.UUID `json:"id"`
	Name         string    `json:"name"`
	BaseURL      string    `json:"base_url"`
	Repositories []string  `json:"repositories"`
	AuthType     string    `json:"auth_type"`
	Username     string    `json:"username"`
	MaxTags      int       `json:"max_tags"`
	AllowPrivate bool      `json:"allow_private"`
	Enabled      bool      `json:"enabled"`
	// CABundlePEM is the private CA bundle added to the system trust store
	// for this registry ("" = system trust store only).
	CABundlePEM     string       `json:"ca_bundle_pem"`
	CACertificates  []scm.CACert `json:"ca_certificates"`
	IntervalMinutes int          `json:"sync_interval_minutes"`
	SyncRequestedAt *time.Time   `json:"sync_requested_at"`
	LastSyncAt      *time.Time   `json:"last_sync_at"`
	LastStatus      string       `json:"last_status"`
	LastError       string       `json:"last_error"`
	Images          int          `json:"images"`
	WithSource      int          `json:"images_with_source"`
	CreatedAt       time.Time    `json:"created_at"`
}

const registrySelect = `SELECT c.id, c.name, c.base_url, c.repositories, c.auth_type, c.username, c.max_tags, c.allow_private, c.enabled,
	c.ca_bundle_pem, c.sync_interval_minutes, c.sync_requested_at, c.last_sync_at, c.last_status, c.last_error,
	(SELECT count(*) FROM registry_images i WHERE i.registry_id = c.id),
	(SELECT count(*) FROM registry_images i WHERE i.registry_id = c.id AND i.source_url <> ''), c.created_at
	FROM registry_connections c`

func scanRegistry(r pgx.Row) (Registry, error) {
	var c Registry
	err := r.Scan(&c.ID, &c.Name, &c.BaseURL, &c.Repositories, &c.AuthType, &c.Username, &c.MaxTags, &c.AllowPrivate, &c.Enabled,
		&c.CABundlePEM, &c.IntervalMinutes, &c.SyncRequestedAt, &c.LastSyncAt, &c.LastStatus, &c.LastError, &c.Images, &c.WithSource, &c.CreatedAt)
	_, c.CACertificates, _ = scm.ParseCABundle(c.CABundlePEM, time.Now())
	if c.CACertificates == nil {
		c.CACertificates = []scm.CACert{}
	}
	return c, err
}

func (s *Service) listRegistries(w http.ResponseWriter, r *http.Request) {
	p, err := s.reader(r)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	rows, err := s.DB.Query(r.Context(), registrySelect+` WHERE c.organization_id = $1 ORDER BY lower(c.name)`, p.OrganizationID)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	items, err := pgx.CollectRows(rows, func(r pgx.CollectableRow) (Registry, error) { return scanRegistry(r) })
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if items == nil {
		items = []Registry{}
	}
	if !p.HasOrgWide(authz.PermSettingsManage) {
		for i := range items {
			items[i].Username, items[i].LastError = "", ""
		}
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"items": items, "can_manage": p.HasOrgWide(authz.PermSettingsManage)})
}

type registryInput struct {
	Name            string   `json:"name"`
	BaseURL         string   `json:"base_url"`
	Repositories    []string `json:"repositories"`
	AuthType        string   `json:"auth_type"`
	Username        string   `json:"username"`
	Secret          string   `json:"secret"`
	MaxTags         int      `json:"max_tags"`
	AllowPrivate    bool     `json:"allow_private"`
	Enabled         *bool    `json:"enabled"`
	IntervalMinutes int      `json:"sync_interval_minutes"`
	// CABundlePEM: private CA bundle (PEM certificates). On update, absent
	// keeps the stored bundle and "" removes it.
	CABundlePEM *string `json:"ca_bundle_pem"`
}

func (in *registryInput) caBundle() string {
	if in.CABundlePEM == nil {
		return ""
	}
	return *in.CABundlePEM
}

func (s *Service) validateRegistry(in *registryInput, update, hadSecret bool) error {
	in.Name, in.Username = strings.TrimSpace(in.Name), strings.TrimSpace(in.Username)
	in.BaseURL = strings.TrimRight(strings.TrimSpace(in.BaseURL), "/")
	if in.Name == "" || len(in.Name) > 120 {
		return httpx.BadRequest("name is required (at most 120 characters)")
	}
	if _, err := (scm.NetPolicy{AllowPrivate: in.AllowPrivate, AllowHTTP: s.AllowHTTP, OrgChosen: true}).ValidateBaseURL(in.BaseURL); err != nil {
		return httpx.BadRequest("base_url: " + err.Error())
	}
	if in.CABundlePEM != nil {
		b := strings.TrimSpace(*in.CABundlePEM)
		if _, _, err := scm.ParseCABundle(b, time.Now()); err != nil {
			return httpx.BadRequest("ca_bundle_pem: " + err.Error()).WithDiag(scm.DiagCABundleInvalid)
		}
		in.CABundlePEM = &b
	}
	var repos []string
	for _, x := range in.Repositories {
		x = strings.Trim(strings.TrimSpace(x), "/")
		if x == "" || containsStr(repos, x) {
			continue
		}
		if !ValidRepositoryName(x) {
			return httpx.BadRequest("repository " + strconv.Quote(x) + " is not a valid repository name (namespace/name, lower case)")
		}
		repos = append(repos, x)
	}
	if len(repos) == 0 || len(repos) > 100 {
		return httpx.BadRequest("repositories: between 1 and 100 repository names")
	}
	in.Repositories = repos
	if in.AuthType == "" {
		in.AuthType = "none"
	}
	switch in.AuthType {
	case "none":
		in.Username, in.Secret = "", ""
	case "basic":
		if in.Username == "" {
			return httpx.BadRequest("username is required for basic authentication")
		}
		fallthrough
	case "bearer":
		if in.Secret == "" && (!update || !hadSecret) {
			return httpx.BadRequest("secret (password or token) is required")
		}
	default:
		return httpx.BadRequest("auth_type must be none, basic or bearer")
	}
	if len(in.Secret) > 8192 || len(in.Username) > 200 {
		return httpx.BadRequest("credential too long")
	}
	if in.MaxTags == 0 {
		in.MaxTags = 50
	}
	if in.MaxTags < 1 || in.MaxTags > 500 {
		return httpx.BadRequest("max_tags must be between 1 and 500")
	}
	if in.IntervalMinutes == 0 {
		in.IntervalMinutes = 360
	}
	if in.IntervalMinutes < 15 || in.IntervalMinutes > 10080 {
		return httpx.BadRequest("sync_interval_minutes must be between 15 and 10080")
	}
	return nil
}

func containsStr(l []string, s string) bool {
	for _, x := range l {
		if x == s {
			return true
		}
	}
	return false
}

func (s *Service) createRegistry(w http.ResponseWriter, r *http.Request) {
	p, err := s.manage(r)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	var in registryInput
	if err := httpx.DecodeJSON(w, r, &in); err != nil {
		s.fail(w, r, err)
		return
	}
	if err := s.validateRegistry(&in, false, false); err != nil {
		s.fail(w, r, err)
		return
	}
	id := uuid.Must(uuid.NewV7())
	enabled := in.Enabled == nil || *in.Enabled
	err = db.InTx(r.Context(), s.DB, func(tx pgx.Tx) error {
		var sid *uuid.UUID
		if in.AuthType != "none" {
			x, err := s.Secrets.Create(r.Context(), tx, p.OrganizationID, secrets.KindIntegration, "registry: "+in.Name, []byte(in.Secret), &p.UserID)
			if err != nil {
				return err
			}
			sid = &x
		}
		if _, err := tx.Exec(r.Context(), `INSERT INTO registry_connections (id, organization_id, name, base_url, repositories, auth_type, username,
			secret_id, max_tags, allow_private, enabled, sync_interval_minutes, sync_requested_at, created_by, ca_bundle_pem)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, now(), $13, $14)`,
			id, p.OrganizationID, in.Name, in.BaseURL, in.Repositories, in.AuthType, in.Username, sid, in.MaxTags, in.AllowPrivate, enabled,
			in.IntervalMinutes, p.UserID, in.caBundle()); err != nil {
			return err
		}
		return audit.Write(r.Context(), tx, audit.Entry{OrganizationID: p.OrganizationID, ActorID: &p.UserID, ActorEmail: p.Email,
			Action: "registry_connection.create", TargetType: "registry_connection", TargetID: id.String(),
			Metadata: map[string]any{"name": in.Name, "base_url": in.BaseURL, "repositories": in.Repositories, "auth_type": in.AuthType}})
	})
	if err != nil {
		s.fail(w, r, err)
		return
	}
	c, err := scanRegistry(s.DB.QueryRow(r.Context(), registrySelect+` WHERE c.id = $1`, id))
	if err != nil {
		s.fail(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusCreated, c)
}

func (s *Service) updateRegistry(w http.ResponseWriter, r *http.Request) {
	p, err := s.manage(r)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	id, err := pathUUID(r)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	var in registryInput
	if err := httpx.DecodeJSON(w, r, &in); err != nil {
		s.fail(w, r, err)
		return
	}
	var sid *uuid.UUID
	if err := s.DB.QueryRow(r.Context(), `SELECT secret_id FROM registry_connections WHERE organization_id = $1 AND id = $2`,
		p.OrganizationID, id).Scan(&sid); err != nil {
		s.fail(w, r, err)
		return
	}
	if err := s.validateRegistry(&in, true, sid != nil); err != nil {
		s.fail(w, r, err)
		return
	}
	enabled := in.Enabled == nil || *in.Enabled
	err = db.InTx(r.Context(), s.DB, func(tx pgx.Tx) error {
		newSID := sid
		switch {
		case in.AuthType == "none" && sid != nil:
			newSID = nil
		case in.Secret != "" && sid != nil:
			if err := s.Secrets.Update(r.Context(), tx, p.OrganizationID, *sid, secrets.KindIntegration, []byte(in.Secret)); err != nil {
				return err
			}
		case in.Secret != "":
			x, err := s.Secrets.Create(r.Context(), tx, p.OrganizationID, secrets.KindIntegration, "registry: "+in.Name, []byte(in.Secret), &p.UserID)
			if err != nil {
				return err
			}
			newSID = &x
		}
		if _, err := tx.Exec(r.Context(), `UPDATE registry_connections SET name = $3, base_url = $4, repositories = $5, auth_type = $6, username = $7,
			secret_id = $8, max_tags = $9, allow_private = $10, enabled = $11, sync_interval_minutes = $12,
			ca_bundle_pem = CASE WHEN $13 THEN $14 ELSE ca_bundle_pem END, updated_at = now()
			WHERE organization_id = $1 AND id = $2`, p.OrganizationID, id, in.Name, in.BaseURL, in.Repositories, in.AuthType, in.Username, newSID,
			in.MaxTags, in.AllowPrivate, enabled, in.IntervalMinutes, in.CABundlePEM != nil, in.caBundle()); err != nil {
			return err
		}
		if newSID == nil && sid != nil {
			if err := s.Secrets.Delete(r.Context(), tx, p.OrganizationID, *sid); err != nil {
				return err
			}
		}
		return audit.Write(r.Context(), tx, audit.Entry{OrganizationID: p.OrganizationID, ActorID: &p.UserID, ActorEmail: p.Email,
			Action: "registry_connection.update", TargetType: "registry_connection", TargetID: id.String(),
			Metadata: map[string]any{"name": in.Name, "base_url": in.BaseURL, "repositories": in.Repositories, "auth_type": in.AuthType,
				"credential_replaced": in.Secret != "", "enabled": enabled}})
	})
	if err != nil {
		s.fail(w, r, err)
		return
	}
	c, err := scanRegistry(s.DB.QueryRow(r.Context(), registrySelect+` WHERE c.id = $1`, id))
	if err != nil {
		s.fail(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, c)
}

func (s *Service) deleteRegistry(w http.ResponseWriter, r *http.Request) {
	s.deleteConn(w, r, "registry_connections", "registry_connection")
}

func (s *Service) registryImages(w http.ResponseWriter, r *http.Request) {
	p, err := s.reader(r)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	id, err := pathUUID(r)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if !s.exists(r.Context(), "registry_connections", p.OrganizationID, id) {
		s.fail(w, r, httpx.ErrNotFound)
		return
	}
	rows, err := s.DB.Query(r.Context(), `SELECT i.registry, i.repository, i.tag, i.digest, i.media_type, i.source_url, i.revision, i.created, i.last_seen_at,
		EXISTS (SELECT 1 FROM runtime_workload_images wi WHERE wi.organization_id = i.organization_id AND wi.digest = i.digest)
		FROM registry_images i WHERE i.organization_id = $1 AND i.registry_id = $2 ORDER BY i.repository, i.last_seen_at DESC, i.tag LIMIT 2000`,
		p.OrganizationID, id)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	type img struct {
		Registry   string    `json:"registry"`
		Repository string    `json:"repository"`
		Tag        string    `json:"tag"`
		Digest     string    `json:"digest"`
		MediaType  string    `json:"media_type"`
		SourceURL  string    `json:"source_url"`
		Revision   string    `json:"revision"`
		Created    string    `json:"created"`
		LastSeenAt time.Time `json:"last_seen_at"`
		Running    bool      `json:"running"`
	}
	items, err := pgx.CollectRows(rows, func(r pgx.CollectableRow) (img, error) {
		var x img
		err := r.Scan(&x.Registry, &x.Repository, &x.Tag, &x.Digest, &x.MediaType, &x.SourceURL, &x.Revision, &x.Created, &x.LastSeenAt, &x.Running)
		return x, err
	})
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if items == nil {
		items = []img{}
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"items": items})
}

// --- workloads -------------------------------------------------------------------

// findingJoin selects the open findings deployed through a deployment row d.
const findingJoin = `f.organization_id = d.organization_id AND f.status IN ('open', 'in_progress', 'needs_review')
	AND ((d.scan_target_id IS NOT NULL AND f.scan_target_id = d.scan_target_id)
	     OR (f.scan_target_id IS NULL AND f.repository_id = d.repository_id AND NOT (f.category = ANY($NOTIN))))`

func notInImageSQL(n int) string {
	return strings.ReplaceAll(findingJoin, "$NOTIN", "$"+strconv.Itoa(n))
}

// WorkloadView is a workload with its images and finding counts.
type WorkloadView struct {
	ID              uuid.UUID         `json:"id"`
	ClusterID       uuid.UUID         `json:"cluster_id"`
	Cluster         string            `json:"cluster"`
	Namespace       string            `json:"namespace"`
	Kind            string            `json:"kind"`
	Name            string            `json:"name"`
	Labels          map[string]string `json:"labels"`
	Replicas        *int              `json:"replicas"`
	Ready           *int              `json:"ready_replicas"`
	Privileged      bool              `json:"privileged"`
	HostNetwork     bool              `json:"host_network"`
	HostPID         bool              `json:"host_pid"`
	RunAsRoot       string            `json:"run_as_root"`
	InternetExposed bool              `json:"internet_exposed"`
	Exposure        []Exposure        `json:"exposure"`
	NetworkPolicies []string          `json:"network_policies"`
	ApplicationID   *uuid.UUID        `json:"application_id"`
	Application     *string           `json:"application_name"`
	AppBasis        string            `json:"application_basis"`
	Images          []ImageView       `json:"images"`
	Findings        FindingCounts     `json:"findings"`
	Alerts          int               `json:"runtime_alerts"`
	LastSeenAt      time.Time         `json:"last_seen_at"`
}

// ImageView is a workload image with its links.
type ImageView struct {
	Container string     `json:"container"`
	Init      bool       `json:"init"`
	Image     string     `json:"image"`
	Digest    string     `json:"digest"`
	Links     []LinkView `json:"links"`
}

// LinkView is how an image is linked to a scan target or repository.
type LinkView struct {
	Basis        string     `json:"basis"`
	Detail       string     `json:"detail"`
	TargetID     *uuid.UUID `json:"scan_target_id"`
	TargetName   *string    `json:"scan_target_name"`
	RepositoryID *uuid.UUID `json:"repository_id"`
	Repository   *string    `json:"repository_name"`
}

// FindingCounts are the open findings deployed in a workload.
type FindingCounts struct {
	Total    int `json:"total"`
	Critical int `json:"critical"`
	High     int `json:"high"`
}

const workloadSelect = `SELECT w.id, w.cluster_id, c.name, w.namespace, w.kind, w.name, w.labels, w.replicas, w.ready_replicas, w.privileged,
	w.host_network, w.host_pid, w.run_as_root, w.internet_exposed, w.exposure, w.network_policies, w.application_id, a.name, w.application_basis,
	w.last_seen_at,
	COALESCE(fc.total, 0), COALESCE(fc.critical, 0), COALESCE(fc.high, 0),
	(SELECT count(*) FROM runtime_alert_matches am WHERE am.workload_id = w.id)
	FROM runtime_workloads w JOIN runtime_clusters c ON c.id = w.cluster_id LEFT JOIN applications a ON a.id = w.application_id
	LEFT JOIN LATERAL (SELECT count(DISTINCT f.id) AS total, count(DISTINCT f.id) FILTER (WHERE f.severity = 'critical') AS critical,
	       count(DISTINCT f.id) FILTER (WHERE f.severity = 'high') AS high
	       FROM runtime_deployments d JOIN findings f ON `

func scanWorkload(r pgx.Row) (WorkloadView, error) {
	var v WorkloadView
	var labels, exp []byte
	err := r.Scan(&v.ID, &v.ClusterID, &v.Cluster, &v.Namespace, &v.Kind, &v.Name, &labels, &v.Replicas, &v.Ready, &v.Privileged, &v.HostNetwork,
		&v.HostPID, &v.RunAsRoot, &v.InternetExposed, &exp, &v.NetworkPolicies, &v.ApplicationID, &v.Application, &v.AppBasis, &v.LastSeenAt,
		&v.Findings.Total, &v.Findings.Critical, &v.Findings.High, &v.Alerts)
	_ = json.Unmarshal(labels, &v.Labels)
	_ = json.Unmarshal(exp, &v.Exposure)
	if v.Exposure == nil {
		v.Exposure = []Exposure{}
	}
	v.Images = []ImageView{}
	return v, err
}

func (s *Service) listWorkloads(w http.ResponseWriter, r *http.Request) {
	p, err := s.reader(r)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	q := r.URL.Query()
	args := []any{p.OrganizationID, notInImage}
	where := []string{"w.organization_id = $1"}
	add := func(cond string, v any) {
		args = append(args, v)
		where = append(where, strings.ReplaceAll(cond, "?", "$"+strconv.Itoa(len(args))))
	}
	if v := q.Get("cluster_id"); v != "" {
		id, err := uuid.Parse(v)
		if err != nil {
			s.fail(w, r, httpx.BadRequest("invalid cluster_id"))
			return
		}
		add("w.cluster_id = ?", id)
	}
	if v := q.Get("namespace"); v != "" {
		add("w.namespace = ?", v)
	}
	if v := q.Get("application_id"); v != "" {
		id, err := uuid.Parse(v)
		if err != nil {
			s.fail(w, r, httpx.BadRequest("invalid application_id"))
			return
		}
		add("w.application_id = ?", id)
	}
	switch q.Get("exposed") {
	case "":
	case "true":
		where = append(where, "w.internet_exposed")
	case "false":
		where = append(where, "NOT w.internet_exposed")
	default:
		s.fail(w, r, httpx.BadRequest("exposed must be true or false"))
		return
	}
	if q.Get("privileged") == "true" {
		where = append(where, "(w.privileged OR w.host_network OR w.host_pid)")
	}
	if q.Get("with_findings") == "true" {
		where = append(where, "COALESCE(fc.total, 0) > 0")
	}
	if v := strings.TrimSpace(q.Get("q")); v != "" {
		add(`(w.name ILIKE '%' || ? || '%' OR w.namespace ILIKE '%' || ? || '%'
			OR EXISTS (SELECT 1 FROM runtime_workload_images i WHERE i.workload_id = w.id AND i.image ILIKE '%' || ? || '%'))`, v)
	}
	// #nosec G202 -- where is built from constants and placeholders
	rows, err := s.DB.Query(r.Context(), workloadSelect+notInImageSQL(2)+` WHERE d.workload_id = w.id) fc ON true
		WHERE `+strings.Join(where, " AND ")+`
		ORDER BY w.internet_exposed DESC, COALESCE(fc.critical, 0) DESC, COALESCE(fc.total, 0) DESC, c.name, w.namespace, w.name LIMIT 1000`, args...)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	items, err := pgx.CollectRows(rows, func(r pgx.CollectableRow) (WorkloadView, error) { return scanWorkload(r) })
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if items == nil {
		items = []WorkloadView{}
	}
	if err := s.attachImages(r.Context(), items); err != nil {
		s.fail(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"items": items, "truncated": len(items) >= 1000})
}

func (s *Service) attachImages(ctx context.Context, items []WorkloadView) error {
	if len(items) == 0 {
		return nil
	}
	idx := map[uuid.UUID]int{}
	ids := make([]uuid.UUID, len(items))
	for i, it := range items {
		idx[it.ID], ids[i] = i, it.ID
	}
	rows, err := s.DB.Query(ctx, `SELECT i.id, i.workload_id, i.container, i.init, i.image, i.digest
		FROM runtime_workload_images i WHERE i.workload_id = ANY($1) ORDER BY i.init, i.container, i.digest`, ids)
	if err != nil {
		return err
	}
	imgIdx := map[uuid.UUID][2]int{}
	for rows.Next() {
		var id, wid uuid.UUID
		var iv ImageView
		if err := rows.Scan(&id, &wid, &iv.Container, &iv.Init, &iv.Image, &iv.Digest); err != nil {
			rows.Close()
			return err
		}
		iv.Links = []LinkView{}
		i := idx[wid]
		items[i].Images = append(items[i].Images, iv)
		imgIdx[id] = [2]int{i, len(items[i].Images) - 1}
	}
	rows.Close()
	rows, err = s.DB.Query(ctx, `SELECT d.image_id, d.basis, d.detail, d.scan_target_id, t.name, d.repository_id, COALESCE(NULLIF(r.display_name, ''), r.full_name)
		FROM runtime_deployments d LEFT JOIN scan_targets t ON t.id = d.scan_target_id LEFT JOIN repositories r ON r.id = d.repository_id
		WHERE d.workload_id = ANY($1)`, ids)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var imgID uuid.UUID
		var l LinkView
		if err := rows.Scan(&imgID, &l.Basis, &l.Detail, &l.TargetID, &l.TargetName, &l.RepositoryID, &l.Repository); err != nil {
			return err
		}
		if p, ok := imgIdx[imgID]; ok {
			items[p[0]].Images[p[1]].Links = append(items[p[0]].Images[p[1]].Links, l)
		}
	}
	return rows.Err()
}

func (s *Service) getWorkload(w http.ResponseWriter, r *http.Request) {
	p, err := s.reader(r)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	id, err := pathUUID(r)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	v, err := scanWorkload(s.DB.QueryRow(r.Context(), workloadSelect+notInImageSQL(3)+` WHERE d.workload_id = w.id) fc ON true
		WHERE w.organization_id = $1 AND w.id = $2`, p.OrganizationID, id, notInImage))
	if err != nil {
		s.fail(w, r, err)
		return
	}
	items := []WorkloadView{v}
	if err := s.attachImages(r.Context(), items); err != nil {
		s.fail(w, r, err)
		return
	}
	rows, err := s.DB.Query(r.Context(), `SELECT f.id, f.title, f.severity, f.file_path, m.basis FROM runtime_alert_matches m
		JOIN findings f ON f.id = m.finding_id WHERE m.workload_id = $1 ORDER BY f.last_seen_at DESC LIMIT 50`, id)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	alerts, err := pgx.CollectRows(rows, func(r pgx.CollectableRow) (Alert, error) {
		var a Alert
		var fid uuid.UUID
		err := r.Scan(&fid, &a.Title, &a.Severity, &a.Location, &a.Basis)
		a.FindingID = fid.String()
		return a, err
	})
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if alerts == nil {
		alerts = []Alert{}
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"workload": items[0], "alerts": alerts})
}

func (s *Service) summary(w http.ResponseWriter, r *http.Request) {
	p, err := s.reader(r)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	var out struct {
		Clusters        int `json:"clusters"`
		Registries      int `json:"registries"`
		Workloads       int `json:"workloads"`
		Exposed         int `json:"internet_exposed_workloads"`
		Privileged      int `json:"privileged_workloads"`
		Images          int `json:"running_images"`
		LinkedImages    int `json:"linked_images"`
		Deployed        int `json:"deployed_findings"`
		ExposedFindings int `json:"exposed_findings"`
		NotDeployed     int `json:"not_deployed_findings"`
		Alerts          int `json:"matched_runtime_alerts"`
	}
	err = s.DB.QueryRow(r.Context(), `SELECT
		(SELECT count(*) FROM runtime_clusters WHERE organization_id = $1),
		(SELECT count(*) FROM registry_connections WHERE organization_id = $1),
		(SELECT count(*) FROM runtime_workloads WHERE organization_id = $1),
		(SELECT count(*) FROM runtime_workloads WHERE organization_id = $1 AND internet_exposed),
		(SELECT count(*) FROM runtime_workloads WHERE organization_id = $1 AND (privileged OR host_network OR host_pid)),
		(SELECT count(DISTINCT COALESCE(NULLIF(digest, ''), image)) FROM runtime_workload_images WHERE organization_id = $1),
		(SELECT count(DISTINCT image_id) FROM runtime_deployments WHERE organization_id = $1),
		(SELECT count(*) FROM findings WHERE organization_id = $1 AND runtime_status = 'deployed' AND status IN ('open', 'in_progress', 'needs_review')),
		(SELECT count(*) FROM findings WHERE organization_id = $1 AND runtime_exposed AND status IN ('open', 'in_progress', 'needs_review')),
		(SELECT count(*) FROM findings WHERE organization_id = $1 AND runtime_status = 'not_deployed' AND status IN ('open', 'in_progress', 'needs_review')),
		(SELECT count(DISTINCT finding_id) FROM runtime_alert_matches WHERE organization_id = $1)`, p.OrganizationID).
		Scan(&out.Clusters, &out.Registries, &out.Workloads, &out.Exposed, &out.Privileged, &out.Images, &out.LinkedImages, &out.Deployed,
			&out.ExposedFindings, &out.NotDeployed, &out.Alerts)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, out)
}

// --- application mappings ---------------------------------------------------------

// MappingView is a stored mapping.
type MappingView struct {
	ID            uuid.UUID  `json:"id"`
	ClusterID     *uuid.UUID `json:"cluster_id"`
	Cluster       *string    `json:"cluster_name"`
	Namespace     string     `json:"namespace"`
	LabelKey      string     `json:"label_key"`
	LabelValue    string     `json:"label_value"`
	ApplicationID uuid.UUID  `json:"application_id"`
	Application   string     `json:"application_name"`
	// Workloads mapped to the application (by any mapping).
	Workloads int       `json:"application_workloads"`
	CreatedAt time.Time `json:"created_at"`
}

const mappingSelect = `SELECT m.id, m.cluster_id, c.name, m.namespace, m.label_key, m.label_value, m.application_id, a.name,
	(SELECT count(*) FROM runtime_workloads w WHERE w.application_id = m.application_id),
	m.created_at
	FROM runtime_app_mappings m JOIN applications a ON a.id = m.application_id LEFT JOIN runtime_clusters c ON c.id = m.cluster_id`

func (s *Service) listMappings(w http.ResponseWriter, r *http.Request) {
	p, err := s.reader(r)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	rows, err := s.DB.Query(r.Context(), mappingSelect+` WHERE m.organization_id = $1 ORDER BY a.name, m.namespace, m.label_key`, p.OrganizationID)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	items, err := pgx.CollectRows(rows, func(r pgx.CollectableRow) (MappingView, error) {
		var m MappingView
		err := r.Scan(&m.ID, &m.ClusterID, &m.Cluster, &m.Namespace, &m.LabelKey, &m.LabelValue, &m.ApplicationID, &m.Application, &m.Workloads, &m.CreatedAt)
		return m, err
	})
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if items == nil {
		items = []MappingView{}
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"items": items})
}

var labelKeyRe = regexp.MustCompile(`^([a-z0-9]([-a-z0-9.]{0,251}[a-z0-9])?/)?[A-Za-z0-9]([-A-Za-z0-9_.]{0,61}[A-Za-z0-9])?$`)
var labelValueRe = regexp.MustCompile(`^([A-Za-z0-9]([-A-Za-z0-9_.]{0,61}[A-Za-z0-9])?)?$`)

func (s *Service) createMapping(w http.ResponseWriter, r *http.Request) {
	p, err := s.manage(r)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	var in struct {
		ClusterID     *uuid.UUID `json:"cluster_id"`
		Namespace     string     `json:"namespace"`
		LabelKey      string     `json:"label_key"`
		LabelValue    string     `json:"label_value"`
		ApplicationID uuid.UUID  `json:"application_id"`
	}
	if err := httpx.DecodeJSON(w, r, &in); err != nil {
		s.fail(w, r, err)
		return
	}
	in.Namespace, in.LabelKey, in.LabelValue = strings.TrimSpace(in.Namespace), strings.TrimSpace(in.LabelKey), strings.TrimSpace(in.LabelValue)
	switch {
	case in.Namespace == "" && in.LabelKey == "":
		s.fail(w, r, httpx.BadRequest("a namespace, a label key or both are required"))
		return
	case in.Namespace != "" && !dns1123Label.MatchString(in.Namespace):
		s.fail(w, r, httpx.BadRequest("namespace is not a valid namespace name"))
		return
	case in.LabelKey != "" && !labelKeyRe.MatchString(in.LabelKey):
		s.fail(w, r, httpx.BadRequest("label_key is not a valid label key"))
		return
	case in.LabelKey == "" && in.LabelValue != "":
		s.fail(w, r, httpx.BadRequest("label_value needs a label_key"))
		return
	case !labelValueRe.MatchString(in.LabelValue):
		s.fail(w, r, httpx.BadRequest("label_value is not a valid label value"))
		return
	}
	var ok bool
	if err := s.DB.QueryRow(r.Context(), `SELECT EXISTS (SELECT 1 FROM applications WHERE organization_id = $1 AND id = $2 AND archived_at IS NULL)
		AND ($3::uuid IS NULL OR EXISTS (SELECT 1 FROM runtime_clusters WHERE organization_id = $1 AND id = $3))`,
		p.OrganizationID, in.ApplicationID, in.ClusterID).Scan(&ok); err != nil {
		s.fail(w, r, err)
		return
	}
	if !ok {
		s.fail(w, r, httpx.BadRequest("unknown application or cluster"))
		return
	}
	id := uuid.Must(uuid.NewV7())
	err = db.InTx(r.Context(), s.DB, func(tx pgx.Tx) error {
		if _, err := tx.Exec(r.Context(), `INSERT INTO runtime_app_mappings (id, organization_id, cluster_id, namespace, label_key, label_value,
			application_id, created_by) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`,
			id, p.OrganizationID, in.ClusterID, in.Namespace, in.LabelKey, in.LabelValue, in.ApplicationID, p.UserID); err != nil {
			return err
		}
		return audit.Write(r.Context(), tx, audit.Entry{OrganizationID: p.OrganizationID, ActorID: &p.UserID, ActorEmail: p.Email,
			Action: "runtime_mapping.create", TargetType: "runtime_mapping", TargetID: id.String(),
			Metadata: map[string]any{"namespace": in.Namespace, "label_key": in.LabelKey, "label_value": in.LabelValue, "application_id": in.ApplicationID}})
	})
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if err := Link(r.Context(), s.DB, p.OrganizationID); err != nil {
		s.Log.Warn("runtime linking failed", "err", err)
	}
	var m MappingView
	if err := s.DB.QueryRow(r.Context(), mappingSelect+` WHERE m.id = $1`, id).Scan(&m.ID, &m.ClusterID, &m.Cluster, &m.Namespace, &m.LabelKey,
		&m.LabelValue, &m.ApplicationID, &m.Application, &m.Workloads, &m.CreatedAt); err != nil {
		s.fail(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusCreated, m)
}

func (s *Service) deleteMapping(w http.ResponseWriter, r *http.Request) {
	p, err := s.manage(r)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	id, err := pathUUID(r)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	err = db.InTx(r.Context(), s.DB, func(tx pgx.Tx) error {
		tag, err := tx.Exec(r.Context(), `DELETE FROM runtime_app_mappings WHERE organization_id = $1 AND id = $2`, p.OrganizationID, id)
		if err != nil {
			return err
		}
		if tag.RowsAffected() == 0 {
			return pgx.ErrNoRows
		}
		return audit.Write(r.Context(), tx, audit.Entry{OrganizationID: p.OrganizationID, ActorID: &p.UserID, ActorEmail: p.Email,
			Action: "runtime_mapping.delete", TargetType: "runtime_mapping", TargetID: id.String()})
	})
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if err := Link(r.Context(), s.DB, p.OrganizationID); err != nil {
		s.Log.Warn("runtime linking failed", "err", err)
	}
	w.WriteHeader(http.StatusNoContent)
}

// --- finding drawer ----------------------------------------------------------------

// findingRuntime returns where a finding is deployed (the evidence the
// risk factors use), readable by whoever can read the finding.
func (s *Service) findingRuntime(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	p := s.Principal(ctx)
	id, err := pathUUID(r)
	if err != nil || p == nil {
		s.fail(w, r, pgx.ErrNoRows)
		return
	}
	var repo uuid.UUID
	var status string
	var exposed, priv, alert bool
	var raw []byte
	if err := s.DB.QueryRow(ctx, `SELECT repository_id, runtime_status, runtime_exposed, runtime_privileged, runtime_alert, runtime_context
		FROM findings WHERE organization_id = $1 AND id = $2`, p.OrganizationID, id).Scan(&repo, &status, &exposed, &priv, &alert, &raw); err != nil {
		s.fail(w, r, err)
		return
	}
	if ok, _ := s.Authz.Can(ctx, p, authz.PermFindingsRead, authz.Scope{Type: authz.ScopeRepository, ID: repo}); !ok {
		s.fail(w, r, pgx.ErrNoRows)
		return
	}
	var clusters int
	_ = s.DB.QueryRow(ctx, `SELECT count(*) FROM runtime_clusters WHERE organization_id = $1`, p.OrganizationID).Scan(&clusters)
	ctxJSON := json.RawMessage("null")
	if len(raw) > 0 {
		ctxJSON = raw
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"status": status, "internet_exposed": exposed, "privileged": priv, "runtime_alert": alert,
		"context": ctxJSON, "clusters_connected": clusters})
}
