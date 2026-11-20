package runtimectx

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"pathos/internal/authz"
	"pathos/internal/platform/logging"
	"pathos/internal/scm"
	"pathos/internal/secrets"
)

// Service serves the runtime API and runs synchronisations (jobs role).
type Service struct {
	DB        *pgxpool.Pool
	Authz     *authz.Authorizer
	Secrets   *secrets.Store
	Log       *slog.Logger
	Principal func(context.Context) *authz.Principal
	// AllowHTTP accepts http:// registry URLs (development only,
	// PATHOS_SCM_ALLOW_HTTP).
	AllowHTTP bool
	// NewHTTP builds the HTTP client of a connection. The default applies
	// the outbound network policy (no loopback, link-local or metadata
	// addresses; private ranges only with allow_private); tests override it.
	NewHTTP func(allowPrivate bool, tlsCfg *tls.Config) *http.Client
	// RegistryInterval spaces registry requests (default 200 ms).
	RegistryInterval time.Duration
}

func (s *Service) client(allowPrivate bool, tlsCfg *tls.Config) *http.Client {
	if s.NewHTTP != nil {
		return s.NewHTTP(allowPrivate, tlsCfg)
	}
	c := scm.NetPolicy{AllowPrivate: allowPrivate, AllowHTTP: s.AllowHTTP}.Client()
	if tr, ok := c.Transport.(*http.Transport); ok && tlsCfg != nil {
		tr = tr.Clone()
		tr.TLSClientConfig = tlsCfg
		c.Transport = tr
	}
	return c
}

// registryTLS is the TLS configuration of a registry with a private CA
// bundle: the system trust store plus the bundle, verification on, TLS 1.2
// minimum (nil without a bundle: the default client, also TLS 1.2+).
func registryTLS(bundle string) (*tls.Config, error) {
	pool, err := scm.CAPool(bundle)
	if err != nil || pool == nil {
		return nil, err
	}
	return &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}, nil
}

const (
	syncTimeout  = 10 * time.Minute
	staleRunning = 30 * time.Minute
)

// SyncStats is stored with every run.
type SyncStats struct {
	Namespaces      int      `json:"namespaces,omitempty"`
	Workloads       int      `json:"workloads,omitempty"`
	Images          int      `json:"images,omitempty"`
	Services        int      `json:"services,omitempty"`
	Ingresses       int      `json:"ingresses,omitempty"`
	NetworkPolicies int      `json:"network_policies,omitempty"`
	Exposed         int      `json:"internet_exposed,omitempty"`
	Privileged      int      `json:"privileged,omitempty"`
	Repositories    int      `json:"repositories,omitempty"`
	Tags            int      `json:"tags,omitempty"`
	Skipped         int      `json:"skipped,omitempty"`
	Warnings        []string `json:"warnings,omitempty"`
}

func (st *SyncStats) warn(w string) {
	if len(st.Warnings) < 20 {
		st.Warnings = append(st.Warnings, truncate(logging.RedactString(w), 300))
	}
}

func truncate(s string, n int) string {
	if len(s) > n {
		return s[:n]
	}
	return s
}

// claim marks a connection as running unless another replica runs it.
func (s *Service) claim(ctx context.Context, table string, id uuid.UUID) (bool, error) {
	// table is one of two constants.
	tag, err := s.DB.Exec(ctx, `UPDATE `+table+` SET last_status = 'running', sync_started_at = now(), sync_requested_at = NULL
		WHERE id = $1 AND enabled AND (last_status <> 'running' OR sync_started_at < now() - $2::interval)`, id, staleRunning.String())
	return err == nil && tag.RowsAffected() == 1, err
}

func (s *Service) finish(ctx context.Context, table string, id, runID uuid.UUID, st SyncStats, err error) (string, error) {
	status := "succeeded"
	msg := ""
	switch {
	case err != nil:
		status, msg = "failed", truncate(logging.RedactString(err.Error()), 2000)
	case len(st.Warnings) > 0:
		status = "partial"
	}
	raw, _ := json.Marshal(st)
	ctx = context.WithoutCancel(ctx)
	if _, uerr := s.DB.Exec(ctx, `UPDATE runtime_sync_runs SET finished_at = now(), status = $2, stats = $3, error = $4 WHERE id = $1`,
		runID, status, raw, msg); uerr != nil {
		return status, uerr
	}
	// table is one of two constants.
	_, uerr := s.DB.Exec(ctx, `UPDATE `+table+` SET last_status = $2, last_error = $3, last_sync_at = now() WHERE id = $1`, id, status, msg)
	return status, uerr
}

// clusterConn is a cluster with its credentials.
type clusterConn struct {
	OrgID, ID    uuid.UUID
	Name         string
	Namespaces   []string
	AllowPrivate bool
	Creds        Credentials
}

func (s *Service) loadCluster(ctx context.Context, id uuid.UUID) (clusterConn, error) {
	var c clusterConn
	var sid uuid.UUID
	var server, auth, ca string
	if err := s.DB.QueryRow(ctx, `SELECT organization_id, id, name, api_server, auth_type, secret_id, ca_cert, namespaces, allow_private
		FROM runtime_clusters WHERE id = $1`, id).Scan(&c.OrgID, &c.ID, &c.Name, &server, &auth, &sid, &ca, &c.Namespaces, &c.AllowPrivate); err != nil {
		return c, err
	}
	raw, err := s.Secrets.Reveal(ctx, s.DB, c.OrgID, sid, secrets.KindIntegration)
	if err != nil {
		return c, err
	}
	if err := json.Unmarshal(raw, &c.Creds); err != nil {
		return c, errors.New("stored cluster credentials are unreadable")
	}
	if auth == "token" {
		c.Creds.Server, c.Creds.CAData = server, ca
	}
	return c, nil
}

// SyncCluster reads a cluster's inventory, stores it and relinks the
// organization. It returns the run status.
func (s *Service) SyncCluster(ctx context.Context, id uuid.UUID) (string, error) {
	ok, err := s.claim(ctx, "runtime_clusters", id)
	if err != nil || !ok {
		return "", err
	}
	var orgID uuid.UUID
	if err := s.DB.QueryRow(ctx, `SELECT organization_id FROM runtime_clusters WHERE id = $1`, id).Scan(&orgID); err != nil {
		return "", err
	}
	runID := uuid.Must(uuid.NewV7())
	if _, err := s.DB.Exec(ctx, `INSERT INTO runtime_sync_runs (id, organization_id, cluster_id) VALUES ($1, $2, $3)`, runID, orgID, id); err != nil {
		return "", err
	}
	var st SyncStats
	err = s.syncCluster(ctx, id, &st)
	status, ferr := s.finish(ctx, "runtime_clusters", id, runID, st, err)
	if err == nil {
		if lerr := Link(ctx, s.DB, orgID); lerr != nil {
			s.Log.Warn("runtime linking failed", "err", lerr)
		}
	}
	return status, errors.Join(err, ferr)
}

func (s *Service) syncCluster(ctx context.Context, id uuid.UUID, st *SyncStats) error {
	c, err := s.loadCluster(ctx, id)
	if err != nil {
		return err
	}
	u, err := (scm.NetPolicy{AllowPrivate: c.AllowPrivate, AllowHTTP: false}).ValidateBaseURL(c.Creds.Server)
	if err != nil && s.NewHTTP == nil {
		return fmt.Errorf("API server URL: %w", err)
	}
	if u == nil {
		if u, err = url.Parse(c.Creds.Server); err != nil {
			return err
		}
	}
	tlsCfg, err := c.Creds.TLSConfig()
	if err != nil {
		return err
	}
	kc := &KubeClient{Base: u, HTTP: s.client(c.AllowPrivate, tlsCfg), Token: c.Creds.Token}
	cctx, cancel := context.WithTimeout(ctx, syncTimeout)
	defer cancel()
	raw, warnings, err := kc.Collect(cctx, c.Namespaces)
	if err != nil {
		return err
	}
	for _, w := range warnings {
		st.warn(w)
	}
	inv := Build(raw)
	st.Skipped = inv.Skipped
	return s.storeInventory(ctx, c, inv, len(warnings) > 0, st)
}

func (s *Service) storeInventory(ctx context.Context, c clusterConn, inv Inventory, partial bool, st *SyncStats) error {
	return pgx.BeginFunc(ctx, s.DB, func(tx pgx.Tx) error {
		var started time.Time
		if err := tx.QueryRow(ctx, `SELECT now()`).Scan(&started); err != nil {
			return err
		}
		b := &pgx.Batch{}
		for _, n := range inv.Namespaces {
			labels, _ := json.Marshal(n.Labels)
			b.Queue(`INSERT INTO runtime_namespaces (organization_id, cluster_id, name, labels) VALUES ($1, $2, $3, $4)
				ON CONFLICT (cluster_id, name) DO UPDATE SET labels = EXCLUDED.labels, last_seen_at = now()`, c.OrgID, c.ID, truncate(n.Name, 253), labels)
		}
		st.Namespaces = len(inv.Namespaces)
		ids := make([]uuid.UUID, len(inv.Workloads))
		for i, w := range inv.Workloads {
			labels, _ := json.Marshal(w.Labels)
			exp, _ := json.Marshal(w.Exposure)
			i := i
			b.Queue(`INSERT INTO runtime_workloads (id, organization_id, cluster_id, namespace, kind, name, labels, replicas, ready_replicas, pod_names,
				  privileged, host_network, host_pid, run_as_root, internet_exposed, exposure, network_policies)
				VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17)
				ON CONFLICT (cluster_id, namespace, kind, name) DO UPDATE SET labels = EXCLUDED.labels, replicas = EXCLUDED.replicas,
				  ready_replicas = EXCLUDED.ready_replicas, pod_names = EXCLUDED.pod_names, privileged = EXCLUDED.privileged,
				  host_network = EXCLUDED.host_network, host_pid = EXCLUDED.host_pid, run_as_root = EXCLUDED.run_as_root,
				  internet_exposed = EXCLUDED.internet_exposed, exposure = EXCLUDED.exposure, network_policies = EXCLUDED.network_policies,
				  last_seen_at = now()
				RETURNING id`, uuid.Must(uuid.NewV7()), c.OrgID, c.ID, w.Namespace, w.Kind, truncate(w.Name, 253), labels, w.Replicas, w.Ready,
				w.PodNames, w.Privileged, w.HostNetwork, w.HostPID, w.RunAsRoot, w.InternetExposed, exp, w.NetworkPolicies).
				QueryRow(func(r pgx.Row) error { return r.Scan(&ids[i]) })
			if w.InternetExposed {
				st.Exposed++
			}
			if w.Privileged || w.HostNetwork || w.HostPID {
				st.Privileged++
			}
		}
		st.Workloads = len(inv.Workloads)
		for _, n := range inv.Network {
			data, _ := json.Marshal(n.Data)
			if len(data) > 60000 {
				data = []byte(`{"truncated":true}`)
			}
			b.Queue(`INSERT INTO runtime_network_objects (organization_id, cluster_id, kind, namespace, name, data) VALUES ($1, $2, $3, $4, $5, $6)
				ON CONFLICT (cluster_id, kind, namespace, name) DO UPDATE SET data = EXCLUDED.data, last_seen_at = now()`,
				c.OrgID, c.ID, n.Kind, n.Namespace, truncate(n.Name, 253), data)
			switch n.Kind {
			case "Service":
				st.Services++
			case "Ingress":
				st.Ingresses++
			case "NetworkPolicy":
				st.NetworkPolicies++
			}
		}
		if err := tx.SendBatch(ctx, b).Close(); err != nil {
			return err
		}
		// Images are replaced (their digests change with every rollout).
		b = &pgx.Batch{}
		b.Queue(`DELETE FROM runtime_workload_images WHERE workload_id = ANY($1)`, ids)
		for i, w := range inv.Workloads {
			for _, im := range w.Images {
				b.Queue(`INSERT INTO runtime_workload_images (id, organization_id, workload_id, container, init, image, registry, repository, tag, digest)
					VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10) ON CONFLICT DO NOTHING`,
					uuid.Must(uuid.NewV7()), c.OrgID, ids[i], truncate(im.Container, 253), im.Init, truncate(im.Image, 1000),
					truncate(im.Ref.Registry, 255), truncate(im.Ref.Repository, 500), truncate(im.Ref.Tag, 128), im.Ref.Digest)
				st.Images++
			}
		}
		if !partial {
			// What the cluster no longer has (a partial read proves nothing).
			b.Queue(`DELETE FROM runtime_workloads WHERE cluster_id = $1 AND last_seen_at < $2`, c.ID, started)
			b.Queue(`DELETE FROM runtime_namespaces WHERE cluster_id = $1 AND last_seen_at < $2`, c.ID, started)
			b.Queue(`DELETE FROM runtime_network_objects WHERE cluster_id = $1 AND last_seen_at < $2`, c.ID, started)
		}
		return tx.SendBatch(ctx, b).Close()
	})
}

// --- registries ----------------------------------------------------------------

type registryConn struct {
	OrgID, ID    uuid.UUID
	BaseURL      string
	Repositories []string
	Auth, User   string
	Secret       string
	MaxTags      int
	AllowPrivate bool
	CABundle     string
}

func (s *Service) loadRegistry(ctx context.Context, id uuid.UUID) (registryConn, error) {
	var c registryConn
	var sid *uuid.UUID
	if err := s.DB.QueryRow(ctx, `SELECT organization_id, id, base_url, repositories, auth_type, username, secret_id, max_tags, allow_private, ca_bundle_pem
		FROM registry_connections WHERE id = $1`, id).Scan(&c.OrgID, &c.ID, &c.BaseURL, &c.Repositories, &c.Auth, &c.User, &sid, &c.MaxTags, &c.AllowPrivate,
		&c.CABundle); err != nil {
		return c, err
	}
	if sid != nil {
		raw, err := s.Secrets.Reveal(ctx, s.DB, c.OrgID, *sid, secrets.KindIntegration)
		if err != nil {
			return c, err
		}
		c.Secret = string(raw)
	}
	return c, nil
}

// RegistryHost is the host[:port] a registry URL names in image references.
func RegistryHost(base string) string {
	u, err := url.Parse(base)
	if err != nil {
		return ""
	}
	h := strings.ToLower(u.Host)
	switch h {
	case "registry-1.docker.io", "index.docker.io":
		return "docker.io"
	}
	return h
}

// SyncRegistry lists the configured repositories of a registry.
func (s *Service) SyncRegistry(ctx context.Context, id uuid.UUID) (string, error) {
	ok, err := s.claim(ctx, "registry_connections", id)
	if err != nil || !ok {
		return "", err
	}
	var orgID uuid.UUID
	if err := s.DB.QueryRow(ctx, `SELECT organization_id FROM registry_connections WHERE id = $1`, id).Scan(&orgID); err != nil {
		return "", err
	}
	runID := uuid.Must(uuid.NewV7())
	if _, err := s.DB.Exec(ctx, `INSERT INTO runtime_sync_runs (id, organization_id, registry_id) VALUES ($1, $2, $3)`, runID, orgID, id); err != nil {
		return "", err
	}
	var st SyncStats
	err = s.syncRegistry(ctx, id, &st)
	status, ferr := s.finish(ctx, "registry_connections", id, runID, st, err)
	if err == nil {
		if lerr := Link(ctx, s.DB, orgID); lerr != nil {
			s.Log.Warn("runtime linking failed", "err", lerr)
		}
	}
	return status, errors.Join(err, ferr)
}

func (s *Service) syncRegistry(ctx context.Context, id uuid.UUID, st *SyncStats) error {
	c, err := s.loadRegistry(ctx, id)
	if err != nil {
		return err
	}
	u, err := (scm.NetPolicy{AllowPrivate: c.AllowPrivate, AllowHTTP: s.AllowHTTP}).ValidateBaseURL(c.BaseURL)
	if err != nil && s.NewHTTP == nil {
		return fmt.Errorf("registry URL: %w", err)
	}
	if u == nil {
		if u, err = url.Parse(c.BaseURL); err != nil {
			return err
		}
	}
	tlsCfg, err := registryTLS(c.CABundle)
	if err != nil {
		return fmt.Errorf("ca_bundle_pem: %w", err)
	}
	hc := s.client(c.AllowPrivate, tlsCfg)
	// Blobs are often served from a CDN or object store: follow https
	// redirects (the dialer still applies the network policy).
	hc.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		if len(via) >= 3 || (req.URL.Scheme != "https" && req.URL.Host != via[0].URL.Host) {
			return http.ErrUseLastResponse
		}
		return nil
	}
	iv := s.RegistryInterval
	if iv == 0 {
		iv = 200 * time.Millisecond
	}
	rc := &RegistryClient{Base: u, HTTP: hc, Auth: c.Auth, Username: c.User, Secret: c.Secret, MinInterval: iv, MaxTags: c.MaxTags}
	cctx, cancel := context.WithTimeout(ctx, syncTimeout)
	defer cancel()
	host := RegistryHost(c.BaseURL)
	failedRepos := 0
	for _, repo := range c.Repositories {
		if cctx.Err() != nil {
			return cctx.Err()
		}
		tags, truncated, err := rc.Tags(cctx, repo, c.MaxTags)
		if err != nil {
			var re *RegistryError
			if errors.As(err, &re) && re.Status == http.StatusUnauthorized && len(c.Repositories) == 1 {
				return err
			}
			st.warn(repo + ": " + scm.WithCAHint(err).Error())
			failedRepos++
			continue
		}
		if truncated {
			st.warn(fmt.Sprintf("%s: only the first %d tags were read (max_tags)", repo, c.MaxTags))
		}
		st.Repositories++
		var imgs []RegistryImage
		for _, t := range tags {
			img, err := rc.Image(cctx, repo, t)
			if err != nil {
				st.warn(repo + ":" + t + ": " + err.Error())
				if img.Digest == "" {
					continue
				}
			}
			imgs = append(imgs, img)
		}
		err = pgx.BeginFunc(ctx, s.DB, func(tx pgx.Tx) error {
			var started time.Time
			if err := tx.QueryRow(ctx, `SELECT now()`).Scan(&started); err != nil {
				return err
			}
			b := &pgx.Batch{}
			for _, im := range imgs {
				b.Queue(`INSERT INTO registry_images (organization_id, registry_id, registry, repository, tag, digest, media_type, source_url, revision, created)
					VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
					ON CONFLICT (registry_id, repository, tag) DO UPDATE SET registry = EXCLUDED.registry, digest = EXCLUDED.digest,
					  media_type = EXCLUDED.media_type, source_url = EXCLUDED.source_url, revision = EXCLUDED.revision, created = EXCLUDED.created,
					  last_seen_at = now()`,
					c.OrgID, c.ID, truncate(host, 255), repo, im.Tag, im.Digest, truncate(im.MediaType, 200), im.SourceURL, im.Revision, im.Created)
				st.Tags++
			}
			if !truncated {
				b.Queue(`DELETE FROM registry_images WHERE registry_id = $1 AND repository = $2 AND last_seen_at < $3`, c.ID, repo, started)
			}
			return tx.SendBatch(ctx, b).Close()
		})
		if err != nil {
			return err
		}
	}
	if failedRepos == len(c.Repositories) {
		return errors.New("no repository could be listed: " + strings.Join(st.Warnings, "; "))
	}
	// Repositories removed from the configuration.
	_, err = s.DB.Exec(ctx, `DELETE FROM registry_images WHERE registry_id = $1 AND NOT (repository = ANY($2))`, c.ID, c.Repositories)
	return err
}

// --- background -----------------------------------------------------------------

// RunBackground synchronises due connections every minute and relinks
// every organization with a cluster hourly (new scans change the links).
func (s *Service) RunBackground(ctx context.Context) {
	t := time.NewTicker(time.Minute)
	defer t.Stop()
	lastLink := time.Time{}
	for {
		s.runDue(ctx)
		if time.Since(lastLink) > time.Hour {
			lastLink = time.Now()
			rows, err := s.DB.Query(ctx, `SELECT DISTINCT organization_id FROM runtime_clusters`)
			if err == nil {
				orgs, _ := pgx.CollectRows(rows, pgx.RowTo[uuid.UUID])
				for _, o := range orgs {
					if err := Link(ctx, s.DB, o); err != nil {
						s.Log.Warn("runtime linking failed", "err", err)
					}
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

func (s *Service) runDue(ctx context.Context) {
	for _, x := range []struct {
		table string
		sync  func(context.Context, uuid.UUID) (string, error)
	}{{"runtime_clusters", s.SyncCluster}, {"registry_connections", s.SyncRegistry}} {
		// x.table is one of two constants.
		rows, err := s.DB.Query(ctx, `SELECT id FROM `+x.table+` WHERE enabled
			AND (last_status <> 'running' OR sync_started_at < now() - $1::interval)
			AND (sync_requested_at IS NOT NULL OR last_sync_at IS NULL OR last_sync_at < now() - make_interval(mins => sync_interval_minutes))
			ORDER BY sync_requested_at NULLS LAST, last_sync_at NULLS FIRST LIMIT 20`, staleRunning.String())
		if err != nil {
			s.Log.Warn("runtime sync: listing connections failed", "err", err)
			continue
		}
		ids, err := pgx.CollectRows(rows, pgx.RowTo[uuid.UUID])
		if err != nil {
			continue
		}
		for _, id := range ids {
			if ctx.Err() != nil {
				return
			}
			status, err := x.sync(ctx, id)
			if err != nil {
				s.Log.Warn("runtime sync failed", "table", x.table, "id", id, "err", err, "error_code", "PTH-MON-1001")
			} else if status != "" {
				s.Log.Info("runtime sync finished", "table", x.table, "id", id, "status", status)
			}
		}
	}
}
