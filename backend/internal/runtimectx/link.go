package runtimectx

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"slices"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Linking runs after every synchronisation and hourly. It is set-based per
// organization: running images → image scan targets (digest or tag) and
// repositories (the target's repository, or the OCI source label of the
// registry image with the same digest); runtime alerts → workloads;
// workloads → applications; and finally each finding's runtime facts.

// recentInventory is how long a cluster's last successful inventory
// counts for "not deployed".
const recentInventory = "7 days"

// repoCategories are the finding categories of a repository's own code
// that ship in its images. Infrastructure code, pipelines and imported
// runtime or test results are not in the image.
var notInImage = []string{"iac", "cicd", "runtime", "dast", "mobile", "compliance", "api", "fuzz"}

type linkWorkload struct {
	ID        uuid.UUID
	ClusterID uuid.UUID
	Cluster   string
	W         Workload
	AppID     *uuid.UUID
	AppBasis  string
}

type linkImage struct {
	ID         uuid.UUID
	WorkloadID uuid.UUID
	Container  string
	Image      string
	Ref        ImageRef
}

type imageTarget struct {
	// Built: the target is marked as built from its repository's code.
	Built    bool
	ID       uuid.UUID
	RepoID   uuid.UUID
	Ref      ImageRef
	RefText  string
	Digests  []string
	Parsable bool
}

type deployRow struct {
	workload, image uuid.UUID
	target, repo    *uuid.UUID
	basis, detail   string
}

// Link recomputes the organization's runtime links and finding facts.
func Link(ctx context.Context, pool *pgxpool.Pool, orgID uuid.UUID) error {
	var clusters []string
	rows, err := pool.Query(ctx, `SELECT c.name FROM runtime_clusters c WHERE c.organization_id = $1 AND c.enabled
		AND EXISTS (SELECT 1 FROM runtime_sync_runs r WHERE r.cluster_id = c.id AND r.status IN ('succeeded', 'partial')
		            AND r.finished_at > now() - $2::interval) ORDER BY lower(c.name)`, orgID, recentInventory)
	if err != nil {
		return err
	}
	if clusters, err = pgx.CollectRows(rows, pgx.RowTo[string]); err != nil {
		return err
	}

	// Workloads and images.
	rows, err = pool.Query(ctx, `SELECT w.id, w.cluster_id, c.name, w.namespace, w.kind, w.name, w.labels, w.pod_names, w.privileged,
		w.host_network, w.host_pid, w.run_as_root, w.internet_exposed, w.exposure, w.application_id, w.application_basis
		FROM runtime_workloads w JOIN runtime_clusters c ON c.id = w.cluster_id WHERE w.organization_id = $1 AND c.enabled`, orgID)
	if err != nil {
		return err
	}
	workloads, err := pgx.CollectRows(rows, func(r pgx.CollectableRow) (linkWorkload, error) {
		var x linkWorkload
		var labels, exp []byte
		err := r.Scan(&x.ID, &x.ClusterID, &x.Cluster, &x.W.Namespace, &x.W.Kind, &x.W.Name, &labels, &x.W.PodNames, &x.W.Privileged,
			&x.W.HostNetwork, &x.W.HostPID, &x.W.RunAsRoot, &x.W.InternetExposed, &exp, &x.AppID, &x.AppBasis)
		_ = json.Unmarshal(labels, &x.W.Labels)
		_ = json.Unmarshal(exp, &x.W.Exposure)
		return x, err
	})
	if err != nil {
		return err
	}
	wByID := map[uuid.UUID]*linkWorkload{}
	for i := range workloads {
		wByID[workloads[i].ID] = &workloads[i]
	}
	rows, err = pool.Query(ctx, `SELECT i.id, i.workload_id, i.container, i.image, i.registry, i.repository, i.tag, i.digest
		FROM runtime_workload_images i WHERE i.organization_id = $1`, orgID)
	if err != nil {
		return err
	}
	all, err := pgx.CollectRows(rows, func(r pgx.CollectableRow) (linkImage, error) {
		var x linkImage
		err := r.Scan(&x.ID, &x.WorkloadID, &x.Container, &x.Image, &x.Ref.Registry, &x.Ref.Repository, &x.Ref.Tag, &x.Ref.Digest)
		return x, err
	})
	if err != nil {
		return err
	}
	// Images of disabled clusters do not count.
	var images []linkImage
	for _, im := range all {
		if _, ok := wByID[im.WorkloadID]; ok {
			images = append(images, im)
		}
	}

	// Application mappings.
	rows, err = pool.Query(ctx, `SELECT id::text, COALESCE(cluster_id::text, ''), namespace, label_key, label_value, application_id::text
		FROM runtime_app_mappings WHERE organization_id = $1`, orgID)
	if err != nil {
		return err
	}
	mappings, err := pgx.CollectRows(rows, func(r pgx.CollectableRow) (Mapping, error) {
		var m Mapping
		err := r.Scan(&m.ID, &m.ClusterID, &m.Namespace, &m.LabelKey, &m.LabelValue, &m.ApplicationID)
		return m, err
	})
	if err != nil {
		return err
	}

	// Image scan targets with the digests their scans resolved to.
	rows, err = pool.Query(ctx, `SELECT t.id, t.repository_id, t.reference,
		COALESCE((SELECT array_agg(d.digest ORDER BY d.digest) FROM image_scan_digests d WHERE d.scan_target_id = t.id), '{}'),
		COALESCE(t.config->>'built_from_repository', '') = 'true'
		FROM scan_targets t JOIN repositories r ON r.id = t.repository_id
		WHERE t.organization_id = $1 AND t.kind = 'image' AND r.archived_at IS NULL`, orgID)
	if err != nil {
		return err
	}
	targets, err := pgx.CollectRows(rows, func(r pgx.CollectableRow) (imageTarget, error) {
		var t imageTarget
		err := r.Scan(&t.ID, &t.RepoID, &t.RefText, &t.Digests, &t.Built)
		t.Ref, t.Parsable = ParseImageRef(t.RefText)
		return t, err
	})
	if err != nil {
		return err
	}

	// Repositories by normalised URL, and registry images with a source label.
	rows, err = pool.Query(ctx, `SELECT id, url, clone_url FROM repositories WHERE organization_id = $1 AND archived_at IS NULL`, orgID)
	if err != nil {
		return err
	}
	repoByURL := map[string]uuid.UUID{}
	for rows.Next() {
		var id uuid.UUID
		var u, cu string
		if err := rows.Scan(&id, &u, &cu); err != nil {
			rows.Close()
			return err
		}
		for _, x := range []string{u, cu} {
			if n := NormalizeSourceURL(x); n != "" {
				repoByURL[n] = id
			}
		}
	}
	rows.Close()
	type regImage struct{ ref, source, revision string }
	regByDigest := map[string][]regImage{}
	repoImages := map[uuid.UUID][]string{} // repository → image references PATHOS knows
	rows, err = pool.Query(ctx, `SELECT DISTINCT digest, registry, repository, tag, source_url, revision FROM registry_images
		WHERE organization_id = $1 AND source_url <> ''`, orgID)
	if err != nil {
		return err
	}
	for rows.Next() {
		var d, reg, repo, tag, src, rev string
		if err := rows.Scan(&d, &reg, &repo, &tag, &src, &rev); err != nil {
			rows.Close()
			return err
		}
		ref := reg + "/" + repo + ":" + tag
		regByDigest[d] = append(regByDigest[d], regImage{ref: ref, source: src, revision: rev})
		if id, ok := repoByURL[NormalizeSourceURL(src)]; ok && len(repoImages[id]) < 50 && !slices.Contains(repoImages[id], reg+"/"+repo) {
			repoImages[id] = append(repoImages[id], reg+"/"+repo)
		}
	}
	rows.Close()
	// An image scan target is attached to a repository record for
	// ownership; that does not mean the image is built from the
	// repository's code (VALIDATION_REPORT O10: one image target marked all
	// 2,608 code findings of kubernetes-goat as deployed and exposed). Only
	// targets marked built_from_repository count for the repository's code
	// findings; the OCI source label (above) links without the mark.
	builtTarget := map[uuid.UUID]bool{}
	for _, t := range targets {
		if !t.Built {
			continue
		}
		builtTarget[t.ID] = true
		if !slices.Contains(repoImages[t.RepoID], t.RefText) && len(repoImages[t.RepoID]) < 50 {
			repoImages[t.RepoID] = append(repoImages[t.RepoID], t.RefText)
		}
	}

	// Runtime alerts (open imported Falco/Tetragon/Tracee findings).
	rows, err = pool.Query(ctx, `SELECT id, title, severity, file_path FROM findings WHERE organization_id = $1 AND category = 'runtime'
		AND status IN ('open', 'in_progress', 'needs_review')`, orgID)
	if err != nil {
		return err
	}
	type alertRow struct {
		id                    uuid.UUID
		title, severity, path string
	}
	alertRows, err := pgx.CollectRows(rows, func(r pgx.CollectableRow) (alertRow, error) {
		var a alertRow
		err := r.Scan(&a.id, &a.title, &a.severity, &a.path)
		return a, err
	})
	if err != nil {
		return err
	}
	type alertMatch struct {
		finding, workload uuid.UUID
		basis             string
	}
	var matches []alertMatch
	alertsByWorkload := map[uuid.UUID][]Alert{}
	for _, a := range alertRows {
		ns, pod, ok := AlertLocation(a.path)
		if !ok {
			continue
		}
		for _, w := range workloads {
			if basis, ok := MatchAlertPod(ns, pod, w.W); ok {
				matches = append(matches, alertMatch{a.id, w.ID, basis})
				if len(alertsByWorkload[w.ID]) < 5 {
					alertsByWorkload[w.ID] = append(alertsByWorkload[w.ID], Alert{FindingID: a.id.String(), Title: truncate(a.title, 200),
						Severity: a.severity, Location: truncate(a.path, 300), Basis: basis})
				}
			}
		}
	}

	// Deployments.
	var deploys []deployRow
	for _, im := range images {
		for _, t := range targets {
			if !t.Parsable {
				continue
			}
			if basis, detail, ok := MatchTarget(im.Ref, t.Ref, t.Digests); ok {
				tid, rid := t.ID, t.RepoID
				var repo *uuid.UUID
				if builtTarget[t.ID] {
					repo = &rid
				}
				deploys = append(deploys, deployRow{im.WorkloadID, im.ID, &tid, repo, basis, "image scan target " + t.RefText + ": " + detail})
			}
		}
		if im.Ref.Digest == "" {
			continue
		}
		seen := map[uuid.UUID]bool{}
		for _, ri := range regByDigest[im.Ref.Digest] {
			rid, ok := repoByURL[NormalizeSourceURL(ri.source)]
			if !ok || seen[rid] {
				continue
			}
			seen[rid] = true
			detail := "registry image " + ri.ref + " has org.opencontainers.image.source=" + ri.source
			if ri.revision != "" {
				detail += " (revision " + ri.revision + ")"
			}
			rid2 := rid
			deploys = append(deploys, deployRow{im.WorkloadID, im.ID, nil, &rid2, "oci_source", truncate(detail, 1000)})
		}
	}

	imgByID := map[uuid.UUID]linkImage{}
	for _, im := range images {
		imgByID[im.ID] = im
	}
	evidence := func(d deployRow) DeploymentEvidence {
		w, im := wByID[d.workload], imgByID[d.image]
		var exp []Exposure
		for _, x := range w.W.Exposure {
			if x.Internet {
				exp = append(exp, x)
			}
		}
		return DeploymentEvidence{ClusterID: w.ClusterID.String(), Cluster: w.Cluster, WorkloadID: w.ID.String(), Namespace: w.W.Namespace,
			Kind: w.W.Kind, Workload: w.W.Name, Container: im.Container, Image: im.Image, Digest: im.Ref.Digest, Basis: d.basis,
			BasisDetail: d.detail, Exposed: w.W.InternetExposed, Exposure: exp, Privileged: w.W.Privileged, HostNetwork: w.W.HostNetwork,
			HostPID: w.W.HostPID, RunAsRoot: w.W.RunAsRoot, Alerts: alertsByWorkload[w.ID]}
	}
	byTarget := map[uuid.UUID][]DeploymentEvidence{}
	byRepo := map[uuid.UUID][]DeploymentEvidence{}
	repoSeen := map[string]bool{}
	for _, d := range deploys {
		ev := evidence(d)
		if d.target != nil {
			byTarget[*d.target] = append(byTarget[*d.target], ev)
		}
		if d.repo != nil {
			k := d.repo.String() + "|" + d.image.String()
			if !repoSeen[k] {
				repoSeen[k] = true
				byRepo[*d.repo] = append(byRepo[*d.repo], ev)
			}
		}
	}
	targetRef := map[uuid.UUID]string{}
	for _, t := range targets {
		targetRef[t.ID] = t.RefText
	}

	return pgx.BeginFunc(ctx, pool, func(tx pgx.Tx) error {
		// One linker per organization at a time (jobs replicas, the API
		// after a mapping change, scans finishing).
		if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtext('pathos-runtime-link'), hashtext($1::text))`, orgID); err != nil {
			return err
		}
		b := &pgx.Batch{}
		for _, w := range workloads {
			var app *uuid.UUID
			basis := ""
			if m, ok := MapApplication(w.ClusterID.String(), w.W, mappings); ok {
				id := uuid.MustParse(m.ApplicationID)
				app, basis = &id, "mapping: "+m.Describe()
			}
			if !sameUUID(app, w.AppID) || basis != w.AppBasis {
				b.Queue(`UPDATE runtime_workloads SET application_id = $2, application_basis = $3 WHERE id = $1`, w.ID, app, basis)
			}
		}
		b.Queue(`DELETE FROM runtime_deployments WHERE organization_id = $1`, orgID)
		for _, d := range deploys {
			b.Queue(`INSERT INTO runtime_deployments (organization_id, workload_id, image_id, scan_target_id, repository_id, basis, detail)
				VALUES ($1, $2, $3, $4, $5, $6, $7)`, orgID, d.workload, d.image, d.target, d.repo, d.basis, d.detail)
		}
		b.Queue(`DELETE FROM runtime_alert_matches WHERE organization_id = $1`, orgID)
		for _, m := range matches {
			b.Queue(`INSERT INTO runtime_alert_matches (organization_id, finding_id, workload_id, basis) VALUES ($1, $2, $3, $4)
				ON CONFLICT DO NOTHING`, orgID, m.finding, m.workload, m.basis)
		}
		if err := tx.SendBatch(ctx, b).Close(); err != nil {
			return err
		}

		// Findings: open ones, and any that carries runtime facts.
		rows, err := tx.Query(ctx, `SELECT f.id, f.repository_id, f.scan_target_id, COALESCE(st.kind, ''), f.category, f.runtime_status,
			f.runtime_exposed, f.runtime_privileged, f.runtime_alert, COALESCE(f.runtime_context->>'hash', '')
			FROM findings f LEFT JOIN scan_targets st ON st.id = f.scan_target_id
			WHERE f.organization_id = $1 AND (f.status IN ('open', 'in_progress', 'needs_review') OR f.runtime_status <> '' OR f.runtime_context IS NOT NULL)`, orgID)
		if err != nil {
			return err
		}
		type fr struct {
			id, repo             uuid.UUID
			target               *uuid.UUID
			kind, category       string
			status               string
			exposed, priv, alert bool
			hash                 string
		}
		list, err := pgx.CollectRows(rows, func(r pgx.CollectableRow) (fr, error) {
			var x fr
			err := r.Scan(&x.id, &x.repo, &x.target, &x.kind, &x.category, &x.status, &x.exposed, &x.priv, &x.alert, &x.hash)
			return x, err
		})
		if err != nil {
			return err
		}
		b = &pgx.Batch{}
		flush := func() error {
			if b.Len() == 0 {
				return nil
			}
			err := tx.SendBatch(ctx, b).Close()
			b = &pgx.Batch{}
			return err
		}
		for _, f := range list {
			var deps []DeploymentEvidence
			eligible := false
			var imgs []string
			switch {
			case f.target != nil && f.kind == "image":
				deps = slices.Clone(byTarget[*f.target])
				eligible, imgs = true, []string{targetRef[*f.target]}
			case f.target == nil && !slices.Contains(notInImage, f.category):
				deps = slices.Clone(byRepo[f.repo])
				imgs = repoImages[f.repo]
				eligible = len(imgs) > 0
			}
			res := Summarize(deps, eligible, imgs, clusters)
			var raw []byte
			hash := ""
			if res.Context != nil {
				raw, _ = json.Marshal(res.Context)
				sum := sha256.Sum256(raw)
				hash = hex.EncodeToString(sum[:8])
				var m map[string]any
				_ = json.Unmarshal(raw, &m)
				m["hash"] = hash
				raw, _ = json.Marshal(m)
				if len(raw) > 60000 {
					res.Context.Deployments = res.Context.Deployments[:min(3, len(res.Context.Deployments))]
					raw, _ = json.Marshal(res.Context)
					_ = json.Unmarshal(raw, &m)
					m["hash"] = hash
					raw, _ = json.Marshal(m)
				}
			}
			if res.Status == f.status && res.Exposed == f.exposed && res.Privileged == f.priv && res.Alert == f.alert && hash == f.hash {
				continue
			}
			b.Queue(`UPDATE findings SET runtime_status = $2, runtime_exposed = $3, runtime_privileged = $4, runtime_alert = $5,
				runtime_context = $6, risk_dirty = true WHERE id = $1`, f.id, res.Status, res.Exposed, res.Privileged, res.Alert, raw)
			if b.Len() >= 500 {
				if err := flush(); err != nil {
					return err
				}
			}
		}
		return flush()
	})
}

func sameUUID(a, b *uuid.UUID) bool {
	if a == nil || b == nil {
		return a == nil && b == nil
	}
	return *a == *b
}

// LinkAfterScan relinks an organization after a scan when it has a
// connected cluster (new findings get their runtime facts without waiting
// for the hourly run). Database only.
func LinkAfterScan(ctx context.Context, pool *pgxpool.Pool, orgID uuid.UUID) error {
	var has bool
	if err := pool.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM runtime_clusters WHERE organization_id = $1)`, orgID).Scan(&has); err != nil || !has {
		return err
	}
	return Link(ctx, pool, orgID)
}

// ScannedDigest is a digest an image scan resolved a reference to.
type ScannedDigest struct {
	Reference string
	Digest    string
}

// TrivyRepoDigests reads the image digests of a Trivy SARIF report
// (runs[].properties.repoDigests, "name@sha256:...").
func TrivyRepoDigests(raw []byte) []ScannedDigest {
	var doc struct {
		Runs []struct {
			Properties struct {
				ImageName   string   `json:"imageName"`
				RepoDigests []string `json:"repoDigests"`
			} `json:"properties"`
		} `json:"runs"`
	}
	if json.Unmarshal(raw, &doc) != nil {
		return nil
	}
	var out []ScannedDigest
	for _, r := range doc.Runs {
		for _, d := range r.Properties.RepoDigests {
			if ref, ok := ParseImageRef(d); ok && ref.Digest != "" && len(out) < 20 {
				out = append(out, ScannedDigest{Reference: truncate(d, 1000), Digest: ref.Digest})
			}
		}
	}
	return out
}
