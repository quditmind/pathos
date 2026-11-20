package codegraph

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"pathos/internal/monitoring"
	"pathos/internal/platform/db"
)

// Architecture drift (PATHOS 3.0 M9, flag continuous_monitoring): every new
// snapshot is compared with the previous ready snapshot of the same
// repository. Only architectural elements count: routes, API operations,
// external services, datastores, queues, internet exposure (an edge that
// crosses an internet trust boundary), other trust-boundary crossings and
// components (dependencies). Each item carries the evidence of its edge or
// the source location of its node (rule 5).

// Drift categories.
const (
	DriftRoute       = "route"
	DriftAPIOp       = "api_operation"
	DriftExternal    = "external_service"
	DriftDatastore   = "datastore"
	DriftQueue       = "queue"
	DriftInternet    = "internet_exposure"
	DriftBoundary    = "boundary_crossing"
	DriftComponent   = "component"
	maxDriftItems    = 500
	maxDriftEvidence = 5
)

var driftNodeTypes = map[string]string{"route": DriftRoute, "api_operation": DriftAPIOp, "external_service": DriftExternal,
	"datastore": DriftDatastore, "queue": DriftQueue}

// countKey maps a category to its counts key stem.
var countKey = map[string]string{DriftRoute: "routes", DriftAPIOp: "api_operations", DriftExternal: "external_services",
	DriftDatastore: "datastores", DriftQueue: "queues", DriftInternet: "internet_exposure", DriftBoundary: "boundary_crossings",
	DriftComponent: "components"}

// DriftResult is the comparison of a snapshot with its predecessor.
type DriftResult struct {
	ID             uuid.UUID
	OrgID          uuid.UUID
	AppID          uuid.UUID
	RepoID         uuid.UUID
	FromSnapshotID *uuid.UUID
	ToSnapshotID   uuid.UUID
	FromCommit     string
	ToCommit       string
	Severity       string
	Counts         map[string]int
	Items          []monitoring.DriftItem
	Truncated      bool
	// Architectural: routes, services, datastores, exposure or boundary
	// crossings changed (components alone do not count).
	Architectural bool
	// Components: added, removed or changed components (loop 2).
	ComponentChanges []monitoring.DriftItem
}

// HasChanges reports whether anything changed.
func (d *DriftResult) HasChanges() bool { return len(d.Items) > 0 || d.Truncated }

func isInternetNode(n *snode) bool {
	k := strings.ToLower(n.key + " " + n.label)
	return n.typ == "trust_boundary" && (strings.Contains(k, "internet") || strings.Contains(k, "public"))
}

type compInfo struct {
	key, label, version, purl, file string
}

func loadComponents(ctx context.Context, q db.Querier, snapshotID uuid.UUID) (map[string]compInfo, error) {
	rows, err := q.Query(ctx, `SELECT node_key, label, COALESCE(attrs->>'version', ''), COALESCE(attrs->>'purl', ''), file_path
		FROM codegraph_nodes WHERE snapshot_id = $1 AND type = 'component'`, snapshotID)
	if err != nil {
		return nil, err
	}
	out := map[string]compInfo{}
	for rows.Next() {
		var c compInfo
		if err := rows.Scan(&c.key, &c.label, &c.version, &c.purl, &c.file); err != nil {
			rows.Close()
			return nil, err
		}
		out[c.key] = c
	}
	rows.Close()
	return out, rows.Err()
}

// edgeEvidence loads up to maxDriftEvidence evidence rows per edge.
func edgeEvidence(ctx context.Context, q db.Querier, ids []uuid.UUID) (map[uuid.UUID][]monitoring.EvidenceRef, error) {
	out := map[uuid.UUID][]monitoring.EvidenceRef{}
	if len(ids) == 0 {
		return out, nil
	}
	rows, err := q.Query(ctx, `SELECT edge_id, kind, ref, detail, file_path, line FROM (
		SELECT edge_id, kind, ref, detail, file_path, line, row_number() OVER (PARTITION BY edge_id ORDER BY id) AS n
		FROM codegraph_evidence WHERE edge_id = ANY($1)) x WHERE n <= $2`, ids, maxDriftEvidence)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var id uuid.UUID
		var e monitoring.EvidenceRef
		if err := rows.Scan(&id, &e.Kind, &e.Ref, &e.Detail, &e.File, &e.Line); err != nil {
			return nil, err
		}
		out[id] = append(out[id], e)
	}
	return out, rows.Err()
}

func nodeEvidence(n *snode) []monitoring.EvidenceRef {
	if n.file == "" {
		return []monitoring.EvidenceRef{}
	}
	return []monitoring.EvidenceRef{{Kind: "file_line", Ref: n.file, File: n.file}}
}

// ComputeDrift compares a snapshot with the previous ready snapshot of its
// repository (snapshots still stored in rows). Without one it returns a
// baseline (FromSnapshotID nil, no items).
func ComputeDrift(ctx context.Context, q db.Querier, orgID, toID uuid.UUID) (*DriftResult, error) {
	d := &DriftResult{OrgID: orgID, ToSnapshotID: toID, Severity: "info", Counts: map[string]int{}, Items: []monitoring.DriftItem{}}
	var created any
	if err := q.QueryRow(ctx, `SELECT application_id, repository_id, commit_sha, created_at FROM codegraph_snapshots
		WHERE id = $1 AND organization_id = $2`, toID, orgID).Scan(&d.AppID, &d.RepoID, &d.ToCommit, &created); err != nil {
		return nil, err
	}
	var from uuid.UUID
	err := q.QueryRow(ctx, `SELECT id, commit_sha FROM codegraph_snapshots WHERE organization_id = $1 AND repository_id = $2 AND id <> $3
		AND status IN ('ready', 'partial') AND storage = 'rows' AND created_at <= $4 ORDER BY created_at DESC, id DESC LIMIT 1`,
		orgID, d.RepoID, toID, created).Scan(&from, &d.FromCommit)
	if errors.Is(err, pgx.ErrNoRows) {
		return d, nil
	}
	if err != nil {
		return nil, err
	}
	d.FromSnapshotID = &from
	base, err := loadSkeleton(ctx, q, from)
	if err != nil {
		return nil, fmt.Errorf("previous snapshot: %w", err)
	}
	head, err := loadSkeleton(ctx, q, toID)
	if err != nil {
		return nil, fmt.Errorf("new snapshot: %w", err)
	}
	type pending struct {
		item   monitoring.DriftItem
		edgeID *uuid.UUID
	}
	var list []pending
	// Architectural nodes added or removed.
	nodeItems := func(a, b *skeleton, change string) {
		for i := range a.nodes {
			n := &a.nodes[i]
			cat, ok := driftNodeTypes[n.typ]
			if !ok {
				continue
			}
			if _, in := b.byKey[n.key]; in {
				continue
			}
			list = append(list, pending{item: monitoring.DriftItem{Change: change, Category: cat, Key: n.key, Label: n.label, File: n.file,
				EvidenceLabel: monitoring.EvidenceVerified, Evidence: nodeEvidence(n)}})
		}
	}
	nodeItems(head, base, "added")
	nodeItems(base, head, "removed")
	// Boundary crossings (internet exposure separately).
	edgeItems := func(a, b *skeleton, change string) {
		keys := make(map[string]bool, len(b.edges))
		for i := range b.edges {
			keys[b.edges[i].key] = true
		}
		for i := range a.edges {
			e := &a.edges[i]
			if e.typ != "crosses_boundary" || keys[e.key] {
				continue
			}
			src, dst := &a.nodes[e.src], &a.nodes[e.dst]
			cat := DriftBoundary
			if isInternetNode(dst) || isInternetNode(src) {
				cat = DriftInternet
			}
			id := e.id
			list = append(list, pending{edgeID: &id, item: monitoring.DriftItem{Change: change, Category: cat, Key: e.key,
				Label: src.label + " → " + dst.label, File: src.file, EvidenceLabel: e.evidence}})
		}
	}
	edgeItems(head, base, "added")
	edgeItems(base, head, "removed")
	archCount := len(list)
	// Components.
	bc, err := loadComponents(ctx, q, from)
	if err != nil {
		return nil, err
	}
	hc, err := loadComponents(ctx, q, toID)
	if err != nil {
		return nil, err
	}
	comp := func(c compInfo, change, detail string) {
		it := monitoring.DriftItem{Change: change, Category: DriftComponent, Key: c.key, Label: c.label, Detail: detail, File: c.file,
			EvidenceLabel: monitoring.EvidenceVerified, Evidence: []monitoring.EvidenceRef{}}
		if c.purl != "" {
			it.Evidence = append(it.Evidence, monitoring.EvidenceRef{Kind: "sbom", Ref: c.purl, File: c.file})
		} else if c.file != "" {
			it.Evidence = append(it.Evidence, monitoring.EvidenceRef{Kind: "file_line", Ref: c.file, File: c.file})
		}
		list = append(list, pending{item: it})
		d.ComponentChanges = append(d.ComponentChanges, it)
	}
	for k, c := range hc {
		b, ok := bc[k]
		switch {
		case !ok:
			comp(c, "added", strings.TrimSpace("version "+c.version))
		case b.version != c.version:
			comp(c, "changed", "version "+orDash(b.version)+" → "+orDash(c.version))
		}
	}
	for k, c := range bc {
		if _, ok := hc[k]; !ok {
			comp(c, "removed", strings.TrimSpace("version "+c.version))
		}
	}
	d.Architectural = archCount > 0
	sort.SliceStable(list, func(i, j int) bool {
		a, b := list[i].item, list[j].item
		if a.Category != b.Category {
			return a.Category < b.Category
		}
		if a.Change != b.Change {
			return a.Change < b.Change
		}
		return a.Key < b.Key
	})
	for _, p := range list {
		stem := countKey[p.item.Category]
		d.Counts[p.item.Change+"_"+stem]++
	}
	if len(list) > maxDriftItems {
		list, d.Truncated = list[:maxDriftItems], true
	}
	var edgeIDs []uuid.UUID
	for _, p := range list {
		if p.edgeID != nil {
			edgeIDs = append(edgeIDs, *p.edgeID)
		}
	}
	ev, err := edgeEvidence(ctx, q, edgeIDs)
	if err != nil {
		return nil, err
	}
	for _, p := range list {
		it := p.item
		if p.edgeID != nil {
			it.Evidence = ev[*p.edgeID]
			if it.Evidence == nil {
				it.Evidence = []monitoring.EvidenceRef{}
			}
		}
		d.Items = append(d.Items, it)
	}
	d.Severity = driftSeverity(d.Counts)
	return d, nil
}

func orDash(s string) string {
	if s == "" {
		return "—"
	}
	return s
}

// driftSeverity: new internet exposure is high; new boundary crossings,
// external services or datastores medium; new routes, operations, queues
// or component changes low; removals only info.
func driftSeverity(c map[string]int) string {
	switch {
	case c["added_internet_exposure"] > 0:
		return "high"
	case c["added_boundary_crossings"]+c["added_external_services"]+c["added_datastores"] > 0:
		return "medium"
	case c["added_routes"]+c["added_api_operations"]+c["added_queues"]+c["added_components"]+c["changed_components"] > 0:
		return "low"
	}
	return "info"
}

// DriftTitle is a one-line description of the changes.
func DriftTitle(d *DriftResult, repoName string) string {
	if !d.HasChanges() {
		return "No architectural change in " + repoName
	}
	order := []struct{ key, one, many string }{
		{"added_internet_exposure", "new internet exposure", "new internet exposures"},
		{"added_boundary_crossings", "new trust-boundary crossing", "new trust-boundary crossings"},
		{"added_external_services", "new external service", "new external services"},
		{"added_datastores", "new datastore", "new datastores"},
		{"added_routes", "new route", "new routes"},
		{"added_api_operations", "new API operation", "new API operations"},
		{"added_queues", "new queue", "new queues"},
		{"added_components", "new component", "new components"},
		{"changed_components", "changed component", "changed components"},
		{"removed_internet_exposure", "removed internet exposure", "removed internet exposures"},
		{"removed_routes", "removed route", "removed routes"},
		{"removed_external_services", "removed external service", "removed external services"},
		{"removed_datastores", "removed datastore", "removed datastores"},
		{"removed_boundary_crossings", "removed trust-boundary crossing", "removed trust-boundary crossings"},
		{"removed_components", "removed component", "removed components"},
	}
	var parts []string
	for _, o := range order {
		if n := d.Counts[o.key]; n > 0 && len(parts) < 3 {
			w := o.many
			if n == 1 {
				w = o.one
			}
			parts = append(parts, fmt.Sprintf("%d %s", n, w))
		}
	}
	if len(parts) == 0 {
		parts = append(parts, "architecture changed")
	}
	return strings.Join(parts, ", ") + " in " + repoName
}

// StoreDrift writes the drift record (idempotent per snapshot) and returns
// its id.
func StoreDrift(ctx context.Context, q db.Querier, d *DriftResult) (uuid.UUID, error) {
	counts, _ := json.Marshal(d.Counts)
	items, _ := json.Marshal(d.Items)
	id := uuid.Must(uuid.NewV7())
	err := q.QueryRow(ctx, `INSERT INTO architecture_drifts (id, organization_id, application_id, repository_id, from_snapshot_id, to_snapshot_id,
		from_commit, to_commit, severity, has_changes, counts, items, truncated)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)
		ON CONFLICT (to_snapshot_id) DO UPDATE SET to_snapshot_id = EXCLUDED.to_snapshot_id RETURNING id`,
		id, d.OrgID, d.AppID, d.RepoID, d.FromSnapshotID, d.ToSnapshotID, clip(d.FromCommit, 64), clip(d.ToCommit, 64), d.Severity,
		d.HasChanges(), counts, items, d.Truncated).Scan(&d.ID)
	return d.ID, err
}

// recordDrift computes and stores the drift of a new snapshot and its feed
// event, when the organization has continuous monitoring on.
func (s *Service) recordDrift(ctx context.Context, ref snapshotRef) {
	on, err := monitoring.Enabled(ctx, s.DB, ref.OrgID)
	if err != nil || !on {
		return
	}
	d, err := ComputeDrift(ctx, s.DB, ref.OrgID, ref.ID)
	if err != nil {
		s.Log.Warn("architecture drift not computed", "snapshot_id", ref.ID, "err", err, "error_code", monitoring.CodeDriftFailed)
		return
	}
	if _, err := StoreDrift(ctx, s.DB, d); err != nil {
		s.Log.Warn("architecture drift not stored", "snapshot_id", ref.ID, "err", err, "error_code", monitoring.CodeDriftFailed)
		return
	}
	if !d.HasChanges() {
		return
	}
	var repoName string
	_ = s.DB.QueryRow(ctx, `SELECT COALESCE(NULLIF(display_name, ''), full_name) FROM repositories WHERE id = $1`, ref.RepoID).Scan(&repoName)
	app, repo, did := ref.AppID, ref.RepoID, d.ID
	if _, err := monitoring.Record(ctx, s.DB, monitoring.Event{OrgID: ref.OrgID, ApplicationID: &app, RepositoryID: &repo,
		Type: monitoring.TypeArchitectureDrift, Severity: d.Severity, Title: DriftTitle(d, repoName),
		Summary:       "The new CodeGraph snapshot was compared with the previous snapshot of the repository (commit " + shortSHA(d.FromCommit) + "); the evidence names both snapshots and commits.",
		EvidenceLabel: monitoring.EvidenceVerified,
		Evidence: map[string]any{"from_snapshot_id": d.FromSnapshotID, "to_snapshot_id": d.ToSnapshotID, "from_commit": d.FromCommit,
			"commit": d.ToCommit, "drift_id": d.ID},
		SubjectType: "drift", SubjectID: &did, Details: map[string]any{"counts": d.Counts, "architectural": d.Architectural}}); err != nil {
		s.Log.Warn("monitoring event not recorded", "err", err, "error_code", monitoring.CodeRecordFailed)
	}
}

func shortSHA(s string) string {
	if s == "" {
		return "unknown"
	}
	if len(s) > 12 {
		return s[:12]
	}
	return s
}
