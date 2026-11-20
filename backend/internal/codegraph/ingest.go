package codegraph

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"path"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"pathos/internal/platform/db"
	"pathos/internal/platform/tenant"
	"pathos/internal/scans"
)

// Error codes raised by the build and ingest path (catalogue:
// internal/platform/diag/catalogue_disc_graph.go).
const (
	CodeNoWorker       = "PTH-DISC-1001"
	CodeToolFailed     = "PTH-DISC-1002"
	CodeNoGraph        = "PTH-DISC-1003"
	CodeInvalidDoc     = "PTH-DISC-1004"
	CodeNoRepositories = "PTH-DISC-1005"
	CodeNotBuildable   = "PTH-DISC-1006"
	CodeTruncated      = "PTH-DISC-1007"
	CodeNotReady       = "PTH-GRAPH-1001"
	CodeStoreFailed    = "PTH-GRAPH-1002"
	CodeBadQuery       = "PTH-GRAPH-1003"
	CodeDiffMismatch   = "PTH-GRAPH-1004"
	CodeArchived       = "PTH-GRAPH-1005"
)

// snapshotRef identifies the snapshot a discovery job builds.
type snapshotRef struct {
	ID, OrgID, AppID, RepoID uuid.UUID
}

// OnGraphResult stores the graph of a discovery job (scans.Service hook).
// Errors are recorded on the snapshot, never returned: the scan result
// itself is already stored.
func (s *Service) OnGraphResult(ctx context.Context, orgID, jobID uuid.UUID, res scans.GraphResult) {
	ctx = tenant.WithOrg(ctx, orgID)
	log := s.Log.With("scan_job_id", jobID)
	var ref snapshotRef
	err := s.DB.QueryRow(ctx, `SELECT id, organization_id, application_id, repository_id FROM codegraph_snapshots
		WHERE scan_job_id = $1 AND organization_id = $2`, jobID, orgID).Scan(&ref.ID, &ref.OrgID, &ref.AppID, &ref.RepoID)
	if errors.Is(err, pgx.ErrNoRows) {
		log.Warn("CodeGraph result without a snapshot ignored")
		return
	}
	if err != nil {
		log.Error("CodeGraph snapshot lookup failed", "err", err, "error_code", CodeStoreFailed)
		return
	}
	if res.Status != "succeeded" {
		msg := "the discovery tool " + strings.ReplaceAll(res.Status, "_", " ")
		if res.Error != "" {
			msg += ": " + res.Error
		}
		s.failSnapshot(ctx, ref.ID, CodeToolFailed, msg)
		log.Warn("CodeGraph discovery did not succeed", "status", res.Status, "error_code", CodeToolFailed)
		return
	}
	start := time.Now()
	n, e, err := s.Load(ctx, ref, res.Commit, res.Raw)
	var ve *ValidationError
	switch {
	case errors.As(err, &ve):
		s.failSnapshot(ctx, ref.ID, CodeInvalidDoc, ve.Error())
		log.Warn("CodeGraph document refused", "err", err, "error_code", CodeInvalidDoc)
	case err != nil:
		s.failSnapshot(ctx, ref.ID, CodeStoreFailed, "the graph could not be stored")
		log.Error("CodeGraph store failed", "err", err, "error_code", CodeStoreFailed)
	default:
		log.Info("CodeGraph snapshot stored", "snapshot_id", ref.ID, "nodes", n, "edges", e, "duration_ms", time.Since(start).Milliseconds())
	}
}

func (s *Service) failSnapshot(ctx context.Context, id uuid.UUID, code, msg string) {
	if _, err := s.DB.Exec(ctx, `UPDATE codegraph_snapshots SET status = 'failed', error_code = $2, error = left($3, 2000),
		finished_at = now() WHERE id = $1 AND status IN ('queued', 'building')`, id, code, msg); err != nil {
		s.Log.Error("CodeGraph snapshot status update failed", "snapshot_id", id, "err", err)
	}
}

// node is a node prepared for storage.
type node struct {
	DocNode
	id       uuid.UUID
	parentID *uuid.UUID
	depth    int
	group    string
	file     string
	start    *int
	end      *int
	language string
	tech     string
	counts   map[string]int
	total    int
}

// edge is an edge prepared for storage.
type edge struct {
	id       uuid.UUID
	key      string
	source   uuid.UUID
	target   uuid.UUID
	typ      string
	evidence string
	refs     []EvidenceRef
}

// Load validates a discovery document, enriches it and stores it in the
// snapshot (one transaction). It returns the stored node and edge counts.
func (s *Service) Load(ctx context.Context, ref snapshotRef, commit string, raw []byte) (int, int, error) {
	var d Doc
	dec := json.NewDecoder(bytes.NewReader(raw))
	if err := dec.Decode(&d); err != nil {
		return 0, 0, invalid("not JSON: %v", err)
	}
	if err := Validate(&d); err != nil {
		return 0, 0, err
	}
	nodes, edges, err := s.enrich(ctx, ref, &d)
	if err != nil {
		return 0, 0, err
	}
	status := "ready"
	errCode, errText := "", ""
	if t, _ := d.Stats["truncated"].(bool); t {
		status, errCode, errText = "partial", CodeTruncated, "discovery stopped at its size limits; the graph is incomplete"
	}
	engines, _ := json.Marshal(d.Engines)
	stats, _ := json.Marshal(trimStats(d.Stats))
	err = db.InTx(ctx, s.DB, func(tx pgx.Tx) error {
		var cur string
		if err := tx.QueryRow(ctx, `SELECT status FROM codegraph_snapshots WHERE id = $1 FOR UPDATE`, ref.ID).Scan(&cur); err != nil {
			return err
		}
		if cur != "queued" && cur != "building" {
			return fmt.Errorf("snapshot is %s", cur)
		}
		if err := insertNodes(ctx, tx, ref, nodes); err != nil {
			return err
		}
		if err := insertEdges(ctx, tx, ref, edges); err != nil {
			return err
		}
		_, err := tx.Exec(ctx, `UPDATE codegraph_snapshots SET status = $2, node_count = $3, edge_count = $4, engines = $5, stats = $6,
			commit_sha = CASE WHEN $7 <> '' THEN $7 ELSE commit_sha END, error_code = $8, error = $9,
			started_at = COALESCE(started_at, now()), finished_at = now() WHERE id = $1`,
			ref.ID, status, len(nodes), len(edges), engines, stats, commit, errCode, errText)
		return err
	})
	if err != nil {
		return 0, 0, err
	}
	s.cache.drop(ref.ID)
	return len(nodes), len(edges), nil
}

// trimStats keeps the scalar statistics and at most 50 skipped entries.
func trimStats(st map[string]any) map[string]any {
	out := map[string]any{}
	for k, v := range st {
		switch x := v.(type) {
		case []any:
			if len(x) > 50 {
				x = x[:50]
				out[k+"_truncated"] = true
			}
			out[k] = x
		default:
			out[k] = v
		}
	}
	if b, _ := json.Marshal(out); len(b) > 60000 {
		delete(out, "skipped")
	}
	return out
}

// enrich turns the document into storable nodes and edges and adds what
// only PATHOS knows: the application (ownership), runtime observations and
// the repository's open findings.
func (s *Service) enrich(ctx context.Context, ref snapshotRef, d *Doc) ([]*node, []*edge, error) {
	byKey := make(map[string]*node, len(d.Nodes)+16)
	nodes := make([]*node, 0, len(d.Nodes)+16)
	add := func(dn DocNode) *node {
		n := &node{DocNode: dn, id: uuid.Must(uuid.NewV7())}
		n.Attrs = cleanAttrs(n.Attrs)
		n.file = clip(attrString(n.Attrs, "file"), 1000)
		n.language = clip(attrString(n.Attrs, "language"), 64)
		n.tech = clip(firstNonEmpty(attrString(n.Attrs, "technology"), attrString(n.Attrs, "framework")), 200)
		if v, ok := attrInt(n.Attrs, "line"); ok {
			n.start = &v
		}
		if v, ok := attrInt(n.Attrs, "end_line"); ok {
			n.end = &v
		}
		byKey[n.Key] = n
		nodes = append(nodes, n)
		return n
	}
	var repoNode *node
	for _, dn := range d.Nodes {
		n := add(dn)
		if n.Type == "repository" {
			repoNode = n
		}
	}
	var edges []*edge
	edgeIdx := map[string]*edge{}
	link := func(src, dst *node, typ, evidence string, refs []EvidenceRef) {
		k := EdgeKey(src.Key, typ, dst.Key)
		if e, ok := edgeIdx[k]; ok {
			if evidenceRank(evidence) < evidenceRank(e.evidence) {
				e.evidence = evidence
			}
			for _, r := range refs {
				if len(e.refs) < maxRefsPerEdge+2 {
					e.refs = append(e.refs, r)
				}
			}
			return
		}
		e := &edge{id: uuid.Must(uuid.NewV7()), key: k, source: src.id, target: dst.id, typ: typ, evidence: evidence, refs: refs}
		edgeIdx[k] = e
		edges = append(edges, e)
	}
	for _, de := range d.Edges {
		link(byKey[de.Source], byKey[de.Target], de.Type, de.Evidence, de.EvidenceRefs)
	}

	// Ownership: the application owns the repository (PATHOS inventory).
	var repoName, appName, criticality, bu string
	if err := s.DB.QueryRow(ctx, `SELECT COALESCE(NULLIF(r.display_name, ''), r.full_name), a.name, a.criticality,
		COALESCE((SELECT b.name FROM business_units b WHERE b.id = a.business_unit_id), '')
		FROM repositories r JOIN applications a ON a.id = $2 AND a.organization_id = r.organization_id
		WHERE r.id = $1`, ref.RepoID, ref.AppID).Scan(&repoName, &appName, &criticality, &bu); err != nil {
		return nil, nil, fmt.Errorf("ownership: %w", err)
	}
	repoNode.Label = clip(repoName, maxLabelLen)
	repoNode.Attrs["repository_id"] = ref.RepoID.String()
	app := add(DocNode{Key: "app:" + ref.AppID.String(), Type: "application", Label: clip(appName, maxLabelLen), Layer: "ownership",
		Attrs: map[string]any{"application_id": ref.AppID.String(), "criticality": criticality, "business_unit": bu,
			// The existing context graph is the full ownership layer.
			"context_graph": "/posture/graph"}})
	link(app, repoNode, "owns", EvidenceVerified, []EvidenceRef{{Kind: "registry", Ref: "applications/" + ref.AppID.String(),
		Detail: "repository assigned to this application in the PATHOS inventory"}})

	// Runtime (observed): workloads running an image linked to this
	// repository, and their internet exposure.
	if err := s.runtimeEdges(ctx, ref, repoNode, add, link, byKey); err != nil {
		return nil, nil, err
	}

	// Parents, depth and aggregation groups.
	for _, n := range nodes {
		if n.Type == "application" {
			continue
		}
		if n.Parent == "" && n != repoNode && isContained(n.Type) {
			n.Parent = repoNode.Key
		}
		if p := byKey[n.Parent]; p != nil {
			n.parentID = &p.id
		}
	}
	for _, n := range nodes {
		n.depth = depthOf(n, byKey)
		n.group = groupKey(n, byKey)
	}
	if err := s.attachFindings(ctx, ref, nodes); err != nil {
		return nil, nil, err
	}
	// Parents before children (the parent foreign key is not deferred).
	sort.SliceStable(nodes, func(i, j int) bool { return nodes[i].depth < nodes[j].depth })
	return nodes, edges, nil
}

// isContained reports whether a node type belongs under the repository in
// the containment tree when the document gives no parent.
func isContained(t string) bool {
	switch t {
	case "module", "file", "function", "class", "route", "api_operation", "container", "iac_resource":
		return true
	}
	return false
}

func depthOf(n *node, byKey map[string]*node) int {
	d := 0
	for p := byKey[n.Parent]; p != nil && d < 64; p = byKey[p.Parent] {
		d++
	}
	return d
}

// groupKey is the aggregation group of a node: "dir:<directory>" for nodes
// located in a file or module directory, otherwise "type:<type>".
func groupKey(n *node, byKey map[string]*node) string {
	switch n.Type {
	case "repository", "application":
		return "type:" + n.Type
	case "module":
		if p := firstNonEmpty(attrString(n.Attrs, "path"), attrString(n.Attrs, "dir"), n.file); p != "" {
			return "dir:" + cleanDir(p, true)
		}
	}
	if n.file != "" {
		return "dir:" + cleanDir(n.file, false)
	}
	for p := byKey[n.Parent]; p != nil; p = byKey[p.Parent] {
		if p.file != "" {
			return "dir:" + cleanDir(p.file, false)
		}
		if p.Type == "module" {
			return groupKey(p, byKey)
		}
	}
	return "type:" + n.Type
}

// cleanDir returns the directory of a repository path ("." for the root);
// isDir: p is a directory already.
func cleanDir(p string, isDir bool) string {
	p = strings.TrimPrefix(path.Clean("/"+strings.ReplaceAll(p, "\\", "/")), "/")
	if !isDir {
		p = path.Dir(p)
	}
	if p == "" || p == "/" {
		return "."
	}
	return clip(p, 280)
}

// runtimeEdges adds observed nodes and edges from the runtime context:
// repository → running workload (deployed_as) when a running image is
// linked to the repository, and workload → internet (crosses_boundary)
// for internet-exposed workloads.
func (s *Service) runtimeEdges(ctx context.Context, ref snapshotRef, repo *node, add func(DocNode) *node,
	link func(src, dst *node, typ, evidence string, refs []EvidenceRef), byKey map[string]*node) error {
	rows, err := s.DB.Query(ctx, `SELECT DISTINCT ON (w.id) w.id, c.name, w.namespace, w.kind, w.name, w.internet_exposed, d.basis, d.detail, i.image
		FROM runtime_deployments d JOIN runtime_workloads w ON w.id = d.workload_id
		JOIN runtime_clusters c ON c.id = w.cluster_id JOIN runtime_workload_images i ON i.id = d.image_id
		WHERE d.repository_id = $1 AND d.organization_id = $2 ORDER BY w.id, d.basis LIMIT 500`, ref.RepoID, ref.OrgID)
	if err != nil {
		return fmt.Errorf("runtime context: %w", err)
	}
	type wl struct {
		id                             uuid.UUID
		cluster, ns, kind, name, basis string
		detail, image                  string
		exposed                        bool
	}
	var ws []wl
	for rows.Next() {
		var w wl
		if err := rows.Scan(&w.id, &w.cluster, &w.ns, &w.kind, &w.name, &w.exposed, &w.basis, &w.detail, &w.image); err != nil {
			rows.Close()
			return err
		}
		ws = append(ws, w)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return err
	}
	for _, w := range ws {
		key := clip("runtime:"+w.cluster+"/"+w.ns+"/"+w.kind+"/"+w.name, maxKeyLen)
		n := byKey[key]
		if n == nil {
			n = add(DocNode{Key: key, Type: "container", Label: clip(w.ns+"/"+w.name, maxLabelLen), Layer: "deploy",
				Attrs: map[string]any{"runtime": "kubernetes", "cluster": w.cluster, "namespace": w.ns, "workload_kind": w.kind,
					"image": clip(w.image, 500), "exposure": map[bool]string{true: "internet", false: "internal"}[w.exposed]}})
		}
		rt := EvidenceRef{Kind: "runtime", Ref: "runtime_workloads/" + w.id.String(),
			Detail: clip("running image "+w.image+" linked to the repository by "+w.basis+": "+w.detail, maxDetailLen)}
		link(repo, n, "deployed_as", EvidenceObserved, []EvidenceRef{rt})
		if w.exposed {
			tb := byKey["tb:internet"]
			if tb == nil {
				tb = add(DocNode{Key: "tb:internet", Type: "trust_boundary", Label: "Internet", Layer: "deploy", Attrs: map[string]any{}})
			}
			link(n, tb, "crosses_boundary", EvidenceObserved, []EvidenceRef{{Kind: "runtime", Ref: "runtime_workloads/" + w.id.String(),
				Detail: "the workload is exposed to the internet (Ingress, LoadBalancer or NodePort) at the last runtime sync"}})
		}
	}
	return nil
}

// attachFindings counts the repository's open findings on the innermost
// node that contains their file and line (function or class, else file;
// dependency findings on the matching component).
func (s *Service) attachFindings(ctx context.Context, ref snapshotRef, nodes []*node) error {
	byFile := map[string][]*node{}
	comps := map[string]*node{}
	for _, n := range nodes {
		switch {
		case n.Type == "component":
			name := strings.ToLower(firstNonEmpty(attrString(n.Attrs, "name"), n.Label))
			comps[name+"@"+attrString(n.Attrs, "version")] = n
			if _, ok := comps[name]; !ok {
				comps[name] = n
			}
		case n.file != "":
			byFile[n.file] = append(byFile[n.file], n)
		}
	}
	rows, err := s.DB.Query(ctx, `SELECT severity, file_path, COALESCE(start_line, 0), package_name, package_version FROM findings
		WHERE repository_id = $1 AND organization_id = $2 AND status IN ('open', 'in_progress', 'needs_review') AND scan_target_id IS NULL
		LIMIT 200000`, ref.RepoID, ref.OrgID)
	if err != nil {
		return fmt.Errorf("findings: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var sev, file, pkg, ver string
		var line int
		if err := rows.Scan(&sev, &file, &line, &pkg, &ver); err != nil {
			return err
		}
		var target *node
		if pkg != "" {
			k := strings.ToLower(pkg)
			if c := comps[k+"@"+ver]; c != nil {
				target = c
			} else {
				target = comps[k]
			}
		}
		if target == nil && file != "" {
			target = innermost(byFile[strings.TrimPrefix(path.Clean("/"+file), "/")], line)
		}
		if target == nil {
			continue
		}
		if target.counts == nil {
			target.counts = map[string]int{}
		}
		target.counts[sev]++
		target.total++
	}
	return rows.Err()
}

// innermost returns the smallest node whose line range contains line; the
// file node when none does.
func innermost(ns []*node, line int) *node {
	var best, file *node
	bestSpan := 1 << 30
	for _, n := range ns {
		if n.Type == "file" {
			file = n
			continue
		}
		if line <= 0 || n.start == nil || n.end == nil || *n.end < *n.start {
			continue
		}
		if line >= *n.start && line <= *n.end && *n.end-*n.start < bestSpan && (n.Type == "function" || n.Type == "class") {
			best, bestSpan = n, *n.end-*n.start
		}
	}
	if best != nil {
		return best
	}
	return file
}

// insertNodes writes nodes in multi-row INSERT batches (COPY is refused
// under row-level security).
func insertNodes(ctx context.Context, tx pgx.Tx, ref snapshotRef, nodes []*node) error {
	const cols = 17
	const batch = 1000
	for i := 0; i < len(nodes); i += batch {
		part := nodes[i:min(i+batch, len(nodes))]
		var sb strings.Builder
		sb.WriteString(`INSERT INTO codegraph_nodes (id, organization_id, snapshot_id, node_key, type, label, layer, parent_id, depth,
			group_key, language, technology, file_path, start_line, end_line, attrs, finding_counts, finding_total) VALUES `)
		args := make([]any, 0, len(part)*(cols+1))
		for j, n := range part {
			if j > 0 {
				sb.WriteByte(',')
			}
			base := len(args)
			sb.WriteByte('(')
			for c := 1; c <= cols+1; c++ {
				if c > 1 {
					sb.WriteByte(',')
				}
				sb.WriteString("$" + strconv.Itoa(base+c))
			}
			sb.WriteByte(')')
			attrs, _ := json.Marshal(n.Attrs)
			counts, _ := json.Marshal(nonNilCounts(n.counts))
			args = append(args, n.id, ref.OrgID, ref.ID, n.Key, n.Type, n.Label, n.Layer, n.parentID, n.depth,
				n.group, n.language, n.tech, n.file, n.start, n.end, attrs, counts, n.total)
		}
		if _, err := tx.Exec(ctx, sb.String(), args...); err != nil {
			return fmt.Errorf("insert nodes: %w", err)
		}
	}
	return nil
}

func nonNilCounts(m map[string]int) map[string]int {
	if m == nil {
		return map[string]int{}
	}
	return m
}

func insertEdges(ctx context.Context, tx pgx.Tx, ref snapshotRef, edges []*edge) error {
	const batch = 2000
	for i := 0; i < len(edges); i += batch {
		part := edges[i:min(i+batch, len(edges))]
		var sb strings.Builder
		sb.WriteString(`INSERT INTO codegraph_edges (id, organization_id, snapshot_id, edge_key, source_id, target_id, type, evidence) VALUES `)
		args := make([]any, 0, len(part)*8)
		for j, e := range part {
			if j > 0 {
				sb.WriteByte(',')
			}
			b := len(args)
			fmt.Fprintf(&sb, "($%d,$%d,$%d,$%d,$%d,$%d,$%d,$%d)", b+1, b+2, b+3, b+4, b+5, b+6, b+7, b+8)
			args = append(args, e.id, ref.OrgID, ref.ID, clip(e.key, 700), e.source, e.target, e.typ, e.evidence)
		}
		if _, err := tx.Exec(ctx, sb.String(), args...); err != nil {
			return fmt.Errorf("insert edges: %w", err)
		}
	}
	// Evidence rows.
	type ev struct {
		edge uuid.UUID
		r    EvidenceRef
	}
	var all []ev
	for _, e := range edges {
		for _, r := range e.refs {
			all = append(all, ev{e.id, r})
		}
	}
	for i := 0; i < len(all); i += batch {
		part := all[i:min(i+batch, len(all))]
		var sb strings.Builder
		sb.WriteString(`INSERT INTO codegraph_evidence (id, organization_id, snapshot_id, edge_id, evidence, kind, ref, detail, file_path, line) VALUES `)
		args := make([]any, 0, len(part)*10)
		for j, x := range part {
			if j > 0 {
				sb.WriteByte(',')
			}
			b := len(args)
			fmt.Fprintf(&sb, "($%d,$%d,$%d,$%d,$%d,$%d,$%d,$%d,$%d,$%d)", b+1, b+2, b+3, b+4, b+5, b+6, b+7, b+8, b+9, b+10)
			file, line := "", 0
			if x.r.Kind == "file_line" {
				file, line = splitFileLine(x.r.Ref)
				file = clip(file, 1000)
			}
			var lp *int
			if line > 0 {
				lp = &line
			}
			args = append(args, uuid.Must(uuid.NewV7()), ref.OrgID, ref.ID, x.edge, refEvidence[x.r.Kind], x.r.Kind,
				clip(x.r.Ref, maxRefLen), clip(x.r.Detail, maxDetailLen), file, lp)
		}
		if _, err := tx.Exec(ctx, sb.String(), args...); err != nil {
			return fmt.Errorf("insert evidence: %w", err)
		}
	}
	return nil
}

// cleanAttrs keeps scalar attributes (strings, numbers, booleans) within
// maxAttrBytes; nested values are dropped.
func cleanAttrs(in map[string]any) map[string]any {
	out := make(map[string]any, len(in))
	keys := make([]string, 0, len(in))
	for k := range in {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	size := 2
	for _, k := range keys {
		if len(k) > 64 {
			continue
		}
		v := in[k]
		switch x := v.(type) {
		case string:
			v = clip(x, 500)
		case float64, bool, json.Number:
		default:
			continue
		}
		b, _ := json.Marshal(v)
		if size+len(k)+len(b)+4 > maxAttrBytes {
			continue
		}
		size += len(k) + len(b) + 4
		out[k] = v
	}
	return out
}

func attrString(a map[string]any, k string) string {
	if v, ok := a[k].(string); ok {
		return v
	}
	return ""
}

func attrInt(a map[string]any, k string) (int, bool) {
	switch v := a[k].(type) {
	case float64:
		if v >= 0 && v < 1<<30 {
			return int(v), true
		}
	case json.Number:
		if n, err := v.Int64(); err == nil && n >= 0 && n < 1<<30 {
			return int(n), true
		}
	}
	return 0, false
}

func firstNonEmpty(v ...string) string {
	for _, s := range v {
		if s != "" {
			return s
		}
	}
	return ""
}
