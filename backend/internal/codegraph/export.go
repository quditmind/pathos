package codegraph

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"pathos/internal/authz"
	"pathos/internal/platform/buildinfo"
	"pathos/internal/platform/db"
	"pathos/internal/platform/httpx"
	"pathos/internal/platform/objstore"
	"pathos/internal/platform/tenant"
)

func (s *Service) export(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	p, sn, err := s.loadFor(r)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if f := r.URL.Query().Get("format"); f != "" && f != "json" {
		s.fail(w, r, errBadQuery("format must be json (PNG and SVG are rendered in the browser)"))
		return
	}
	if err := s.requireRepo(ctx, p, authz.PermFindingsExport, sn.RepositoryID); err != nil {
		s.fail(w, r, err)
		return
	}
	name := fmt.Sprintf("codegraph-%s.json", sn.ID)
	switch {
	case sn.Storage == "object" && sn.objectKey != nil && s.Artifacts != nil:
		gz, err := s.Artifacts.Get(ctx, *sn.objectKey)
		if err != nil {
			s.fail(w, r, err)
			return
		}
		zr, err := gzip.NewReader(bytes.NewReader(gz))
		if err != nil {
			s.fail(w, r, err)
			return
		}
		httpx.Download(w, "application/json", name)
		// #nosec G110 -- the archive was written by PATHOS itself (bounded by the store limits)
		_, _ = io.Copy(w, zr)
		return
	case sn.Storage != "rows":
		s.fail(w, r, httpx.E(http.StatusConflict, "snapshot_archived", "the snapshot was archived without object storage; only its summary remains").WithDiag(CodeArchived))
		return
	}
	if err := ready(sn); err != nil {
		s.fail(w, r, err)
		return
	}
	httpx.Download(w, "application/json", name)
	bw := bufio.NewWriterSize(w, 64<<10)
	if err := writeExport(ctx, s.DB, sn, bw); err != nil {
		s.Log.Warn("CodeGraph export interrupted", "snapshot_id", sn.ID, "err", err)
		return
	}
	_ = bw.Flush()
}

// writeExport streams a snapshot as version-stamped JSON
// (pathos.codegraph.export/v1): the snapshot summary, every node and every
// edge with all of its evidence references.
func writeExport(ctx context.Context, q db.Querier, sn Snapshot, w io.Writer) error {
	now := time.Now().UTC()
	head, _ := json.Marshal(map[string]any{"schema": ExportSchema, "pathos_version": buildinfo.Version, "pathos_build": buildinfo.Commit,
		"generated_by": buildinfo.Stamp(now), "exported_at": now, "snapshot": sn})
	if _, err := w.Write(head[:len(head)-1]); err != nil {
		return err
	}
	if _, err := io.WriteString(w, `,"nodes":[`); err != nil {
		return err
	}
	rows, err := q.Query(ctx, `SELECT n.id, n.node_key, n.type, n.label, n.layer, p.id, n.group_key, n.attrs, n.finding_counts,
		n.file_path, n.start_line, n.end_line, n.language, n.technology
		FROM codegraph_nodes n LEFT JOIN codegraph_nodes p ON p.id = n.parent_id WHERE n.snapshot_id = $1 ORDER BY n.depth, n.node_key`, sn.ID)
	if err != nil {
		return err
	}
	first := true
	for rows.Next() {
		var n NodeOut
		var parent *uuid.UUID
		var attrs, counts []byte
		var file, lang, tech string
		var start, end *int
		if err := rows.Scan(&n.ID, &n.Key, &n.Type, &n.Label, &n.Layer, &parent, &n.Group, &attrs, &counts, &file, &start, &end, &lang, &tech); err != nil {
			rows.Close()
			return err
		}
		n.Group = "agg:" + n.Group
		_ = json.Unmarshal(attrs, &n.Attrs)
		_ = json.Unmarshal(counts, &n.FindingCounts)
		if n.Attrs == nil {
			n.Attrs = map[string]any{}
		}
		for k, v := range map[string]string{"file": file, "language": lang, "technology": tech} {
			if v != "" {
				n.Attrs[k] = v
			}
		}
		if start != nil {
			n.Attrs["line"] = *start
		}
		if end != nil {
			n.Attrs["end_line"] = *end
		}
		if parent != nil {
			ps := parent.String()
			n.Parent = &ps
		}
		b, _ := json.Marshal(n)
		if !first {
			b = append([]byte{','}, b...)
		}
		first = false
		if _, err := w.Write(b); err != nil {
			rows.Close()
			return err
		}
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return err
	}
	if _, err := io.WriteString(w, `],"edges":[`); err != nil {
		return err
	}
	rows, err = q.Query(ctx, `SELECT e.id, e.source_id, e.target_id, e.type, e.evidence, e.edge_key,
		COALESCE((SELECT json_agg(json_build_object('kind', v.kind, 'ref', v.ref, 'detail', v.detail) ORDER BY v.id)
		          FROM codegraph_evidence v WHERE v.edge_id = e.id), '[]')
		FROM codegraph_edges e WHERE e.snapshot_id = $1 ORDER BY e.edge_key`, sn.ID)
	if err != nil {
		return err
	}
	defer rows.Close()
	first = true
	for rows.Next() {
		var e struct {
			EdgeOut
			Key string `json:"key"`
		}
		var refs []byte
		if err := rows.Scan(&e.ID, &e.Source, &e.Target, &e.Type, &e.Evidence, &e.Key, &refs); err != nil {
			return err
		}
		e.Count = 1
		_ = json.Unmarshal(refs, &e.EvidenceRefs)
		b, _ := json.Marshal(e)
		if !first {
			b = append([]byte{','}, b...)
		}
		first = false
		if _, err := w.Write(b); err != nil {
			return err
		}
	}
	if err := rows.Err(); err != nil {
		return err
	}
	_, err = io.WriteString(w, "]}\n")
	return err
}

// Retain archives each repository's snapshots beyond the organization's
// keep_snapshots setting (the newest ready or partial ones are kept; failed
// snapshots are counted separately and deleted beyond the same number). With object storage the full
// export is written to graphs/<org>/<snapshot>.json.gz first (storage
// "object"); without it only the summary row remains (storage "none").
// Failed snapshots beyond the limit are deleted. It runs in the jobs
// runner across organizations and returns how many snapshots it archived.
func Retain(ctx context.Context, pool *pgxpool.Pool, store objstore.Store) (int, error) {
	if err := Reconcile(ctx, pool, nil); err != nil {
		return 0, err
	}
	rows, err := pool.Query(ctx, `SELECT id, organization_id, status FROM (
		SELECT s.id, s.organization_id, s.status, s.storage,
		       row_number() OVER (PARTITION BY s.repository_id, s.status = 'failed' ORDER BY s.created_at DESC) AS rn,
		       COALESCE(cs.keep_snapshots, 10) AS keep
		FROM codegraph_snapshots s LEFT JOIN codegraph_settings cs ON cs.organization_id = s.organization_id
		WHERE s.status IN ('ready', 'partial', 'failed')) x
		WHERE rn > keep AND storage = 'rows' ORDER BY id LIMIT 200`)
	if err != nil {
		return 0, err
	}
	type item struct {
		id, org uuid.UUID
		status  string
	}
	items, err := pgx.CollectRows(rows, func(r pgx.CollectableRow) (item, error) {
		var it item
		err := r.Scan(&it.id, &it.org, &it.status)
		return it, err
	})
	if err != nil {
		return 0, err
	}
	n := 0
	for _, it := range items {
		octx := tenant.WithOrg(ctx, it.org)
		if it.status == "failed" {
			if _, err := pool.Exec(octx, `DELETE FROM codegraph_snapshots WHERE id = $1`, it.id); err != nil {
				return n, err
			}
			continue
		}
		storage, key := "none", (*string)(nil)
		if store != nil {
			sn, err := scanSnapshot(pool.QueryRow(octx, snapshotSelect+` WHERE s.id = $1`, it.id))
			if err != nil {
				return n, err
			}
			var buf bytes.Buffer
			zw := gzip.NewWriter(&buf)
			if err := writeExport(octx, pool, sn, zw); err != nil {
				return n, err
			}
			if err := zw.Close(); err != nil {
				return n, err
			}
			k := "graphs/" + it.org.String() + "/" + it.id.String() + ".json.gz"
			if err := store.Put(octx, k, buf.Bytes(), "application/gzip"); err != nil {
				return n, fmt.Errorf("archive %s: %w", it.id, err)
			}
			storage, key = "object", &k
		}
		err := db.InTx(octx, pool, func(tx pgx.Tx) error {
			if _, err := tx.Exec(octx, `DELETE FROM codegraph_edges WHERE snapshot_id = $1`, it.id); err != nil {
				return err
			}
			if _, err := tx.Exec(octx, `DELETE FROM codegraph_nodes WHERE snapshot_id = $1`, it.id); err != nil {
				return err
			}
			_, err := tx.Exec(octx, `UPDATE codegraph_snapshots SET status = 'archived', storage = $2, object_key = $3, archived_at = now()
				WHERE id = $1`, it.id, storage, key)
			return err
		})
		if err != nil {
			return n, err
		}
		n++
	}
	return n, nil
}
