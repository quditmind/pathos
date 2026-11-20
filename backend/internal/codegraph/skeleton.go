package codegraph

import (
	"context"
	"encoding/json"
	"slices"
	"sync"

	"github.com/google/uuid"

	"pathos/internal/platform/db"
)

// skeleton is the compact in-memory form of a ready snapshot used by the
// view, path and diff computations: every node and edge, without
// attributes or evidence (those are read for the result only). Snapshots
// never change once ready, so skeletons are cached by snapshot id; every
// request checks access to the snapshot in the database before using one.
type skeleton struct {
	id     uuid.UUID
	nodes  []snode
	edges  []sedge
	byID   map[uuid.UUID]int32
	byKey  map[string]int32
	out    [][]int32 // edge indexes by source node
	in     [][]int32 // edge indexes by target node
	childs [][]int32 // containment children
}

type snode struct {
	id       uuid.UUID
	key      string
	typ      string
	layer    string
	parent   int32 // -1: none
	group    string
	label    string
	file     string
	language string
	tech     string
	total    int32
	sev      map[string]int32
}

type sedge struct {
	id       uuid.UUID
	src, dst int32
	typ      string
	evidence string
	key      string
}

func loadSkeleton(ctx context.Context, q db.Querier, snapshotID uuid.UUID) (*skeleton, error) {
	sk := &skeleton{id: snapshotID, byID: map[uuid.UUID]int32{}, byKey: map[string]int32{}}
	rows, err := q.Query(ctx, `SELECT id, node_key, type, layer, parent_id, group_key, label, file_path, language, technology,
		finding_total, finding_counts FROM codegraph_nodes WHERE snapshot_id = $1`, snapshotID)
	if err != nil {
		return nil, err
	}
	parents := []*uuid.UUID{}
	for rows.Next() {
		var n snode
		var parent *uuid.UUID
		var counts []byte
		if err := rows.Scan(&n.id, &n.key, &n.typ, &n.layer, &parent, &n.group, &n.label, &n.file, &n.language, &n.tech,
			&n.total, &counts); err != nil {
			rows.Close()
			return nil, err
		}
		if n.total > 0 {
			_ = json.Unmarshal(counts, &n.sev)
		}
		// #nosec G115 -- a snapshot holds at most maxNodes (400,000) nodes (Validate)
		idx := int32(len(sk.nodes))
		sk.byID[n.id] = idx
		sk.byKey[n.key] = idx
		sk.nodes = append(sk.nodes, n)
		parents = append(parents, parent)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}
	sk.childs = make([][]int32, len(sk.nodes))
	for i, p := range parents {
		sk.nodes[i].parent = -1
		if p != nil {
			if j, ok := sk.byID[*p]; ok {
				sk.nodes[i].parent = j
				sk.childs[j] = append(sk.childs[j], int32(i))
			}
		}
	}
	rows, err = q.Query(ctx, `SELECT id, source_id, target_id, type, evidence, edge_key FROM codegraph_edges WHERE snapshot_id = $1`, snapshotID)
	if err != nil {
		return nil, err
	}
	sk.out = make([][]int32, len(sk.nodes))
	sk.in = make([][]int32, len(sk.nodes))
	for rows.Next() {
		var e sedge
		var src, dst uuid.UUID
		if err := rows.Scan(&e.id, &src, &dst, &e.typ, &e.evidence, &e.key); err != nil {
			rows.Close()
			return nil, err
		}
		s, ok1 := sk.byID[src]
		d, ok2 := sk.byID[dst]
		if !ok1 || !ok2 {
			continue
		}
		e.src, e.dst = s, d
		i := int32(len(sk.edges)) // #nosec G115 -- a snapshot holds at most maxEdges (600,000) edges plus the enrichment ones
		sk.edges = append(sk.edges, e)
		sk.out[s] = append(sk.out[s], i)
		sk.in[d] = append(sk.in[d], i)
	}
	rows.Close()
	return sk, rows.Err()
}

// skeletonCache keeps the skeletons of recently used snapshots, bounded by
// their total node and edge count.
type skeletonCache struct {
	mu    sync.Mutex
	order []uuid.UUID
	m     map[uuid.UUID]*skeleton
	size  int
	max   int
}

func (c *skeletonCache) get(id uuid.UUID) *skeleton {
	if c == nil {
		return nil
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	sk := c.m[id]
	if sk != nil {
		c.order = append(slices.DeleteFunc(c.order, func(x uuid.UUID) bool { return x == id }), id)
	}
	return sk
}

func (c *skeletonCache) put(sk *skeleton) {
	if c == nil {
		return
	}
	n := len(sk.nodes) + len(sk.edges)
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.m == nil {
		c.m = map[uuid.UUID]*skeleton{}
	}
	if c.max == 0 {
		c.max = 1_500_000
	}
	if n > c.max {
		return
	}
	if old := c.m[sk.id]; old != nil {
		c.size -= len(old.nodes) + len(old.edges)
		c.order = slices.DeleteFunc(c.order, func(x uuid.UUID) bool { return x == sk.id })
	}
	for c.size+n > c.max && len(c.order) > 0 {
		ev := c.m[c.order[0]]
		c.size -= len(ev.nodes) + len(ev.edges)
		delete(c.m, c.order[0])
		c.order = c.order[1:]
	}
	c.m[sk.id] = sk
	c.order = append(c.order, sk.id)
	c.size += n
}

func (c *skeletonCache) drop(id uuid.UUID) {
	if c == nil {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if old := c.m[id]; old != nil {
		c.size -= len(old.nodes) + len(old.edges)
		delete(c.m, id)
		c.order = slices.DeleteFunc(c.order, func(x uuid.UUID) bool { return x == id })
	}
}
