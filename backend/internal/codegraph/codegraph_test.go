package codegraph

import (
	"fmt"
	"net/url"
	"path"
	"slices"
	"strings"
	"testing"

	"github.com/google/uuid"
)

// Test fixtures below are synthetic graphs (labelled test data).

func ref(file string, line int) []EvidenceRef {
	return []EvidenceRef{{Kind: "file_line", Ref: fmt.Sprintf("%s:%d", file, line), Detail: "test"}}
}

// sampleDoc is a small service: two packages, an HTTP route, a database,
// a component.
func sampleDoc() *Doc {
	return &Doc{Schema: Schema, Engines: map[string]string{"pathos-graph": "test"}, Stats: map[string]any{},
		Nodes: []DocNode{
			{Key: "repository", Type: "repository", Label: "svc"},
			{Key: "mod:api", Type: "module", Label: "api", Parent: "repository", Attrs: map[string]any{"path": "api"}},
			{Key: "mod:store", Type: "module", Label: "store", Parent: "repository", Attrs: map[string]any{"path": "store"}},
			{Key: "file:api/h.go", Type: "file", Label: "h.go", Parent: "mod:api", Attrs: map[string]any{"file": "api/h.go", "language": "Go"}},
			{Key: "file:store/db.go", Type: "file", Label: "db.go", Parent: "mod:store", Attrs: map[string]any{"file": "store/db.go", "language": "Go"}},
			{Key: "fn:api.Get", Type: "function", Label: "Get", Parent: "file:api/h.go", Attrs: map[string]any{"file": "api/h.go", "line": 10.0, "end_line": 20.0}},
			{Key: "fn:store.Load", Type: "function", Label: "Load", Parent: "file:store/db.go", Attrs: map[string]any{"file": "store/db.go", "line": 5.0, "end_line": 15.0}},
			{Key: "route:GET /x", Type: "route", Label: "GET /x", Parent: "file:api/h.go", Attrs: map[string]any{"file": "api/h.go", "line": 3.0}},
			{Key: "ds:postgres", Type: "datastore", Label: "PostgreSQL"},
			{Key: "tb:http-ingress", Type: "trust_boundary", Label: "HTTP ingress"},
			{Key: "comp:pkg:golang/x/y", Type: "component", Label: "x/y", Attrs: map[string]any{"name": "x/y", "version": "1.0.0"}},
		},
		Edges: []DocEdge{
			{Source: "fn:api.Get", Target: "fn:store.Load", Type: "calls", Evidence: "verified", EvidenceRefs: ref("api/h.go", 12)},
			{Source: "fn:api.Get", Target: "fn:store.Load", Type: "calls", Evidence: "verified", EvidenceRefs: ref("api/h.go", 14)},
			{Source: "route:GET /x", Target: "fn:api.Get", Type: "exposes", Evidence: "verified", EvidenceRefs: ref("api/h.go", 3)},
			{Source: "route:GET /x", Target: "tb:http-ingress", Type: "crosses_boundary", Evidence: "verified", EvidenceRefs: ref("api/h.go", 3)},
			{Source: "fn:store.Load", Target: "ds:postgres", Type: "reads", Evidence: "verified", EvidenceRefs: ref("store/db.go", 8)},
			{Source: "file:api/h.go", Target: "mod:store", Type: "imports", Evidence: "verified", EvidenceRefs: ref("api/h.go", 4)},
			{Source: "repository", Target: "comp:pkg:golang/x/y", Type: "depends_on", Evidence: "verified",
				EvidenceRefs: []EvidenceRef{{Kind: "sbom", Ref: "pkg:golang/x/y@1.0.0"}}},
		}}
}

// skeletonFromDoc builds a skeleton without a database.
func skeletonFromDoc(t *testing.T, d *Doc) *skeleton {
	t.Helper()
	if err := Validate(d); err != nil {
		t.Fatal(err)
	}
	sk := &skeleton{id: uuid.New(), byID: map[uuid.UUID]int32{}, byKey: map[string]int32{}}
	tmp := map[string]*node{}
	for _, dn := range d.Nodes {
		n := &node{DocNode: dn}
		n.Attrs = cleanAttrs(n.Attrs)
		n.file = attrString(n.Attrs, "file")
		tmp[n.Key] = n
	}
	for _, dn := range d.Nodes {
		n := tmp[dn.Key]
		sn := snode{id: uuid.New(), key: dn.Key, typ: dn.Type, layer: dn.Layer, label: dn.Label, file: n.file, group: groupKey(n, tmp), parent: -1}
		sk.byID[sn.id] = int32(len(sk.nodes))
		sk.byKey[sn.key] = int32(len(sk.nodes))
		sk.nodes = append(sk.nodes, sn)
	}
	sk.childs = make([][]int32, len(sk.nodes))
	for i, dn := range d.Nodes {
		if p, ok := sk.byKey[dn.Parent]; ok {
			sk.nodes[i].parent = p
			sk.childs[p] = append(sk.childs[p], int32(i))
		}
	}
	sk.out = make([][]int32, len(sk.nodes))
	sk.in = make([][]int32, len(sk.nodes))
	for _, de := range d.Edges {
		e := sedge{id: uuid.New(), src: sk.byKey[de.Source], dst: sk.byKey[de.Target], typ: de.Type, evidence: de.Evidence,
			key: EdgeKey(de.Source, de.Type, de.Target)}
		i := int32(len(sk.edges))
		sk.edges = append(sk.edges, e)
		sk.out[e.src] = append(sk.out[e.src], i)
		sk.in[e.dst] = append(sk.in[e.dst], i)
	}
	return sk
}

func TestValidateAcceptsAndMerges(t *testing.T) {
	d := sampleDoc()
	if err := Validate(d); err != nil {
		t.Fatal(err)
	}
	if len(d.Edges) != 6 {
		t.Fatalf("duplicate calls edge not merged: %d edges", len(d.Edges))
	}
	for _, e := range d.Edges {
		if len(e.EvidenceRefs) == 0 {
			t.Fatalf("edge without evidence after validation: %+v", e)
		}
		if e.Type == "calls" && len(e.EvidenceRefs) != 2 {
			t.Errorf("merged calls edge keeps both call sites, got %v", e.EvidenceRefs)
		}
	}
	for _, n := range d.Nodes {
		if n.Layer == "" {
			t.Errorf("node %s has no layer", n.Key)
		}
	}
}

func TestValidateRefuses(t *testing.T) {
	cases := map[string]func(d *Doc){
		"schema":            func(d *Doc) { d.Schema = "other" },
		"edge without refs": func(d *Doc) { d.Edges[0].EvidenceRefs = nil },
		"ai_inferred":       func(d *Doc) { d.Edges[0].Evidence = "ai_inferred" },
		"observed":          func(d *Doc) { d.Edges[0].Evidence = "observed" },
		"runtime ref":       func(d *Doc) { d.Edges[0].EvidenceRefs = []EvidenceRef{{Kind: "runtime", Ref: "x"}} },
		"bad file_line":     func(d *Doc) { d.Edges[0].EvidenceRefs = []EvidenceRef{{Kind: "file_line", Ref: ":"}} },
		"unknown edge type": func(d *Doc) { d.Edges[0].Type = "flows" },
		"owns from doc":     func(d *Doc) { d.Edges[0].Type = "owns" },
		"missing target":    func(d *Doc) { d.Edges[0].Target = "nope" },
		"unknown node type": func(d *Doc) { d.Nodes[3].Type = "thing" },
		"application node":  func(d *Doc) { d.Nodes[3].Type = "application" },
		"duplicate key":     func(d *Doc) { d.Nodes[4].Key = d.Nodes[3].Key },
		"two repositories":  func(d *Doc) { d.Nodes[1].Type = "repository" },
		"cycle": func(d *Doc) {
			d.Nodes[1].Parent = "file:api/h.go"
		},
		"missing parent": func(d *Doc) { d.Nodes[3].Parent = "mod:none" },
		"bad layer":      func(d *Doc) { d.Nodes[3].Layer = "runtime" },
	}
	for name, mutate := range cases {
		d := sampleDoc()
		mutate(d)
		err := Validate(d)
		var ve *ValidationError
		if err == nil || !asValidation(err, &ve) {
			t.Errorf("%s: want a validation error, got %v", name, err)
		}
	}
}

func asValidation(err error, ve **ValidationError) bool {
	v, ok := err.(*ValidationError)
	*ve = v
	return ok
}

func TestViewsReturnOnlyTheirTypesAndEvidence(t *testing.T) {
	sk := skeletonFromDoc(t, sampleDoc())
	if len(Views) != 15 {
		t.Fatalf("%d views, want 15", len(Views))
	}
	for _, def := range Views {
		res, err := sk.compute(def, viewParams{limit: defaultLimit, depth: 1, diff: &diffResult{}})
		if err != nil {
			t.Fatalf("%s: %v", def.Name, err)
		}
		for _, u := range res.units {
			if u.node >= 0 && !slices.Contains(def.NodeTypes, sk.nodes[u.node].typ) {
				t.Errorf("%s shows a %s node", def.Name, sk.nodes[u.node].typ)
			}
		}
		for _, e := range res.edges {
			if !slices.Contains(def.EdgeTypes, e.typ) || len(e.samples) == 0 || e.evidence == "" {
				t.Errorf("%s: edge %+v", def.Name, e)
			}
		}
	}
}

func TestArchitectureLiftsCallsToModules(t *testing.T) {
	sk := skeletonFromDoc(t, sampleDoc())
	def, _ := ViewByName("architecture")
	res, err := sk.compute(def, viewParams{limit: defaultLimit, depth: 1})
	if err != nil {
		t.Fatal(err)
	}
	found := map[string]vedge{}
	for _, e := range res.edges {
		found[sk.nodes[res.units[e.a].node].key+" "+e.typ+" "+sk.nodes[res.units[e.b].node].key] = e
	}
	calls, ok := found["mod:api calls mod:store"]
	if !ok || calls.original {
		t.Fatalf("calls not lifted to modules: %v", found)
	}
	if _, ok := found["mod:api imports mod:store"]; !ok {
		t.Errorf("imports not lifted: %v", found)
	}
	if _, ok := found["mod:store reads ds:postgres"]; !ok {
		t.Errorf("reads not lifted: %v", found)
	}
}

func TestPruneAndFocus(t *testing.T) {
	sk := skeletonFromDoc(t, sampleDoc())
	def, _ := ViewByName("datastores")
	res, _ := sk.compute(def, viewParams{limit: defaultLimit, depth: 1})
	var keys []string
	for _, u := range res.units {
		keys = append(keys, sk.nodes[u.node].key)
	}
	if slices.Contains(keys, "fn:api.Get") || !slices.Contains(keys, "fn:store.Load") || !slices.Contains(keys, "ds:postgres") {
		t.Errorf("datastores view keeps only connected functions: %v", keys)
	}
	// Focus on a module of the architecture view expands its children.
	arch, _ := ViewByName("architecture")
	mod := sk.nodes[sk.byKey["mod:api"]].id.String()
	res, err := sk.compute(arch, viewParams{limit: defaultLimit, depth: 1, focus: mod})
	if err != nil {
		t.Fatal(err)
	}
	keys = keys[:0]
	for _, u := range res.units {
		keys = append(keys, sk.nodes[u.node].key)
	}
	if !slices.Contains(keys, "file:api/h.go") || !slices.Contains(keys, "mod:store") {
		t.Errorf("focus did not expand children and neighbours: %v", keys)
	}
	if _, err := sk.compute(arch, viewParams{limit: 5, depth: 1, focus: "not-a-uuid"}); err == nil {
		t.Error("bad focus accepted")
	}
}

// bigDoc is a synthetic graph of n functions spread over directories.
func bigDoc(n int) *Doc {
	d := &Doc{Schema: Schema, Nodes: []DocNode{{Key: "repository", Type: "repository", Label: "big"}}}
	for i := 0; i < n; i++ {
		dir := fmt.Sprintf("pkg%d/sub%d", i%7, i%13)
		file := path.Join(dir, fmt.Sprintf("f%d.go", i%50))
		fk := "file:" + file
		if !slices.ContainsFunc(d.Nodes, func(x DocNode) bool { return x.Key == fk }) {
			d.Nodes = append(d.Nodes, DocNode{Key: fk, Type: "file", Label: path.Base(file), Parent: "repository", Attrs: map[string]any{"file": file}})
		}
		d.Nodes = append(d.Nodes, DocNode{Key: fmt.Sprintf("fn:%d", i), Type: "function", Label: fmt.Sprintf("F%d", i), Parent: fk,
			Attrs: map[string]any{"file": file, "line": float64(i)}})
		if i > 0 {
			d.Edges = append(d.Edges, DocEdge{Source: fmt.Sprintf("fn:%d", i), Target: fmt.Sprintf("fn:%d", (i*7)%i), Type: "calls",
				Evidence: "verified", EvidenceRefs: ref(file, i)})
		}
	}
	return d
}

func TestAggregationAndExpansion(t *testing.T) {
	sk := skeletonFromDoc(t, bigDoc(3000))
	def, _ := ViewByName("call_graph")
	res, err := sk.compute(def, viewParams{limit: 50, depth: 1})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.units) > 50 {
		t.Fatalf("%d units over the limit", len(res.units))
	}
	aggs := 0
	members := 0
	for _, u := range res.units {
		if u.node < 0 {
			aggs++
			members += len(u.members)
		} else {
			members++
		}
	}
	if aggs == 0 || members != 3000 {
		t.Fatalf("aggregation: %d aggregates, %d members", aggs, members)
	}
	for _, e := range res.edges {
		if e.count < 1 || len(e.samples) == 0 {
			t.Fatalf("aggregated edge without samples: %+v", e)
		}
	}
	// Expanding an aggregate shows its members one level deeper.
	var g string
	for _, u := range res.units {
		if u.node < 0 {
			g = u.group
			break
		}
	}
	res2, err := sk.compute(def, viewParams{limit: 2000, depth: 1, focus: "agg:" + g})
	if err != nil {
		t.Fatal(err)
	}
	in := 0
	for _, u := range res2.units {
		if (u.node >= 0 && inGroup(sk.nodes[u.node].group, g)) || (u.node < 0 && u.group != g && inGroup(u.group, g)) {
			in++
		}
	}
	if in == 0 {
		t.Errorf("expanding %s returned no member nodes", g)
	}
}

func TestPathsBounded(t *testing.T) {
	sk := skeletonFromDoc(t, sampleDoc())
	from := sk.byKey["route:GET /x"]
	to := sk.byKey["ds:postgres"]
	res := sk.paths(from, to, "out", 8, 10, nil)
	if len(res.paths) != 1 || len(res.paths[0]) != 3 {
		t.Fatalf("route → handler → load → postgres: %v", res.paths)
	}
	in := sk.paths(to, -1, "in", 8, 10, nil)
	if len(in.paths) == 0 {
		t.Fatal("no inbound paths to the datastore")
	}
	short := sk.paths(from, to, "out", 2, 10, nil)
	if len(short.paths) != 0 {
		t.Errorf("hop limit ignored: %v", short.paths)
	}
	typed := sk.paths(from, to, "out", 8, 10, []string{"exposes"})
	if len(typed.paths) != 0 {
		t.Errorf("edge type filter ignored: %v", typed.paths)
	}
}

func TestDiffByKeys(t *testing.T) {
	a := skeletonFromDoc(t, sampleDoc())
	d2 := sampleDoc()
	d2.Nodes = append(d2.Nodes, DocNode{Key: "fn:api.Put", Type: "function", Label: "Put", Parent: "file:api/h.go"})
	d2.Edges = d2.Edges[1:] // drop one call (merged duplicate goes with it)
	d2.Edges = slices.DeleteFunc(d2.Edges, func(e DocEdge) bool { return e.Type == "calls" })
	d2.Nodes[5].Label = "GetAll"
	b := skeletonFromDoc(t, d2)
	df := diff(a, b)
	if !slices.Equal(df.addedNodes, []string{"fn:api.Put"}) || !slices.Contains(df.changedNodes, "fn:api.Get") || len(df.removedNodes) != 0 {
		t.Errorf("nodes: %+v", df)
	}
	if len(df.removedEdges) != 1 || !strings.Contains(df.removedEdges[0], "|calls|") {
		t.Errorf("edges: %+v", df.removedEdges)
	}
	// change_impact shows the changed and added nodes with neighbours.
	def, _ := ViewByName("change_impact")
	res, err := b.compute(def, viewParams{limit: defaultLimit, depth: 1, diff: df})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.changed) != 2 {
		t.Errorf("change marks: %v", res.changed)
	}
}

func TestParseViewParams(t *testing.T) {
	ok := []string{"view=call_graph&limit=2000&depth=3&layers=code,api&filters=type:function,language:Go,severity:high,evidence:verified,q:auth"}
	bad := []string{"view=nope", "limit=2001", "depth=4", "layers=x", "filters=type", "filters=severity:urgent", "filters=evidence:guess", "filters=color:red"}
	for _, q := range ok {
		v, _ := url.ParseQuery(q)
		if _, _, err := parseViewParams(v); err != nil {
			t.Errorf("%s: %v", q, err)
		}
	}
	for _, q := range bad {
		v, _ := url.ParseQuery(q)
		if _, _, err := parseViewParams(v); err == nil {
			t.Errorf("%s accepted", q)
		}
	}
}

func TestGroupHelpers(t *testing.T) {
	if groupAt("dir:a/b/c", 1) != "dir:a" || groupAt("dir:a/b/c", 5) != "dir:a/b/c" || groupAt("type:component", 1) != "type:component" {
		t.Error("groupAt")
	}
	if !inGroup("dir:a/b", "dir:a") || inGroup("dir:ab", "dir:a") || !inGroup("dir:x", "dir:.") {
		t.Error("inGroup")
	}
	if f, l := splitFileLine("a/b.go:12"); f != "a/b.go" || l != 12 {
		t.Error("splitFileLine")
	}
	if cleanDir("../../etc/passwd", false) != "etc" {
		t.Errorf("cleanDir escapes: %q", cleanDir("../../etc/passwd", false))
	}
}

func TestInnermost(t *testing.T) {
	i := func(v int) *int { return &v }
	file := &node{DocNode: DocNode{Type: "file"}}
	outer := &node{DocNode: DocNode{Type: "class"}, start: i(1), end: i(100)}
	inner := &node{DocNode: DocNode{Type: "function"}, start: i(10), end: i(20)}
	ns := []*node{file, outer, inner}
	if innermost(ns, 15) != inner || innermost(ns, 50) != outer || innermost(ns, 200) != file || innermost(ns, 0) != file {
		t.Error("innermost")
	}
}
