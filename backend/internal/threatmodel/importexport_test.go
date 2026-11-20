package threatmodel

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"pathos/internal/platform/httpx"
)

// sampleExport is test data: a small exported model.
func sampleExport() Export {
	repo := uuid.Must(uuid.NewV7())
	route := ElementOut{ID: uuid.Must(uuid.NewV7()), Kind: KindProcess, Name: "POST /api/orders", CodegraphKey: "route:POST /api/orders", NodeType: "route",
		RepositoryID: &repo, ElementKey: elementKey(&repo, "route:POST /api/orders")}
	store := ElementOut{ID: uuid.Must(uuid.NewV7()), Kind: KindDataStore, Name: "PostgreSQL", CodegraphKey: "ds:postgresql", NodeType: "datastore",
		RepositoryID: &repo, ElementKey: elementKey(&repo, "ds:postgresql")}
	flow := ElementOut{ID: uuid.Must(uuid.NewV7()), Kind: KindDataFlow, Name: "createOrder → PostgreSQL", CodegraphKey: "a|writes|b", NodeType: "writes",
		RepositoryID: &repo, SourceKey: "route:POST /api/orders", TargetKey: "ds:postgresql", ElementKey: elementKey(&repo, "a|writes|b")}
	now := time.Now()
	m := Model{ID: uuid.Must(uuid.NewV7()), Version: 2, Title: "Orders | threat model", ApplicationName: "Orders", Status: "approved",
		Summary: "Test model\nsecond line", ApprovedBy: &Person{Name: "Lee"}, ApprovedAt: &now}
	threats := []ThreatOut{
		{ID: uuid.Must(uuid.NewV7()), Title: "Unauthenticated entry point POST /api/orders", Category: Spoofing, Method: MethodRule, RuleID: "TM-S-001",
			RuleVersion: "1", Severity: "critical", Confidence: 0.55, Status: "open", Mitigation: "Require authentication.", Label: "verified",
			EvidenceType: EvidenceVerified, Elements: []ElementOut{route},
			Evidence: Evidence{Nodes: []EvNode{{Key: "route:POST /api/orders", Type: "route", Label: "POST /api/orders", File: "api.go", Line: 3}},
				Edges: []EvEdge{{Key: "k", Source: "route:POST /api/orders", Target: "tb:http-ingress", Type: "crosses_boundary", Evidence: "verified",
					Refs: []Ref{{Kind: "file_line", Ref: "api.go:3"}}}}},
			Mappings: []MappingOut{{Framework: "attack", ID: "T1190", Name: "Exploit Public-Facing Application", Source: "rule"}}},
		{ID: uuid.Must(uuid.NewV7()), Title: "Tampering with PostgreSQL", Category: Tampering, Method: MethodRule, RuleID: "TM-T-001", RuleVersion: "1",
			Severity: "high", Confidence: 0.8, Status: "not_applicable", StatusReason: "parameterised queries everywhere", Mitigation: "Validate input.",
			Label: "verified", EvidenceType: EvidenceVerified, Elements: []ElementOut{store}},
		{ID: uuid.Must(uuid.NewV7()), Title: "Linkable order history", Category: "linking", Method: MethodManual, Severity: "low", Confidence: 0.5,
			Status: "mitigated", Mitigation: "Pseudonymise customer ids.", Label: "manual, unverified", EvidenceType: EvidenceUnverified, Elements: []ElementOut{flow}},
		{ID: uuid.Must(uuid.NewV7()), Title: "Attack path to SQL injection", Category: Tampering, Method: MethodAttackPath, RuleID: "TM-AP-001", RuleVersion: "1",
			Severity: "medium", Confidence: 0.8, Status: "accepted", Mitigation: "Fix the finding.", Label: "verified", EvidenceType: EvidenceVerified},
	}
	return Export{Schema: ExportSchema, GeneratedBy: "Quditmind PATHOS vtest · build x · generated now", Notices: []string{"notice"}, Model: m,
		Elements: []ElementOut{route, store, flow}, Threats: threats}
}

func TestThreatDragonRoundTrip(t *testing.T) {
	ex := sampleExport()
	td := ThreatDragon(ex)
	raw, err := json.Marshal(td)
	if err != nil {
		t.Fatal(err)
	}
	if td.Version == "" || len(td.Detail.Diagrams) != 1 || td.Detail.ThreatTop != 4 || td.Detail.Reviewer != "Lee" {
		t.Fatalf("export: %+v", td.Detail)
	}
	var flows int
	for _, c := range td.Detail.Diagrams[0].Cells {
		if c.Shape == "flow" {
			flows++
			if c.Source == nil || c.Target == nil {
				t.Errorf("flow without ends: %+v", c)
			}
		}
	}
	if flows != 1 {
		t.Errorf("%d flows", flows)
	}
	doc, err := ParseThreatDragon(raw)
	if err != nil {
		t.Fatal(err)
	}
	if doc.title != ex.Model.Title || len(doc.threats) != 4 || len(doc.elements) != 4 {
		t.Fatalf("import: title %q, %d threats, %d elements", doc.title, len(doc.threats), len(doc.elements))
	}
	by := map[string]importedThreat{}
	for _, it := range doc.threats {
		by[it.row.Title] = it
		if it.row.Method != MethodImported || it.row.EvidenceType != EvidenceUnverified || it.row.Evidence.Imported["format"] != "threat_dragon" {
			t.Errorf("imported threat not labelled imported, unverified: %+v", it.row)
		}
	}
	checks := []struct{ title, category, severity, status string }{
		{"Unauthenticated entry point POST /api/orders", Spoofing, "high", "open"}, // critical → High in Threat Dragon
		{"Tampering with PostgreSQL", Tampering, "high", "not_applicable"},
		{"Linkable order history", "linking", "low", "mitigated"},
		{"Attack path to SQL injection", Tampering, "medium", "open"}, // accepted → Open (noted in the description)
	}
	for _, c := range checks {
		it, ok := by[c.title]
		if !ok {
			t.Errorf("missing %q", c.title)
			continue
		}
		if it.row.Category != c.category || it.row.Severity != c.severity || it.row.Status != c.status {
			t.Errorf("%q: %s %s %s", c.title, it.row.Category, it.row.Severity, it.row.Status)
		}
		if it.row.Mitigation == "" {
			t.Errorf("%q lost its mitigation", c.title)
		}
	}
	if !strings.Contains(by["Attack path to SQL injection"].row.Description, "status accepted") {
		t.Error("accepted status not carried in the description")
	}
	if !strings.Contains(by["Unauthenticated entry point POST /api/orders"].row.Description, "TM-S-001") {
		t.Error("rule not carried in the description")
	}
	// The flow keeps its ends.
	for _, e := range doc.elements {
		if e.ref.Kind == KindDataFlow && (e.ref.Source == "" || e.ref.Target == "") {
			t.Errorf("flow ends lost: %+v", e.ref)
		}
	}
}

// A Threat Dragon v2 model as the Threat Dragon application writes it
// (hand-written test data, shapes and fields of the v2 format).
const tdSample = `{
  "version": "2.2.0",
  "summary": {"title": "Demo shop", "owner": "", "description": "test data", "id": 0},
  "detail": {
    "contributors": [], "reviewer": "", "threatTop": 2, "diagramTop": 1,
    "diagrams": [{
      "id": 0, "title": "Main", "diagramType": "STRIDE", "placeholder": "", "thumbnail": "", "version": "2.2.0",
      "cells": [
        {"position": {"x": 10, "y": 10}, "size": {"width": 100, "height": 100}, "shape": "actor", "id": "a1", "zIndex": 1,
         "data": {"type": "tm.Actor", "name": "Customer", "description": "", "outOfScope": false, "reasonOutOfScope": "", "providesAuthentication": false, "threats": []}},
        {"position": {"x": 200, "y": 10}, "size": {"width": 100, "height": 100}, "shape": "process", "id": "p1", "zIndex": 2,
         "data": {"type": "tm.Process", "name": "Web shop", "description": "", "outOfScope": false, "reasonOutOfScope": "", "privilegeLevel": "",
           "threats": [{"id": "t1", "title": "Session hijack", "status": "Open", "severity": "High", "type": "Spoofing", "description": "cookie theft",
             "mitigation": "Secure cookies", "modelType": "STRIDE", "new": false, "number": 1, "score": ""},
             {"id": "t2", "title": "Unclear scoring", "status": "NotApplicable", "severity": "TBD", "type": "Detectability", "description": "",
             "mitigation": "", "modelType": "LINDDUN", "new": false, "number": 2, "score": ""}]}},
        {"shape": "flow", "id": "f1", "zIndex": 3, "source": {"cell": "a1"}, "target": {"cell": "p1"},
         "data": {"type": "tm.Flow", "name": "HTTPS", "description": "", "outOfScope": false, "reasonOutOfScope": "", "protocol": "https",
           "isEncrypted": true, "isPublicNetwork": true, "isBidirectional": false, "threats": []}},
        {"shape": "td-text-block", "id": "x1", "zIndex": 4, "data": {"type": "tm.Text", "name": "note"}}
      ]
    }]
  }
}`

func TestParseThreatDragonSample(t *testing.T) {
	doc, err := ParseThreatDragon([]byte(tdSample))
	if err != nil {
		t.Fatal(err)
	}
	if doc.title != "Demo shop" || len(doc.elements) != 3 || len(doc.threats) != 2 {
		t.Fatalf("%q %d elements %d threats", doc.title, len(doc.elements), len(doc.threats))
	}
	t2 := doc.threats[1].row
	if t2.Category != "detecting" || t2.Severity != "medium" || t2.Status != "not_applicable" || !strings.Contains(t2.SeverityReason, "TBD") {
		t.Errorf("LINDDUN / TBD threat: %+v", t2)
	}
}

func TestParseErrors(t *testing.T) {
	for name, c := range map[string]struct {
		raw  string
		f    func([]byte) (*imported, error)
		code string
	}{
		"not json":         {`{"version": `, ParseThreatDragon, CodeImportParse},
		"no diagrams":      {`{"version": "2.0", "summary": {"title": "x"}, "detail": {}}`, ParseThreatDragon, CodeImportParse},
		"v1":               {`{"summary": {"title": "x"}, "detail": {"diagrams": [{"diagramJson": {"cells": []}}]}}`, ParseThreatDragon, CodeImportParse},
		"flow without end": {`{"detail": {"diagrams": [{"cells": [{"id": "f", "shape": "flow", "data": {"type": "tm.Flow"}}]}]}}`, ParseThreatDragon, CodeImportParse},
		"wrong schema":     {`{"schema": "other"}`, ParsePathos, CodeImportParse},
		"bad threat":       {`{"schema": "pathos.threatmodel/v1", "threats": [{"title": "x", "category": "nope", "severity": "high"}]}`, ParsePathos, CodeImportParse},
	} {
		_, err := c.f([]byte(c.raw))
		var he *httpx.Error
		if !errors.As(err, &he) || he.DiagCode() != c.code {
			t.Errorf("%s: %v", name, err)
		}
	}
	// Line numbers in parse errors.
	_, err := ParseThreatDragon([]byte("{\n\"version\": \"2\",\n\"detail\": [}\n"))
	if err == nil || !strings.Contains(err.Error(), "line 3") {
		t.Errorf("no line in %v", err)
	}
}

func TestPathosRoundTrip(t *testing.T) {
	ex := sampleExport()
	raw, _ := json.Marshal(ex)
	doc, err := ParsePathos(raw)
	if err != nil {
		t.Fatal(err)
	}
	if len(doc.threats) != 4 || len(doc.elements) != 3 {
		t.Fatalf("%d threats %d elements", len(doc.threats), len(doc.elements))
	}
	first := doc.threats[0]
	if len(first.keys) != 1 || first.keys[0] != "route:POST /api/orders" || len(first.mappings) != 1 || first.mappings[0].Source != "imported" {
		t.Errorf("keys %v mappings %v", first.keys, first.mappings)
	}
	if first.row.Evidence.Imported["rule_id"] != "TM-S-001" || first.row.Severity != "critical" {
		t.Errorf("imported evidence %+v", first.row)
	}
}

func TestPytmAndMarkdown(t *testing.T) {
	ex := sampleExport()
	py := Pytm(ex)
	for _, want := range []string{"from pytm import", `tm = TM("Orders | threat model")`, `Process("POST /api/orders")`, `Datastore("PostgreSQL")`,
		"Dataflow(e1, e2", "tm.process()", "# T1 [critical, open]"} {
		if !strings.Contains(py, want) {
			t.Errorf("pytm lacks %q:\n%s", want, py)
		}
	}
	// Strings cannot break out of their literal.
	ex.Model.Title = "x\")\nimport os\n(\""
	if py := Pytm(ex); strings.Contains(py, "\nimport os") {
		t.Error("unescaped title in pytm output")
	}
	md := Markdown(sampleExport())
	for _, want := range []string{"# Orders \\| threat model", "| 1 | Unauthenticated entry point", "TM-S-001 v1", "api.go:3", "**Mitigation.**", "notice"} {
		if !strings.Contains(md, want) {
			t.Errorf("markdown lacks %q", want)
		}
	}
	if fileName("Orders | threat model", 2, "md") != "orders---threat-model-v2.md" {
		t.Errorf("file name %s", fileName("Orders | threat model", 2, "md"))
	}
}
