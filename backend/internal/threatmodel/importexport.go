package threatmodel

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"pathos/internal/authz"
	"pathos/internal/platform/buildinfo"
	"pathos/internal/platform/db"
	"pathos/internal/platform/httpx"
	"pathos/internal/threatmodel/frameworks"
)

// ExportSchema is the PATHOS threat-model export schema.
const ExportSchema = "pathos.threatmodel/v1"

// Import limits (PTH-TM-1103).
const (
	maxImportElements = 2000
	maxImportThreats  = 5000
)

// Export is the PATHOS JSON export of one version.
type Export struct {
	Schema      string       `json:"schema"`
	GeneratedBy string       `json:"generated_by"`
	Notices     []string     `json:"notices"`
	Model       Model        `json:"model"`
	Elements    []ElementOut `json:"elements"`
	Threats     []ThreatOut  `json:"threats"`
	Approvals   []Approval   `json:"approvals"`
}

func (s *Service) loadExport(ctx context.Context, m Model, now time.Time) (Export, error) {
	els, err := listElements(ctx, s.DB, m.ID)
	if err != nil {
		return Export{}, err
	}
	ts, err := listThreats(ctx, s.DB, m.ID, ThreatFilter{})
	if err != nil {
		return Export{}, err
	}
	as, err := listApprovals(ctx, s.DB, m.LineageID)
	if err != nil {
		return Export{}, err
	}
	if els == nil {
		els = []ElementOut{}
	}
	if ts == nil {
		ts = []ThreatOut{}
	}
	if as == nil {
		as = []Approval{}
	}
	return Export{Schema: ExportSchema, GeneratedBy: buildinfo.Stamp(now), Notices: frameworks.Notices(), Model: m, Elements: els, Threats: ts, Approvals: as}, nil
}

func fileName(title string, version int, ext string) string {
	name := strings.Map(func(c rune) rune {
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9', c == '-', c == '_':
			return c
		}
		return '-'
	}, strings.ToLower(title))
	name = strings.Trim(name, "-")
	if len(name) > 60 {
		name = name[:60]
	}
	if name == "" {
		name = "threat-model"
	}
	return fmt.Sprintf("%s-v%d.%s", name, version, ext)
}

func (s *Service) export(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	p, err := s.caller(r)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	format := r.URL.Query().Get("format")
	if format == "" {
		format = "pathos"
	}
	if !slices.Contains([]string{"pathos", "threat_dragon", "pytm", "markdown"}, format) {
		s.fail(w, r, httpx.BadRequest("format must be pathos, threat_dragon, pytm or markdown"))
		return
	}
	id, err := pathUUID(r, "id")
	if err != nil {
		s.fail(w, r, err)
		return
	}
	m, err := s.model(ctx, p, id, authz.PermThreatsRead)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	now := time.Now().UTC()
	ex, err := s.loadExport(ctx, m, now)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	var body []byte
	var ctype, ext string
	switch format {
	case "pathos":
		body, err = json.MarshalIndent(ex, "", "  ")
		ctype, ext = "application/json", "pathos.json"
	case "threat_dragon":
		body, err = json.MarshalIndent(ThreatDragon(ex), "", "  ")
		ctype, ext = "application/json", "threat-dragon.json"
	case "pytm":
		body, ctype, ext = []byte(Pytm(ex)), "text/x-python; charset=utf-8", "pytm.py"
	case "markdown":
		body, ctype, ext = []byte(Markdown(ex)), "text/markdown; charset=utf-8", "md"
	}
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if err := s.audit(ctx, s.DB, r, p, "threat_model.export", m, map[string]any{"format": format}); err != nil {
		s.fail(w, r, err)
		return
	}
	httpx.Download(w, ctype, fileName(m.Title, m.Version, ext))
	w.Header().Set(httpx.HeaderGeneratedBy, ex.GeneratedBy)
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(body)
}

// --- OWASP Threat Dragon v2 -------------------------------------------------------

// TDModel is an OWASP Threat Dragon v2 model (the parts PATHOS reads and
// writes).
type TDModel struct {
	Version string    `json:"version"`
	Summary TDSummary `json:"summary"`
	Detail  TDDetail  `json:"detail"`
}

// TDSummary is the model summary.
type TDSummary struct {
	Title       string `json:"title"`
	Owner       string `json:"owner"`
	Description string `json:"description"`
	ID          int    `json:"id"`
}

// TDDetail holds the diagrams.
type TDDetail struct {
	Contributors []map[string]string `json:"contributors"`
	Diagrams     []TDDiagram         `json:"diagrams"`
	DiagramTop   int                 `json:"diagramTop"`
	Reviewer     string              `json:"reviewer"`
	ThreatTop    int                 `json:"threatTop"`
}

// TDDiagram is one diagram.
type TDDiagram struct {
	ID          int      `json:"id"`
	Title       string   `json:"title"`
	DiagramType string   `json:"diagramType"`
	Placeholder string   `json:"placeholder"`
	Thumbnail   string   `json:"thumbnail"`
	Version     string   `json:"version"`
	Description string   `json:"description"`
	Cells       []TDCell `json:"cells"`
	// DiagramJSON marks a Threat Dragon v1 model (refused).
	DiagramJSON json.RawMessage `json:"diagramJson,omitempty"`
}

// TDCell is a diagram cell (element or flow).
type TDCell struct {
	ID       string         `json:"id"`
	Shape    string         `json:"shape"`
	Position *TDPoint       `json:"position,omitempty"`
	Size     *TDSize        `json:"size,omitempty"`
	Attrs    map[string]any `json:"attrs,omitempty"`
	Source   *TDEnd         `json:"source,omitempty"`
	Target   *TDEnd         `json:"target,omitempty"`
	Labels   []any          `json:"labels,omitempty"`
	ZIndex   int            `json:"zIndex"`
	Visible  *bool          `json:"visible,omitempty"`
	Data     TDData         `json:"data"`
}

// TDPoint is a position.
type TDPoint struct {
	X int `json:"x"`
	Y int `json:"y"`
}

// TDSize is a size.
type TDSize struct {
	Width  int `json:"width"`
	Height int `json:"height"`
}

// TDEnd is a flow end.
type TDEnd struct {
	Cell string `json:"cell"`
}

// TDData is a cell's model data.
type TDData struct {
	Type             string     `json:"type"`
	Name             string     `json:"name"`
	Description      string     `json:"description"`
	OutOfScope       bool       `json:"outOfScope"`
	ReasonOutOfScope string     `json:"reasonOutOfScope"`
	HasOpenThreats   bool       `json:"hasOpenThreats"`
	IsTrustBoundary  bool       `json:"isTrustBoundary,omitempty"`
	IsEncrypted      bool       `json:"isEncrypted,omitempty"`
	IsPublicNetwork  bool       `json:"isPublicNetwork,omitempty"`
	Protocol         string     `json:"protocol,omitempty"`
	Threats          []TDThreat `json:"threats,omitempty"`
}

// TDThreat is a Threat Dragon threat.
type TDThreat struct {
	ID          string `json:"id"`
	Title       string `json:"title"`
	Status      string `json:"status"`
	Severity    string `json:"severity"`
	Type        string `json:"type"`
	Description string `json:"description"`
	Mitigation  string `json:"mitigation"`
	ModelType   string `json:"modelType"`
	New         bool   `json:"new"`
	Number      int    `json:"number"`
	Score       string `json:"score"`
}

var tdStride = map[string]string{Spoofing: "Spoofing", Tampering: "Tampering", Repudiation: "Repudiation",
	InformationDisclosure: "Information disclosure", DenialOfService: "Denial of service", ElevationOfPrivilege: "Elevation of privilege"}

var tdLinddun = map[string]string{"linking": "Linkability", "identifying": "Identifiability", "non_repudiation": "Non-repudiation",
	"detecting": "Detectability", "data_disclosure": "Disclosure of information", "unawareness": "Unawareness", "non_compliance": "Non-compliance"}

var tdShape = map[string]struct{ shape, typ string }{
	KindProcess: {"process", "tm.Process"}, KindDataStore: {"store", "tm.Store"}, KindExternalEntity: {"actor", "tm.Actor"},
	KindTrustBoundary: {"trust-boundary-box", "tm.BoundaryBox"},
}

// ThreatDragon converts an export to a Threat Dragon v2 model. PATHOS
// fields Threat Dragon has no place for (rule, evidence label, confidence,
// accepted status) are written into the threat's description.
func ThreatDragon(ex Export) TDModel {
	visible := true
	d := TDDiagram{ID: 0, Title: ex.Model.Title + " (version " + strconv.Itoa(ex.Model.Version) + ")", DiagramType: "STRIDE",
		Thumbnail: "./public/content/images/thumbnail.stride.jpg", Version: "2.2.0",
		Description: "Exported from " + ex.GeneratedBy}
	cellOf := map[string]string{}
	col := map[string]int{KindExternalEntity: 0, KindProcess: 1, KindDataStore: 2, KindTrustBoundary: 3}
	row := map[string]int{}
	byElement := map[uuid.UUID][]ThreatOut{}
	var unassigned []ThreatOut
	for _, t := range ex.Threats {
		if len(t.Elements) == 0 {
			unassigned = append(unassigned, t)
			continue
		}
		byElement[t.Elements[0].ID] = append(byElement[t.Elements[0].ID], t)
	}
	num := 0
	tdThreats := func(ts []ThreatOut) ([]TDThreat, bool) {
		var out []TDThreat
		open := false
		for _, t := range ts {
			num++
			sev := map[string]string{"critical": "High", "high": "High", "medium": "Medium", "low": "Low", "info": "Low"}[t.Severity]
			status := map[string]string{"open": "Open", "accepted": "Open", "mitigated": "Mitigated", "not_applicable": "NotApplicable"}[t.Status]
			if status == "Open" {
				open = true
			}
			typ, model := tdStride[t.Category], "STRIDE"
			if typ == "" {
				typ, model = tdLinddun[t.Category], "LINDDUN"
			}
			method := t.Method
			if t.RuleID != "" {
				method += " " + t.RuleID + " v" + t.RuleVersion
			}
			desc := fmt.Sprintf("[PATHOS: %s · severity %s · confidence %.2f · status %s · evidence %s]\n%s", method, t.Severity, t.Confidence,
				strings.ReplaceAll(t.Status, "_", " "), t.Label, t.Description)
			if t.StatusReason != "" {
				desc += "\nStatus reason: " + t.StatusReason
			}
			out = append(out, TDThreat{ID: t.ID.String(), Title: t.Title, Status: status, Severity: sev, Type: typ, Description: desc,
				Mitigation: t.Mitigation, ModelType: model, Number: num})
		}
		return out, open
	}
	z := 0
	for _, e := range ex.Elements {
		if e.Kind == KindDataFlow {
			continue
		}
		sh, ok := tdShape[e.Kind]
		if !ok {
			continue
		}
		cid := e.ID.String()
		cellOf[e.ElementKey] = cid
		ts, open := tdThreats(byElement[e.ID])
		z++
		c := TDCell{ID: cid, Shape: sh.shape, Position: &TDPoint{X: 40 + col[e.Kind]*260, Y: 40 + row[e.Kind]*130},
			Size: &TDSize{Width: 180, Height: 80}, ZIndex: z, Visible: &visible,
			Attrs: map[string]any{"text": map[string]any{"text": e.Name}},
			Data: TDData{Type: sh.typ, Name: e.Name, Description: firstNonEmpty(e.CodegraphKey, e.NodeType), HasOpenThreats: open, Threats: ts,
				IsTrustBoundary: e.Kind == KindTrustBoundary}}
		row[e.Kind]++
		d.Cells = append(d.Cells, c)
	}
	if len(unassigned) > 0 {
		ts, open := tdThreats(unassigned)
		z++
		d.Cells = append(d.Cells, TDCell{ID: uuid.NewSHA1(uuid.NameSpaceOID, []byte(ex.Model.ID.String()+"/application")).String(), Shape: "process",
			Position: &TDPoint{X: 40 + 260, Y: 40 + row[KindProcess]*130}, Size: &TDSize{Width: 180, Height: 80}, ZIndex: z, Visible: &visible,
			Attrs: map[string]any{"text": map[string]any{"text": ex.Model.ApplicationName}},
			Data:  TDData{Type: "tm.Process", Name: ex.Model.ApplicationName, Description: "threats without a diagram element", HasOpenThreats: open, Threats: ts}})
	}
	for _, e := range ex.Elements {
		if e.Kind != KindDataFlow {
			continue
		}
		src, ok1 := cellOf[elementKey(e.RepositoryID, e.SourceKey)]
		dst, ok2 := cellOf[elementKey(e.RepositoryID, e.TargetKey)]
		if !ok1 || !ok2 {
			continue
		}
		ts, open := tdThreats(byElement[e.ID])
		z++
		d.Cells = append(d.Cells, TDCell{ID: e.ID.String(), Shape: "flow", Source: &TDEnd{Cell: src}, Target: &TDEnd{Cell: dst}, ZIndex: z,
			Labels: []any{e.NodeType}, Visible: &visible,
			Data: TDData{Type: "tm.Flow", Name: firstNonEmpty(e.NodeType, e.Name), Description: e.Name, HasOpenThreats: open, Threats: ts,
				Protocol: e.NodeType}})
	}
	reviewer := ""
	if ex.Model.ApprovedBy != nil {
		reviewer = ex.Model.ApprovedBy.Name
	}
	return TDModel{Version: "2.2.0", Summary: TDSummary{Title: ex.Model.Title, Description: ex.Model.Summary},
		Detail: TDDetail{Contributors: []map[string]string{}, Diagrams: []TDDiagram{d}, DiagramTop: 1, Reviewer: reviewer, ThreatTop: num}}
}

// parseError is an import that cannot be read (PTH-TM-1101).
func parseError(msg string) error {
	return httpx.E(http.StatusUnprocessableEntity, "threat_import_parse", msg).WithDiag(CodeImportParse)
}

func tooLarge(msg string) error {
	return httpx.E(http.StatusUnprocessableEntity, "threat_import_too_large", msg).WithDiag(CodeImportTooLarge)
}

// importedThreat is a threat read from an import.
type importedThreat struct {
	row      threatRow
	elements []int // indexes into the imported elements
	keys     []string
	mappings []Mapping
}

type importedElement struct {
	ref   ElementRef
	attrs map[string]any
}

type imported struct {
	title, summary string
	elements       []importedElement
	threats        []importedThreat
}

func categoryFromTD(typ, model string) string {
	t := strings.ToLower(strings.TrimSpace(typ))
	for k, v := range tdStride {
		if strings.ToLower(v) == t {
			return k
		}
	}
	for k, v := range tdLinddun {
		if strings.ToLower(v) == t {
			return k
		}
	}
	// Threat Dragon's other model types (CIA, DIE, PLOT4ai) have no STRIDE
	// equivalent: closest category by keyword.
	switch {
	case strings.Contains(t, "confidential") || strings.Contains(t, "disclos"):
		return InformationDisclosure
	case strings.Contains(t, "integrity") || strings.Contains(t, "tamper"):
		return Tampering
	case strings.Contains(t, "availab") || strings.Contains(t, "denial"):
		return DenialOfService
	case strings.Contains(t, "spoof") || strings.Contains(t, "authent"):
		return Spoofing
	case strings.Contains(t, "privilege") || strings.Contains(t, "elevat"):
		return ElevationOfPrivilege
	case strings.Contains(t, "repudiat"):
		return Repudiation
	}
	return Tampering
}

// ParseThreatDragon reads an OWASP Threat Dragon v2 model.
func ParseThreatDragon(raw []byte) (*imported, error) {
	var td TDModel
	dec := json.NewDecoder(bytes.NewReader(raw))
	if err := dec.Decode(&td); err != nil {
		return nil, parseError("not a Threat Dragon v2 JSON model: " + jsonErr(raw, err))
	}
	if td.Detail.Diagrams == nil {
		return nil, parseError("detail.diagrams is missing: not a Threat Dragon v2 model")
	}
	out := &imported{title: strings.TrimSpace(td.Summary.Title), summary: td.Summary.Description}
	idx := map[string]int{}
	cells := 0
	type pending struct {
		t    TDThreat
		cell string
		di   int
		ci   int
	}
	var threats []pending
	for di, d := range td.Detail.Diagrams {
		if len(d.DiagramJSON) > 0 && len(d.Cells) == 0 {
			return nil, parseError(fmt.Sprintf("detail.diagrams[%d] is a Threat Dragon v1 diagram (diagramJson); open and save it in Threat Dragon 2 first", di))
		}
		for ci, c := range d.Cells {
			cells++
			if c.ID == "" {
				return nil, parseError(fmt.Sprintf("detail.diagrams[%d].cells[%d].id is missing", di, ci))
			}
			name := strings.TrimSpace(c.Data.Name)
			if name == "" {
				if t, ok := c.Attrs["text"].(map[string]any); ok {
					name, _ = t["text"].(string)
				}
			}
			var kind string
			switch {
			case c.Data.Type == "tm.Process" || c.Shape == "process":
				kind = KindProcess
			case c.Data.Type == "tm.Store" || c.Shape == "store":
				kind = KindDataStore
			case c.Data.Type == "tm.Actor" || c.Shape == "actor":
				kind = KindExternalEntity
			case c.Data.Type == "tm.Flow" || c.Shape == "flow":
				kind = KindDataFlow
			case strings.HasPrefix(c.Data.Type, "tm.Boundary") || strings.HasPrefix(c.Shape, "trust-boundary"):
				kind = KindTrustBoundary
			default:
				continue // text blocks and unknown shapes
			}
			ref := ElementRef{Kind: kind, Key: "td:" + c.ID, Name: firstNonEmpty(name, kind)}
			if kind == KindDataFlow {
				if c.Source == nil || c.Target == nil || c.Source.Cell == "" || c.Target.Cell == "" {
					return nil, parseError(fmt.Sprintf("detail.diagrams[%d].cells[%d]: a flow needs source.cell and target.cell", di, ci))
				}
				ref.Source, ref.Target = "td:"+c.Source.Cell, "td:"+c.Target.Cell
			}
			idx[c.ID] = len(out.elements)
			out.elements = append(out.elements, importedElement{ref: ref, attrs: map[string]any{"imported": "threat_dragon", "diagram": d.Title,
				"out_of_scope": c.Data.OutOfScope}})
			for _, t := range c.Data.Threats {
				threats = append(threats, pending{t, c.ID, di, ci})
			}
		}
	}
	if cells > maxImportElements {
		return nil, tooLarge(fmt.Sprintf("%d cells; at most %d", cells, maxImportElements))
	}
	if len(threats) > maxImportThreats {
		return nil, tooLarge(fmt.Sprintf("%d threats; at most %d", len(threats), maxImportThreats))
	}
	for _, p := range threats {
		t := p.t
		title := strings.TrimSpace(t.Title)
		if title == "" {
			return nil, parseError(fmt.Sprintf("detail.diagrams[%d].cells[%d]: a threat has no title", p.di, p.ci))
		}
		sev := map[string]string{"critical": "critical", "high": "high", "medium": "medium", "low": "low"}[strings.ToLower(t.Severity)]
		sevReason := "imported from Threat Dragon (" + firstNonEmpty(t.Severity, "no severity") + ")"
		if sev == "" {
			sev = "medium"
			sevReason += "; set to medium"
		}
		status := map[string]string{"open": "open", "mitigated": "mitigated", "notapplicable": "not_applicable", "na": "not_applicable",
			"not applicable": "not_applicable"}[strings.ToLower(t.Status)]
		if status == "" {
			status = "open"
		}
		row := threatRow{Title: clip(title, 300), Description: clip(t.Description, 8000), Category: categoryFromTD(t.Type, t.ModelType),
			Method: MethodImported, EvidenceType: EvidenceUnverified, Severity: sev, SeverityReason: sevReason, Confidence: 0.5,
			ConfidenceReason: "imported from Threat Dragon; not verified by PATHOS", Status: status, Mitigation: clip(strings.TrimSpace(t.Mitigation), 8000),
			MitigationEdited: true, SeverityOverridden: true,
			Evidence: Evidence{Imported: map[string]any{"format": "threat_dragon", "model": out.title, "cell": p.cell, "threat_id": t.ID, "type": t.Type, "model_type": t.ModelType}}}
		if status != "open" {
			row.StatusReason = "imported from Threat Dragon"
		}
		out.threats = append(out.threats, importedThreat{row: row, elements: []int{idx[p.cell]}})
	}
	return out, nil
}

// ParsePathos reads a PATHOS threat-model export.
func ParsePathos(raw []byte) (*imported, error) {
	var ex Export
	if err := json.Unmarshal(raw, &ex); err != nil {
		return nil, parseError("not a PATHOS threat-model export: " + jsonErr(raw, err))
	}
	if ex.Schema != ExportSchema {
		return nil, parseError(fmt.Sprintf("schema %q, want %q", ex.Schema, ExportSchema))
	}
	if len(ex.Elements) > maxImportElements {
		return nil, tooLarge(fmt.Sprintf("%d elements; at most %d", len(ex.Elements), maxImportElements))
	}
	if len(ex.Threats) > maxImportThreats {
		return nil, tooLarge(fmt.Sprintf("%d threats; at most %d", len(ex.Threats), maxImportThreats))
	}
	out := &imported{title: ex.Model.Title, summary: ex.Model.Summary}
	idx := map[uuid.UUID]int{}
	for _, e := range ex.Elements {
		if _, ok := tdShape[e.Kind]; !ok && e.Kind != KindDataFlow {
			return nil, parseError("elements: unknown kind " + strconv.Quote(e.Kind))
		}
		idx[e.ID] = len(out.elements)
		key := firstNonEmpty(e.CodegraphKey, "import:"+e.ID.String())
		out.elements = append(out.elements, importedElement{ref: ElementRef{Kind: e.Kind, Key: key, Name: e.Name, NodeType: e.NodeType,
			Source: e.SourceKey, Target: e.TargetKey}, attrs: map[string]any{"imported": "pathos"}})
	}
	for i, t := range ex.Threats {
		if strings.TrimSpace(t.Title) == "" || !validCategory(t.Category) || !slices.Contains(Severities, t.Severity) {
			return nil, parseError(fmt.Sprintf("threats[%d]: title, category or severity is missing or unknown", i))
		}
		status := t.Status
		if !slices.Contains(Statuses, status) {
			status = "open"
		}
		row := threatRow{Title: clip(t.Title, 300), Description: clip(t.Description, 8000), Category: t.Category, Method: MethodImported,
			EvidenceType: EvidenceUnverified, Severity: t.Severity, SeverityReason: "imported from a PATHOS export: " + clip(t.SeverityReason, 1500),
			SeverityOverridden: true, Confidence: 0.5, ConfidenceReason: "imported from a PATHOS export; not verified in this installation",
			Status: status, StatusReason: t.StatusReason, Mitigation: clip(t.Mitigation, 8000), MitigationEdited: true,
			Evidence: Evidence{Imported: map[string]any{"format": "pathos", "model": ex.Model.Title, "version": ex.Model.Version, "threat_id": t.ID,
				"method": t.Method, "rule_id": t.RuleID, "rule_version": t.RuleVersion, "evidence_type": t.EvidenceType}}}
		it := importedThreat{row: row}
		for _, e := range t.Elements {
			if j, ok := idx[e.ID]; ok {
				it.elements = append(it.elements, j)
			}
		}
		for _, n := range t.Evidence.Nodes {
			if n.Key != "" && !slices.Contains(it.keys, n.Key) {
				it.keys = append(it.keys, n.Key)
			}
		}
		for _, m := range t.Mappings {
			if _, ok := frameworks.Lookup(m.Framework, m.ID); ok {
				it.mappings = append(it.mappings, Mapping{Framework: m.Framework, ID: m.ID, Source: "imported"})
			}
		}
		out.threats = append(out.threats, it)
	}
	return out, nil
}

// jsonErr describes a JSON error with its byte offset and line.
func jsonErr(raw []byte, err error) string {
	var se *json.SyntaxError
	var te *json.UnmarshalTypeError
	off := int64(-1)
	switch {
	case errors.As(err, &se):
		off = se.Offset
	case errors.As(err, &te):
		off = te.Offset
		if te.Field != "" {
			return fmt.Sprintf("field %s: %v", te.Field, err)
		}
	}
	if off >= 0 && off <= int64(len(raw)) {
		return fmt.Sprintf("line %d: %v", bytes.Count(raw[:off], []byte("\n"))+1, err)
	}
	return err.Error()
}

type importRequest struct {
	ApplicationID uuid.UUID       `json:"application_id"`
	RepositoryID  *uuid.UUID      `json:"repository_id"`
	Format        string          `json:"format"`
	Title         string          `json:"title"`
	Document      json.RawMessage `json:"document"`
}

func (s *Service) importModel(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	p, err := s.caller(r)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if ct := r.Header.Get("Content-Type"); !strings.HasPrefix(ct, "application/json") {
		s.fail(w, r, httpx.E(http.StatusUnsupportedMediaType, "unsupported_media_type", "Content-Type must be application/json"))
		return
	}
	raw, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxImportBodyBytes))
	if err != nil {
		s.fail(w, r, tooLarge("the request is larger than 10 MB"))
		return
	}
	var in importRequest
	if err := json.Unmarshal(raw, &in); err != nil {
		s.fail(w, r, httpx.BadRequest("invalid JSON body: "+jsonErr(raw, err)))
		return
	}
	var doc *imported
	switch in.Format {
	case "threat_dragon":
		doc, err = ParseThreatDragon(in.Document)
	case "pathos":
		doc, err = ParsePathos(in.Document)
	default:
		err = httpx.E(http.StatusUnsupportedMediaType, "threat_import_format",
			"format must be threat_dragon or pathos (pytm models are Python programs, which PATHOS does not run)").WithDiag(CodeImportFormat)
	}
	if err == nil && len(in.Document) == 0 {
		err = parseError("document is missing")
	}
	if err != nil {
		s.fail(w, r, err)
		return
	}
	title := firstNonEmpty(strings.TrimSpace(in.Title), doc.title, "Imported threat model")
	if title, err = validTitle(clip(title, 200)); err != nil {
		s.fail(w, r, err)
		return
	}
	if err := s.requireScope(ctx, p, authz.PermThreatsManage, in.ApplicationID, in.RepositoryID); err != nil {
		s.fail(w, r, err)
		return
	}
	// A PATHOS export's threats are linked at once when their CodeGraph
	// elements exist in the application's latest snapshot.
	probe := Model{orgID: p.OrganizationID, ApplicationID: in.ApplicationID, RepositoryID: in.RepositoryID}
	linked := map[int]resolvedEvidence{}
	for i, t := range doc.threats {
		if len(t.keys) == 0 || len(t.keys) > 50 {
			continue
		}
		var keys []elementKeyRef
		for _, k := range t.keys {
			keys = append(keys, elementKeyRef{Key: k})
		}
		if ev, err := s.resolveEvidence(ctx, probe, keys, nil); err == nil {
			linked[i] = ev
		}
	}
	var id uuid.UUID
	err = db.InTx(ctx, s.DB, func(tx pgx.Tx) error {
		var err error
		if id, err = s.newModel(ctx, tx, p, in.ApplicationID, in.RepositoryID, title, clip(doc.summary, 8000), MethodImported, in.Format); err != nil {
			return err
		}
		m, err := getModel(ctx, tx, p.OrganizationID, id)
		if err != nil {
			return err
		}
		elIDs := make([]uuid.UUID, len(doc.elements))
		for i, e := range doc.elements {
			if elIDs[i], err = upsertElement(ctx, tx, m.orgID, m.ID, nil, e.ref, e.attrs); err != nil {
				return err
			}
		}
		verified := 0
		for i, t := range doc.threats {
			row := t.row
			row.CreatedBy = &p.UserID
			var extra []uuid.UUID
			if ev, ok := linked[i]; ok {
				row.EvidenceType, row.Evidence.Nodes, row.Evidence.SnapshotID = EvidenceVerified, ev.nodes, ev.snapshot
				verified++
				for j, e := range ev.elements {
					r := ev.repos[j]
					eid, err := upsertElement(ctx, tx, m.orgID, m.ID, &r, e, map[string]any{"linked": true})
					if err != nil {
						return err
					}
					extra = append(extra, eid)
				}
			}
			tid, err := insertThreat(ctx, tx, m.orgID, m.ID, row)
			if err != nil {
				return err
			}
			var els []uuid.UUID
			for _, j := range t.elements {
				els = append(els, elIDs[j])
			}
			if err := linkElements(ctx, tx, m.orgID, tid, append(els, extra...), false); err != nil {
				return err
			}
			if err := setMappings(ctx, tx, m.orgID, tid, t.mappings); err != nil {
				return err
			}
			if err := addEvent(ctx, tx, m.orgID, tid, "created", "", "imported ("+in.Format+")", "", &p.UserID); err != nil {
				return err
			}
		}
		return s.audit(ctx, tx, r, p, "threat_model.import", m, map[string]any{"format": in.Format, "elements": len(doc.elements),
			"threats": len(doc.threats), "linked": verified})
	})
	if err != nil {
		s.fail(w, r, err)
		return
	}
	s.respondModel(w, r, p, id, http.StatusCreated, map[string]any{"elements": len(doc.elements), "threats": len(doc.threats), "linked": len(linked)})
}

// --- pytm and Markdown ---------------------------------------------------------------

func pyStr(s string) string { return strconv.Quote(s) }

func oneLine(s string) string {
	s = strings.Join(strings.Fields(s), " ")
	return clip(s, 300)
}

// Pytm writes a pytm model description of the diagram (OWASP pytm, a
// Python framework: review the file before running it). pytm computes its
// own threats; PATHOS's threats are listed as comments.
func Pytm(ex Export) string {
	var b strings.Builder
	fmt.Fprintf(&b, "#!/usr/bin/env python3\n# pytm model description of the PATHOS threat model %s, version %d (%s).\n", pyStr(ex.Model.Title), ex.Model.Version, ex.Model.Status)
	fmt.Fprintf(&b, "# %s\n# Generated by PATHOS for OWASP pytm (https://github.com/OWASP/pytm). Review it before running:\n", ex.GeneratedBy)
	b.WriteString("# pytm derives its own threats from this description; the PATHOS threats are listed at the end as comments.\n\n")
	b.WriteString("from pytm import TM, Actor, Boundary, Dataflow, Datastore, Process, Server\n\n")
	fmt.Fprintf(&b, "tm = TM(%s)\ntm.description = %s\n\n", pyStr(ex.Model.Title), pyStr(firstNonEmpty(oneLine(ex.Model.Summary), "Exported from PATHOS")))
	vars := map[string]string{}
	n := 0
	for _, e := range ex.Elements {
		if e.Kind == KindDataFlow {
			continue
		}
		n++
		v := "e" + strconv.Itoa(n)
		vars[e.ElementKey] = v
		class := "Process"
		switch {
		case e.Kind == KindDataStore:
			class = "Datastore"
		case e.Kind == KindExternalEntity:
			class = "Actor"
		case e.Kind == KindTrustBoundary:
			class = "Boundary"
		case e.NodeType == "container" || e.NodeType == "iac_resource":
			class = "Server"
		}
		fmt.Fprintf(&b, "%s = %s(%s)\n", v, class, pyStr(clip(e.Name, 200)))
		if e.CodegraphKey != "" {
			fmt.Fprintf(&b, "%s.description = %s\n", v, pyStr("CodeGraph "+clip(e.CodegraphKey, 300)))
		}
	}
	b.WriteString("\n")
	f := 0
	for _, e := range ex.Elements {
		if e.Kind != KindDataFlow {
			continue
		}
		src, ok1 := vars[elementKey(e.RepositoryID, e.SourceKey)]
		dst, ok2 := vars[elementKey(e.RepositoryID, e.TargetKey)]
		if !ok1 || !ok2 {
			continue
		}
		f++
		fmt.Fprintf(&b, "f%d = Dataflow(%s, %s, %s)\n", f, src, dst, pyStr(firstNonEmpty(e.NodeType, "flow")))
	}
	b.WriteString("\n# PATHOS threats (rule, evidence label, severity, status):\n")
	for i, t := range ex.Threats {
		rule := t.Method
		if t.RuleID != "" {
			rule = t.RuleID + " v" + t.RuleVersion
		}
		fmt.Fprintf(&b, "# T%d [%s, %s] %s (%s, %s, %s)\n#     Mitigation: %s\n", i+1, t.Severity, strings.ReplaceAll(t.Status, "_", " "),
			oneLine(t.Title), CategoryLabels[t.Category], rule, t.Label, oneLine(t.Mitigation))
	}
	b.WriteString("\nif __name__ == \"__main__\":\n    tm.process()\n")
	return b.String()
}

func mdCell(s string) string {
	return strings.ReplaceAll(strings.ReplaceAll(oneLine(s), "|", "\\|"), "\n", " ")
}

// Markdown writes a readable report of the version.
func Markdown(ex Export) string {
	var b strings.Builder
	m := ex.Model
	fmt.Fprintf(&b, "# %s\n\n", mdCell(m.Title))
	fmt.Fprintf(&b, "Application **%s** · version %d · %s · %s\n\n", mdCell(m.ApplicationName), m.Version, strings.ReplaceAll(m.Status, "_", " "), ex.GeneratedBy)
	if m.ApprovedBy != nil && m.ApprovedAt != nil {
		fmt.Fprintf(&b, "Approved by %s on %s.\n\n", mdCell(m.ApprovedBy.Name), m.ApprovedAt.UTC().Format("2006-01-02"))
	}
	if m.Summary != "" {
		b.WriteString(m.Summary + "\n\n")
	}
	fmt.Fprintf(&b, "%d threats: %d open, %d mitigated, %d accepted, %d not applicable.\n\n", m.Counts.Total, m.Counts.Open, m.Counts.Mitigated,
		m.Counts.Accepted, m.Counts.NotApplicable)
	b.WriteString("| # | Threat | Category | Severity | Confidence | Status | Evidence | Method |\n|---|---|---|---|---|---|---|---|\n")
	for i, t := range ex.Threats {
		rule := t.Method
		if t.RuleID != "" {
			rule = t.RuleID + " v" + t.RuleVersion
		}
		fmt.Fprintf(&b, "| %d | %s | %s | %s | %.2f | %s | %s | %s |\n", i+1, mdCell(t.Title), CategoryLabels[t.Category], t.Severity, t.Confidence,
			strings.ReplaceAll(t.Status, "_", " "), t.Label, rule)
	}
	for i, t := range ex.Threats {
		fmt.Fprintf(&b, "\n## %d. %s\n\n%s\n\n", i+1, mdCell(t.Title), t.Description)
		fmt.Fprintf(&b, "- Severity: %s (%s)\n- Confidence: %.2f (%s)\n", t.Severity, mdCell(t.SeverityReason), t.Confidence, mdCell(t.ConfidenceReason))
		if t.StatusReason != "" {
			fmt.Fprintf(&b, "- Status: %s (%s)\n", strings.ReplaceAll(t.Status, "_", " "), mdCell(t.StatusReason))
		}
		if len(t.Evidence.Edges) > 0 || len(t.Evidence.Nodes) > 0 {
			b.WriteString("- Evidence:\n")
			for _, n := range t.Evidence.Nodes {
				loc := ""
				if n.File != "" {
					loc = " (" + n.File
					if n.Line > 0 {
						loc += ":" + strconv.Itoa(n.Line)
					}
					loc += ")"
				}
				fmt.Fprintf(&b, "  - %s `%s`%s\n", n.Type, mdCell(n.Key), loc)
			}
			for _, e := range t.Evidence.Edges {
				ref := ""
				if len(e.Refs) > 0 {
					ref = " — " + e.Refs[0].Kind + " " + mdCell(e.Refs[0].Ref)
				}
				fmt.Fprintf(&b, "  - %s → %s (%s, %s)%s\n", mdCell(e.Source), mdCell(e.Target), e.Type, e.Evidence, ref)
			}
		}
		for _, a := range t.Evidence.Absent {
			fmt.Fprintf(&b, "- Not found: %s\n", mdCell(a))
		}
		for _, f := range t.Findings {
			fmt.Fprintf(&b, "- Finding: %s (%s)\n", mdCell(f.Title), f.Severity)
		}
		if len(t.Mappings) > 0 {
			var ms []string
			for _, x := range t.Mappings {
				ms = append(ms, x.ID+" "+x.Name)
			}
			fmt.Fprintf(&b, "- Mappings: %s\n", mdCell(strings.Join(ms, "; ")))
		}
		fmt.Fprintf(&b, "\n**Mitigation.** %s\n", firstNonEmpty(t.Mitigation, "(none yet)"))
	}
	b.WriteString("\n---\n\n")
	for _, n := range ex.Notices {
		b.WriteString(n + "\n\n")
	}
	return b.String()
}
