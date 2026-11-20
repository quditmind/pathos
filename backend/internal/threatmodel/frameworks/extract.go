package frameworks

import (
	"archive/zip"
	"bytes"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"io"
	"regexp"
	"sort"
	"strings"
)

// Source is one pinned download (sources.json): a versioned release URL
// and the SHA-256 of the file. The updater refuses a file whose checksum
// differs.
type Source struct {
	Framework string `json:"framework"`
	Title     string `json:"title"`
	Release   string `json:"release"`
	URL       string `json:"url"`
	SHA256    string `json:"sha256"`
	Licence   string `json:"licence"`
	Notice    string `json:"notice"`
}

// SourcesFile is the pin file, relative to this package.
const SourcesFile = "sources.json"

// summaryMax bounds a bundled summary (first sentences of the description).
const summaryMax = 300

var (
	citationRe = regexp.MustCompile(`\(Citation:[^)]*\)`)
	linkRe     = regexp.MustCompile(`\[([^\]]+)\]\([^)]+\)`)
	spaceRe    = regexp.MustCompile(`\s+`)
)

// summarize keeps the first sentences of a description, without citations
// or markdown links, up to summaryMax bytes.
func summarize(s string) string {
	s = citationRe.ReplaceAllString(s, "")
	s = linkRe.ReplaceAllString(s, "$1")
	s = strings.TrimSpace(spaceRe.ReplaceAllString(s, " "))
	if len(s) <= summaryMax {
		return s
	}
	cut := s[:summaryMax]
	if i := strings.LastIndex(cut, ". "); i > 80 {
		return cut[:i+1]
	}
	for len(cut) > 0 && cut[len(cut)-1]&0xC0 == 0x80 {
		cut = cut[:len(cut)-1]
	}
	if i := strings.LastIndexByte(cut, ' '); i > 0 {
		cut = cut[:i]
	}
	return cut + "…"
}

func finish(src Source, entries []Entry, rels []Relation) *Dataset {
	sort.Slice(entries, func(i, j int) bool { return idLess(entries[i].ID, entries[j].ID) })
	sort.Slice(rels, func(i, j int) bool {
		if rels[i].From != rels[j].From {
			return idLess(rels[i].From, rels[j].From)
		}
		if rels[i].To != rels[j].To {
			return idLess(rels[i].To, rels[j].To)
		}
		return rels[i].Relation < rels[j].Relation
	})
	// Drop duplicate relations.
	out := rels[:0]
	for i, r := range rels {
		if i == 0 || r != rels[i-1] {
			out = append(out, r)
		}
	}
	return &Dataset{Framework: src.Framework, Title: src.Title, Release: src.Release, Source: src.URL, SHA256: src.SHA256,
		Licence: src.Licence, Notice: src.Notice, Entries: entries, Relations: out}
}

// idLess orders ids naturally (CWE-9 before CWE-10).
func idLess(a, b string) bool {
	pa, na := splitNum(a)
	pb, nb := splitNum(b)
	if pa != pb {
		return pa < pb
	}
	if na != nb {
		return na < nb
	}
	return a < b
}

func splitNum(s string) (string, int) {
	i := len(s)
	for i > 0 && s[i-1] >= '0' && s[i-1] <= '9' {
		i--
	}
	// T1059.001: the number after the dot sorts within its parent.
	if j := strings.IndexByte(s, '.'); j > 0 {
		p, n := splitNum(s[:j])
		_, m := splitNum(s[j+1:])
		return p, n*1000 + m
	}
	n := 0
	for _, c := range s[i:] {
		n = n*10 + int(c-'0')
		if n > 1<<30 {
			break
		}
	}
	return s[:i], n
}

// ExtractATTACK reads an ATT&CK STIX 2.1 bundle (enterprise-attack-<v>.json):
// techniques and sub-techniques (attack-pattern objects), not revoked, and
// their CAPEC references.
func ExtractATTACK(src Source, r io.Reader) (*Dataset, error) {
	var bundle struct {
		Objects []struct {
			Type        string `json:"type"`
			Name        string `json:"name"`
			Description string `json:"description"`
			Revoked     bool   `json:"revoked"`
			Deprecated  bool   `json:"x_mitre_deprecated"`
			Refs        []struct {
				Source string `json:"source_name"`
				ID     string `json:"external_id"`
				URL    string `json:"url"`
			} `json:"external_references"`
		} `json:"objects"`
	}
	if err := json.NewDecoder(r).Decode(&bundle); err != nil {
		return nil, fmt.Errorf("ATT&CK bundle: %w", err)
	}
	var entries []Entry
	var rels []Relation
	for _, o := range bundle.Objects {
		if o.Type != "attack-pattern" || o.Revoked {
			continue
		}
		var e Entry
		var capecs []string
		for _, ref := range o.Refs {
			switch ref.Source {
			case "mitre-attack":
				e.ID, e.URL = ref.ID, ref.URL
			case "capec":
				capecs = append(capecs, ref.ID)
			}
		}
		if e.ID == "" {
			continue
		}
		e.Name, e.Summary, e.Deprecated = o.Name, summarize(o.Description), o.Deprecated
		entries = append(entries, e)
		for _, c := range capecs {
			rels = append(rels, Relation{From: c, To: e.ID, Relation: "related"})
		}
	}
	if len(entries) < 100 {
		return nil, fmt.Errorf("ATT&CK bundle: only %d techniques", len(entries))
	}
	return finish(src, entries, rels), nil
}

// ExtractCAPEC reads the CAPEC XML catalogue (capec_v<v>.xml): attack
// patterns, the CWE weaknesses they exploit and their ATT&CK mappings.
func ExtractCAPEC(src Source, r io.Reader) (*Dataset, error) {
	var cat struct {
		Patterns []struct {
			ID          string `xml:"ID,attr"`
			Name        string `xml:"Name,attr"`
			Status      string `xml:"Status,attr"`
			Description string `xml:"Description"`
			Weaknesses  []struct {
				ID string `xml:"CWE_ID,attr"`
			} `xml:"Related_Weaknesses>Related_Weakness"`
			Taxonomy []struct {
				Name  string `xml:"Taxonomy_Name,attr"`
				Entry string `xml:"Entry_ID"`
			} `xml:"Taxonomy_Mappings>Taxonomy_Mapping"`
		} `xml:"Attack_Patterns>Attack_Pattern"`
	}
	if err := xml.NewDecoder(r).Decode(&cat); err != nil {
		return nil, fmt.Errorf("CAPEC catalogue: %w", err)
	}
	var entries []Entry
	var rels []Relation
	for _, p := range cat.Patterns {
		id := "CAPEC-" + p.ID
		entries = append(entries, Entry{ID: id, Name: p.Name, Summary: summarize(p.Description),
			URL: "https://capec.mitre.org/data/definitions/" + p.ID + ".html", Deprecated: p.Status == "Deprecated" || p.Status == "Obsolete"})
		for _, w := range p.Weaknesses {
			rels = append(rels, Relation{From: id, To: "CWE-" + w.ID, Relation: "exploits"})
		}
		for _, t := range p.Taxonomy {
			if t.Name == "ATTACK" && t.Entry != "" {
				tid := strings.TrimSpace(t.Entry)
				if !strings.HasPrefix(tid, "T") {
					tid = "T" + tid
				}
				rels = append(rels, Relation{From: id, To: tid, Relation: "related"})
			}
		}
	}
	if len(entries) < 100 {
		return nil, fmt.Errorf("CAPEC catalogue: only %d attack patterns", len(entries))
	}
	return finish(src, entries, rels), nil
}

// ExtractCWE reads the CWE XML catalogue (cwec_v<v>.xml.zip): weaknesses
// and their ChildOf relations.
func ExtractCWE(src Source, zipped []byte) (*Dataset, error) {
	zr, err := zip.NewReader(bytes.NewReader(zipped), int64(len(zipped)))
	if err != nil {
		return nil, fmt.Errorf("CWE archive: %w", err)
	}
	var f *zip.File
	for _, x := range zr.File {
		if strings.HasSuffix(x.Name, ".xml") {
			f = x
			break
		}
	}
	if f == nil {
		return nil, fmt.Errorf("CWE archive: no XML file")
	}
	rc, err := f.Open()
	if err != nil {
		return nil, err
	}
	defer rc.Close()
	var cat struct {
		Weaknesses []struct {
			ID          string `xml:"ID,attr"`
			Name        string `xml:"Name,attr"`
			Status      string `xml:"Status,attr"`
			Description string `xml:"Description"`
			Related     []struct {
				Nature string `xml:"Nature,attr"`
				ID     string `xml:"CWE_ID,attr"`
				View   string `xml:"View_ID,attr"`
			} `xml:"Related_Weaknesses>Related_Weakness"`
		} `xml:"Weaknesses>Weakness"`
	}
	// The archive holds one ~20 MB XML file; bound the read.
	if err := xml.NewDecoder(io.LimitReader(rc, 256<<20)).Decode(&cat); err != nil {
		return nil, fmt.Errorf("CWE catalogue: %w", err)
	}
	var entries []Entry
	var rels []Relation
	for _, w := range cat.Weaknesses {
		id := "CWE-" + w.ID
		entries = append(entries, Entry{ID: id, Name: w.Name, Summary: summarize(w.Description),
			URL: "https://cwe.mitre.org/data/definitions/" + w.ID + ".html", Deprecated: w.Status == "Deprecated" || w.Status == "Obsolete"})
		for _, rel := range w.Related {
			if rel.Nature == "ChildOf" && rel.View == "1000" {
				rels = append(rels, Relation{From: id, To: "CWE-" + rel.ID, Relation: "child_of"})
			}
		}
	}
	if len(entries) < 100 {
		return nil, fmt.Errorf("CWE catalogue: only %d weaknesses", len(entries))
	}
	return finish(src, entries, rels), nil
}

// ExtractD3FEND reads the D3FEND ontology (d3fend.json, JSON-LD):
// defensive techniques with a "D3-" identifier (countermeasures; the
// "D3A-" analytic techniques are left out).
func ExtractD3FEND(src Source, r io.Reader) (*Dataset, error) {
	var doc struct {
		Graph []map[string]any `json:"@graph"`
	}
	if err := json.NewDecoder(r).Decode(&doc); err != nil {
		return nil, fmt.Errorf("D3FEND ontology: %w", err)
	}
	var entries []Entry
	for _, x := range doc.Graph {
		id, _ := x["d3f:d3fend-id"].(string)
		if !strings.HasPrefix(id, "D3-") {
			continue
		}
		name := literal(x["rdfs:label"])
		iri, _ := x["@id"].(string)
		if name == "" || iri == "" {
			continue
		}
		entries = append(entries, Entry{ID: id, Name: name, Summary: summarize(literal(x["d3f:definition"])),
			URL: "https://d3fend.mitre.org/technique/" + iri + "/"})
	}
	if len(entries) < 50 {
		return nil, fmt.Errorf("D3FEND ontology: only %d countermeasures", len(entries))
	}
	return finish(src, entries, nil), nil
}

// literal reads a JSON-LD literal (a string or {"@value": ...}).
func literal(v any) string {
	switch x := v.(type) {
	case string:
		return x
	case map[string]any:
		s, _ := x["@value"].(string)
		return s
	case []any:
		if len(x) > 0 {
			return literal(x[0])
		}
	}
	return ""
}
