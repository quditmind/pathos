package frameworks

import (
	"archive/zip"
	"bytes"
	"encoding/json"
	"os"
	"strings"
	"testing"
)

func TestBundledData(t *testing.T) {
	raw, err := os.ReadFile(SourcesFile)
	if err != nil {
		t.Fatal(err)
	}
	var sources []Source
	if err := json.Unmarshal(raw, &sources); err != nil {
		t.Fatal(err)
	}
	if len(sources) != len(Bundled) {
		t.Fatalf("%d pinned sources, %d bundled frameworks", len(sources), len(Bundled))
	}
	for _, s := range sources {
		d, err := Get(s.Framework)
		if err != nil {
			t.Fatal(err)
		}
		// The data file was extracted from exactly the pinned download.
		if d.Release != s.Release || d.SHA256 != s.SHA256 || d.Source != s.URL || len(s.SHA256) != 64 {
			t.Errorf("%s: data %s %s, pin %s %s: run make threat-frameworks", s.Framework, d.Release, d.SHA256, s.Release, s.SHA256)
		}
		if !strings.HasPrefix(s.URL, "https://") || d.Notice == "" || d.Licence == "" || len(d.Entries) < 100 && s.Framework != D3FEND {
			t.Errorf("%s: url, notice, licence or entries missing", s.Framework)
		}
		for _, e := range d.Entries[:5] {
			if e.ID == "" || e.Name == "" || !strings.HasPrefix(e.URL, "https://") {
				t.Errorf("%s entry %+v", s.Framework, e)
			}
		}
	}
	for id, fw := range map[string]string{"T1190": ATTACK, "CAPEC-66": CAPEC, "CWE-89": CWE, "D3-ITF": D3FEND, "linking": LINDDUN} {
		if _, ok := Lookup(fw, id); !ok {
			t.Errorf("%s %s not found", fw, id)
		}
	}
	if got := Related(CAPEC, "CWE-89", "CAPEC-"); len(got) == 0 {
		t.Error("no CAPEC pattern exploits CWE-89")
	}
	res, _ := Search(ATTACK, "public-facing", 5)
	if len(res) == 0 || res[0].ID != "T1190" {
		t.Errorf("search: %+v", res)
	}
	if res, _ := Search(CWE, "cwe-79", 5); len(res) == 0 || res[0].ID != "CWE-79" {
		t.Errorf("exact id first: %+v", res)
	}
	if len(Linddun()) != 7 || len(Notices()) != 5 {
		t.Errorf("linddun %d notices %d", len(Linddun()), len(Notices()))
	}
	for _, n := range Notices()[:3] {
		if !strings.Contains(n, "The MITRE Corporation") {
			t.Errorf("MITRE notice missing: %s", n)
		}
	}
}

// Small inputs in the formats of the four sources (test data).
func TestExtractors(t *testing.T) {
	src := Source{Framework: "x", Release: "1", URL: "https://example.test/x", SHA256: strings.Repeat("0", 64)}
	var objs []map[string]any
	for i := 0; i < 120; i++ {
		objs = append(objs, map[string]any{"type": "attack-pattern", "name": "Tech", "description": "Does a thing. (Citation: X) More text.",
			"external_references": []map[string]string{{"source_name": "mitre-attack", "external_id": "T" + itoa(1000+i), "url": "https://attack.mitre.org/x"},
				{"source_name": "capec", "external_id": "CAPEC-1"}}})
	}
	objs = append(objs, map[string]any{"type": "attack-pattern", "revoked": true, "external_references": []map[string]string{{"source_name": "mitre-attack", "external_id": "T9999"}}})
	b, _ := json.Marshal(map[string]any{"objects": objs})
	d, err := ExtractATTACK(src, bytes.NewReader(b))
	if err != nil || len(d.Entries) != 120 || strings.Contains(d.Entries[0].Summary, "Citation") || len(d.Relations) != 120 {
		t.Fatalf("attack: %v %d", err, len(d.Entries))
	}
	var capec strings.Builder
	capec.WriteString(`<Attack_Pattern_Catalog xmlns="http://capec.mitre.org/capec-3"><Attack_Patterns>`)
	for i := 0; i < 110; i++ {
		capec.WriteString(`<Attack_Pattern ID="` + itoa(i) + `" Name="P" Status="Draft"><Description>D.</Description><Related_Weaknesses><Related_Weakness CWE_ID="89"/></Related_Weaknesses><Taxonomy_Mappings><Taxonomy_Mapping Taxonomy_Name="ATTACK"><Entry_ID>1190</Entry_ID></Taxonomy_Mapping></Taxonomy_Mappings></Attack_Pattern>`)
	}
	capec.WriteString(`</Attack_Patterns></Attack_Pattern_Catalog>`)
	d, err = ExtractCAPEC(src, strings.NewReader(capec.String()))
	if err != nil || len(d.Entries) != 110 || d.Relations[0].To != "CWE-89" && d.Relations[0].To != "T1190" {
		t.Fatalf("capec: %v %+v", err, d.Relations[:2])
	}
	var cwe strings.Builder
	cwe.WriteString(`<Weakness_Catalog xmlns="http://cwe.mitre.org/cwe-8"><Weaknesses>`)
	for i := 0; i < 105; i++ {
		cwe.WriteString(`<Weakness ID="` + itoa(i) + `" Name="W" Status="Draft"><Description>W.</Description><Related_Weaknesses><Related_Weakness Nature="ChildOf" CWE_ID="20" View_ID="1000"/></Related_Weaknesses></Weakness>`)
	}
	cwe.WriteString(`</Weaknesses></Weakness_Catalog>`)
	var zb bytes.Buffer
	zw := zip.NewWriter(&zb)
	f, _ := zw.Create("cwec.xml")
	_, _ = f.Write([]byte(cwe.String()))
	_ = zw.Close()
	d, err = ExtractCWE(src, zb.Bytes())
	if err != nil || len(d.Entries) != 105 || d.Entries[0].ID != "CWE-0" || d.Entries[10].ID != "CWE-10" {
		t.Fatalf("cwe: %v", err)
	}
	var graph []map[string]any
	for i := 0; i < 60; i++ {
		graph = append(graph, map[string]any{"@id": "d3f:T" + itoa(i), "d3f:d3fend-id": "D3-T" + itoa(i), "rdfs:label": "Tech", "d3f:definition": "Def."})
	}
	graph = append(graph, map[string]any{"@id": "d3f:A", "d3f:d3fend-id": "D3A-A", "rdfs:label": "Analytic"})
	b, _ = json.Marshal(map[string]any{"@graph": graph})
	d, err = ExtractD3FEND(src, bytes.NewReader(b))
	if err != nil || len(d.Entries) != 60 {
		t.Fatalf("d3fend: %v", err)
	}
	if s := summarize(strings.Repeat("Word ", 200)); len(s) > summaryMax+4 {
		t.Errorf("summary %d bytes", len(s))
	}
}

func itoa(i int) string {
	b, _ := json.Marshal(i)
	return string(b)
}
