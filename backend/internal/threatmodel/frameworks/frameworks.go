// Package frameworks is the offline reference data of threat modelling
// (PATHOS 3.0 M5, ADR-007): MITRE ATT&CK (Enterprise), CAPEC, CWE and
// D3FEND, extracted from pinned, checksum-verified releases by
// cmd/pathos-frameworks (`make threat-frameworks`) and embedded in the
// build, so no online fetch is needed (air-gapped installs included).
//
// Licences (checked 2026-11-20, docs/aspm/PATHOS_THREAT_MODELLING.md §5):
// ATT&CK, CAPEC and CWE are used under the MITRE terms of use
// (non-exclusive, royalty-free licence for research, development and
// commercial use, provided MITRE's copyright designation and the licence
// are reproduced: NOTICE and Notices()); D3FEND is MIT. LINDDUN has no
// stated licence, so only its seven category names are used, with a
// citation and PATHOS's own one-line descriptions (Linddun()).
package frameworks

import (
	"embed"
	"encoding/json"
	"fmt"
	"slices"
	"sort"
	"strings"
	"sync"
)

//go:embed data/*.json
var dataFS embed.FS

// Framework keys.
const (
	ATTACK = "attack"
	CAPEC  = "capec"
	CWE    = "cwe"
	D3FEND = "d3fend"
	// LINDDUN is a code catalogue of category names only.
	LINDDUN = "linddun"
)

// Bundled lists the frameworks with bundled entry data.
var Bundled = []string{ATTACK, CAPEC, CWE, D3FEND}

// Entry is one framework entry.
type Entry struct {
	ID         string `json:"id"`
	Name       string `json:"name"`
	Summary    string `json:"summary,omitempty"`
	URL        string `json:"url"`
	Deprecated bool   `json:"deprecated,omitempty"`
}

// Relation links two entries (from the source data, e.g. a CAPEC attack
// pattern and the CWE weakness it exploits).
type Relation struct {
	From     string `json:"from"`
	To       string `json:"to"`
	Relation string `json:"relation"`
}

// Dataset is one bundled data file.
type Dataset struct {
	Framework string     `json:"framework"`
	Title     string     `json:"title"`
	Release   string     `json:"release"`
	Source    string     `json:"source"`
	SHA256    string     `json:"sha256"`
	Licence   string     `json:"licence"`
	Notice    string     `json:"notice"`
	Entries   []Entry    `json:"entries"`
	Relations []Relation `json:"relations,omitempty"`
	byID      map[string]int
}

var (
	loadOnce sync.Once
	loaded   map[string]*Dataset
	loadErr  error
)

func load() (map[string]*Dataset, error) {
	loadOnce.Do(func() {
		loaded = map[string]*Dataset{}
		for _, f := range Bundled {
			raw, err := dataFS.ReadFile("data/" + f + ".json")
			if err != nil {
				loadErr = fmt.Errorf("framework data %s: %w", f, err)
				return
			}
			var d Dataset
			if err := json.Unmarshal(raw, &d); err != nil {
				loadErr = fmt.Errorf("framework data %s: %w", f, err)
				return
			}
			d.byID = make(map[string]int, len(d.Entries))
			for i, e := range d.Entries {
				d.byID[e.ID] = i
			}
			loaded[f] = &d
		}
	})
	return loaded, loadErr
}

// Get returns the dataset of a bundled framework.
func Get(framework string) (*Dataset, error) {
	m, err := load()
	if err != nil {
		return nil, err
	}
	d, ok := m[framework]
	if !ok {
		return nil, fmt.Errorf("unknown framework %q", framework)
	}
	return d, nil
}

// Lookup returns an entry by id ("T1190", "CAPEC-66", "CWE-89", "D3-ITF").
func Lookup(framework, id string) (Entry, bool) {
	if framework == LINDDUN {
		for _, c := range Linddun() {
			if c.ID == id {
				return Entry{ID: c.ID, Name: c.Name, Summary: c.Summary, URL: c.URL}, true
			}
		}
		return Entry{}, false
	}
	d, err := Get(framework)
	if err != nil {
		return Entry{}, false
	}
	i, ok := d.byID[id]
	if !ok {
		return Entry{}, false
	}
	return d.Entries[i], true
}

// Search returns entries whose id or name contains q (case-insensitive),
// ids that match exactly first, at most limit.
func Search(framework, q string, limit int) ([]Entry, error) {
	var entries []Entry
	if framework == LINDDUN {
		for _, c := range Linddun() {
			entries = append(entries, Entry{ID: c.ID, Name: c.Name, Summary: c.Summary, URL: c.URL})
		}
	} else {
		d, err := Get(framework)
		if err != nil {
			return nil, err
		}
		entries = d.Entries
	}
	q = strings.ToLower(strings.TrimSpace(q))
	var exact, other []Entry
	for _, e := range entries {
		switch {
		case q == "":
			other = append(other, e)
		case strings.ToLower(e.ID) == q:
			exact = append(exact, e)
		case strings.Contains(strings.ToLower(e.ID), q) || strings.Contains(strings.ToLower(e.Name), q):
			other = append(other, e)
		}
		if len(exact)+len(other) >= limit*4 && q == "" {
			break
		}
	}
	out := append(exact, other...)
	if len(out) > limit {
		out = out[:limit]
	}
	return out, nil
}

// Related returns the ids related to id in the dataset's relations (both
// directions), restricted to the target framework's id prefix.
func Related(framework, id, prefix string) []string {
	d, err := Get(framework)
	if err != nil {
		return nil
	}
	var out []string
	for _, r := range d.Relations {
		switch {
		case r.From == id && strings.HasPrefix(r.To, prefix):
			out = append(out, r.To)
		case r.To == id && strings.HasPrefix(r.From, prefix):
			out = append(out, r.From)
		}
	}
	sort.Strings(out)
	return slices.Compact(out)
}

// Release is the bundled release of a framework (for the API and exports).
type Release struct {
	Framework string `json:"framework"`
	Title     string `json:"title"`
	Release   string `json:"release"`
	Source    string `json:"source"`
	SHA256    string `json:"sha256"`
	Licence   string `json:"licence"`
	Notice    string `json:"notice"`
	Entries   int    `json:"entries"`
}

// Releases lists the bundled frameworks, then LINDDUN (citation only).
func Releases() ([]Release, error) {
	var out []Release
	for _, f := range Bundled {
		d, err := Get(f)
		if err != nil {
			return nil, err
		}
		out = append(out, Release{Framework: f, Title: d.Title, Release: d.Release, Source: d.Source, SHA256: d.SHA256,
			Licence: d.Licence, Notice: d.Notice, Entries: len(d.Entries)})
	}
	out = append(out, Release{Framework: LINDDUN, Title: "LINDDUN privacy threat categories", Release: "categories only",
		Source: LinddunCitation, Licence: "none stated: category names cited, no LINDDUN text bundled",
		Notice: "LINDDUN is developed by DistriNet, KU Leuven (" + LinddunCitation + ").", Entries: len(Linddun())})
	return out, nil
}

// Notices returns the attribution notices to reproduce wherever bundled
// framework text is shown or exported (NOTICE, About, exports).
func Notices() []string {
	rs, err := Releases()
	if err != nil {
		return nil
	}
	var out []string
	for _, r := range rs {
		out = append(out, r.Notice)
	}
	return out
}

// LinddunCitation is the source the LINDDUN categories are cited from.
const LinddunCitation = "https://linddun.org"

// LinddunCategory is one LINDDUN privacy threat category. The names are
// cited from LINDDUN; the descriptions are PATHOS's own wording (no
// LINDDUN text is bundled: no licence is stated).
type LinddunCategory struct {
	ID      string `json:"id"`
	Name    string `json:"name"`
	Summary string `json:"summary"`
	URL     string `json:"url"`
}

// Linddun returns the seven LINDDUN categories.
func Linddun() []LinddunCategory {
	return []LinddunCategory{
		{"linking", "Linking", "Records about the same person can be connected.", LinddunCitation},
		{"identifying", "Identifying", "A person can be singled out from the data.", LinddunCitation},
		{"non_repudiation", "Non-repudiation", "A person cannot deny an action when they should be able to.", LinddunCitation},
		{"detecting", "Detecting", "Someone can tell that a person is involved, from the system's behaviour.", LinddunCitation},
		{"data_disclosure", "Data disclosure", "More personal data is collected, kept or shared than needed.", LinddunCitation},
		{"unawareness", "Unawareness", "People are not informed about or in control of their data.", LinddunCitation},
		{"non_compliance", "Non-compliance", "Processing does not follow data protection rules or policy.", LinddunCitation},
	}
}
