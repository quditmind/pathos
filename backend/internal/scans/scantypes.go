package scans

import (
	"context"
	"encoding/json"
	"net/http"
	"slices"

	"github.com/google/uuid"

	"pathos/internal/authz"
	"pathos/internal/platform/db"
	"pathos/internal/platform/httpx"
	"pathos/internal/scanners"
)

// Scan types: GET /api/v1/scan-types reports, for each of the 25 scan
// types, the tools that cover it, which of them an online worker of this
// deployment can run, and the import formats that carry its results.

func (s *Service) registerScanTypes(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/v1/scan-types", s.listScanTypes)
}

// onlineTool is what the online workers advertise about one tool.
type onlineTool struct {
	Workers  int
	Manifest *ToolManifest
}

// onlineTools returns the tools that online, non-revoked workers advertise.
func onlineTools(ctx context.Context, q db.Querier, orgID uuid.UUID) (map[string]*onlineTool, int, error) {
	rows, err := q.Query(ctx, `SELECT scanners, tools FROM workers
		WHERE organization_id = $1 AND revoked_at IS NULL AND last_seen_at > now() - $2::interval`, orgID, WorkerOnlineWindow.String())
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	out := map[string]*onlineTool{}
	n := 0
	for rows.Next() {
		var scRaw, toolsRaw []byte
		if err := rows.Scan(&scRaw, &toolsRaw); err != nil {
			return nil, 0, err
		}
		n++
		var sc map[string]string
		var tools map[string]ToolManifest
		_ = json.Unmarshal(scRaw, &sc)
		_ = json.Unmarshal(toolsRaw, &tools)
		for k := range sc {
			t := out[k]
			if t == nil {
				t = &onlineTool{}
				out[k] = t
			}
			t.Workers++
			if m, ok := tools[k]; ok {
				if t.Manifest == nil {
					t.Manifest = &m
				} else {
					// Conservative merge: the strictest authorization wins.
					t.Manifest.Intrusive = t.Manifest.Intrusive || m.Intrusive
					if m.Network == "target" {
						t.Manifest.Network = "target"
					}
				}
			}
		}
	}
	return out, n, rows.Err()
}

// ScanTypeTool is a tool of a scan type.
type ScanTypeTool struct {
	Key      string `json:"key"`
	Name     string `json:"name"`
	Category string `json:"category"`
	License  string `json:"license_spdx"`
	// Source: catalog (a catalog integration), plugin (an operator plugin
	// advertised by a worker) or server (evaluated by the PATHOS server).
	Source string `json:"source"`
	// AdapterAvailable: a PATHOS worker image or manifest can run the tool.
	AdapterAvailable bool `json:"adapter_available"`
	// Runnable: an online worker of this deployment advertises the tool
	// (for server checks: the check is active).
	Runnable  bool     `json:"runnable"`
	Workers   int      `json:"workers"`
	Network   string   `json:"network"`
	Intrusive bool     `json:"intrusive"`
	Targets   []string `json:"targets"`
	Decision  string   `json:"decision"`
}

// ScanTypeFormat is an import format of a scan type.
type ScanTypeFormat struct {
	ID    string `json:"id"`
	Label string `json:"label"`
	Tool  string `json:"tool"`
}

// ScanTypeCoverage is one scan type with what this deployment provides.
type ScanTypeCoverage struct {
	ID            string           `json:"id"`
	Name          string           `json:"name"`
	Description   string           `json:"description"`
	Categories    []string         `json:"categories"`
	Note          string           `json:"note,omitempty"`
	Tools         []ScanTypeTool   `json:"tools"`
	ImportFormats []ScanTypeFormat `json:"import_formats"`
	// RunnableTools counts the tools an online worker can run now.
	RunnableTools int `json:"runnable_tools"`
	// Runnable: a live worker (or the server) can produce this type's
	// results in this deployment.
	Runnable bool `json:"runnable"`
	// Importable: results can be imported in a format specific to the type
	// (the generic formats always apply).
	Importable bool `json:"importable"`
}

// targetsInclude reports whether an online tool's manifest lists target t
// (tools without a manifest scan repositories).
func targetsInclude(o *onlineTool, t string) bool {
	if o == nil || o.Manifest == nil || len(o.Manifest.Targets) == 0 {
		return t == "repository"
	}
	return slices.Contains(o.Manifest.Targets, t)
}

func formatsOut(fs []scanners.ImportFormat) []ScanTypeFormat {
	out := make([]ScanTypeFormat, 0, len(fs))
	for _, f := range fs {
		out = append(out, ScanTypeFormat{ID: f.ID, Label: f.Label, Tool: f.Tool})
	}
	return out
}

func (s *Service) listScanTypes(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	p := s.Principal(ctx)
	if !p.HasAnywhere(authz.PermScannersRead) {
		s.fail(w, r, authz.ErrForbidden)
		return
	}
	online, workers, err := onlineTools(ctx, s.DB, p.OrganizationID)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	var eolEnabled bool
	_ = s.DB.QueryRow(ctx, `SELECT COALESCE((SELECT enabled FROM intel_feeds WHERE feed = 'endoflife'), false)`).Scan(&eolEnabled)

	// Operator plugins advertised by online workers, by scan type.
	type pluginRow struct {
		key, name, category, license, network string
		targets, types                        []string
		intrusive                             bool
	}
	var plugins []pluginRow
	rows, err := s.DB.Query(ctx, `SELECT key, name, category, license_spdx, network, targets, scan_types, intrusive
		FROM scanner_catalog WHERE worker_family = 'plugin' ORDER BY key`)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	for rows.Next() {
		var pr pluginRow
		if err := rows.Scan(&pr.key, &pr.name, &pr.category, &pr.license, &pr.network, &pr.targets, &pr.types, &pr.intrusive); err != nil {
			rows.Close()
			s.fail(w, r, err)
			return
		}
		if online[pr.key] != nil {
			plugins = append(plugins, pr)
		}
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		s.fail(w, r, err)
		return
	}

	items := make([]ScanTypeCoverage, 0, len(scanners.ScanTypes))
	for _, t := range scanners.ScanTypes {
		c := ScanTypeCoverage{ID: t.ID, Name: t.Name, Description: t.Description, Categories: t.Categories, Note: t.Note,
			Tools: []ScanTypeTool{}, ImportFormats: formatsOut(scanners.ScanTypeImportFormats(t))}
		for _, key := range t.Tools {
			var tool ScanTypeTool
			switch key {
			case scanners.LicensePolicy:
				tool = ScanTypeTool{Key: key, Name: "Licence policy", Category: "license", License: "Apache-2.0", Source: "server",
					AdapterAvailable: true, Runnable: true, Network: "none", Targets: []string{}, Decision: "use"}
			case scanners.EndOfLife:
				sc, _ := scanners.Lookup(key)
				tool = ScanTypeTool{Key: key, Name: sc.Name, Category: sc.Category, License: sc.License, Source: "server",
					AdapterAvailable: true, Runnable: eolEnabled, Network: sc.Network, Targets: []string{}, Decision: sc.Decision}
			default:
				sc, ok := scanners.Lookup(key)
				if !ok {
					continue
				}
				tool = ScanTypeTool{Key: key, Name: sc.Name, Category: sc.Category, License: sc.License, Source: "catalog",
					AdapterAvailable: sc.AdapterAvailable, Network: sc.Network, Intrusive: sc.Intrusive, Targets: scanners.TargetsOf(sc),
					Decision: sc.Decision}
				if o := online[key]; o != nil {
					tool.Runnable, tool.Workers = true, o.Workers
					if o.Manifest != nil {
						tool.AdapterAvailable = true
						tool.Targets = o.Manifest.Targets
						tool.Intrusive = tool.Intrusive || o.Manifest.Intrusive
						if o.Manifest.Network == "target" || tool.Network == "" {
							tool.Network = o.Manifest.Network
						}
					}
				}
			}
			c.Tools = append(c.Tools, tool)
		}
		for _, pr := range plugins {
			if !slices.Contains(pr.types, t.ID) {
				continue
			}
			c.Tools = append(c.Tools, ScanTypeTool{Key: pr.key, Name: pr.name, Category: pr.category, License: pr.license, Source: "plugin",
				AdapterAvailable: true, Runnable: true, Workers: online[pr.key].Workers, Network: pr.network, Intrusive: pr.intrusive,
				Targets: pr.targets, Decision: "use"})
		}
		for _, tool := range c.Tools {
			if tool.Runnable {
				c.RunnableTools++
			}
		}
		c.Runnable = c.RunnableTools > 0
		c.Importable = len(c.ImportFormats) > 0
		items = append(items, c)
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"items": items, "generic_import_formats": formatsOut(scanners.GenericImportFormats()),
		"workers_online": workers})
}
