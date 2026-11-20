package main

import (
	"context"
	"fmt"
	"path/filepath"
	"runtime"
	"runtime/debug"
	"strings"
	"time"
)

// Version is set at build time (-ldflags -X main.Version=...).
var Version = "dev"

// engineVersions lists the parser and library versions compiled in.
func engineVersions() map[string]string {
	out := map[string]string{"pathos-graph": Version, "go-parser": runtime.Version()}
	names := map[string]string{
		"github.com/tree-sitter/go-tree-sitter":         "tree-sitter",
		"github.com/tree-sitter/tree-sitter-java":       "tree-sitter-java",
		"github.com/tree-sitter/tree-sitter-python":     "tree-sitter-python",
		"github.com/tree-sitter/tree-sitter-javascript": "tree-sitter-javascript",
		"github.com/tree-sitter/tree-sitter-typescript": "tree-sitter-typescript",
		"github.com/tree-sitter/tree-sitter-c-sharp":    "tree-sitter-c-sharp",
		"github.com/tree-sitter/tree-sitter-php":        "tree-sitter-php",
		"github.com/tree-sitter/tree-sitter-ruby":       "tree-sitter-ruby",
		"github.com/go-enry/go-enry/v2":                 "go-enry",
		"github.com/getkin/kin-openapi":                 "kin-openapi",
	}
	if bi, ok := debug.ReadBuildInfo(); ok {
		for _, d := range bi.Deps {
			if n, ok := names[d.Path]; ok {
				v := d.Version
				if d.Replace != nil {
					v = d.Replace.Version
				}
				out[n] = strings.TrimPrefix(v, "v")
			}
		}
	}
	return out
}

// Discover builds the graph of the repository at src.
func Discover(ctx context.Context, src string, opts Options) (*Output, error) {
	start := time.Now()
	abs, err := filepath.Abs(src)
	if err != nil {
		return nil, err
	}
	st := &Stats{Languages: map[string]int{}, Skipped: []Skipped{}}
	p := &project{root: abs, opts: opts, g: newGraph(opts.MaxNodes, opts.MaxEdges), stats: st, byRel: map[string]*srcFile{}}
	engines := engineVersions()
	if err := p.walk(); err != nil {
		return nil, err
	}
	p.g.AddNode("repository", "repository", filepath.Base(abs), "", map[string]any{"technology": "source"})

	// SBOM components first, so that imports link to them.
	if opts.sbomJSON != nil {
		if err := p.addSBOM(opts.sbomJSON); err != nil {
			return nil, err
		}
	} else if opts.Syft != "" {
		data, ver, err := runSyft(ctx, opts.Syft, abs)
		if err != nil {
			p.skip("", "SBOM components skipped: "+clip(err.Error(), 200))
		} else if err := p.addSBOM(data); err != nil {
			p.skip("", "SBOM could not be read: "+clip(err.Error(), 200))
		}
		if ver != "" {
			engines["syft"] = ver
		}
	} else {
		p.skip("", "SBOM components skipped: syft not available")
	}

	p.extractGo()
	p.resolveTreeSitter(p.extractTreeSitter())

	if opts.opengrepJSON != nil {
		if _, err := p.applyOpengrep(opts.opengrepJSON, abs); err != nil {
			return nil, err
		}
	} else if opts.Opengrep != "" && opts.RulesDir != "" {
		data, err := runOpengrep(ctx, opts.Opengrep, opts.RulesDir, abs)
		if err != nil {
			p.skip("", "routes and data access rules skipped: "+clip(err.Error(), 200))
		} else if _, err := p.applyOpengrep(data, abs); err != nil {
			p.skip("", "rule results could not be read: "+clip(err.Error(), 200))
		}
		if v := toolVersion(ctx, opts.Opengrep, "--version"); v != "" {
			engines["opengrep"] = v
		}
	} else {
		p.skip("", "routes and data access rules skipped: opengrep not available")
	}
	p.extractOpenAPI()
	p.extractDockerfiles()
	p.extractCompose()
	p.extractKubernetes()
	p.extractTerraform()
	p.extractConfig()
	p.extractSecretRefs()

	p.g.fixParents()
	if err := p.g.Validate(); err != nil {
		return nil, fmt.Errorf("graph invariant violated: %w", err)
	}
	nodes, edges := p.g.Sorted()
	st.Truncated = st.Truncated || p.g.truncated
	st.NodeCount, st.EdgeCount = len(nodes), len(edges)
	st.DurationMS = time.Since(start).Milliseconds()
	return &Output{Schema: Schema, Generator: map[string]string{"name": "pathos-graph", "version": Version},
		Engines: engines, Stats: *st, Nodes: nodes, Edges: edges}, nil
}
