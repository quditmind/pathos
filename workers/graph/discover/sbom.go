package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path"
	"sort"
	"strings"
	"time"
)

// SBOM components come from Syft (a separate process, no network). Each
// component becomes a node keyed by its package URL without version; the
// repository depends on the top-level components and components depend
// on each other as the CycloneDX dependency list says. Evidence: "sbom"
// with the package URL, and the manifest the package was found in.

type cdxComponent struct {
	BOMRef     string `json:"bom-ref"`
	Type       string `json:"type"`
	Name       string `json:"name"`
	Group      string `json:"group"`
	Version    string `json:"version"`
	PURL       string `json:"purl"`
	Properties []struct {
		Name  string `json:"name"`
		Value string `json:"value"`
	} `json:"properties"`
}

type cdxBOM struct {
	Components   []cdxComponent `json:"components"`
	Dependencies []struct {
		Ref       string   `json:"ref"`
		DependsOn []string `json:"dependsOn"`
	} `json:"dependencies"`
}

// purlBase returns "pkg:type/namespace/name" (no version, qualifiers or
// subpath) and the ecosystem type.
func purlBase(purl string) (string, string) {
	if !strings.HasPrefix(purl, "pkg:") {
		return "", ""
	}
	s := purl
	for _, sep := range []string{"#", "?", "@"} {
		if i := strings.LastIndex(s, sep); i > 0 && (sep != "@" || i > strings.LastIndex(s, "/")) {
			s = s[:i]
		}
	}
	typ := strings.SplitN(strings.TrimPrefix(s, "pkg:"), "/", 2)[0]
	return s, typ
}

func runSyft(ctx context.Context, bin, src string) ([]byte, string, error) {
	tmp, err := os.MkdirTemp("", "pathos-graph-syft-")
	if err != nil {
		return nil, "", err
	}
	defer func() { _ = os.RemoveAll(tmp) }()
	out := path.Join(tmp, "sbom.json")
	ctx, cancel := context.WithTimeout(ctx, 15*time.Minute)
	defer cancel()
	// #nosec G204 -- the syft binary path comes from the worker image configuration
	cmd := exec.CommandContext(ctx, bin, "scan", "dir:"+src, "-o", "cyclonedx-json="+out, "-q")
	cmd.Env = append(safeEnv(), "SYFT_CHECK_FOR_APP_UPDATE=false", "SYFT_CACHE_DIR="+path.Join(tmp, "cache"))
	if msg, err := cmd.CombinedOutput(); err != nil {
		return nil, "", fmt.Errorf("syft: %v: %s", err, clip(strings.TrimSpace(string(msg)), 300))
	}
	// #nosec G304 -- written by syft in our own temporary directory
	data, err := os.ReadFile(out)
	ver := toolVersion(ctx, bin, "version")
	return data, ver, err
}

// addSBOM adds component nodes and dependency edges from a CycloneDX BOM.
func (p *project) addSBOM(data []byte) error {
	var bom cdxBOM
	if err := json.Unmarshal(data, &bom); err != nil {
		return err
	}
	byRef := map[string]string{} // bom-ref -> node key
	purls := map[string]string{} // node key -> purl
	where := map[string]string{} // node key -> manifest path
	for _, c := range bom.Components {
		base, eco := purlBase(c.PURL)
		if base == "" || c.Type == "file" {
			continue
		}
		key := "comp:" + base
		loc := ""
		for _, pr := range c.Properties {
			if strings.HasPrefix(pr.Name, "syft:location:") && strings.HasSuffix(pr.Name, ":path") {
				loc = strings.TrimPrefix(pr.Value, "/")
				break
			}
		}
		name := c.Name
		if c.Group != "" {
			name = c.Group + "/" + c.Name
		}
		if p.g.AddNode(key, "component", name, "", map[string]any{"purl": c.PURL, "version": c.Version, "ecosystem": eco,
			"technology": eco, "file": loc, "source": "sbom"}) {
			byRef[c.BOMRef] = key
			purls[key] = c.PURL
			where[key] = loc
		}
	}
	child := map[string]bool{}
	for _, d := range bom.Dependencies {
		from, ok := byRef[d.Ref]
		if !ok {
			continue
		}
		for _, to := range d.DependsOn {
			if tk, ok := byRef[to]; ok && tk != from {
				child[tk] = true
				p.g.AddEdge(from, "depends_on", tk, Ref{Kind: "sbom", Ref: purls[tk], Detail: depDetail(where[from])})
			}
		}
	}
	keys := make([]string, 0, len(purls))
	for k := range purls {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		if !child[k] {
			p.g.AddEdge("repository", "depends_on", k, Ref{Kind: "sbom", Ref: purls[k], Detail: depDetail(where[k])})
		}
	}
	return nil
}

func depDetail(manifest string) string {
	if manifest == "" {
		return "SBOM dependency"
	}
	return "declared in " + manifest
}

// componentForImport returns the component node an external import
// belongs to: the SBOM component with the longest matching name, or a
// component created from the import itself (evidence: the import line).
func (p *project) componentForImport(eco, name string) string {
	name = strings.TrimSpace(name)
	if name == "" {
		return ""
	}
	prefix := "comp:pkg:" + eco + "/"
	switch eco {
	case "golang":
		// Longest SBOM module path that prefixes the import path.
		best := ""
		for cand := name; cand != "." && cand != "/" && cand != ""; cand = path.Dir(cand) {
			if p.g.Has(prefix + cand) {
				best = prefix + cand
				break
			}
		}
		if best != "" {
			return best
		}
		name = goModuleGuess(name)
	case "npm":
		parts := strings.Split(name, "/")
		if strings.HasPrefix(name, "@") && len(parts) >= 2 {
			name = parts[0] + "/" + parts[1]
		} else {
			name = parts[0]
		}
		if strings.HasPrefix(name, "node:") {
			return ""
		}
	case "pypi":
		name = strings.ToLower(strings.SplitN(name, ".", 2)[0])
		name = strings.ReplaceAll(name, "_", "-")
	case "gem":
		name = strings.SplitN(name, "/", 2)[0]
	}
	key := prefix + name
	if eco == "npm" && strings.HasPrefix(name, "@") {
		// purl form of scoped npm packages: pkg:npm/%40scope/name
		alt := prefix + "%40" + strings.TrimPrefix(name, "@")
		if p.g.Has(alt) {
			return alt
		}
	}
	if !p.g.Has(key) {
		p.g.AddNode(key, "component", name, "", map[string]any{"ecosystem": eco, "technology": eco, "source": "import"})
	}
	if p.g.Has(key) {
		return key
	}
	return ""
}

// goModuleGuess trims a Go import path to its likely module path on the
// common hosts (github.com/org/repo/sub -> github.com/org/repo).
func goModuleGuess(ip string) string {
	parts := strings.Split(ip, "/")
	switch parts[0] {
	case "github.com", "gitlab.com", "bitbucket.org", "golang.org", "go.googlesource.com":
		if len(parts) > 3 {
			return strings.Join(parts[:3], "/")
		}
	case "gopkg.in":
		if len(parts) > 2 {
			return strings.Join(parts[:2], "/")
		}
	}
	return ip
}
