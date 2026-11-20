package main

import (
	"bytes"
	"path"
	"regexp"
	"strings"

	"github.com/getkin/kin-openapi/openapi3"
	"go.yaml.in/yaml/v3"
)

// OpenAPI 3 and Swagger 2 documents in the repository declare API
// operations. kin-openapi validates OpenAPI 3 documents (external
// references are never followed); positions come from the YAML/JSON
// node tree. An operation is linked to the route with the same method
// and path template.

var specHeadRe = regexp.MustCompile(`(?m)^\s*"?(openapi|swagger)"?\s*:\s*["']?[23]`)

func isSpecCandidate(rel string) bool {
	ext := strings.ToLower(path.Ext(rel))
	return ext == ".yaml" || ext == ".yml" || ext == ".json"
}

var paramRe = regexp.MustCompile(`\{[^}]*\}|:[A-Za-z_][A-Za-z0-9_]*|<[^>]*>|\*[A-Za-z_]*`)

// pathTemplate normalises path parameters ({id}, :id, <int:id>, *rest).
func pathTemplate(p string) string {
	p = strings.TrimSuffix(paramRe.ReplaceAllString(p, "{}"), "/")
	if p == "" {
		return "/"
	}
	return strings.ToLower(p)
}

func (p *project) extractOpenAPI() int {
	routes := map[string][]string{} // METHOD template -> route keys
	for key, n := range p.g.nodes {
		if n.Type != "route" {
			continue
		}
		m, _ := n.Attrs["method"].(string)
		rp, _ := n.Attrs["path"].(string)
		routes[m+" "+pathTemplate(rp)] = append(routes[m+" "+pathTemplate(rp)], key)
	}
	count := 0
	for _, rel := range p.paths {
		if !isSpecCandidate(rel) || strings.Contains(rel, "node_modules/") {
			continue
		}
		data, err := p.read(rel)
		if err != nil || !specHeadRe.Match(firstBytes(data, 4096)) {
			continue
		}
		var root yaml.Node
		if err := yaml.Unmarshal(data, &root); err != nil || len(root.Content) == 0 {
			p.skip(rel, "OpenAPI document could not be parsed")
			continue
		}
		doc := root.Content[0]
		version := "swagger-2"
		if v := mapValue(doc, "openapi"); v != nil {
			version = "openapi-" + v.Value
			loader := openapi3.NewLoader()
			loader.IsExternalRefsAllowed = false
			if _, err := loader.LoadFromData(data); err != nil {
				p.skip(rel, "OpenAPI document not valid: "+clip(oneLine(err.Error()), 160))
			}
		}
		base := ""
		if bp := mapValue(doc, "basePath"); bp != nil {
			base = strings.TrimSuffix(bp.Value, "/")
		}
		paths := mapValue(doc, "paths")
		if paths == nil || paths.Kind != yaml.MappingNode {
			continue
		}
		fileKey := p.fileNode(rel, "")
		if n := p.g.Node(fileKey); n != nil {
			n.Attrs["technology"] = version
		}
		for i := 0; i+1 < len(paths.Content); i += 2 {
			pk, pv := paths.Content[i], paths.Content[i+1]
			if pv.Kind != yaml.MappingNode {
				continue
			}
			for j := 0; j+1 < len(pv.Content); j += 2 {
				mk, mv := pv.Content[j], pv.Content[j+1]
				method := strings.ToUpper(mk.Value)
				if !httpMethods[method] {
					continue
				}
				full := base + pk.Value
				key := "api:" + method + " " + full
				opID := ""
				if o := mapValue(mv, "operationId"); o != nil {
					opID = o.Value
				}
				label := method + " " + full
				if !p.g.AddNode(key, "api_operation", label, fileKey, map[string]any{"method": method, "path": full,
					"operation_id": opID, "file": rel, "line": mk.Line, "technology": version}) {
					continue
				}
				count++
				ev := fileLine(rel, mk.Line, "OpenAPI operation "+label)
				p.g.AddEdge(fileKey, "defines", key, ev)
				for _, rk := range routes[method+" "+pathTemplate(full)] {
					p.g.AddEdge(key, "exposes", rk, ev)
				}
				for _, rk := range routes["ANY "+pathTemplate(full)] {
					p.g.AddEdge(key, "exposes", rk, ev)
				}
			}
		}
	}
	return count
}

func firstBytes(b []byte, n int) []byte {
	if len(b) > n {
		return b[:n]
	}
	return b
}

func mapValue(n *yaml.Node, key string) *yaml.Node {
	if n == nil || n.Kind != yaml.MappingNode {
		return nil
	}
	for i := 0; i+1 < len(n.Content); i += 2 {
		if n.Content[i].Value == key {
			return n.Content[i+1]
		}
	}
	return nil
}

// yamlDocs decodes every document of a YAML stream ("---" separated).
func yamlDocs(data []byte) []*yaml.Node {
	dec := yaml.NewDecoder(bytes.NewReader(data))
	var out []*yaml.Node
	for i := 0; i < 500; i++ {
		var n yaml.Node
		if err := dec.Decode(&n); err != nil {
			break
		}
		if len(n.Content) > 0 {
			out = append(out, n.Content[0])
		}
	}
	return out
}
