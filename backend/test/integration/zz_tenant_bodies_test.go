//go:build integration

package integration

// Valid request bodies for the cross-tenant write probes
// (zz_tenant_isolation_test.go). For every route the AST scan finds, the
// handler's decoded request struct (the argument of httpx.DecodeJSON) is
// located and a body is generated from its fields; fixtures below override
// the values a generator cannot guess (enumerations, formats). The probe
// then passes validation and reaches the organization check.

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
)

type srcPkg struct {
	funcs map[string][]*ast.FuncDecl
	types map[string]ast.Expr
	file  map[ast.Node]*ast.File
}

type bodyIndex struct {
	pkgs map[string]*srcPkg // by import path (pathos/internal/...)
	// route ("METHOD /path") -> decoded type and the file it is resolved in
	routes map[string]routeBody
}

type routeBody struct {
	typ  ast.Expr
	pkg  string
	file *ast.File
}

func buildBodyIndex(t *testing.T) *bodyIndex {
	t.Helper()
	root := filepath.Join("..", "..", "internal")
	idx := &bodyIndex{pkgs: map[string]*srcPkg{}, routes: map[string]routeBody{}}
	fset := token.NewFileSet()
	type reg struct {
		key, pkg string
		file     *ast.File
		handler  ast.Expr
	}
	var regs []reg
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return err
		}
		f, err := parser.ParseFile(fset, path, nil, 0)
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(root, filepath.Dir(path))
		pkgPath := "pathos/internal/" + filepath.ToSlash(rel)
		p := idx.pkgs[pkgPath]
		if p == nil {
			p = &srcPkg{funcs: map[string][]*ast.FuncDecl{}, types: map[string]ast.Expr{}, file: map[ast.Node]*ast.File{}}
			idx.pkgs[pkgPath] = p
		}
		for _, d := range f.Decls {
			switch x := d.(type) {
			case *ast.FuncDecl:
				p.funcs[x.Name.Name] = append(p.funcs[x.Name.Name], x)
				p.file[x] = f
			case *ast.GenDecl:
				for _, s := range x.Specs {
					if ts, ok := s.(*ast.TypeSpec); ok {
						p.types[ts.Name.Name] = ts.Type
						p.file[ts.Type] = f
					}
				}
			}
		}
		ast.Inspect(f, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok || len(call.Args) < 2 {
				return true
			}
			sel, ok := call.Fun.(*ast.SelectorExpr)
			if !ok || (sel.Sel.Name != "HandleFunc" && sel.Sel.Name != "Handle") {
				return true
			}
			lit, ok := call.Args[0].(*ast.BasicLit)
			if !ok || lit.Kind != token.STRING {
				return true
			}
			pat, _ := strconv.Unquote(lit.Value)
			regs = append(regs, reg{key: pat, pkg: pkgPath, file: f, handler: call.Args[1]})
			return true
		})
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range regs {
		p := idx.pkgs[r.pkg]
		var nodes []ast.Node
		switch h := r.handler.(type) {
		case *ast.SelectorExpr:
			for _, fd := range p.funcs[h.Sel.Name] {
				nodes = append(nodes, fd)
			}
		case *ast.CallExpr: // s.requestSync("...") returning a handler, s.webhookScope(s.x)
			if sel, ok := h.Fun.(*ast.SelectorExpr); ok {
				for _, fd := range p.funcs[sel.Sel.Name] {
					nodes = append(nodes, fd)
				}
			}
			for _, a := range h.Args {
				if sel, ok := a.(*ast.SelectorExpr); ok {
					for _, fd := range p.funcs[sel.Sel.Name] {
						nodes = append(nodes, fd)
					}
				}
			}
		case *ast.FuncLit:
			nodes = append(nodes, h)
		}
		for _, n := range nodes {
			if typ, file := idx.decodedType(p, n, 0); typ != nil {
				if file == nil {
					file = r.file
					if fd, ok := n.(*ast.FuncDecl); ok {
						file = p.file[fd]
					}
				}
				idx.routes[r.key] = routeBody{typ: typ, pkg: r.pkg, file: file}
				break
			}
		}
	}
	return idx
}

// decodedType finds the type of the variable passed to httpx.DecodeJSON in
// n, following calls to functions of the same package that receive the
// request (one level deep, for example setStatus(w, r, ...)).
func (idx *bodyIndex) decodedType(p *srcPkg, n ast.Node, depth int) (ast.Expr, *ast.File) {
	var target string
	var callees []string
	ast.Inspect(n, func(x ast.Node) bool {
		call, ok := x.(*ast.CallExpr)
		if !ok {
			return true
		}
		name := ""
		switch f := call.Fun.(type) {
		case *ast.SelectorExpr:
			name = f.Sel.Name
		case *ast.Ident:
			name = f.Name
		}
		if name == "DecodeJSON" && len(call.Args) == 3 && target == "" {
			if u, ok := call.Args[2].(*ast.UnaryExpr); ok && u.Op == token.AND {
				if id, ok := u.X.(*ast.Ident); ok {
					target = id.Name
				}
			}
		} else if name != "" {
			callees = append(callees, name)
		}
		return true
	})
	if target != "" {
		var typ ast.Expr
		ast.Inspect(n, func(x ast.Node) bool {
			if typ != nil {
				return false
			}
			switch s := x.(type) {
			case *ast.ValueSpec:
				for i, nm := range s.Names {
					if nm.Name == target {
						if s.Type != nil {
							typ = s.Type
						} else if i < len(s.Values) {
							if cl, ok := s.Values[i].(*ast.CompositeLit); ok {
								typ = cl.Type
							}
						}
					}
				}
			case *ast.AssignStmt:
				for i, l := range s.Lhs {
					if id, ok := l.(*ast.Ident); ok && id.Name == target && i < len(s.Rhs) {
						if cl, ok := s.Rhs[i].(*ast.CompositeLit); ok {
							typ = cl.Type
						}
					}
				}
			}
			return true
		})
		if typ != nil {
			return typ, nil
		}
		return nil, nil
	}
	if depth > 0 {
		return nil, nil
	}
	for _, c := range callees {
		for _, fd := range p.funcs[c] {
			if typ, _ := idx.decodedType(p, fd, depth+1); typ != nil {
				return typ, p.file[fd]
			}
		}
	}
	return nil, nil
}

// idFunc returns an id (string) for a body field naming a referenced
// resource, or "" when the field is not a known reference.
type idFunc func(field string) string

// refTables maps id field names of request bodies to tenant tables.
var refTables = map[string]string{
	"repository_id": "repositories", "repository_ids": "repositories", "repo_id": "repositories",
	"application_id": "applications", "application_ids": "applications",
	"target_id": "scan_targets", "scan_target_id": "scan_targets", "target_ids": "scan_targets",
	"finding_id": "findings", "finding_ids": "findings", "duplicate_of": "findings",
	"connection_id": "scm_connections", "scm_connection_id": "scm_connections",
	"profile_id": "scan_profiles", "scan_profile_id": "scan_profiles",
	"user_id": "users", "owner_id": "users", "assignee_id": "users", "reviewer_id": "users", "business_owner_id": "users",
	"technical_owner_id": "users", "risk_owner_id": "users", "user_ids": "users", "approver_id": "users",
	"team_id": "teams", "team_ids": "teams", "business_unit_id": "business_units", "parent_id": "business_units",
	"region_id": "regions", "business_region_id": "regions", "country_id": "countries",
	"schedule_id": "scan_schedules", "version_id": "application_versions", "application_version_id": "application_versions",
	"cluster_id": "runtime_clusters", "registry_id": "registry_connections", "category_id": "tag_categories",
	"tag_ids": "tags", "review_ids": "human_reviews", "review_id": "human_reviews", "owner_user_id": "users", "security_owner_user_id": "users", "technical_owner_user_id": "users", "tag_id": "tags", "scan_id": "scan_jobs", "job_id": "scan_jobs", "scan_job_id": "scan_jobs",
	"base_scan_id": "scan_jobs", "head_scan_id": "scan_jobs", "provider_id": "ai_providers",
	"configuration_id": "ai_configurations", "role_id": "roles", "ticket_connection_id": "ticket_connections",
	"rule_id": "custom_rules", "policy_id": "security_policies", "upload_id": "source_uploads",
	"conversation_id": "ai_conversations", "classification_id": "asset_classifications", "oauth_app_id": "scm_oauth_apps",
}

func jsonName(f *ast.Field) (string, bool) {
	if f.Tag != nil {
		tag, _ := strconv.Unquote(f.Tag.Value)
		name, _, _ := strings.Cut(reflect.StructTag(tag).Get("json"), ",")
		if name == "-" {
			return "", false
		}
		if name != "" {
			return name, true
		}
	}
	if len(f.Names) == 0 {
		return "", true // embedded
	}
	if !ast.IsExported(f.Names[0].Name) {
		return "", false
	}
	return f.Names[0].Name, true
}

func (idx *bodyIndex) resolve(file *ast.File, sel *ast.SelectorExpr) (*srcPkg, ast.Expr) {
	pkgName, ok := sel.X.(*ast.Ident)
	if !ok {
		return nil, nil
	}
	for _, im := range file.Imports {
		path, _ := strconv.Unquote(im.Path.Value)
		name := path[strings.LastIndex(path, "/")+1:]
		if im.Name != nil {
			name = im.Name.Name
		}
		if name == pkgName.Name {
			if p := idx.pkgs[path]; p != nil {
				return p, p.types[sel.Sel.Name]
			}
		}
	}
	return nil, nil
}

// gen builds a value for a field of type t named name.
func (idx *bodyIndex) gen(p *srcPkg, file *ast.File, t ast.Expr, name string, depth int, ids idFunc) any {
	if depth > 4 {
		return nil
	}
	switch x := t.(type) {
	case *ast.StarExpr:
		return idx.gen(p, file, x.X, name, depth, ids)
	case *ast.ArrayType:
		if id, ok := x.Elt.(*ast.Ident); ok && id.Name == "byte" {
			return "aXNvbGF0aW9u"
		}
		el := idx.gen(p, file, x.Elt, strings.TrimSuffix(name, "s"), depth+1, ids)
		if el == nil {
			return []any{}
		}
		if s, ok := el.(string); ok && strings.HasSuffix(name, "_ids") {
			if v := ids(name); v != "" {
				s = v
			}
			return []any{s}
		}
		return []any{el}
	case *ast.MapType:
		return map[string]any{}
	case *ast.InterfaceType:
		return nil
	case *ast.StructType:
		out := map[string]any{}
		for _, f := range x.Fields.List {
			n, ok := jsonName(f)
			if !ok {
				continue
			}
			v := idx.gen(p, file, f.Type, n, depth+1, ids)
			if n == "" { // embedded: merge
				if m, ok := v.(map[string]any); ok {
					for k, vv := range m {
						out[k] = vv
					}
				}
				continue
			}
			if v != nil {
				out[n] = v
			}
		}
		return out
	case *ast.SelectorExpr:
		switch x.Sel.Name {
		case "UUID":
			if v := ids(name); v != "" {
				return v
			}
			return uuid.NewString()
		case "Time":
			return time.Now().Add(30 * 24 * time.Hour).UTC().Format(time.RFC3339)
		case "RawMessage":
			return map[string]any{}
		case "Duration":
			return 60
		}
		if q, def := idx.resolve(file, x); def != nil {
			return idx.gen(q, q.file[def], def, name, depth+1, ids)
		}
		return nil
	case *ast.Ident:
		switch x.Name {
		case "string":
			return stringFor(name)
		case "bool":
			return true
		case "int", "int32", "int64", "uint", "uint32", "uint64", "int16", "int8":
			return intFor(name)
		case "float64", "float32":
			return 0.5
		case "any":
			return nil
		}
		if strings.Contains(x.Name, "UUID") { // optional-UUID wrapper types
			if v := ids(name); v != "" {
				return v
			}
			return uuid.NewString()
		}
		if def := p.types[x.Name]; def != nil {
			return idx.gen(p, p.file[def], def, name, depth+1, ids)
		}
		return nil
	}
	return nil
}

func intFor(name string) int {
	switch {
	case strings.Contains(name, "days"):
		return 30
	case strings.Contains(name, "minutes"):
		return 60
	case strings.Contains(name, "pull_request"), strings.Contains(name, "line"):
		return 1
	case strings.Contains(name, "priority"):
		return 50
	}
	return 1
}

func stringFor(name string) string {
	n := strings.ToLower(name)
	switch {
	case strings.Contains(n, "email"):
		return "iso-probe@iso-a.test"
	case strings.Contains(n, "url") || n == "endpoint" || n == "api_server" || n == "reference":
		// Unique per body (targets are unique per reference); .invalid
		// never resolves, so nothing is contacted.
		return "https://iso-probe-" + uuid.NewString()[:8] + ".invalid"
	case n == "severity" || strings.HasSuffix(n, "_severity") || n == "min_severity":
		return "low"
	case n == "reason" || n == "justification" || strings.Contains(n, "comment") || strings.Contains(n, "note") ||
		n == "rationale" || n == "description" || n == "body" || n == "message" || n == "statement" || n == "content" ||
		strings.Contains(n, "authorization"):
		return "Isolation probe: a valid text long enough for every length check."
	case n == "name" || n == "title" || n == "display_name":
		return "iso-probe-" + uuid.NewString()[:8]
	case n == "cron":
		return "0 3 * * *"
	case n == "timezone":
		return "UTC"
	case n == "decision":
		return "false_positive"
	case n == "disposition":
		return "false_positive"
	case n == "scope_type":
		return "organization"
	case n == "provider":
		return "github"
	case n == "version":
		return "1.0.0"
	case n == "ref" || n == "branch" || strings.HasSuffix(n, "_branch"):
		return "main"
	case strings.Contains(n, "sha") || n == "commit":
		return strings.Repeat("a", 40)
	case n == "role":
		return "viewer"
	case n == "verdict":
		return "false_positive"
	case n == "token" || strings.Contains(n, "secret") || strings.Contains(n, "password") || n == "api_key":
		return "iso-probe-credential-value"
	case n == "slug":
		return "iso-probe"
	case strings.HasSuffix(n, "name"):
		return "iso-probe-" + uuid.NewString()[:8]
	}
	return "iso-probe"
}

// writeFixtures override generated fields per route ("METHOD pattern").
// Values here are the ones validation needs (enumerations, formats).
var writeFixtures = map[string]map[string]any{
	"PATCH /api/v1/asset-classifications/{id}":                {"kind": nil, "key": nil, "color": "#336699"},
	"PATCH /api/v1/scm-connections/{id}":                      {"provider": nil, "auth_type": nil, "base_url": nil},
	"PATCH /api/v1/scm-oauth-apps/{id}":                       {"provider": nil},
	"PATCH /api/v1/tags/{id}":                                 {"color": "blue"},
	"POST /api/v1/tag-categories/{id}/tags":                   {"color": "blue"},
	"POST /api/v1/human-reviews/{id}/ai/{rid}/patch-decision": {"decision": "rejected"},
	"POST /api/v1/human-reviews/{id}/ai":                      {"kind": "explanation"},
	"POST /api/v1/human-reviews/{id}/independent-review":      {"outcome": "approved"},
	"POST /api/v1/human-reviews/{id}/status":                  {"status": "in_progress"},
	"POST /api/v1/mcp-servers/{id}/decision":                  {"status": "approved"},
	"PUT /api/v1/ai/configurations/{id}":                      {"effort": "low", "approval_policy": "never"},
	"PUT /api/v1/component-policies/{id}":                     {"violation_state": "warn", "condition_kind": "outdated"},
	"PUT /api/v1/human-reviews/{id}/remediation":              {"status": "open", "priority": "p2", "link": "https://tracker.iso-probe.invalid/1"},
	"PUT /api/v1/human-reviews/{id}/severity":                 {"cvss_vector": nil, "cvss_score": nil},
	"PUT /api/v1/mcp-servers/{id}/tools":                      {"tools": []any{map[string]any{"tool": "list_pending_findings", "access": "read", "allowed": true}}},
	"PUT /api/v1/notifications/webhooks/{id}":                 {"format": "json", "events": []any{"findings.new"}, "trigger_auth": nil},
	"PUT /api/v1/scm-connections/{id}/webhook-signing-token":  {"token": "whsec_aXNvbGF0aW9uLXByb2JlLXNpZ25pbmcta2V5LTEyMzQ="},
	"PUT /api/v1/scan-profiles/{id}":                          {"severity_threshold": "high", "timeout_seconds": 600},
	"POST /api/v1/applications":                               {"criticality": "high", "lifecycle": nil, "environment": nil},
	"POST /api/v1/ai/configurations":                          {"effort": "low", "approval_policy": "never"},
	"POST /api/v1/repositories/bulk-tags":                     {"add": []any{"@tags"}, "remove": nil},
	"POST /api/v1/findings/bulk":                              {"action": "assign"},
	"POST /api/v1/human-reviews/bulk":                         {"action": "priority", "priority": "p2", "reviewer_id": nil},
	"POST /api/v1/human-reviews":                              {"priority": "p2"},
	"POST /api/v1/runtime/mappings":                           {"cluster_id": nil, "namespace": "iso-probe", "label_key": nil, "label_value": nil},
	"POST /api/v1/scans":                                      {"trigger": "manual"},
	"POST /api/v1/scan-targets": {"kind": "url", "config": nil, "api_spec": nil, "auth_type": nil,
		"auth_username": nil, "auth_header_name": nil, "auth_secret": nil, "signature_material": nil, "intrusive_authorized": nil,
		"intrusive_authorization_note": nil, "authorized": true},
	"PUT /api/v1/ticket-connections/{id}": {"kind": "jira", "auth_type": "bearer", "config": map[string]any{"project_key": "ISO"}},
	// PATHOS 3.0 M3 (inventory).
	"POST /api/v1/tag-rules":                      {"target_type": "repository", "condition": "path_pattern", "field": nil, "value": "iso/*"},
	"PATCH /api/v1/tag-rules/{id}":                {"target_type": "repository", "condition": "path_pattern", "field": nil, "value": "iso/*"},
	"PATCH /api/v1/tag-categories/{id}/framework": {"color": "#336699", "mandatory_asset_types": nil},
	"POST /api/v1/onboarding":                     {"mode": "link", "application": nil},
	"POST /api/v1/tag-assignments/bulk":           {"target_type": "application", "ids": []any{"@applications"}, "add_tag_ids": []any{"@tags"}, "remove_tag_ids": nil},
	// Threat models (M5).
	"POST /api/v1/threat-models": {"generate": false, "repository_id": nil},
	"POST /api/v1/threat-models/import": {"format": "threat_dragon", "repository_id": nil, "document": map[string]any{"summary": map[string]any{"title": "iso-probe"},
		"detail": map[string]any{"diagrams": []any{map[string]any{"cells": []any{}}}}}},
	"POST /api/v1/threat-models/{id}/threats": {"category": "spoofing", "severity": "high", "confidence": nil, "element_keys": nil, "mappings": nil},
	"PATCH /api/v1/threats/{id}": {"severity": "low", "status": nil, "reason": "isolation probe", "owner_id": nil, "link": nil,
		"mappings_add": nil, "mappings_remove": nil, "unlink_findings": nil, "title": nil, "description": nil, "clear_owner": nil},
	"POST /api/v1/threat-models/{id}/reject":   {"decision": "changes_requested", "note": "isolation probe"},
	"POST /api/v1/threat-models/{id}/generate": {"engines": nil},
}

// controlSkip lists creates whose control request (with A's parents)
// would contact an external system (an SCM API) or needs an uploaded
// archive; they are still probed with B's parents.
var controlSkip = map[string]bool{
	"POST /api/v1/repositories/import":         true,
	"POST /api/v1/scm-connections/oauth/start": true,
	"POST /api/v1/repository-imports":          true,
	"POST /api/v1/repository-imports/validate": true,
}

// writeQueries add query parameters a write route validates.
var writeQueries = map[string]string{
	"DELETE /api/v1/human-reviews/{id}/evidence/{eid}": "reason=isolation+probe",
}

// bodyFor returns a JSON-ready body for the route, or nil when neither the
// AST nor a fixture describes one.
func (idx *bodyIndex) bodyFor(key string, ids idFunc) map[string]any {
	var out map[string]any
	if rb, ok := idx.routes[key]; ok {
		p := idx.pkgs[rb.pkg]
		if m, ok := idx.gen(p, rb.file, rb.typ, "", 0, ids).(map[string]any); ok {
			out = m
		}
	}
	if fx, ok := writeFixtures[key]; ok {
		if out == nil {
			out = map[string]any{}
		}
		for k, v := range fx {
			if v == nil {
				delete(out, k)
				continue
			}
			out[k] = v
		}
	}
	// "@table" placeholders in fixtures name a reference by table.
	for k, v := range out {
		if l, ok := v.([]any); ok && len(l) == 1 {
			if ph, ok := l[0].(string); ok && strings.HasPrefix(ph, "@") {
				out[k] = []any{ids("@" + ph[1:])}
			}
		}
	}
	// References inside the body follow the caller's choice of
	// organization (ids), also when the generator made something else.
	for k := range out {
		if _, ref := refTables[k]; ref {
			if v := ids(k); v != "" {
				if _, isList := out[k].([]any); isList {
					out[k] = []any{v}
				} else {
					out[k] = v
				}
			}
		}
	}
	return out
}
