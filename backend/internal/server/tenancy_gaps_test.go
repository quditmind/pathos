package server

// Static tenancy gap checks (docs/MULTI_TENANCY.md). They parse the backend
// source and fail when code is added that could take the organization
// from client input, widen the row-level security scope, drop the request
// scope, or serve a route outside the authenticated mux, until the new
// use is reviewed and added to the allowlists below.

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"path/filepath"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"testing"
)

type srcFile struct {
	path string
	file *ast.File
	fset *token.FileSet
}

func parseBackend(t *testing.T) []srcFile {
	t.Helper()
	var out []srcFile
	fset := token.NewFileSet()
	for _, root := range []string{"..", filepath.Join("..", "..", "cmd")} {
		err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
			if err != nil || d.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
				return err
			}
			f, err := parser.ParseFile(fset, path, nil, parser.ParseComments)
			if err != nil {
				return err
			}
			rel := filepath.ToSlash(path)
			rel = strings.TrimPrefix(strings.TrimPrefix(rel, "../../"), "../")
			if !strings.HasPrefix(rel, "cmd/") {
				rel = "internal/" + rel
			}
			out = append(out, srcFile{path: rel, file: f, fset: fset})
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	if len(out) < 200 {
		t.Fatalf("parsed only %d files", len(out))
	}
	return out
}

// enclosing returns the name of the function declaration containing pos.
func enclosing(f *ast.File, pos token.Pos) string {
	for _, d := range f.Decls {
		fd, ok := d.(*ast.FuncDecl)
		if !ok || pos < fd.Pos() || pos > fd.End() {
			continue
		}
		if fd.Recv != nil && len(fd.Recv.List) > 0 {
			typ := fd.Recv.List[0].Type
			if s, ok := typ.(*ast.StarExpr); ok {
				typ = s.X
			}
			if id, ok := typ.(*ast.Ident); ok {
				return id.Name + "." + fd.Name.Name
			}
		}
		return fd.Name.Name
	}
	return ""
}

func selectorCall(call *ast.CallExpr) (pkg, name string) {
	sel, ok := call.Fun.(*ast.SelectorExpr)
	if !ok {
		return "", ""
	}
	if id, ok := sel.X.(*ast.Ident); ok {
		return id.Name, sel.Sel.Name
	}
	return "", sel.Sel.Name
}

// systemScopeAllowed lists every function allowed to widen the database
// scope to all organizations (row-level security bypass). Each one either
// authenticates a request before its organization is known (and narrows
// to it right after), runs installation administration behind an explicit
// installation-administrator check, or is background work that carries the
// organization of every row it processes.
var systemScopeAllowed = []string{
	"cmd/pathos/main.go:runAPI",                        // MFA enforcement across users (background)
	"cmd/pathos/main.go:runJobs",                       // background jobs
	"cmd/pathos/main.go:runScheduler",                  // scheduler
	"cmd/pathos/main.go:tenancyStartup",                // default organization lookup at startup
	"internal/auth/oidc.go:Service.tokenPrincipal",     // API token hash lookup, then the token's organization
	"internal/identity/http.go:hasOtherMemberships",    // does the same person belong elsewhere (boolean only)
	"internal/mcp/tokens.go:Service.authenticate",      // MCP token hash lookup, then the token's organization
	"internal/repos/service.go:Service.webhookScope",   // connection id -> organization, then signature check
	"internal/scans/worker_api.go:Service.workerAuth",  // worker token hash lookup, then the worker's organization
	"internal/scans/worker_api.go:Service.register",    // organization slug lookup (operator bootstrap token)
	"internal/tenancy/lifecycle.go:CreateOrganization", // installation administrator
	"internal/tenancy/lifecycle.go:DeleteOrganization", // installation administrator
	"internal/tenancy/tenancy.go:MultiTenant",
	"internal/tenancy/tenancy.go:RLSGaps",
	"internal/tenancy/tenancy.go:CheckStartup",
	"internal/tenancy/tenancy.go:ListOrganizations",
	"internal/tenancy/tenancy.go:GetOrganization",
	"internal/tenancy/tenancy.go:GetOrganizationBySlug",
	"internal/tenancy/tenancy.go:SetStatus",
	"internal/tenancy/tenancy.go:Memberships",         // the caller's own verified subject
	"internal/tenancy/tenancy.go:PendingInvites",      // the caller's own verified email
	"internal/tenancy/tenancy.go:OrganizationsBySlug", // the caller's verified token claim
	"internal/tenancy/tenancy.go:IsInstallationAdmin",
	"internal/tenancy/tenancy.go:GrantInstallationAdmin",
	"internal/tenancy/tenancy.go:RevokeInstallationAdmin",
	"internal/tenancy/tenancy.go:ListInstallationAdmins",
	"internal/tenancy/tenancy.go:WriteInstallationAudit",
	"internal/tenancy/tenancy.go:ListInstallationAudit",
}

func TestSystemScopeUsesAreReviewed(t *testing.T) {
	for _, sf := range parseBackend(t) {
		ast.Inspect(sf.file, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			if pkg, name := selectorCall(call); name == "WithSystem" && (pkg == "tenant" || sf.path == "internal/platform/tenant/tenant.go") {
				where := sf.path + ":" + enclosing(sf.file, call.Pos())
				if !slices.Contains(systemScopeAllowed, where) {
					t.Errorf("%s (%s) widens the database scope to every organization; review it and add it to systemScopeAllowed",
						where, sf.fset.Position(call.Pos()))
				}
			}
			return true
		})
	}
}

// backgroundContextAllowed lists functions in request-serving packages
// that start from context.Background() (which carries no organization).
var backgroundContextAllowed = []string{
	"internal/schedule/scheduler.go:Scheduler.lead", // advisory unlock on shutdown (no tenant table)
}

func TestRequestCodeKeepsTheTenantScope(t *testing.T) {
	for _, sf := range parseBackend(t) {
		if strings.HasPrefix(sf.path, "cmd/") || strings.HasPrefix(sf.path, "internal/worker/") ||
			strings.HasPrefix(sf.path, "internal/scanners/") || strings.HasPrefix(sf.path, "internal/platform/") {
			continue // processes, the worker agent and parsers own their contexts
		}
		ast.Inspect(sf.file, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			if pkg, name := selectorCall(call); pkg == "context" && (name == "Background" || name == "TODO") {
				where := sf.path + ":" + enclosing(sf.file, call.Pos())
				if !slices.Contains(backgroundContextAllowed, where) {
					t.Errorf("%s (%s) uses context.%s, which drops the request's organization scope; derive from the request context "+
						"(context.WithoutCancel keeps it) or add a reviewed exception", where, sf.fset.Position(call.Pos()), name)
				}
			}
			return true
		})
	}
}

// orgFieldAllowed lists struct fields that carry an organization in JSON.
// Request bodies must never: the organization comes from the session.
var orgFieldAllowed = []string{
	"internal/identity/store.go:User.OrganizationID",                    // response only
	"internal/scans/worker_api.go:registerRequest.Organization",         // worker registration (operator bootstrap token)
	"internal/tenancy/http.go:MembershipsResponse.Active",               // response only
	"internal/tenancy/tenancy.go:Membership.OrganizationID",             // response only
	"internal/tenancy/tenancy.go:InstallationAuditEntry.OrganizationID", // response only (installation API)
	"internal/auth/organizations.go:switchRequest.OrganizationID",       // checked against the caller's memberships
	"internal/scm/contract.go:RepoRef.Organization",                     // SCM organization (GitHub organization, Azure DevOps organization)
	"internal/scm/scm.go:RemoteRepo.Organization",                       // SCM organization
	"internal/inventory/onboarding.go:SourceRef.Organization",           // SCM organization of a repository being onboarded
	"internal/inventory/onboarding.go:OnboardingSource.Organization",    // SCM organization (response only)
}

func TestNoOrganizationFromClientInput(t *testing.T) {
	orgTag := func(tag string) bool {
		name, _, _ := strings.Cut(reflect.StructTag(tag).Get("json"), ",")
		return name == "organization_id" || name == "organization" || name == "org_id" || name == "active_organization_id"
	}
	for _, sf := range parseBackend(t) {
		ast.Inspect(sf.file, func(n ast.Node) bool {
			switch x := n.(type) {
			case *ast.TypeSpec:
				st, ok := x.Type.(*ast.StructType)
				if !ok {
					return true
				}
				for _, f := range st.Fields.List {
					if f.Tag == nil || len(f.Names) == 0 {
						continue
					}
					tag, _ := strconv.Unquote(f.Tag.Value)
					if orgTag(tag) {
						where := sf.path + ":" + x.Name.Name + "." + f.Names[0].Name
						if !slices.Contains(orgFieldAllowed, where) {
							t.Errorf("%s has an organization JSON field; request bodies must not choose the organization (review and allowlist)", where)
						}
					}
				}
			case *ast.CallExpr:
				// r.PathValue("org..."), r.URL.Query().Get("organization...")
				_, name := selectorCall(x)
				if (name == "PathValue" || name == "Get" || name == "FormValue") && len(x.Args) == 1 {
					if lit, ok := x.Args[0].(*ast.BasicLit); ok && lit.Kind == token.STRING {
						v, _ := strconv.Unquote(lit.Value)
						if strings.HasPrefix(v, "org") || strings.HasPrefix(v, "tenant") {
							t.Errorf("%s reads %q from the request: the organization comes from the session", sf.fset.Position(x.Pos()), v)
						}
					}
				}
			}
			return true
		})
	}
}

// publicRoutes are the only routes served without the authenticated mux
// (RequireAuth): health, sign-in, inbound SCM webhooks (signature-checked
// per connection), the MCP endpoint (its own token authentication) and the
// organization switcher (session-checked, usable while the session's
// organization is suspended) and the product metadata (product, vendor and
// version without authentication; the rest only with a principal).
var publicRoutes = []string{
	"GET /healthz", "GET /readyz", "GET /api/auth/login", "GET /api/auth/callback", "GET /api/v1/meta",
	"GET /api/v1/me/organizations", "POST /api/v1/me/organization", "/mcp", "/api/", "/api",
	"POST /api/webhooks/github/{id}", "POST /api/webhooks/azure-devops/{id}", "POST /api/webhooks/gitlab/{id}", "POST /api/webhooks/bitbucket/{id}",
}

func TestOnlyReviewedRoutesBypassAuthentication(t *testing.T) {
	for _, sf := range parseBackend(t) {
		ast.Inspect(sf.file, func(n ast.Node) bool {
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
				t.Errorf("%s: route patterns must be string literals (the isolation suite scans them)", sf.fset.Position(call.Pos()))
				return true
			}
			pat, _ := strconv.Unquote(lit.Value)
			recv := ""
			if id, ok := sel.X.(*ast.Ident); ok {
				recv = id.Name
			}
			fn := enclosing(sf.file, call.Pos())
			public := (sf.path == "internal/server/server.go" && recv == "public") || fn == "Service.RegisterPublic"
			if public && !slices.Contains(publicRoutes, pat) {
				t.Errorf("%s: %q is served without authentication; review it and add it to publicRoutes", sf.fset.Position(call.Pos()), pat)
			}
			return true
		})
	}
}
