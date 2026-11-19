// Package connectors is the Connectors hub of PATHOS 3.0 (milestone M2): one
// catalogue of connector kinds, one list over every connection PATHOS
// keeps (a registry that points at the existing connection tables, plus
// kinds stored in the registry itself), real health checks with a stored
// history, and AI troubleshooting with redacted context.
//
// Everything is behind the "connectors" feature flag. The existing pages
// and APIs (SCM connections, integrations, notifications, runtime, AI
// settings) keep working whatever the flag.
//
// Adding a kind: declare it with RegisterKind from an init function in this
// package (a file per kind family). A kind already listed as planned is
// replaced by the registration. A kind stored in the registry sets
// Creatable, Validate and Checker; a kind backed by a legacy table also
// needs a source (sources.go).
package connectors

import (
	"context"
	"fmt"
	"slices"
	"sort"
	"sync"

	"pathos/internal/authz"
)

// Categories of the Connectors page, in display order.
var Categories = []Category{
	{"scm_ide", "SCM & IDE"},
	{"cicd", "CI/CD"},
	{"cloud", "Cloud"},
	{"containers", "Containers"},
	{"security", "Security"},
	{"iam_secrets", "IAM & Secrets"},
	{"apis", "APIs"},
	{"databases", "Databases"},
	{"monitoring", "Monitoring"},
}

// Category is one category of the Connectors page.
type Category struct {
	Key   string `json:"key"`
	Label string `json:"label"`
}

// Implementation status of a kind.
const (
	KindExisting = "existing"
	KindPartial  = "partial"
	KindPlanned  = "planned"
)

// Where a kind's health check runs.
const (
	RunsInAPI  = "api"  // the API server may call the system (it already does for its test button)
	RunsInJobs = "jobs" // only the jobs service calls it (the API server never does)
	RunsNone   = ""     // no connector rows (inbound integrations, planned kinds)
)

// Direction of a kind.
const (
	Outbound = "outbound" // PATHOS calls the system
	Inbound  = "inbound"  // the system calls PATHOS (CLI, IDE, CI templates, MCP)
	Platform = "platform" // part of the installation (object storage, egress proxy)
)

// Kind is one entry of the kinds catalogue (GET /api/v1/connectors/kinds).
type Kind struct {
	Kind        string   `json:"kind"`
	Category    string   `json:"category"`
	Label       string   `json:"label"`
	Status      string   `json:"status"`
	AuthMethods []string `json:"auth_methods"`
	// DocsSlug is the user-guide anchor ("connectors#github"); the help
	// route is /help/user-guide/<slug>.
	DocsSlug string `json:"docs_slug"`
	// OfflineOK: the kind can work with PATHOS_OFFLINE=true (internal
	// systems). Per connection, internet-only hosts are still disabled.
	OfflineOK bool   `json:"offline_ok"`
	Direction string `json:"direction"`
	// ManagedAt is the page where connections of an existing kind are
	// created and edited until the Connectors page reaches parity.
	ManagedAt string `json:"managed_at,omitempty"`
	// Creatable: POST /api/v1/connectors accepts the kind (kinds stored in
	// the registry). Existing kinds keep their own create endpoints.
	Creatable bool `json:"creatable"`
	// CheckedBy is where health checks run: "api", "jobs" or "" (no
	// connector rows).
	CheckedBy string `json:"checked_by"`
	// Note explains a planned or partial kind.
	Note string `json:"note,omitempty"`

	// Source is the legacy table of an existing kind ("" for kinds stored
	// in the registry and catalogue-only kinds).
	Source string `json:"-"`
	// Checker runs the health check (nil: catalogue only).
	Checker Checker `json:"-"`
	// CanRead and CanManage decide access per kind; they reuse the
	// permissions of the existing pages (nil: settings.manage).
	CanRead   func(p *authz.Principal) bool `json:"-"`
	CanManage func(p *authz.Principal) bool `json:"-"`
	// Validate normalizes and checks the non-secret configuration of a
	// creatable kind; it returns the configuration to store.
	Validate func(cfg map[string]any) (map[string]any, error) `json:"-"`
	// CredentialRequired: a creatable kind needs a credential on create.
	CredentialRequired bool `json:"-"`
	// ConfigFields is the form of a creatable kind (Add connector dialog).
	ConfigFields []ConfigField `json:"config_fields,omitempty"`
	// SecretRefs: the credential may be a vault:<mount>/<path>#<key> reference.
	SecretRefs bool `json:"secret_refs"`
	// Create, for a creatable kind kept in a legacy table, creates the
	// source row instead of a registry row (reconciliation then adds the
	// registry row); it returns the source key.
	Create func(ctx context.Context, env *Env, p *authz.Principal, name string, cfg map[string]any, credential string) (string, error) `json:"-"`
	// NeedsInternet reports, for one connection, whether it can only work
	// with internet access (disabled in offline mode). nil: !OfflineOK.
	NeedsInternet func(meta map[string]string, cfg map[string]any) bool `json:"-"`
}

// Checker runs a real health check of one connector.
type Checker interface {
	Check(ctx context.Context, env *Env, t Target) Result
}

// CheckFunc adapts a function to Checker.
type CheckFunc func(ctx context.Context, env *Env, t Target) Result

// Check implements Checker.
func (f CheckFunc) Check(ctx context.Context, env *Env, t Target) Result { return f(ctx, env, t) }

var (
	kindsMu sync.RWMutex
	kinds   = map[string]Kind{}
)

// RegisterKind adds a kind to the catalogue. Registering a kind that is
// already listed replaces it only when the listed entry is planned (a
// builder implementing a planned kind); any other duplicate panics.
func RegisterKind(k Kind) {
	kindsMu.Lock()
	defer kindsMu.Unlock()
	if prev, ok := kinds[k.Kind]; ok && prev.Status != KindPlanned {
		panic("connectors: kind " + k.Kind + " registered twice")
	}
	if err := k.valid(); err != nil {
		panic(err)
	}
	if k.AuthMethods == nil {
		k.AuthMethods = []string{}
	}
	if k.DocsSlug == "" {
		k.DocsSlug = "connectors#" + k.Kind
	}
	kinds[k.Kind] = k
}

func (k Kind) valid() error {
	switch {
	case k.Kind == "" || k.Label == "":
		return fmt.Errorf("connectors: kind %q needs a key and a label", k.Kind)
	case !slices.ContainsFunc(Categories, func(c Category) bool { return c.Key == k.Category }):
		return fmt.Errorf("connectors: kind %s: unknown category %q", k.Kind, k.Category)
	case !slices.Contains([]string{KindExisting, KindPartial, KindPlanned}, k.Status):
		return fmt.Errorf("connectors: kind %s: invalid status %q", k.Kind, k.Status)
	case !slices.Contains([]string{Outbound, Inbound, Platform}, k.Direction):
		return fmt.Errorf("connectors: kind %s: invalid direction %q", k.Kind, k.Direction)
	case k.Creatable && (k.Checker == nil || (k.Source != "" && k.Create == nil) || (k.Source == "" && k.Validate == nil)):
		return fmt.Errorf("connectors: kind %s: a creatable kind needs a Checker, and Validate (registry kinds) or Create (kinds kept in a legacy table)", k.Kind)
	case (k.CheckedBy != RunsNone) != (k.Checker != nil):
		return fmt.Errorf("connectors: kind %s: CheckedBy and Checker go together", k.Kind)
	}
	return nil
}

// LookupKind returns a kind of the catalogue.
func LookupKind(kind string) (Kind, bool) {
	kindsMu.RLock()
	defer kindsMu.RUnlock()
	k, ok := kinds[kind]
	return k, ok
}

// Kinds returns the catalogue ordered by category, then label.
func Kinds() []Kind {
	kindsMu.RLock()
	out := make([]Kind, 0, len(kinds))
	for _, k := range kinds {
		out = append(out, k)
	}
	kindsMu.RUnlock()
	rank := map[string]int{}
	for i, c := range Categories {
		rank[c.Key] = i
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Category != out[j].Category {
			return rank[out[i].Category] < rank[out[j].Category]
		}
		return out[i].Label < out[j].Label
	})
	return out
}

// CategoryOf returns the category of a kind ("" when unknown).
func CategoryOf(kind string) string {
	k, _ := LookupKind(kind)
	return k.Category
}

func (k Kind) canRead(p *authz.Principal) bool {
	if p == nil {
		return false
	}
	if k.CanRead != nil {
		return k.CanRead(p)
	}
	return p.HasOrgWide(authz.PermSettingsManage)
}

func (k Kind) canManage(p *authz.Principal) bool {
	if p == nil {
		return false
	}
	if k.CanManage != nil {
		return k.CanManage(p)
	}
	return p.HasOrgWide(authz.PermSettingsManage)
}

// Permission helpers reused by the kind declarations. They mirror the
// checks of the existing pages exactly.
func anywhere(perms ...authz.Permission) func(*authz.Principal) bool {
	return func(p *authz.Principal) bool {
		for _, perm := range perms {
			if p.HasAnywhere(perm) {
				return true
			}
		}
		return false
	}
}

func orgWide(perms ...authz.Permission) func(*authz.Principal) bool {
	return func(p *authz.Principal) bool {
		for _, perm := range perms {
			if p.HasOrgWide(perm) {
				return true
			}
		}
		return false
	}
}

func either(a, b func(*authz.Principal) bool) func(*authz.Principal) bool {
	return func(p *authz.Principal) bool { return a(p) || b(p) }
}
