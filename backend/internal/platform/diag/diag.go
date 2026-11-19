// Package diag is the PATHOS diagnostic engine: the error catalogue (the
// single source of truth for every PTH-<AREA>-<NNNN> code), the structured
// error details added to API error responses, the generated troubleshooting
// documentation (docs/troubleshooting/*.md, `make docs-errors`) and the
// catalogue fallback of AI troubleshooting.
//
// A code is attached where an error is raised: either explicitly
// (httpx.Error.WithDiag, a log attribute "error_code") or through the
// legacy short code the error already carried ("not_found",
// "invalid_token", ...), which the catalogue maps (Entry.Legacy). Every
// API error therefore carries a code; PTH-PLAT-0001 is the fallback.
package diag

import (
	"fmt"
	"regexp"
	"slices"
	"sort"
	"strings"
)

// Fallback is the code of an unexpected error with no closer match.
const Fallback = "PTH-PLAT-0001"

// Severity values.
const (
	SevInfo     = "info"
	SevWarning  = "warning"
	SevError    = "error"
	SevCritical = "critical"
)

// Area is one catalogue area (one generated troubleshooting page).
type Area struct {
	Key     string `json:"key"` // PLAT, AUTH, ...
	Slug    string `json:"slug"`
	Title   string `json:"title"`
	Summary string `json:"summary"`
}

// Areas are the code areas of prompt §3.1, in display order. Areas without
// entries yet (later milestones) have no generated page.
var Areas = []Area{
	{"PLAT", "plat", "Platform", "Database, queue, object storage, uploads, request handling and the generic API errors."},
	{"AUTH", "auth", "Authentication and access", "Sign-in, sessions, CSRF, API tokens, permissions, organizations and the identity provider."},
	{"CONN", "conn", "Connections", "SCM providers, ticketing, e-mail, outbound webhooks and inbound webhooks: reachability, certificates, credentials, scopes and rate limits."},
	{"SYNC", "sync", "Synchronisation", "Repository inventory, metadata re-sync, intelligence feeds and outbound deliveries."},
	{"ONB", "onb", "Onboarding and imports", "Repository import jobs, source uploads and asset registration."},
	{"DISC", "disc", "Discovery", "Code discovery (CodeGraph worker)."},
	{"GRAPH", "graph", "CodeGraph", "The code graph store and views."},
	{"TM", "tm", "Threat modelling", "Threat models and attack paths."},
	{"REA", "rea", "Reverse engineering", "Binary and artifact reverse engineering."},
	{"SCAN", "scan", "Scanning", "Scan execution, result and SBOM imports, artifacts and custom rules."},
	{"WORK", "work", "Workers", "Scan workers: registration, leases, sandbox and result uploads."},
	{"AI", "ai", "AI", "AI providers and configurations: review, assistance, fixes and reports."},
	{"GATE", "gate", "Security gates", "Policy gates in CI, pull requests and releases."},
	{"REM", "rem", "Remediation", "Fix pull requests and verified AI fixes."},
	{"REP", "rep", "Reporting", "Saved reports, exports, AI analyst reports and developer insights."},
	{"MON", "mon", "Monitoring", "Runtime context, SLA detection and notification dispatch."},
}

// Entry is one catalogue entry.
type Entry struct {
	Code     string `json:"code"`
	Area     string `json:"area"`
	Category string `json:"category"`
	Severity string `json:"severity"`
	Title    string `json:"title"`
	// Description is the technical description.
	Description string `json:"description"`
	// ConfirmedCause is shown as the cause when Proven: the check that
	// raises the code establishes it.
	ConfirmedCause string `json:"confirmed_cause"`
	// Proven: raising the code proves ConfirmedCause. Otherwise the cause
	// is reported as unconfirmed and ProbableCauses lead.
	Proven bool `json:"proven"`
	// ProbableCauses, most likely first.
	ProbableCauses []string `json:"probable_causes"`
	Impact         string   `json:"impact"`
	// Actions are the corrective actions, in order.
	Actions []string `json:"actions"`
	// Verify lists how to check the fix worked.
	Verify []string `json:"verify"`
	// AIHelp: "Troubleshoot with AI" is offered.
	AIHelp bool `json:"ai_help"`
	// HTTPStatus is the API status when the code is returned by the API
	// (0: raised only in background work and logs).
	HTTPStatus int `json:"http_status,omitempty"`
	// Legacy are the short codes this entry covers: API error codes
	// ("not_found"), sign-in redirect reasons ("login:expired") and
	// repository import item codes ("import:duplicate").
	Legacy []string `json:"legacy_codes,omitempty"`
	// Source names where the error is raised (file paths under backend/).
	Source string `json:"source"`
}

// DocsSlug is the generated page and anchor: "<area>#<code>".
func (e Entry) DocsSlug() string { return strings.ToLower(e.Area) + "#" + e.Code }

// DocsURL is the in-app help link of the entry.
func (e Entry) DocsURL() string { return "/help/troubleshooting/" + e.DocsSlug() }

// CodeRe is the code format.
var CodeRe = regexp.MustCompile(`^PTH-(PLAT|AUTH|CONN|SYNC|ONB|DISC|GRAPH|TM|REA|SCAN|WORK|AI|GATE|REM|REP|MON)-[0-9]{4}$`)

var (
	byCode   map[string]Entry
	byLegacy map[string]string
)

func init() {
	byCode = map[string]Entry{}
	byLegacy = map[string]string{}
	for _, e := range catalogue {
		if err := e.check(); err != nil {
			panic(err)
		}
		if _, dup := byCode[e.Code]; dup {
			panic("diag: duplicate code " + e.Code)
		}
		byCode[e.Code] = e
		for _, l := range e.Legacy {
			if prev, dup := byLegacy[l]; dup {
				panic(fmt.Sprintf("diag: legacy code %q mapped by %s and %s", l, prev, e.Code))
			}
			byLegacy[l] = e.Code
		}
	}
}

func (e Entry) check() error {
	switch {
	case !CodeRe.MatchString(e.Code):
		return fmt.Errorf("diag: invalid code %q", e.Code)
	case !strings.HasPrefix(e.Code, "PTH-"+e.Area+"-"):
		return fmt.Errorf("diag: %s: area %q does not match the code", e.Code, e.Area)
	case !slices.Contains([]string{SevInfo, SevWarning, SevError, SevCritical}, e.Severity):
		return fmt.Errorf("diag: %s: invalid severity %q", e.Code, e.Severity)
	case e.Title == "" || e.Description == "" || e.ConfirmedCause == "" || e.Impact == "" || e.Category == "" || e.Source == "":
		return fmt.Errorf("diag: %s: title, description, confirmed cause, impact, category and source are required", e.Code)
	case len(e.ProbableCauses) == 0 || len(e.Actions) == 0 || len(e.Verify) == 0:
		return fmt.Errorf("diag: %s: probable causes, actions and verification steps are required", e.Code)
	}
	return nil
}

// Lookup returns the entry of code.
func Lookup(code string) (Entry, bool) {
	e, ok := byCode[code]
	return e, ok
}

// MustLookup returns the entry of code and panics for an unknown code
// (codes are constants; a test covers every use).
func MustLookup(code string) Entry {
	e, ok := byCode[code]
	if !ok {
		panic("diag: unknown code " + code)
	}
	return e
}

// ForLegacy returns the code covering a legacy short code ("" if none).
func ForLegacy(legacy string) string { return byLegacy[legacy] }

// All returns every entry ordered by area (Areas order), then code.
func All() []Entry {
	rank := map[string]int{}
	for i, a := range Areas {
		rank[a.Key] = i
	}
	out := slices.Clone(catalogue)
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Area != out[j].Area {
			return rank[out[i].Area] < rank[out[j].Area]
		}
		return out[i].Code < out[j].Code
	})
	return out
}

// ForStatus returns the generic platform code of an HTTP status.
func ForStatus(status int) string {
	switch status {
	case 400:
		return "PTH-PLAT-0002"
	case 401:
		return "PTH-AUTH-1001"
	case 403:
		return "PTH-AUTH-1002"
	case 404, 405:
		return "PTH-PLAT-0004"
	case 409:
		return "PTH-PLAT-0005"
	case 410:
		return "PTH-PLAT-0010"
	case 413:
		return "PTH-PLAT-0007"
	case 415:
		return "PTH-PLAT-0006"
	case 422:
		return "PTH-PLAT-0003"
	case 429:
		return "PTH-PLAT-0008"
	case 502, 503, 504:
		return "PTH-PLAT-0009"
	}
	return Fallback
}

// Resolve picks the code of an API error: the explicit code set where it
// was raised, else the legacy code's entry, else the generic code of the
// status.
func Resolve(explicit, legacy string, status int) string {
	if _, ok := byCode[explicit]; ok {
		return explicit
	}
	if c := ForLegacy(legacy); c != "" {
		return c
	}
	return ForStatus(status)
}

// Cause is the cause block of the envelope.
type Cause struct {
	Confirmed bool   `json:"confirmed"`
	Text      string `json:"text"`
}

// Detail is the diagnostic part of an API error ("error" object fields
// added by PATHOS 3.0; the legacy "code" and "message" stay as they were).
type Detail struct {
	ErrorCode      string   `json:"error_code"`
	Title          string   `json:"title"`
	Cause          Cause    `json:"cause"`
	ProbableCauses []string `json:"probable_causes"`
	Impact         string   `json:"impact"`
	Actions        []string `json:"actions"`
	Verify         []string `json:"verify"`
	DocsURL        string   `json:"docs_url"`
	AIHelp         bool     `json:"ai_help"`
	RequestID      string   `json:"request_id"`
}

// DetailFor builds the diagnostic detail of code. cause, when set, is a
// cause established where the error was raised (shown as confirmed).
func DetailFor(code, cause, requestID string) Detail {
	e, ok := byCode[code]
	if !ok {
		e = byCode[Fallback]
	}
	d := Detail{ErrorCode: e.Code, Title: e.Title, ProbableCauses: e.ProbableCauses, Impact: e.Impact,
		Actions: e.Actions, Verify: e.Verify, DocsURL: e.DocsURL(), AIHelp: e.AIHelp, RequestID: requestID}
	switch {
	case cause != "":
		d.Cause = Cause{Confirmed: true, Text: cause}
	case e.Proven:
		d.Cause = Cause{Confirmed: true, Text: e.ConfirmedCause}
	default:
		d.Cause = Cause{Confirmed: false, Text: "Not confirmed automatically; check the probable causes in order."}
	}
	return d
}
