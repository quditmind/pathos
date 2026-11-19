// Package tickets connects PATHOS to issue trackers (Jira, ServiceNow):
// create a ticket for a finding, keep the link and follow the ticket's
// status. Connectors are optional and only talk to the configured server.
package tickets

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"time"
)

// Conn is a configured connection with its credential.
type Conn struct {
	Kind     string // jira | servicenow
	BaseURL  string
	AuthType string // basic | bearer
	Username string
	Secret   string
	Config   Config
	HTTP     *http.Client
	// cloudID caches the looked-up cloud ID of a scoped Jira connection.
	cloudID string
}

// Jira token types.
const (
	TokenUnscoped = "unscoped"
	TokenScoped   = "scoped"
)

// AtlassianGateway is the Atlassian API gateway that scoped API tokens must
// call: https://api.atlassian.com/ex/jira/{cloudId}/rest/... (tests
// replace it).
var AtlassianGateway = "https://api.atlassian.com"

var cloudIDRe = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

// ErrCloudID means the cloud ID of a Jira Cloud site could not be found.
var ErrCloudID = errors.New("the Jira cloud ID could not be found; enter it in the connection (config.cloud_id)")

// apiBase is where REST calls go: the site URL, or for a scoped Jira token
// the Atlassian API gateway with the site's cloud ID.
func (c *Conn) apiBase(ctx context.Context) (string, error) {
	if c.Kind != "jira" || c.Config.TokenType != TokenScoped {
		return strings.TrimRight(c.BaseURL, "/"), nil
	}
	id := c.Config.CloudID
	if id == "" {
		id = c.cloudID
	}
	if id == "" {
		var err error
		if id, err = c.lookupCloudID(ctx); err != nil {
			return "", err
		}
		c.cloudID = id
	}
	return strings.TrimRight(AtlassianGateway, "/") + "/ex/jira/" + url.PathEscape(id), nil
}

// lookupCloudID reads the cloud ID from the site's tenant information
// (GET https://<site>.atlassian.net/_edge/tenant_info, unauthenticated).
func (c *Conn) lookupCloudID(ctx context.Context) (string, error) {
	cctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(cctx, http.MethodGet, strings.TrimRight(c.BaseURL, "/")+"/_edge/tenant_info", nil)
	if err != nil {
		return "", ErrCloudID
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "PATHOS-ASPM")
	resp, err := c.HTTP.Do(req)
	if err != nil {
		var ue *url.Error
		if errors.As(err, &ue) {
			err = ue.Err
		}
		return "", fmt.Errorf("%w: %w", ErrCloudID, err)
	}
	defer resp.Body.Close()
	var out struct {
		CloudID string `json:"cloudId"`
	}
	if resp.StatusCode != http.StatusOK || json.NewDecoder(io.LimitReader(resp.Body, 64<<10)).Decode(&out) != nil || !cloudIDRe.MatchString(strings.ToLower(out.CloudID)) {
		return "", ErrCloudID
	}
	return strings.ToLower(out.CloudID), nil
}

// Config holds connector settings.
type Config struct {
	// Jira
	ProjectKey string   `json:"project_key,omitempty"`
	IssueType  string   `json:"issue_type,omitempty"`
	Labels     []string `json:"labels,omitempty"`
	// TokenType (Jira Cloud): "" or "unscoped" (classic API token, site
	// URL) or "scoped" (API token with scopes, called through the
	// Atlassian API gateway api.atlassian.com/ex/jira/{cloudId}). The two
	// kinds of token look alike, so the administrator chooses.
	TokenType string `json:"token_type,omitempty"`
	// CloudID of the Jira Cloud site (scoped tokens); looked up from the
	// site when empty.
	CloudID string `json:"cloud_id,omitempty"`
	// ServiceNow
	Table           string `json:"table,omitempty"`
	AssignmentGroup string `json:"assignment_group,omitempty"`
	CallerID        string `json:"caller_id,omitempty"`
}

// Issue is what PATHOS sends for a finding.
type Issue struct {
	Summary     string
	Description string
	Severity    string
}

// Ticket is a created or fetched remote ticket.
type Ticket struct {
	Key, ID, URL, Status string
	Done                 bool
}

// Connector is an issue tracker integration. New trackers implement it and
// call Register in an init function; the API, storage, permissions, audit
// and status sync are shared.
type Connector interface {
	// Check validates the connection; it returns who PATHOS acts as.
	Check(ctx context.Context) (string, error)
	// Create opens a ticket.
	Create(ctx context.Context, is Issue) (Ticket, error)
	// Status refreshes a ticket's status.
	Status(ctx context.Context, t Ticket) (Ticket, error)
}

var registry = map[string]func(Conn) Connector{}

// Register adds a connector kind.
func Register(kind string, factory func(Conn) Connector) { registry[kind] = factory }

// Kinds lists the registered connector kinds.
func Kinds() []string {
	out := make([]string, 0, len(registry))
	for k := range registry {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// connector returns the implementation for c.Kind.
func (c Conn) connector() (Connector, error) {
	f, ok := registry[c.Kind]
	if !ok {
		return nil, errors.New("unknown connector " + c.Kind)
	}
	return f(c), nil
}

func init() {
	Register("jira", func(c Conn) Connector { return jira{c} })
	Register("servicenow", func(c Conn) Connector { return serviceNow{c} })
}

type jira struct{ Conn }
type serviceNow struct{ Conn }

// Check, Create and Status dispatch to the connection's connector.
func (c Conn) Check(ctx context.Context) (string, error) {
	k, err := c.connector()
	if err != nil {
		return "", err
	}
	return k.Check(ctx)
}

// Create dispatches to the connection's connector.
func (c Conn) Create(ctx context.Context, is Issue) (Ticket, error) {
	k, err := c.connector()
	if err != nil {
		return Ticket{}, err
	}
	return k.Create(ctx, is)
}

// Status dispatches to the connection's connector.
func (c Conn) Status(ctx context.Context, t Ticket) (Ticket, error) {
	k, err := c.connector()
	if err != nil {
		return t, err
	}
	return k.Status(ctx, t)
}

func (c *Conn) do(ctx context.Context, method, path string, body any, out any) error {
	var rd io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return err
		}
		rd = bytes.NewReader(b)
	}
	cctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	base, err := c.apiBase(cctx)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(cctx, method, base+path, rd)
	if err != nil {
		return errors.New("invalid base URL")
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "PATHOS-ASPM")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if c.AuthType == "bearer" {
		req.Header.Set("Authorization", "Bearer "+c.Secret)
	} else {
		req.Header.Set("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte(c.Username+":"+c.Secret)))
	}
	resp, err := c.HTTP.Do(req)
	if err != nil {
		var ue *url.Error
		if errors.As(err, &ue) {
			err = ue.Err
		}
		return fmt.Errorf("%s unreachable: %w", c.Kind, err)
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	switch {
	case resp.StatusCode == http.StatusUnauthorized:
		return &HTTPError{Status: resp.StatusCode, Msg: "authentication failed (check the user and token)"}
	case resp.StatusCode == http.StatusForbidden:
		return &HTTPError{Status: resp.StatusCode, Msg: "permission denied for this operation"}
	case resp.StatusCode == http.StatusNotFound:
		return &HTTPError{Status: resp.StatusCode, Msg: "not found (check the URL, project or table)"}
	case resp.StatusCode < 200 || resp.StatusCode > 299:
		return &HTTPError{Status: resp.StatusCode, Msg: fmt.Sprintf("HTTP %d%s", resp.StatusCode, remoteMessage(c.Kind, data)),
			RetryAfter: resp.Header.Get("Retry-After")}
	}
	if out == nil || len(data) == 0 {
		return nil
	}
	if err := json.Unmarshal(data, out); err != nil {
		return &HTTPError{Status: resp.StatusCode, Msg: "unexpected response from " + c.Kind, Unreadable: true}
	}
	return nil
}

// HTTPError is a non-2xx (or unreadable) answer of the tracker. Its
// message never contains the request or the credential.
type HTTPError struct {
	Status int
	Msg    string
	// RetryAfter is the tracker's Retry-After header (rate limits).
	RetryAfter string
	// Unreadable: a 2xx answer that is not the expected JSON (often a
	// sign-in page or a wrong base URL).
	Unreadable bool
}

func (e *HTTPError) Error() string { return e.Msg }

// remoteMessage extracts a short validation message (never the request).
func remoteMessage(kind string, b []byte) string {
	var j struct {
		ErrorMessages []string          `json:"errorMessages"`
		Errors        map[string]string `json:"errors"`
		Error         struct {
			Message string `json:"message"`
		} `json:"error"`
	}
	if json.Unmarshal(b, &j) != nil {
		return ""
	}
	var parts []string
	parts = append(parts, j.ErrorMessages...)
	for k, v := range j.Errors {
		parts = append(parts, k+": "+v)
	}
	if j.Error.Message != "" {
		parts = append(parts, j.Error.Message)
	}
	msg := strings.Join(parts, "; ")
	if len(msg) > 300 {
		msg = msg[:300]
	}
	if msg == "" {
		return ""
	}
	return ": " + msg
}

func (c jira) Check(ctx context.Context) (string, error) {
	var me struct {
		DisplayName  string `json:"displayName"`
		EmailAddress string `json:"emailAddress"`
		Name         string `json:"name"`
	}
	if err := c.do(ctx, http.MethodGet, "/rest/api/2/myself", nil, &me); err != nil {
		return "", err
	}
	if c.Config.ProjectKey != "" {
		if err := c.do(ctx, http.MethodGet, "/rest/api/2/project/"+url.PathEscape(c.Config.ProjectKey), nil, nil); err != nil {
			return "", fmt.Errorf("project %s: %w", c.Config.ProjectKey, err)
		}
	}
	return firstNonEmpty(me.DisplayName, me.EmailAddress, me.Name), nil
}

func (c serviceNow) Check(ctx context.Context) (string, error) {
	var out struct {
		Result []map[string]any `json:"result"`
	}
	if err := c.do(ctx, http.MethodGet, "/api/now/table/"+url.PathEscape(c.table())+"?sysparm_limit=1&sysparm_fields=sys_id", nil, &out); err != nil {
		return "", err
	}
	return c.Username, nil
}

func (c Conn) table() string {
	if c.Config.Table != "" {
		return c.Config.Table
	}
	return "incident"
}

func (c jira) Create(ctx context.Context, is Issue) (Ticket, error) {
	typ := c.Config.IssueType
	if typ == "" {
		typ = "Bug"
	}
	fields := map[string]any{"project": map[string]string{"key": c.Config.ProjectKey}, "issuetype": map[string]string{"name": typ},
		"summary": is.Summary, "description": is.Description}
	if len(c.Config.Labels) > 0 {
		fields["labels"] = c.Config.Labels
	}
	var out struct {
		ID  string `json:"id"`
		Key string `json:"key"`
	}
	if err := c.do(ctx, http.MethodPost, "/rest/api/2/issue", map[string]any{"fields": fields}, &out); err != nil {
		return Ticket{}, err
	}
	return Ticket{Key: out.Key, ID: out.ID, URL: strings.TrimRight(c.BaseURL, "/") + "/browse/" + url.PathEscape(out.Key), Status: "Open"}, nil
}

func (c serviceNow) Create(ctx context.Context, is Issue) (Ticket, error) {
	urgency := map[string]string{"critical": "1", "high": "1", "medium": "2"}[is.Severity]
	if urgency == "" {
		urgency = "3"
	}
	rec := map[string]any{"short_description": is.Summary, "description": is.Description, "urgency": urgency, "impact": urgency}
	if c.Config.AssignmentGroup != "" {
		rec["assignment_group"] = c.Config.AssignmentGroup
	}
	if c.Config.CallerID != "" {
		rec["caller_id"] = c.Config.CallerID
	}
	var out struct {
		Result struct {
			SysID  string `json:"sys_id"`
			Number string `json:"number"`
		} `json:"result"`
	}
	if err := c.do(ctx, http.MethodPost, "/api/now/table/"+url.PathEscape(c.table()), rec, &out); err != nil {
		return Ticket{}, err
	}
	u := strings.TrimRight(c.BaseURL, "/") + "/nav_to.do?uri=" + url.QueryEscape(c.table()+".do?sys_id="+out.Result.SysID)
	return Ticket{Key: out.Result.Number, ID: out.Result.SysID, URL: u, Status: "New"}, nil
}

func (c jira) Status(ctx context.Context, t Ticket) (Ticket, error) {
	var out struct {
		Fields struct {
			Status struct {
				Name           string `json:"name"`
				StatusCategory struct {
					Key string `json:"key"`
				} `json:"statusCategory"`
			} `json:"status"`
		} `json:"fields"`
	}
	if err := c.do(ctx, http.MethodGet, "/rest/api/2/issue/"+url.PathEscape(t.Key)+"?fields=status", nil, &out); err != nil {
		return t, err
	}
	t.Status, t.Done = out.Fields.Status.Name, out.Fields.Status.StatusCategory.Key == "done"
	return t, nil
}

func (c serviceNow) Status(ctx context.Context, t Ticket) (Ticket, error) {
	var out struct {
		Result struct {
			State string `json:"state"`
		} `json:"result"`
	}
	if err := c.do(ctx, http.MethodGet, "/api/now/table/"+url.PathEscape(c.table())+"/"+url.PathEscape(t.ID)+"?sysparm_fields=state&sysparm_display_value=true", nil, &out); err != nil {
		return t, err
	}
	t.Status = out.Result.State
	s := strings.ToLower(t.Status)
	t.Done = s == "resolved" || s == "closed" || s == "canceled" || s == "cancelled"
	return t, nil
}

func firstNonEmpty(v ...string) string {
	for _, s := range v {
		if s != "" {
			return s
		}
	}
	return ""
}
