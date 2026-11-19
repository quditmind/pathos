package runtimectx

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
)

// The Kubernetes client is a small read-only REST client: it only issues
// GET list requests for the resources in deploy/kubernetes/pathos-reader-clusterrole.yaml.
// It never reads Secrets or ConfigMaps.

// KubeClient lists objects from one API server.
type KubeClient struct {
	Base  *url.URL
	HTTP  *http.Client
	Token string
	// PageSize and MaxObjects bound every list (per resource kind).
	PageSize   int
	MaxObjects int
}

// resource is one list endpoint.
type resource struct {
	Kind       string
	Group      string // "" (core), apps, batch, networking.k8s.io
	Version    string
	Plural     string
	Namespaced bool
}

func (r resource) path(ns string) string {
	p := "/api/" + r.Version
	if r.Group != "" {
		p = "/apis/" + r.Group + "/" + r.Version
	}
	if ns != "" && r.Namespaced {
		p += "/namespaces/" + url.PathEscape(ns)
	}
	return p + "/" + r.Plural
}

// Resources lists everything the inventory reads (and what the ClusterRole
// grants: get, list, watch).
var Resources = []resource{
	{"Namespace", "", "v1", "namespaces", false},
	{"Pod", "", "v1", "pods", true},
	{"Service", "", "v1", "services", true},
	{"Deployment", "apps", "v1", "deployments", true},
	{"ReplicaSet", "apps", "v1", "replicasets", true},
	{"StatefulSet", "apps", "v1", "statefulsets", true},
	{"DaemonSet", "apps", "v1", "daemonsets", true},
	{"Job", "batch", "v1", "jobs", true},
	{"CronJob", "batch", "v1", "cronjobs", true},
	{"Ingress", "networking.k8s.io", "v1", "ingresses", true},
	{"NetworkPolicy", "networking.k8s.io", "v1", "networkpolicies", true},
}

// APIError is a non-2xx answer of the API server.
type APIError struct {
	Status  int
	Path    string
	Message string
}

func (e *APIError) Error() string {
	switch e.Status {
	case http.StatusUnauthorized:
		return "the API server rejected the credentials (401)"
	case http.StatusForbidden:
		return fmt.Sprintf("forbidden (403) listing %s: the ClusterRole does not grant it", e.Path)
	}
	msg := e.Message
	if len(msg) > 200 {
		msg = msg[:200]
	}
	return fmt.Sprintf("API server answered %d for %s: %s", e.Status, e.Path, msg)
}

// ErrTruncated is returned with a partial list when MaxObjects is reached.
var ErrTruncated = errors.New("object limit reached")

// List returns the raw items of a resource (every page).
func (c *KubeClient) List(ctx context.Context, r resource, ns string) ([]json.RawMessage, error) {
	size := c.PageSize
	if size <= 0 {
		size = 500
	}
	maxN := c.MaxObjects
	if maxN <= 0 {
		maxN = 20000
	}
	var out []json.RawMessage
	cont := ""
	for page := 0; page < 1000; page++ {
		q := url.Values{"limit": {fmt.Sprint(size)}}
		if cont != "" {
			q.Set("continue", cont)
		}
		u := *c.Base
		u.Path = strings.TrimRight(u.Path, "/") + r.path(ns)
		u.RawQuery = q.Encode()
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
		if err != nil {
			return out, err
		}
		req.Header.Set("Accept", "application/json")
		req.Header.Set("User-Agent", "pathos-runtime-inventory")
		if c.Token != "" {
			req.Header.Set("Authorization", "Bearer "+c.Token)
		}
		resp, err := c.HTTP.Do(req)
		if err != nil {
			return out, err
		}
		body, err := io.ReadAll(io.LimitReader(resp.Body, 64<<20))
		_ = resp.Body.Close()
		if err != nil {
			return out, err
		}
		if resp.StatusCode != http.StatusOK {
			var st struct {
				Message string `json:"message"`
			}
			_ = json.Unmarshal(body, &st)
			return out, &APIError{Status: resp.StatusCode, Path: r.path(ns), Message: st.Message}
		}
		var list struct {
			Kind     string            `json:"kind"`
			Items    []json.RawMessage `json:"items"`
			Metadata struct {
				Continue string `json:"continue"`
			} `json:"metadata"`
		}
		if err := json.Unmarshal(body, &list); err != nil {
			return out, fmt.Errorf("%s: invalid list response: %w", r.path(ns), err)
		}
		out = append(out, list.Items...)
		if len(out) >= maxN {
			return out[:maxN], ErrTruncated
		}
		if list.Metadata.Continue == "" {
			return out, nil
		}
		cont = list.Metadata.Continue
	}
	return out, ErrTruncated
}

// Raw is what one sync read from a cluster, by kind.
type Raw map[string][]json.RawMessage

// Collect lists every resource (cluster-wide, or per namespace when
// namespaces are given). Failures of individual resources are returned in
// warnings and the rest is kept (a partial inventory); authentication and
// connection errors abort.
func (c *KubeClient) Collect(ctx context.Context, namespaces []string) (Raw, []string, error) {
	raw := Raw{}
	var warnings []string
	for _, r := range Resources {
		scopes := []string{""}
		if r.Namespaced && len(namespaces) > 0 {
			scopes = namespaces
		}
		if !r.Namespaced && len(namespaces) > 0 {
			// Namespace objects of the configured namespaces only.
			for _, ns := range namespaces {
				raw[r.Kind] = append(raw[r.Kind], json.RawMessage(fmt.Sprintf(`{"metadata":{"name":%q}}`, ns)))
			}
			continue
		}
		for _, ns := range scopes {
			items, err := c.List(ctx, r, ns)
			raw[r.Kind] = append(raw[r.Kind], items...)
			if err == nil {
				continue
			}
			var ae *APIError
			switch {
			case errors.Is(err, ErrTruncated):
				warnings = append(warnings, fmt.Sprintf("%s: only the first %d objects were read", r.Plural, len(items)))
			case errors.As(err, &ae) && ae.Status == http.StatusUnauthorized:
				return raw, warnings, err
			case errors.As(err, &ae) && (ae.Status == http.StatusForbidden || ae.Status == http.StatusNotFound):
				warnings = append(warnings, err.Error())
			default:
				if ctx.Err() != nil {
					return raw, warnings, ctx.Err()
				}
				// The first request failing means the cluster is unreachable.
				if r.Kind == Resources[0].Kind || (len(namespaces) > 0 && r.Kind == "Pod") {
					return raw, warnings, err
				}
				warnings = append(warnings, fmt.Sprintf("%s: %v", r.Plural, err))
			}
		}
	}
	return raw, warnings, nil
}
