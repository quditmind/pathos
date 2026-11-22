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
	"time"

	"github.com/google/uuid"

	"pathos/internal/scm"
)

// Health checks for the Connectors hub. They run in the jobs service only
// (the API server never calls a cluster or a registry) and read no
// inventory: one version request and one single-item list per kind.

// ClusterHealth is what a cluster check reports.
type ClusterHealth struct {
	ServerVersion string
	Readable      []string // resource kinds the role can list
	Denied        []string // kinds answered 403/404 (partial inventory)
	LongLived     bool     // a token credential (no expiry PATHOS can see)
}

// Version reads GET /version (gitVersion).
func (c *KubeClient) Version(ctx context.Context) (string, error) {
	var v struct {
		GitVersion string `json:"gitVersion"`
	}
	if err := c.get(ctx, "/version", &v); err != nil {
		return "", err
	}
	return v.GitVersion, nil
}

// Probe lists at most one object of a resource kind.
func (c *KubeClient) Probe(ctx context.Context, r resource, ns string) error {
	return c.get(ctx, r.path(ns)+"?limit=1", nil)
}

func (c *KubeClient) get(ctx context.Context, path string, out any) error {
	u := *c.Base
	p, q, _ := strings.Cut(path, "?")
	u.Path = strings.TrimRight(u.Path, "/") + p
	u.RawQuery = q
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "pathos-runtime-inventory")
	if c.Token != "" {
		req.Header.Set("Authorization", "Bearer "+c.Token)
	}
	resp, err := c.HTTP.Do(req)
	if err != nil {
		var ue *url.Error
		if errors.As(err, &ue) {
			err = ue.Err
		}
		return err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode != http.StatusOK {
		var st struct {
			Message string `json:"message"`
		}
		_ = json.Unmarshal(body, &st)
		return &APIError{Status: resp.StatusCode, Path: p, Message: st.Message}
	}
	if out != nil {
		if err := json.Unmarshal(body, out); err != nil {
			return fmt.Errorf("%s: invalid response", p)
		}
	}
	return nil
}

// CheckCluster checks one cluster: the API server version, then a
// single-item list of every resource kind the inventory reads. A 401 or an
// unreachable server fails the check; 403/404 on some kinds is reported in
// Denied (the inventory would be partial).
func (s *Service) CheckCluster(ctx context.Context, orgID, id uuid.UUID) (ClusterHealth, error) {
	var h ClusterHealth
	var auth string
	if err := s.DB.QueryRow(ctx, `SELECT auth_type FROM runtime_clusters WHERE organization_id = $1 AND id = $2`, orgID, id).Scan(&auth); err != nil {
		return h, err
	}
	c, err := s.loadCluster(ctx, id)
	if err != nil {
		return h, err
	}
	h.LongLived = c.Creds.Token != ""
	u, err := (scm.NetPolicy{AllowPrivate: c.AllowPrivate, OrgChosen: true}).ValidateBaseURL(c.Creds.Server)
	if err != nil && s.NewHTTP == nil {
		return h, fmt.Errorf("API server URL: %w", err)
	}
	if u == nil {
		if u, err = url.Parse(c.Creds.Server); err != nil {
			return h, err
		}
	}
	tlsCfg, err := c.Creds.TLSConfig()
	if err != nil {
		return h, err
	}
	kc := &KubeClient{Base: u, HTTP: s.client(c.AllowPrivate, tlsCfg), Token: c.Creds.Token}
	ctx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()
	if h.ServerVersion, err = kc.Version(ctx); err != nil {
		var ae *APIError
		// /version can be closed to the role on hardened clusters; the
		// list probes below still prove access.
		if !errors.As(err, &ae) || (ae.Status != http.StatusForbidden && ae.Status != http.StatusNotFound) {
			return h, err
		}
	}
	for _, r := range Resources {
		ns := ""
		if r.Namespaced && len(c.Namespaces) > 0 {
			ns = c.Namespaces[0]
		}
		if !r.Namespaced && len(c.Namespaces) > 0 {
			continue
		}
		err := kc.Probe(ctx, r, ns)
		var ae *APIError
		switch {
		case err == nil:
			h.Readable = append(h.Readable, r.Kind)
		case errors.As(err, &ae) && (ae.Status == http.StatusForbidden || ae.Status == http.StatusNotFound):
			h.Denied = append(h.Denied, r.Kind)
		default:
			return h, err
		}
	}
	return h, nil
}

// RegistryHealth is what a registry check reports.
type RegistryHealth struct {
	Repository string
	Tags       int
	// RateLimitRemaining is Docker Hub's ratelimit-remaining ("" when the
	// registry does not send it).
	RateLimitRemaining string
}

// CheckRegistry checks one registry: GET /v2/ (API version, token
// challenge), then one tags/list?n=1 of the first configured repository
// with the credential.
func (s *Service) CheckRegistry(ctx context.Context, orgID, id uuid.UUID) (RegistryHealth, error) {
	var h RegistryHealth
	var exists bool
	if err := s.DB.QueryRow(ctx, `SELECT true FROM registry_connections WHERE organization_id = $1 AND id = $2`, orgID, id).Scan(&exists); err != nil {
		return h, err
	}
	c, err := s.loadRegistry(ctx, id)
	if err != nil {
		return h, err
	}
	u, err := (scm.NetPolicy{AllowPrivate: c.AllowPrivate, AllowHTTP: s.AllowHTTP, OrgChosen: true}).ValidateBaseURL(c.BaseURL)
	if err != nil && s.NewHTTP == nil {
		return h, fmt.Errorf("registry URL: %w", err)
	}
	if u == nil {
		if u, err = url.Parse(c.BaseURL); err != nil {
			return h, err
		}
	}
	rc := &RegistryClient{Base: u, HTTP: s.client(c.AllowPrivate, nil), Auth: c.Auth, Username: c.User, Secret: c.Secret}
	ctx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()
	if err := rc.Ping(ctx); err != nil {
		return h, err
	}
	if len(c.Repositories) == 0 {
		return h, nil
	}
	h.Repository = c.Repositories[0]
	tags, _, err := rc.Tags(ctx, h.Repository, 1)
	h.Tags = len(tags)
	h.RateLimitRemaining = rc.lastRateLimit
	return h, err
}
