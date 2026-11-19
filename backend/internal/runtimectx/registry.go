package runtimectx

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"
)

// Container registry inventory through the OCI distribution API (read
// only): tags of the configured repositories, the digest each tag points
// to, and the org.opencontainers.image.source / revision labels of the
// image configuration. Only GET and HEAD requests are made, spaced by
// MinInterval.

// RegistryClient reads one registry.
type RegistryClient struct {
	Base *url.URL
	HTTP *http.Client
	// Auth: "none", "basic" (Username + Secret) or "bearer" (Secret is a
	// token). Basic credentials are also used for the token service when
	// the registry asks for one (WWW-Authenticate: Bearer).
	Auth        string
	Username    string
	Secret      string
	MinInterval time.Duration
	// MaxTags bounds the tags read per repository.
	MaxTags int

	last   time.Time
	tokens map[string]string // scope → bearer token
}

// RegistryImage is one tag of a repository.
type RegistryImage struct {
	Repository string `json:"repository"`
	Tag        string `json:"tag"`
	Digest     string `json:"digest"`
	MediaType  string `json:"media_type"`
	SourceURL  string `json:"source_url"`
	Revision   string `json:"revision"`
	Created    string `json:"created"`
}

const manifestAccept = "application/vnd.oci.image.index.v1+json, application/vnd.oci.image.manifest.v1+json, " +
	"application/vnd.docker.distribution.manifest.list.v2+json, application/vnd.docker.distribution.manifest.v2+json"

var repoNameRe = regexp.MustCompile(`^[a-z0-9]+(?:(?:[._]|__|-+)[a-z0-9]+)*(?:/[a-z0-9]+(?:(?:[._]|__|-+)[a-z0-9]+)*)*$`)

// ValidRepositoryName checks an OCI repository name (namespace/name).
func ValidRepositoryName(s string) bool { return len(s) <= 255 && repoNameRe.MatchString(s) }

var tagRe = regexp.MustCompile(`^[A-Za-z0-9_][A-Za-z0-9._-]{0,127}$`)

// RegistryError is a non-2xx answer.
type RegistryError struct {
	Status int
	Path   string
}

func (e *RegistryError) Error() string {
	switch e.Status {
	case http.StatusUnauthorized:
		return "the registry rejected the credentials (401) for " + e.Path
	case http.StatusForbidden:
		return "access denied (403) for " + e.Path
	case http.StatusNotFound:
		return "not found (404): " + e.Path
	}
	return fmt.Sprintf("registry answered %d for %s", e.Status, e.Path)
}

func (c *RegistryClient) wait(ctx context.Context) error {
	if c.MinInterval <= 0 {
		return nil
	}
	if d := time.Until(c.last.Add(c.MinInterval)); d > 0 {
		t := time.NewTimer(d)
		defer t.Stop()
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-t.C:
		}
	}
	c.last = time.Now()
	return nil
}

// do sends a GET or HEAD for a path under /v2/, handling the token
// challenge of the registry once per scope.
func (c *RegistryClient) do(ctx context.Context, method, path, accept, scope string) (*http.Response, error) {
	for attempt := 0; attempt < 2; attempt++ {
		if err := c.wait(ctx); err != nil {
			return nil, err
		}
		u := *c.Base
		u.Path = strings.TrimRight(u.Path, "/") + path
		if i := strings.Index(path, "?"); i >= 0 {
			u.Path = strings.TrimRight(c.Base.Path, "/") + path[:i]
			u.RawQuery = path[i+1:]
		}
		req, err := http.NewRequestWithContext(ctx, method, u.String(), nil)
		if err != nil {
			return nil, err
		}
		req.Header.Set("User-Agent", "pathos-registry-inventory")
		if accept != "" {
			req.Header.Set("Accept", accept)
		}
		switch {
		case c.tokens[scope] != "":
			req.Header.Set("Authorization", "Bearer "+c.tokens[scope])
		case c.Auth == "bearer":
			req.Header.Set("Authorization", "Bearer "+c.Secret)
		case c.Auth == "basic":
			req.SetBasicAuth(c.Username, c.Secret)
		}
		resp, err := c.HTTP.Do(req)
		if err != nil {
			return nil, err
		}
		if resp.StatusCode == http.StatusUnauthorized && attempt == 0 && c.Auth != "bearer" {
			ch := resp.Header.Get("WWW-Authenticate")
			_ = resp.Body.Close()
			if !strings.HasPrefix(strings.ToLower(ch), "bearer ") {
				return nil, &RegistryError{Status: http.StatusUnauthorized, Path: u.Path}
			}
			if err := c.fetchToken(ctx, ch, scope); err != nil {
				return nil, err
			}
			continue
		}
		return resp, nil
	}
	return nil, &RegistryError{Status: http.StatusUnauthorized, Path: path}
}

var challengeParamRe = regexp.MustCompile(`(\w+)="([^"]*)"`)

// fetchToken follows a Bearer challenge (Docker token authentication). The
// realm must use https (or the registry's own scheme and host).
func (c *RegistryClient) fetchToken(ctx context.Context, challenge, scope string) error {
	params := map[string]string{}
	for _, m := range challengeParamRe.FindAllStringSubmatch(challenge, -1) {
		params[strings.ToLower(m[1])] = m[2]
	}
	realm, err := url.Parse(params["realm"])
	if err != nil || realm.Host == "" {
		return errors.New("registry token challenge without a valid realm")
	}
	if realm.Scheme != "https" && !(realm.Scheme == c.Base.Scheme && realm.Host == c.Base.Host) {
		return errors.New("registry token realm must use https")
	}
	q := realm.Query()
	if s := params["service"]; s != "" {
		q.Set("service", s)
	}
	if scope != "" {
		q.Set("scope", scope)
	}
	realm.RawQuery = q.Encode()
	if err := c.wait(ctx); err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, realm.String(), nil)
	if err != nil {
		return err
	}
	req.Header.Set("User-Agent", "pathos-registry-inventory")
	if c.Auth == "basic" {
		req.SetBasicAuth(c.Username, c.Secret)
	}
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("registry token service answered %d", resp.StatusCode)
	}
	var tok struct {
		Token       string `json:"token"`
		AccessToken string `json:"access_token"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&tok); err != nil {
		return errors.New("registry token service: invalid response")
	}
	if c.tokens == nil {
		c.tokens = map[string]string{}
	}
	c.tokens[scope] = firstNonEmpty(tok.Token, tok.AccessToken)
	if c.tokens[scope] == "" {
		return errors.New("registry token service returned no token")
	}
	return nil
}

func (c *RegistryClient) getJSON(ctx context.Context, path, accept, scope string, v any) (http.Header, error) {
	resp, err := c.do(ctx, http.MethodGet, path, accept, scope)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, &RegistryError{Status: resp.StatusCode, Path: strings.SplitN(path, "?", 2)[0]}
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 8<<20)).Decode(v); err != nil {
		return nil, fmt.Errorf("%s: invalid JSON: %w", strings.SplitN(path, "?", 2)[0], err)
	}
	return resp.Header, nil
}

// Ping checks the API version endpoint (GET /v2/).
func (c *RegistryClient) Ping(ctx context.Context) error {
	resp, err := c.do(ctx, http.MethodGet, "/v2/", "", "")
	if err != nil {
		return err
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusUnauthorized {
		return &RegistryError{Status: resp.StatusCode, Path: "/v2/"}
	}
	return nil
}

// Tags lists a repository's tags (following Link pagination on the same
// host), at most max.
func (c *RegistryClient) Tags(ctx context.Context, repo string, max int) ([]string, bool, error) {
	scope := "repository:" + repo + ":pull"
	path := "/v2/" + repo + "/tags/list?n=" + fmt.Sprint(min(max, 1000))
	var tags []string
	for page := 0; page < 100 && path != ""; page++ {
		resp, err := c.do(ctx, http.MethodGet, path, "application/json", scope)
		if err != nil {
			return tags, false, err
		}
		var body struct {
			Tags []string `json:"tags"`
		}
		if resp.StatusCode != http.StatusOK {
			_ = resp.Body.Close()
			return tags, false, &RegistryError{Status: resp.StatusCode, Path: "/v2/" + repo + "/tags/list"}
		}
		err = json.NewDecoder(io.LimitReader(resp.Body, 8<<20)).Decode(&body)
		_ = resp.Body.Close()
		if err != nil {
			return tags, false, fmt.Errorf("tags of %s: invalid JSON", repo)
		}
		for _, t := range body.Tags {
			if tagRe.MatchString(t) {
				tags = append(tags, t)
			}
		}
		if len(tags) >= max {
			return tags[:max], true, nil
		}
		path = nextLink(resp.Header.Get("Link"), c.Base)
	}
	return tags, false, nil
}

// nextLink returns the path of a rel="next" Link on the registry's host.
func nextLink(h string, base *url.URL) string {
	for _, part := range strings.Split(h, ",") {
		if !strings.Contains(part, `rel="next"`) {
			continue
		}
		s, e := strings.Index(part, "<"), strings.Index(part, ">")
		if s < 0 || e <= s {
			return ""
		}
		u, err := url.Parse(part[s+1 : e])
		if err != nil || (u.Host != "" && u.Host != base.Host) || !strings.HasPrefix(u.Path, "/v2/") {
			return ""
		}
		p := u.Path
		if u.RawQuery != "" {
			p += "?" + u.RawQuery
		}
		return p
	}
	return ""
}

type ociDescriptor struct {
	MediaType string `json:"mediaType"`
	Digest    string `json:"digest"`
	Platform  *struct {
		OS           string `json:"os"`
		Architecture string `json:"architecture"`
	} `json:"platform"`
	Annotations map[string]string `json:"annotations"`
}

type ociManifest struct {
	MediaType   string            `json:"mediaType"`
	Config      ociDescriptor     `json:"config"`
	Manifests   []ociDescriptor   `json:"manifests"`
	Annotations map[string]string `json:"annotations"`
}

// Image resolves a tag: its digest (Docker-Content-Digest of the
// manifest or index), and the source and revision labels of its
// configuration (for an index, of the linux/amd64 image, else the first
// image that is not an attestation).
func (c *RegistryClient) Image(ctx context.Context, repo, tag string) (RegistryImage, error) {
	scope := "repository:" + repo + ":pull"
	img := RegistryImage{Repository: repo, Tag: tag}
	var m ociManifest
	h, err := c.getJSON(ctx, "/v2/"+repo+"/manifests/"+url.PathEscape(tag), manifestAccept, scope, &m)
	if err != nil {
		return img, err
	}
	img.Digest = strings.ToLower(h.Get("Docker-Content-Digest"))
	img.MediaType = firstNonEmpty(m.MediaType, h.Get("Content-Type"))
	if !ValidDigest(img.Digest) {
		return img, fmt.Errorf("%s:%s: the registry did not return a content digest", repo, tag)
	}
	ann := m.Annotations
	if len(m.Manifests) > 0 {
		pick := -1
		for i, d := range m.Manifests {
			if d.Platform != nil && d.Platform.OS == "linux" && d.Platform.Architecture == "amd64" {
				pick = i
				break
			}
		}
		if pick < 0 {
			for i, d := range m.Manifests {
				if d.Platform != nil && d.Platform.OS != "unknown" {
					pick = i
					break
				}
			}
		}
		if pick < 0 || !ValidDigest(m.Manifests[pick].Digest) {
			return img, nil
		}
		var child ociManifest
		if _, err := c.getJSON(ctx, "/v2/"+repo+"/manifests/"+m.Manifests[pick].Digest, manifestAccept, scope, &child); err != nil {
			return img, err
		}
		m = child
		if len(ann) == 0 {
			ann = child.Annotations
		}
	}
	img.SourceURL, img.Revision, img.Created = ann["org.opencontainers.image.source"], ann["org.opencontainers.image.revision"], ann["org.opencontainers.image.created"]
	if !ValidDigest(m.Config.Digest) {
		return img, nil
	}
	var cfg struct {
		Created string `json:"created"`
		Config  struct {
			Labels map[string]string `json:"Labels"`
		} `json:"config"`
	}
	if _, err := c.getJSON(ctx, "/v2/"+repo+"/blobs/"+m.Config.Digest, "", scope, &cfg); err != nil {
		return img, err
	}
	l := cfg.Config.Labels
	img.SourceURL = firstNonEmpty(l["org.opencontainers.image.source"], img.SourceURL)
	img.Revision = firstNonEmpty(l["org.opencontainers.image.revision"], img.Revision)
	img.Created = firstNonEmpty(l["org.opencontainers.image.created"], img.Created, cfg.Created)
	img.SourceURL, img.Revision, img.Created = cut(img.SourceURL, 1000), cut(img.Revision, 200), cut(img.Created, 100)
	return img, nil
}

func cut(s string, n int) string {
	if len(s) > n {
		return s[:n]
	}
	return s
}
