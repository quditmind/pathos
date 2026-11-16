package scm

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
)

// ErrInvalidPageToken means a page token was malformed, belongs to another
// query, or points somewhere the client will not go.
var ErrInvalidPageToken = errors.New("scm: invalid page token")

// Page tokens are base64url(JSON) cursors. They are opaque to callers but
// not secret and not signed (they must survive restarts and work across API
// replicas), so they are validated on use instead:
//
//   - F binds the token to the query (provider, organization, project,
//     search); a token replayed with another query is rejected.
//   - N, the next upstream URL, must have the scheme and host of the
//     configured base URL and exactly the path of the first page of this
//     query (checkNext). A crafted token can therefore neither reach another
//     host nor another API endpoint.
//   - O is an offset for providers paginated client-side (Azure DevOps) and
//     must be within the listing.
type pageCursor struct {
	V int    `json:"v"`
	F string `json:"f"`
	N string `json:"n,omitempty"`
	O int    `json:"o,omitempty"`
}

const maxPageTokenLen = 4096

func queryFingerprint(provider string, q RepoQuery) string {
	h := sha256.Sum256([]byte(strings.Join([]string{provider, q.Organization, q.Project, strings.ToLower(strings.TrimSpace(q.Search))}, "\x00")))
	return hex.EncodeToString(h[:8])
}

func encodeCursor(provider string, q RepoQuery, next string, offset int) string {
	b, _ := json.Marshal(pageCursor{V: 1, F: queryFingerprint(provider, q), N: next, O: offset})
	return base64.RawURLEncoding.EncodeToString(b)
}

// decodeCursor returns the zero cursor for an empty token.
func decodeCursor(provider string, q RepoQuery) (pageCursor, error) {
	if q.PageToken == "" {
		return pageCursor{}, nil
	}
	if len(q.PageToken) > maxPageTokenLen {
		return pageCursor{}, ErrInvalidPageToken
	}
	raw, err := base64.RawURLEncoding.DecodeString(q.PageToken)
	if err != nil {
		return pageCursor{}, ErrInvalidPageToken
	}
	var c pageCursor
	if err := json.Unmarshal(raw, &c); err != nil || c.V != 1 || c.F != queryFingerprint(provider, q) || c.O < 0 || (c.N == "" && c.O == 0) {
		return pageCursor{}, ErrInvalidPageToken
	}
	return c, nil
}

// pageSize bounds RepoQuery.PageSize to 1..100 (default 50).
func pageSize(n int) int {
	switch {
	case n <= 0:
		return 50
	case n > 100:
		return 100
	}
	return n
}

// repoFetcher fetches one upstream page and returns its items and the raw
// next-page URL reported by the provider (unvalidated).
type repoFetcher func(ctx context.Context, u string) ([]RemoteRepo, string, error)

// collectRepos fetches upstream pages starting at start (the first page or a
// validated cursor URL). Without a filter it returns one upstream page; with
// a client-side filter it keeps reading (at most 10 upstream pages) until
// size matches are found. allowed lists the paths a next link may use.
// PageSize is therefore a target: a page can hold up to one upstream page
// more than requested.
func collectRepos(ctx context.Context, start string, size int, fetch repoFetcher, keep func(RemoteRepo) bool, allowed ...string) ([]RemoteRepo, string, error) {
	var items []RemoteRepo
	u := start
	for pages := 0; u != "" && pages < 10; pages++ {
		page, rawNext, err := fetch(ctx, u)
		if err != nil {
			return nil, "", err
		}
		for _, r := range page {
			if keep == nil || keep(r) {
				items = append(items, r)
			}
		}
		u, _ = checkNext(rawNext, allowed...)
		if keep == nil || len(items) >= size {
			break
		}
	}
	return items, u, nil
}

// matchesSearch reports whether the repository name or full name contains
// the search term (case-insensitive).
func matchesSearch(r RemoteRepo, term string) bool {
	if term == "" {
		return true
	}
	term = strings.ToLower(term)
	return strings.Contains(strings.ToLower(r.Name), term) || strings.Contains(strings.ToLower(r.FullName), term)
}

// listAll pages through ListRepositoriesPage up to MaxRepositories.
func listAll(ctx context.Context, d Discoverer, q RepoQuery) ([]RemoteRepo, error) {
	var out []RemoteRepo
	q.PageSize = 100
	for {
		p, err := d.ListRepositoriesPage(ctx, q)
		if err != nil {
			return nil, err
		}
		out = append(out, p.Items...)
		if len(out) >= MaxRepositories {
			return out[:MaxRepositories], nil
		}
		if p.NextPageToken == "" {
			return out, nil
		}
		q.PageToken = p.NextPageToken
	}
}
