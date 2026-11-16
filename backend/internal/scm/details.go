package scm

import (
	"context"
	"errors"
)

// Details builds the import preview of a repository: metadata (which also
// proves the credential can read it), branch heads, the latest commit of
// the default branch, languages and, where the provider reports it, the
// credential's permission.
//
// GetRepository errors are returned as is (ErrNotFound, ErrForbidden,
// ErrAuth, ...). The other parts are best effort: an empty repository has
// no commit, and a language or permission lookup the credential may not
// perform leaves the field empty / "unknown". Authentication failures and
// expired OAuth authorizations are always returned.
func Details(ctx context.Context, c FullClient, ref RepoRef) (RepoDetails, error) {
	repo, err := c.GetRepository(ctx, ref)
	if err != nil {
		return RepoDetails{}, err
	}
	full := repo.Ref()
	if full.Organization == "" {
		full.Organization = ref.Organization
	}
	if full.Project == "" {
		full.Project = ref.Project
	}
	d := RepoDetails{Repository: repo, Permission: "unknown", Languages: map[string]int64{}}
	fatal := func(err error) bool {
		return errors.Is(err, ErrAuth) || errors.Is(err, ErrTokenExpired) || errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded)
	}
	if d.Branches, err = c.ListBranchHeads(ctx, full); err != nil {
		if fatal(err) {
			return RepoDetails{}, err
		}
		d.Branches = nil
	}
	if repo.DefaultBranch != "" {
		commit, err := c.LatestCommit(ctx, full, repo.DefaultBranch)
		switch {
		case err == nil:
			d.LatestCommit = &commit
		case fatal(err):
			return RepoDetails{}, err
		}
	}
	if langs, err := c.Languages(ctx, full); err == nil && langs != nil {
		d.Languages = langs
	} else if fatal(err) {
		return RepoDetails{}, err
	}
	if pc, ok := c.(PermissionChecker); ok {
		if p, err := pc.Permission(ctx, full); err == nil && p != "" {
			d.Permission = p
		} else if fatal(err) {
			return RepoDetails{}, err
		}
	}
	return d, nil
}
