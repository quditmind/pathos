package repos

import (
	"context"
	"errors"

	"github.com/google/uuid"

	"pathos/internal/scm"
)

// PullRequestTarget is what fix pull requests need from a repository's SCM
// connection: a writer, the repository reference, the branch findings are
// tracked on (the pull request's target) and the provider.
type PullRequestTarget struct {
	Writer   scm.PullRequestWriter
	Ref      scm.RepoRef
	Branch   string
	Provider string
}

// PullRequestTarget returns the fix pull request target of a repository.
// Errors are safe to show to users.
func (s *Service) PullRequestTarget(ctx context.Context, orgID, repoID uuid.UUID) (PullRequestTarget, error) {
	t, err := loadSyncTarget(ctx, s.DB, orgID, repoID)
	if err != nil {
		return PullRequestTarget{}, err
	}
	if t.ConnID == nil {
		return PullRequestTarget{}, errors.New("uploaded repositories have no SCM connection")
	}
	c, err := s.getConn(ctx, s.DB, orgID, *t.ConnID)
	if err != nil {
		return PullRequestTarget{}, errors.New("the repository's SCM connection is no longer available")
	}
	cl, err := s.client(ctx, c)
	if err != nil {
		return PullRequestTarget{}, errors.New("the repository's SCM connection could not be used")
	}
	w, ok := cl.(scm.PullRequestWriter)
	if !ok {
		return PullRequestTarget{}, errors.New("this SCM provider does not support pull requests")
	}
	return PullRequestTarget{Writer: w, Ref: t.ref(), Branch: t.branch(), Provider: t.Provider}, nil
}
