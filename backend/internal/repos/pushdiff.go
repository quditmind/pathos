package repos

import (
	"context"
	"errors"
	"fmt"

	"github.com/google/uuid"

	"pathos/internal/scm"
)

// PushDiffReader returns the push diff reader of a repository's SCM
// connection and the repository's reference (secret push protection). It
// wraps scm.ErrNotSupported when the provider cannot report push diffs.
func (s *Service) PushDiffReader(ctx context.Context, orgID, repoID uuid.UUID) (scm.DiffReader, scm.RepoRef, error) {
	t, err := loadSyncTarget(ctx, s.DB, orgID, repoID)
	if err != nil {
		return nil, scm.RepoRef{}, err
	}
	if t.ConnID == nil {
		return nil, scm.RepoRef{}, fmt.Errorf("uploaded repositories have no SCM connection: %w", scm.ErrNotSupported)
	}
	c, err := s.getConn(ctx, s.DB, orgID, *t.ConnID)
	if err != nil {
		return nil, scm.RepoRef{}, errors.New("the repository's SCM connection is no longer available")
	}
	cl, err := s.client(ctx, c)
	if err != nil {
		return nil, scm.RepoRef{}, errors.New("the repository's SCM connection could not be used")
	}
	r, ok := cl.(scm.DiffReader)
	if !ok {
		return nil, scm.RepoRef{}, fmt.Errorf("push-event scanning is available for GitHub and GitLab: %w", scm.ErrNotSupported)
	}
	return r, t.ref(), nil
}
