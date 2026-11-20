package repos

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"errors"
	"io"
	"time"

	"github.com/google/uuid"

	"pathos/internal/scm"
)

// SourceUnavailable explains why source code cannot be shown. Code is
// stable for the UI; Message is safe to display.
type SourceUnavailable struct {
	Code    string
	Message string
}

func (e *SourceUnavailable) Error() string { return e.Message }

func unavailable(code, msg string) error { return &SourceUnavailable{Code: code, Message: msg} }

// errAnonymousSource: anonymous (token-less) repositories have no SCM
// connection to read files or history through.
var errAnonymousSource = unavailable("anonymous", "This repository was imported anonymously (public, no token): the source view and history need an SCM connection.")

// SourceRef identifies the exact source a scan analysed: the commit for SCM
// repositories or the snapshot for uploaded ones. Never a branch head.
type SourceRef struct {
	Commit     string
	SnapshotID *uuid.UUID
}

// ReadSourceFile returns path as it was at ref. Callers authorize access to
// the repository first; this method only enforces the source integration.
func (s *Service) ReadSourceFile(ctx context.Context, orgID, repoID uuid.UUID, ref SourceRef, path string) ([]byte, string, error) {
	if !scm.ValidRepoPath(path) {
		return nil, "", unavailable("invalid_path", "The file path is not a valid repository path.")
	}
	t, err := loadSyncTarget(ctx, s.DB, orgID, repoID)
	if err != nil {
		return nil, "", err
	}
	if t.ConnID == nil && t.SourceType == "git" {
		return nil, "", errAnonymousSource
	}
	if t.ConnID == nil {
		return s.snapshotFile(ctx, orgID, ref, path)
	}
	if ref.Commit == "" {
		return nil, "", unavailable("no_commit", "The scan did not record a commit SHA, so the scanned source cannot be identified.")
	}
	cr, err := s.contentReader(ctx, orgID, *t.ConnID)
	if err != nil {
		return nil, "", err
	}
	cctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	b, err := cr.FileAt(cctx, t.ref(), ref.Commit, path)
	if err != nil {
		s.Log.Warn("source file unavailable", "repository_id", repoID, "path", path, "err", err)
		return nil, "", providerUnavailable(err)
	}
	return b, "scm", nil
}

// SourceHistory returns commits that touched path, reachable from commit.
func (s *Service) SourceHistory(ctx context.Context, orgID, repoID uuid.UUID, commit, path string, limit int) ([]scm.Commit, error) {
	t, err := loadSyncTarget(ctx, s.DB, orgID, repoID)
	if err != nil {
		return nil, err
	}
	if t.ConnID == nil && t.SourceType == "git" {
		return nil, errAnonymousSource
	}
	if t.ConnID == nil {
		return nil, unavailable("no_history", "Uploaded repositories have no commit history.")
	}
	cr, err := s.contentReader(ctx, orgID, *t.ConnID)
	if err != nil {
		return nil, err
	}
	cctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	out, err := cr.FileHistory(cctx, t.ref(), commit, path, limit)
	if err != nil {
		s.Log.Warn("source history unavailable", "repository_id", repoID, "path", path, "err", err)
		return nil, providerUnavailable(err)
	}
	return out, nil
}

// BranchHead returns the current head commit of branch ("" = the scan
// branch or default branch), used only to compare against later code.
func (s *Service) BranchHead(ctx context.Context, orgID, repoID uuid.UUID, branch string) (scm.Commit, error) {
	t, err := loadSyncTarget(ctx, s.DB, orgID, repoID)
	if err != nil {
		return scm.Commit{}, err
	}
	if t.ConnID == nil && t.SourceType == "git" {
		return scm.Commit{}, errAnonymousSource
	}
	if t.ConnID == nil {
		return scm.Commit{}, unavailable("no_history", "Uploaded repositories have no branches.")
	}
	if branch == "" {
		branch = t.branch()
	}
	c, err := s.getConn(ctx, s.DB, orgID, *t.ConnID)
	if err != nil {
		return scm.Commit{}, unavailable("connection_unavailable", "The repository's SCM connection is no longer available.")
	}
	cl, err := s.client(ctx, c)
	if err != nil {
		return scm.Commit{}, unavailable("connection_unavailable", "The repository's SCM connection could not be used.")
	}
	cctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	head, err := cl.LatestCommit(cctx, t.ref(), branch)
	if err != nil {
		return scm.Commit{}, providerUnavailable(err)
	}
	return head, nil
}

func (s *Service) contentReader(ctx context.Context, orgID, connID uuid.UUID) (scm.ContentReader, error) {
	c, err := s.getConn(ctx, s.DB, orgID, connID)
	if err != nil {
		return nil, unavailable("connection_unavailable", "The repository's SCM connection is no longer available.")
	}
	cl, err := s.client(ctx, c)
	if err != nil {
		return nil, unavailable("connection_unavailable", "The repository's SCM connection could not be used.")
	}
	cr, ok := cl.(scm.ContentReader)
	if !ok {
		return nil, unavailable("not_supported", "This SCM provider does not support reading files.")
	}
	return cr, nil
}

func providerUnavailable(err error) error {
	switch {
	case errors.Is(err, scm.ErrNotFound):
		return unavailable("not_found", "The file does not exist at the scanned commit (or the connection cannot see it).")
	case errors.Is(err, scm.ErrAuth), errors.Is(err, scm.ErrTokenExpired):
		return unavailable("credential_rejected", "The SCM provider rejected the connection's credential (expired or revoked). Update it under Administration → SCM connections.")
	case errors.Is(err, scm.ErrForbidden):
		return unavailable("forbidden", "The SCM connection is not allowed to read this repository.")
	case errors.Is(err, scm.ErrTooLarge):
		return unavailable("too_large", "The file is larger than 1 MiB and cannot be displayed.")
	case errors.Is(err, scm.ErrRateLimited):
		return unavailable("rate_limited", "The SCM provider rate limit was reached; try again later.")
	case scm.IsTransient(err):
		return unavailable("provider_unreachable", "The SCM provider could not be reached; try again later.")
	}
	return unavailable("provider_error", "The SCM provider returned an error.")
}

// snapshotFile reads one file from an encrypted source snapshot.
func (s *Service) snapshotFile(ctx context.Context, orgID uuid.UUID, ref SourceRef, path string) ([]byte, string, error) {
	if ref.SnapshotID == nil {
		return nil, "", unavailable("no_snapshot", "The scan did not record which source snapshot it analysed.")
	}
	rc, _, _, err := s.OpenSnapshot(ctx, orgID, *ref.SnapshotID)
	if err != nil {
		return nil, "", unavailable("snapshot_unavailable", "The source snapshot that was scanned is no longer available.")
	}
	defer rc.Close()
	zr, err := gzip.NewReader(rc)
	if err != nil {
		return nil, "", unavailable("snapshot_unavailable", "The source snapshot could not be read.")
	}
	defer zr.Close()
	tr := tar.NewReader(zr)
	for {
		h, err := tr.Next()
		if errors.Is(err, io.EOF) {
			return nil, "", unavailable("not_found", "The file is not in the scanned source snapshot.")
		}
		if err != nil {
			return nil, "", unavailable("snapshot_unavailable", "The source snapshot could not be read.")
		}
		if h.Name != path || (h.Typeflag != tar.TypeReg && h.Typeflag != '\x00') {
			continue
		}
		if h.Size > scm.MaxFileBytes {
			return nil, "", unavailable("too_large", "The file is larger than 1 MiB and cannot be displayed.")
		}
		b, err := io.ReadAll(io.LimitReader(tr, scm.MaxFileBytes+1))
		if err != nil {
			return nil, "", unavailable("snapshot_unavailable", "The source snapshot could not be read.")
		}
		return b, "snapshot", nil
	}
}

// StatusWriter returns the commit status writer of a repository's SCM
// connection and the repository's reference (pull request checks).
func (s *Service) StatusWriter(ctx context.Context, orgID, repoID uuid.UUID) (scm.StatusWriter, scm.RepoRef, error) {
	t, err := loadSyncTarget(ctx, s.DB, orgID, repoID)
	if err != nil {
		return nil, scm.RepoRef{}, err
	}
	if t.ConnID == nil {
		return nil, scm.RepoRef{}, errors.New("uploaded repositories have no SCM connection")
	}
	c, err := s.getConn(ctx, s.DB, orgID, *t.ConnID)
	if err != nil {
		return nil, scm.RepoRef{}, errors.New("the repository's SCM connection is no longer available")
	}
	cl, err := s.client(ctx, c)
	if err != nil {
		return nil, scm.RepoRef{}, errors.New("the repository's SCM connection could not be used")
	}
	w, ok := cl.(scm.StatusWriter)
	if !ok {
		return nil, scm.RepoRef{}, errors.New("this SCM provider does not support commit statuses")
	}
	return w, t.ref(), nil
}
