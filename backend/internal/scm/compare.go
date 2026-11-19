package scm

import (
	"context"
	"errors"
	"net/url"
	"strconv"
	"strings"
)

// Push diffs: secret push protection reads what a push added, commit by
// commit, through the provider API (no clone). GitHub and GitLab implement
// DiffReader; other providers do not (callers report "not supported").

// Bounds on what one push diff may contain.
const (
	MaxPushCommits    = 50       // commits read one by one; beyond that the aggregate diff is used
	MaxDiffFiles      = 300      // files per commit (GitHub's own limit)
	MaxPatchBytes     = 1 << 20  // per file
	MaxPushDiffBytes  = 16 << 20 // per push
	maxCommitListPage = 100
)

// DiffFile is one changed file and its unified diff (may be empty for
// binary or oversized files, which providers do not render).
type DiffFile struct {
	Path  string
	Patch string
}

// CommitDiff is the change a commit introduced.
type CommitDiff struct {
	SHA   string
	Files []DiffFile
}

// PushDiff is what a push introduced. When the push has more commits than
// MaxPushCommits, Commits holds a single aggregate entry attributed to the
// head commit and Truncated is set.
type PushDiff struct {
	Commits   []CommitDiff
	Truncated bool
}

// DiffReader returns the changes of a push. before is the previous branch
// head: empty or all zeros for a new branch, in which case the commits not
// on the default branch are read.
type DiffReader interface {
	PushDiff(ctx context.Context, ref RepoRef, before, after string) (PushDiff, error)
}

// ZeroCommit reports whether sha is empty or all zeros (a new branch).
func ZeroCommit(sha string) bool { return strings.Trim(sha, "0") == "" }

// diffBudget enforces MaxPatchBytes and MaxPushDiffBytes.
type diffBudget struct {
	left      int
	truncated bool
}

func (b *diffBudget) file(path, patch string) (DiffFile, bool) {
	if len(patch) > MaxPatchBytes {
		patch, b.truncated = patch[:MaxPatchBytes], true
	}
	if b.left <= 0 {
		b.truncated = true
		return DiffFile{}, false
	}
	if len(patch) > b.left {
		patch, b.truncated = patch[:b.left], true
	}
	b.left -= len(patch)
	return DiffFile{Path: path, Patch: patch}, true
}

func checkPushArgs(before, after string) error {
	if !ValidCommit(after) {
		return errors.New("scm: invalid commit")
	}
	if !ZeroCommit(before) && !ValidCommit(before) {
		return errors.New("scm: invalid commit")
	}
	return nil
}

// PushDiff implements DiffReader for GitHub.
func (g *gitHub) PushDiff(ctx context.Context, ref RepoRef, before, after string) (PushDiff, error) {
	if err := checkPushArgs(before, after); err != nil {
		return PushDiff{}, err
	}
	p, err := g.repoPathFor(ctx, ref)
	if err != nil {
		return PushDiff{}, err
	}
	base := before
	if ZeroCommit(before) {
		repo, err := g.GetRepository(ctx, ref)
		if err != nil {
			return PushDiff{}, err
		}
		if repo.DefaultBranch == "" {
			return PushDiff{}, errors.New("scm: repository has no default branch")
		}
		base = repo.DefaultBranch
	}
	type ghFile struct {
		Filename string `json:"filename"`
		Status   string `json:"status"`
		Patch    string `json:"patch"`
	}
	var cmp struct {
		Commits []struct {
			SHA string `json:"sha"`
		} `json:"commits"`
		TotalCommits int      `json:"total_commits"`
		Files        []ghFile `json:"files"`
	}
	if _, err := g.get(ctx, p+"/compare/"+escapeRef(base)+"..."+url.PathEscape(after)+"?per_page="+strconv.Itoa(maxCommitListPage), &cmp); err != nil {
		return PushDiff{}, err
	}
	b := &diffBudget{left: MaxPushDiffBytes}
	files := func(in []ghFile) []DiffFile {
		var out []DiffFile
		for i, f := range in {
			if i >= MaxDiffFiles {
				b.truncated = true
				break
			}
			if f.Status == "removed" {
				continue
			}
			if df, ok := b.file(f.Filename, f.Patch); ok {
				out = append(out, df)
			}
		}
		return out
	}
	if len(cmp.Commits) > MaxPushCommits || cmp.TotalCommits > len(cmp.Commits) {
		return PushDiff{Commits: []CommitDiff{{SHA: after, Files: files(cmp.Files)}}, Truncated: true}, nil
	}
	var out PushDiff
	for _, c := range cmp.Commits {
		if !ValidCommit(c.SHA) {
			continue
		}
		var cm struct {
			Files []ghFile `json:"files"`
		}
		if _, err := g.get(ctx, p+"/commits/"+url.PathEscape(c.SHA), &cm); err != nil {
			return PushDiff{}, err
		}
		out.Commits = append(out.Commits, CommitDiff{SHA: c.SHA, Files: files(cm.Files)})
	}
	out.Truncated = b.truncated
	return out, nil
}

type glDiff struct {
	NewPath     string `json:"new_path"`
	Diff        string `json:"diff"`
	DeletedFile bool   `json:"deleted_file"`
}

// PushDiff implements DiffReader for GitLab.
func (g *gitLab) PushDiff(ctx context.Context, ref RepoRef, before, after string) (PushDiff, error) {
	if err := checkPushArgs(before, after); err != nil {
		return PushDiff{}, err
	}
	p, err := glProjectPath(ref)
	if err != nil {
		return PushDiff{}, err
	}
	from := before
	if ZeroCommit(before) {
		repo, err := g.GetRepository(ctx, ref)
		if err != nil {
			return PushDiff{}, err
		}
		if repo.DefaultBranch == "" {
			return PushDiff{}, errors.New("scm: repository has no default branch")
		}
		from = repo.DefaultBranch
	}
	var cmp struct {
		Commits []struct {
			ID string `json:"id"`
		} `json:"commits"`
		Diffs []glDiff `json:"diffs"`
	}
	q := url.Values{"from": {from}, "to": {after}}
	if _, err := g.get(ctx, p+"/repository/compare?"+q.Encode(), &cmp); err != nil {
		return PushDiff{}, err
	}
	b := &diffBudget{left: MaxPushDiffBytes}
	files := func(in []glDiff) []DiffFile {
		var out []DiffFile
		for i, d := range in {
			if i >= MaxDiffFiles {
				b.truncated = true
				break
			}
			if d.DeletedFile {
				continue
			}
			if df, ok := b.file(d.NewPath, d.Diff); ok {
				out = append(out, df)
			}
		}
		return out
	}
	if len(cmp.Commits) > MaxPushCommits {
		return PushDiff{Commits: []CommitDiff{{SHA: after, Files: files(cmp.Diffs)}}, Truncated: true}, nil
	}
	var out PushDiff
	for _, c := range cmp.Commits {
		if !ValidCommit(c.ID) {
			continue
		}
		var diffs []glDiff
		if _, err := g.get(ctx, p+"/repository/commits/"+url.PathEscape(c.ID)+"/diff?per_page=100", &diffs); err != nil {
			return PushDiff{}, err
		}
		out.Commits = append(out.Commits, CommitDiff{SHA: c.ID, Files: files(diffs)})
	}
	out.Truncated = b.truncated
	return out, nil
}

var (
	_ DiffReader = (*gitHub)(nil)
	_ DiffReader = (*gitLab)(nil)
)
