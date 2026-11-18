package worker

import (
	"bytes"
	"context"
	"fmt"
	"strings"
	"time"

	"pathos/internal/material"
)

// ChangeReport describes what changed between the previously scanned
// commit and this one: security-material changes found by the explainable
// rules of package material and, when the organization enabled developer
// attribution, the commits in between (author names only, never e-mail
// addresses). It mirrors insights.ChangeReport.
type ChangeReport struct {
	Version int `json:"version"`
	// Status: computed | baseline (first scan) | unchanged | unavailable.
	Status       string            `json:"status"`
	Reason       string            `json:"reason"`
	BaseSHA      string            `json:"base_sha"`
	HeadSHA      string            `json:"head_sha"`
	FilesChanged int               `json:"files_changed"`
	Truncated    bool              `json:"truncated"`
	Changes      []material.Change `json:"changes"`
	// Commits between base and head (newest first), only with
	// Job.CollectAuthors; CommitsComplete is false when the fetched history
	// did not reach the base commit.
	Commits         []CommitInfo `json:"commits"`
	CommitsComplete bool         `json:"commits_complete"`
}

// CommitInfo is one commit: its author's name and the files it touched.
type CommitInfo struct {
	SHA        string    `json:"sha"`
	AuthorName string    `json:"author_name"`
	AuthoredAt time.Time `json:"authored_at"`
	Files      []string  `json:"files"`
}

const (
	changeTimeout     = 5 * time.Minute
	maxDiffBytes      = 32 << 20
	historyDepth      = 100 // commits fetched for attribution
	maxCommits        = 500
	maxFilesPerCommit = 500
)

// capWriter keeps the first max bytes and records whether more came.
type capWriter struct {
	buf      bytes.Buffer
	max      int
	overflow bool
}

func (w *capWriter) Write(p []byte) (int, error) {
	if room := w.max - w.buf.Len(); room > 0 {
		w.buf.Write(p[:min(len(p), room)])
	}
	if w.buf.Len() >= w.max {
		w.overflow = true
	}
	return len(p), nil
}

// gitAuthEnv is the environment for git commands that talk to the remote.
func gitAuthEnv(job Job) []string {
	env := []string{"GIT_TERMINAL_PROMPT=0", "GIT_ASKPASS=/bin/false", "GIT_CONFIG_NOSYSTEM=1", "GIT_CONFIG_GLOBAL=/dev/null"}
	if job.Credential != nil && job.Credential.Token != "" {
		header := "Authorization: Basic " + basicAuth(job.Credential.Username, job.Credential.Token)
		if job.Credential.Scheme == "bearer" {
			header = "Authorization: Bearer " + job.Credential.Token
		}
		env = append(env, "GIT_CONFIG_COUNT=1", "GIT_CONFIG_KEY_0=http.extraHeader", "GIT_CONFIG_VALUE_0="+header)
	}
	return env
}

var gitHardening = []string{
	"-c", "core.hooksPath=/dev/null", "-c", "protocol.file.allow=never", "-c", "protocol.ext.allow=never",
	"-c", "core.fsmonitor=false", "-c", "core.symlinks=false", "-c", "submodule.recurse=false",
	"-c", "transfer.fsckObjects=true", "-c", "http.followRedirects=false", "-c", "core.quotepath=off",
	"-c", "log.showSignature=false",
}

// detectChanges compares the previously scanned commit with head. It must
// run while job.Credential is still set (it may fetch the two commits).
// It never fails the job: problems are reported as status "unavailable".
func detectChanges(ctx context.Context, job Job, head, gitDir, dir string) *ChangeReport {
	out := &ChangeReport{Version: 1, BaseSHA: job.PreviousCommitSHA, HeadSHA: head}
	prev := job.PreviousCommitSHA
	switch {
	case prev == "":
		out.Status, out.Reason = "baseline", "no previously scanned commit of this ref to compare with (first scan of the branch, or a pull request scan)"
		return out
	case !fullSHARe.MatchString(prev) || !fullSHARe.MatchString(head):
		out.Status, out.Reason = "unavailable", "the previous or current commit ID is not a full Git commit ID"
		return out
	case prev == head:
		out.Status, out.Reason = "unchanged", "the commit is the same as in the previous scan"
		return out
	}
	ctx, cancel := context.WithTimeout(ctx, changeTimeout)
	defer cancel()
	git := func(env []string, args ...string) error {
		_, err := command(ctx, env, []int{0}, "git", append(append([]string{}, gitHardening...), args...)...)
		return err
	}
	local := []string{"GIT_TERMINAL_PROMPT=0", "GIT_CONFIG_NOSYSTEM=1", "GIT_CONFIG_GLOBAL=/dev/null"}
	has := func(repo, sha string) bool {
		return git(local, "--git-dir", repo, "cat-file", "-e", sha+"^{commit}") == nil
	}

	repo := gitDir
	baseInWindow := true
	if !job.FullHistory {
		// The scan clone is shallow and its history is removed; fetch the
		// two commits into a private bare repository instead.
		repo = dir
		if err := git(local, "init", "--bare", "--quiet", repo); err != nil {
			return unavailable(out, "preparing the comparison repository failed", err)
		}
		depth := "1"
		if job.CollectAuthors {
			depth = fmt.Sprint(historyDepth)
		}
		if err := git(gitAuthEnv(job), "--git-dir", repo, "fetch", "--quiet", "--no-tags", "--depth", depth, "--", job.CloneURL, head); err != nil {
			return unavailable(out, "fetching the scanned commit for comparison failed", err)
		}
		baseInWindow = has(repo, prev)
		if !baseInWindow {
			if err := git(gitAuthEnv(job), "--git-dir", repo, "fetch", "--quiet", "--no-tags", "--depth", "1", "--", job.CloneURL, prev); err != nil {
				return unavailable(out, "the previously scanned commit could not be fetched (rewritten history or the server does not serve commits by ID)", err)
			}
		}
	}
	if !has(repo, prev) {
		out.Status, out.Reason = "unavailable", "the previously scanned commit is no longer in the repository history (rewritten history)"
		return out
	}
	if !has(repo, head) {
		out.Status, out.Reason = "unavailable", "the scanned commit is not available for comparison"
		return out
	}
	diff := &capWriter{max: maxDiffBytes}
	if _, err := commandTo(ctx, diff, local, []int{0}, "git", append(append([]string{}, gitHardening...),
		"--git-dir", repo, "diff", "--no-color", "--no-ext-diff", "--no-textconv", "-U0", "-M", "--diff-filter=ACDMR", prev, head, "--")...); err != nil {
		return unavailable(out, "computing the diff failed", err)
	}
	files := material.ParseUnified(diff.buf.Bytes())
	out.FilesChanged = len(files)
	out.Changes, out.Truncated = material.Analyze(files)
	out.Truncated = out.Truncated || diff.overflow
	if out.Changes == nil {
		out.Changes = []material.Change{}
	}
	out.Status = "computed"
	if diff.overflow {
		out.Reason = fmt.Sprintf("the diff exceeds %d MB; only its first part was analyzed", maxDiffBytes>>20)
	}
	if job.CollectAuthors {
		out.Commits, out.CommitsComplete = commitsBetween(ctx, repo, prev, head, local)
		if !baseInWindow {
			out.CommitsComplete = false
		}
	}
	return out
}

func unavailable(out *ChangeReport, msg string, err error) *ChangeReport {
	out.Status = "unavailable"
	out.Reason = msg
	if err != nil {
		out.Reason += ": " + lastLine(err.Error())
	}
	if len(out.Reason) > 500 {
		out.Reason = out.Reason[:500]
	}
	return out
}

// commitsBetween lists the non-merge commits in prev..head with their
// author names and files (no e-mail addresses are read).
func commitsBetween(ctx context.Context, repo, prev, head string, env []string) ([]CommitInfo, bool) {
	complete := true
	// is-ancestor fails when prev is not reachable from head (force push)
	// or the shallow history stops before it.
	if _, err := command(ctx, env, []int{0}, "git", append(append([]string{}, gitHardening...),
		"--git-dir", repo, "merge-base", "--is-ancestor", prev, head)...); err != nil {
		complete = false
	}
	w := &capWriter{max: 8 << 20}
	if _, err := commandTo(ctx, w, env, []int{0}, "git", append(append([]string{}, gitHardening...),
		"--git-dir", repo, "log", "--no-merges", "--no-renames", "--name-only", "--format=%x1e%H%x1f%an%x1f%aI",
		"-n", fmt.Sprint(maxCommits+1), prev+".."+head, "--")...); err != nil {
		return nil, false
	}
	commits := parseCommitLog(w.buf.String())
	if len(commits) > maxCommits || w.overflow {
		commits = commits[:min(len(commits), maxCommits)]
		complete = false
	}
	return commits, complete
}

func parseCommitLog(s string) []CommitInfo {
	var out []CommitInfo
	for _, rec := range strings.Split(s, "\x1e") {
		rec = strings.TrimLeft(rec, "\n")
		if rec == "" {
			continue
		}
		lines := strings.Split(rec, "\n")
		head := strings.Split(lines[0], "\x1f")
		if len(head) != 3 || !fullSHARe.MatchString(head[0]) {
			continue
		}
		c := CommitInfo{SHA: head[0], AuthorName: cleanName(head[1]), Files: []string{}}
		c.AuthoredAt, _ = time.Parse(time.RFC3339, strings.TrimSpace(head[2]))
		for _, f := range lines[1:] {
			if f = strings.TrimSpace(f); f != "" && len(c.Files) < maxFilesPerCommit && len(f) <= 1000 {
				c.Files = append(c.Files, f)
			}
		}
		out = append(out, c)
	}
	return out
}

// cleanName bounds an author name and strips control characters.
func cleanName(s string) string {
	s = strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return -1
		}
		return r
	}, strings.ToValidUTF8(s, ""))
	s = strings.TrimSpace(s)
	if r := []rune(s); len(r) > 200 {
		s = string(r[:200])
	}
	return s
}

func changeSummary(c *ChangeReport) string {
	if c == nil {
		return "not run"
	}
	switch c.Status {
	case "computed":
		s := fmt.Sprintf("%d material change(s) in %d changed file(s) since %s", len(c.Changes), c.FilesChanged, c.BaseSHA[:min(12, len(c.BaseSHA))])
		if c.Truncated {
			s += " (truncated)"
		}
		return s
	default:
		return c.Status + ": " + c.Reason
	}
}
