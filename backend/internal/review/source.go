package review

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"path"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"pathos/internal/ai"
	"pathos/internal/authz"
	"pathos/internal/platform/httpx"
	"pathos/internal/repos"
	"pathos/internal/scanners"
	"pathos/internal/scm"
)

// SourceView is a file at an exact commit or snapshot.
type SourceView struct {
	Available    bool       `json:"available"`
	Code         string     `json:"unavailable_code,omitempty"`
	Message      string     `json:"unavailable_message,omitempty"`
	Origin       string     `json:"origin"` // scm | snapshot
	RepositoryID uuid.UUID  `json:"repository_id"`
	Repository   string     `json:"repository"`
	Branch       string     `json:"branch"`
	CommitSHA    string     `json:"commit_sha"`
	SnapshotID   *uuid.UUID `json:"snapshot_id,omitempty"`
	Scanned      bool       `json:"scanned"` // the source the finding was detected in
	Path         string     `json:"path"`
	Language     string     `json:"language"`
	Lines        []string   `json:"lines"`
	FocusLine    *int       `json:"focus_line"`
	Truncated    bool       `json:"truncated"`
	Redacted     bool       `json:"redacted"`
	// ScannerContext is the redacted code the scanner captured, shown when
	// the full source cannot be retrieved.
	ScannerContext      string `json:"scanner_context,omitempty"`
	ScannerContextStart *int   `json:"scanner_context_start,omitempty"`
}

const maxSourceLines = 20000

var languages = map[string]string{
	".go": "go", ".js": "javascript", ".mjs": "javascript", ".cjs": "javascript", ".jsx": "javascript", ".ts": "typescript", ".tsx": "typescript",
	".py": "python", ".rb": "ruby", ".java": "java", ".kt": "kotlin", ".kts": "kotlin", ".scala": "scala", ".cs": "csharp", ".php": "php",
	".c": "c", ".h": "c", ".cc": "cpp", ".cpp": "cpp", ".hpp": "cpp", ".rs": "rust", ".swift": "swift", ".sh": "shell", ".bash": "shell",
	".sql": "sql", ".yaml": "yaml", ".yml": "yaml", ".json": "json", ".tf": "hcl", ".hcl": "hcl", ".xml": "xml", ".html": "html",
	".vue": "javascript", ".dockerfile": "dockerfile", ".gradle": "groovy", ".groovy": "groovy", ".ps1": "powershell",
}

func languageOf(p string) string {
	base := strings.ToLower(path.Base(p))
	if base == "dockerfile" || strings.HasPrefix(base, "dockerfile.") {
		return "dockerfile"
	}
	if l, ok := languages[strings.ToLower(path.Ext(p))]; ok {
		return l
	}
	return "text"
}

func (s *Service) source(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	p := s.Principal(ctx)
	id, err := pathUUID(r, "id")
	if err != nil {
		s.fail(w, r, err)
		return
	}
	v, err := s.load(ctx, s.DB, p, id, false)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if err := s.require(ctx, p, authz.PermFindingsRead, v.RepoID); err != nil {
		s.fail(w, r, errNotFound)
		return
	}
	q := r.URL.Query()
	file := q.Get("path")
	if file == "" {
		file = v.FilePath
	}
	commit := q.Get("commit")
	if commit == "" {
		commit = v.CommitSHA
	} else if !scm.ValidCommit(commit) {
		s.fail(w, r, httpx.BadRequest("commit must be a commit SHA"))
		return
	}
	out := SourceView{Path: file, CommitSHA: commit, Branch: v.Branch, RepositoryID: v.RepoID, SnapshotID: v.SnapshotID, Language: languageOf(file),
		Lines: []string{}}
	out.Scanned = strings.EqualFold(commit, v.CommitSHA) || (commit == "" && v.CommitSHA == "")
	_ = s.DB.QueryRow(ctx, `SELECT full_name FROM repositories WHERE id = $1`, v.RepoID).Scan(&out.Repository)
	if file == v.FilePath && out.Scanned {
		out.FocusLine = v.StartLine
	}
	if file == v.FilePath && v.Category != "secrets" {
		_ = s.DB.QueryRow(ctx, `SELECT snippet, snippet_start_line FROM findings WHERE id = $1`, v.FindingID).Scan(&out.ScannerContext, &out.ScannerContextStart)
	}
	unavailable := func(code, msg string) {
		out.Available, out.Code, out.Message = false, code, msg
		httpx.WriteJSON(w, http.StatusOK, out)
	}
	switch {
	case s.Source == nil:
		unavailable("not_configured", "Source code retrieval is not configured in this deployment.")
		return
	case file == "":
		unavailable("no_location", "The scanner did not report a file for this finding.")
		return
	}
	b, origin, err := s.Source.ReadSourceFile(ctx, p.OrganizationID, v.RepoID, repos.SourceRef{Commit: commit, SnapshotID: v.SnapshotID}, file)
	if err != nil {
		var su *repos.SourceUnavailable
		if errors.As(err, &su) {
			unavailable(su.Code, su.Message)
			return
		}
		s.fail(w, r, err)
		return
	}
	out.Origin = origin
	if bytes.IndexByte(b[:min(len(b), 8192)], 0) >= 0 || !utf8.Valid(b) {
		unavailable("binary", "The file is binary and cannot be displayed.")
		return
	}
	text := strings.ReplaceAll(string(b), "\r\n", "\n")
	lines := strings.Split(text, "\n")
	if len(lines) > 0 && lines[len(lines)-1] == "" {
		lines = lines[:len(lines)-1]
	}
	if len(lines) > maxSourceLines {
		lines, out.Truncated = lines[:maxSourceLines], true
	}
	// Code around a secret is never displayed in clear text.
	if v.Category == "secrets" {
		for i, l := range lines {
			if red := ai.Redact(l, nil); red != l {
				lines[i], out.Redacted = red, true
			}
		}
	}
	out.Available, out.Lines = true, lines
	httpx.WriteJSON(w, http.StatusOK, out)
}

// CommitRef is a commit the reviewer can open.
type CommitRef struct {
	SHA         string     `json:"sha"`
	Label       string     `json:"label"`
	Message     string     `json:"message,omitempty"`
	Author      string     `json:"author,omitempty"`
	CommittedAt *time.Time `json:"committed_at,omitempty"`
	ScanJobID   *uuid.UUID `json:"scan_job_id,omitempty"`
	ScanKey     string     `json:"scan_key,omitempty"`
}

// sourceCommits lists the scanned commit, commits where scans saw the
// finding again, the branch head, and the file's commit history.
func (s *Service) sourceCommits(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	p := s.Principal(ctx)
	id, err := pathUUID(r, "id")
	if err != nil {
		s.fail(w, r, err)
		return
	}
	v, err := s.load(ctx, s.DB, p, id, false)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if err := s.require(ctx, p, authz.PermFindingsRead, v.RepoID); err != nil {
		s.fail(w, r, errNotFound)
		return
	}
	file := r.URL.Query().Get("path")
	if file == "" {
		file = v.FilePath
	}
	res := map[string]any{"scanned": CommitRef{SHA: v.CommitSHA, Label: "Scanned commit", ScanJobID: v.ScanJobID}, "occurrences": []CommitRef{},
		"history": []CommitRef{}, "head": nil, "history_unavailable": ""}
	rows, err := s.DB.Query(ctx, `SELECT DISTINCT ON (o.commit_sha) o.commit_sha, j.id, j.scan_key, o.created_at
		FROM finding_occurrences o JOIN scan_results sr ON sr.id = o.scan_result_id JOIN scan_jobs j ON j.id = sr.scan_job_id
		WHERE o.finding_id = $1 AND o.commit_sha <> '' ORDER BY o.commit_sha, o.created_at DESC`, v.FindingID)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	occ, err := pgx.CollectRows(rows, func(row pgx.CollectableRow) (CommitRef, error) {
		var c CommitRef
		var jid uuid.UUID
		var at time.Time
		err := row.Scan(&c.SHA, &jid, &c.ScanKey, &at)
		c.ScanJobID, c.CommittedAt, c.Label = &jid, &at, "Detected by "+c.ScanKey
		return c, err
	})
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if occ != nil {
		res["occurrences"] = occ
	}
	if s.Source != nil && scm.ValidRepoPath(file) {
		head, herr := s.Source.BranchHead(ctx, p.OrganizationID, v.RepoID, v.Branch)
		if herr == nil {
			res["head"] = CommitRef{SHA: head.SHA, Label: "Branch head (" + v.Branch + ")", Message: head.Message, Author: head.Author, CommittedAt: head.CommittedAt}
			hist, err := s.Source.SourceHistory(ctx, p.OrganizationID, v.RepoID, head.SHA, file, 30)
			if err == nil {
				list := make([]CommitRef, 0, len(hist))
				for _, c := range hist {
					list = append(list, CommitRef{SHA: c.SHA, Label: c.Message, Message: c.Message, Author: c.Author, CommittedAt: c.CommittedAt})
				}
				res["history"] = list
			} else {
				herr = err
			}
		}
		if herr != nil {
			var su *repos.SourceUnavailable
			if errors.As(herr, &su) {
				res["history_unavailable"] = su.Message
			} else {
				s.Log.Warn("source history", "review", v.Key, "err", herr)
				res["history_unavailable"] = "The commit history could not be retrieved."
			}
		}
	} else {
		res["history_unavailable"] = "Source code retrieval is not configured in this deployment."
	}
	httpx.WriteJSON(w, http.StatusOK, res)
}

// FlowNode is one step of a data flow with its role.
type FlowNode struct {
	scanners.FlowStep
	Role string `json:"role"` // source | intermediate | sink | related
}

// FlowPath is one reported path.
type FlowPath struct {
	Message string     `json:"message,omitempty"`
	Status  string     `json:"status"` // confirmed | incomplete
	Nodes   []FlowNode `json:"nodes"`
}

// DataFlow is the data flow view of a finding.
type DataFlow struct {
	// Status: confirmed (the scanner reported complete source-to-sink
	// paths), incomplete (a reported path lacks a distinct source or sink),
	// inferred (the scanner only reported related locations, no flow), or
	// unavailable.
	Status  string             `json:"status"`
	Reason  string             `json:"reason"`
	Scanner string             `json:"scanner"`
	Paths   []FlowPath         `json:"paths"`
	Related []FlowNode         `json:"related"`
	Notes   map[string]any     `json:"notes"`
	Sink    *scanners.FlowStep `json:"sink"`
}

func (s *Service) dataflow(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	p := s.Principal(ctx)
	id, err := pathUUID(r, "id")
	if err != nil {
		s.fail(w, r, err)
		return
	}
	v, err := s.load(ctx, s.DB, p, id, false)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if err := s.captureOriginal(ctx, v); err != nil {
		s.Log.Warn("capture scanner output", "review", v.Key, "err", err)
	}
	df, err := s.buildDataFlow(ctx, v)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, df)
}

func (s *Service) buildDataFlow(ctx context.Context, v rec) (DataFlow, error) {
	df := DataFlow{Scanner: v.ScannerKey, Paths: []FlowPath{}, Related: []FlowNode{}}
	var flowsRaw, relatedRaw []byte
	var captured *time.Time
	var capErr string
	if err := s.DB.QueryRow(ctx, `SELECT original_flows, original_related, original_captured_at, original_capture_error FROM human_reviews WHERE id = $1`, v.ID).
		Scan(&flowsRaw, &relatedRaw, &captured, &capErr); err != nil {
		return df, err
	}
	a, err := loadAssessment(ctx, s.DB, v.ID, v.Round)
	if err != nil {
		return df, err
	}
	df.Notes = a.DataflowNotes
	if v.FilePath != "" {
		sink := scanners.FlowStep{FilePath: v.FilePath}
		if v.StartLine != nil {
			sink.Line = *v.StartLine
		}
		df.Sink = &sink
	}
	var flows []scanners.Flow
	var related []scanners.FlowStep
	_ = json.Unmarshal(flowsRaw, &flows)
	_ = json.Unmarshal(relatedRaw, &related)
	for _, f := range flows {
		fp := FlowPath{Message: f.Message, Status: "confirmed"}
		for i, st := range f.Steps {
			role := "intermediate"
			switch {
			case i == 0:
				role = "source"
			case i == len(f.Steps)-1:
				role = "sink"
			}
			fp.Nodes = append(fp.Nodes, FlowNode{FlowStep: st, Role: role})
		}
		if len(f.Steps) < 2 {
			fp.Status = "incomplete"
		}
		df.Paths = append(df.Paths, fp)
	}
	for _, st := range related {
		df.Related = append(df.Related, FlowNode{FlowStep: st, Role: "related"})
	}
	switch {
	case len(df.Paths) > 0:
		df.Status = "confirmed"
		for _, fp := range df.Paths {
			if fp.Status == "incomplete" {
				df.Status = "incomplete"
				df.Reason = "At least one path reported by the scanner lacks a distinct source or sink."
			}
		}
		if df.Reason == "" {
			df.Reason = "Source-to-sink paths as reported by the scanner."
		}
	case len(df.Related) > 0:
		df.Status = "inferred"
		df.Reason = "The scanner associated these locations with the finding but did not report a data flow between them. Treat the connection as unverified."
	default:
		df.Status = "unavailable"
		switch {
		case v.Category == "sca" || v.Category == "container" || v.Category == "license":
			df.Reason = "Data flow does not apply to dependency findings: trace the use of the vulnerable package in the source code."
		case v.Category == "secrets":
			df.Reason = "Data flow does not apply to secret findings."
		case captured == nil:
			df.Reason = "The scanner output has not been captured yet."
		case capErr != "":
			df.Reason = "No data flow is available: " + capErr + "."
		default:
			df.Reason = "The scanner (" + v.ScannerKey + ") did not report a data flow for this finding. Trace it manually and record it in the Exploitability tab."
		}
	}
	return df, nil
}
