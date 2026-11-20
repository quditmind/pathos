package review

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"strings"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"pathos/internal/authz"
	"pathos/internal/platform/db"
	"pathos/internal/platform/httpx"
)

// AI patch proposals: an AI suggestion of kind "patch" whose code is a
// unified diff for the reviewed file. A person approves or rejects it; an
// approved patch can be downloaded and applied by a developer through the
// normal change process. PATHOS never applies patches to repositories.

var hunkRe = regexp.MustCompile(`^@@ -\d+(?:,\d+)? \+\d+(?:,\d+)? @@`)

func patchPath(header string) string {
	p := strings.TrimSpace(header[4:])
	if i := strings.IndexAny(p, "\t"); i >= 0 {
		p = p[:i]
	}
	p = strings.TrimPrefix(strings.TrimPrefix(p, "a/"), "b/")
	return strings.TrimPrefix(p, "./")
}

// ValidatePatch checks that diff is a unified diff of exactly one file,
// the reviewed one, with well-formed hunks.
func ValidatePatch(diff, file string) error {
	if len(diff) > 16000 {
		return errors.New("the patch is too large")
	}
	lines := strings.Split(strings.ReplaceAll(diff, "\r\n", "\n"), "\n")
	var from, to string
	hunks, files := 0, 0
	inHunk := false
	for i, l := range lines {
		switch {
		case strings.HasPrefix(l, "--- "):
			files++
			from = patchPath(l)
			if i+1 >= len(lines) || !strings.HasPrefix(lines[i+1], "+++ ") {
				return errors.New("a '---' header must be followed by '+++'")
			}
			inHunk = false
		case strings.HasPrefix(l, "+++ "):
			to = patchPath(l)
		case strings.HasPrefix(l, "@@"):
			if !hunkRe.MatchString(l) {
				return fmt.Errorf("malformed hunk header %q", l)
			}
			hunks++
			inHunk = true
		case inHunk && (l == "" || l[0] == ' ' || l[0] == '+' || l[0] == '-' || l[0] == '\\'):
		case strings.HasPrefix(l, "diff --git") || strings.HasPrefix(l, "index "):
		case !inHunk:
			// prose before the first header is ignored
		default:
			return fmt.Errorf("unexpected line in hunk: %q", l)
		}
	}
	if files != 1 || hunks == 0 {
		return errors.New("the patch must change exactly one file with at least one hunk")
	}
	// A patch whose removed and added lines differ only in whitespace
	// changes nothing.
	removed, added := map[string]int{}, map[string]int{}
	for _, l := range lines {
		switch {
		case strings.HasPrefix(l, "---") || strings.HasPrefix(l, "+++"):
		case strings.HasPrefix(l, "-"):
			removed[strings.Join(strings.Fields(l[1:]), " ")]++
		case strings.HasPrefix(l, "+"):
			added[strings.Join(strings.Fields(l[1:]), " ")]++
		}
	}
	same := len(removed) == len(added)
	for k, n := range removed {
		if added[k] != n {
			same = false
		}
	}
	if same {
		return errors.New("the patch makes no change beyond whitespace")
	}
	want := strings.TrimPrefix(file, "./")
	for _, p := range []string{from, to} {
		if p != want && p != "/dev/null" {
			return fmt.Errorf("the patch changes %q, not the reviewed file %q", p, want)
		}
	}
	return nil
}

func (s *Service) decidePatch(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	p := s.Principal(ctx)
	id, err := pathUUID(r, "id")
	if err != nil {
		s.fail(w, r, err)
		return
	}
	rid, err := pathUUID(r, "rid")
	if err != nil {
		s.fail(w, r, err)
		return
	}
	var req struct {
		Decision string `json:"decision"`
		Note     string `json:"note"`
	}
	if err := httpx.DecodeJSON(w, r, &req); err != nil {
		s.fail(w, r, err)
		return
	}
	if req.Decision != "approved" && req.Decision != "rejected" {
		s.fail(w, r, httpx.BadRequest("decision must be approved or rejected"))
		return
	}
	note := strings.TrimSpace(req.Note)
	if len(note) > 2000 || (req.Decision == "rejected" && len(note) < 5) {
		s.fail(w, r, httpx.E(http.StatusUnprocessableEntity, "validation_failed", "a note of 5 to 2000 characters is required to reject a patch"))
		return
	}
	err = db.InTx(ctx, s.DB, func(tx pgx.Tx) error {
		v, err := s.load(ctx, tx, p, id, true)
		if err != nil {
			return err
		}
		if err := s.require(ctx, p, authz.PermReviewsAssess, v.RepoID); err != nil {
			return err
		}
		var status *string
		if err := tx.QueryRow(ctx, `SELECT patch_status FROM human_review_recommendations WHERE id = $1 AND review_id = $2 AND kind = 'patch' FOR UPDATE`,
			rid, v.ID).Scan(&status); err != nil {
			return err
		}
		if status == nil || *status != "proposed" {
			return httpx.Conflict("this patch has already been decided")
		}
		if _, err := tx.Exec(ctx, `UPDATE human_review_recommendations SET patch_status = $2, patch_decided_by = $3, patch_decided_at = now(),
			patch_note = $4 WHERE id = $1`, rid, req.Decision, p.UserID, note); err != nil {
			return err
		}
		if err := hist(ctx, tx, v, &p.UserID, "ai.patch_"+req.Decision, "ai_recommendation_id", nil, rid, note); err != nil {
			return err
		}
		return s.audit(ctx, tx, p, "ai_patch_decision", v, map[string]any{"recommendation_id": rid, "decision": req.Decision})
	})
	if err != nil {
		s.fail(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// downloadPatch serves an approved patch as a .patch file.
func (s *Service) downloadPatch(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	p := s.Principal(ctx)
	id, err := pathUUID(r, "id")
	if err != nil {
		s.fail(w, r, err)
		return
	}
	rid, err := pathUUID(r, "rid")
	if err != nil {
		s.fail(w, r, err)
		return
	}
	v, err := s.load(ctx, s.DB, p, id, false)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	var status *string
	var content []byte
	if err := s.DB.QueryRow(ctx, `SELECT patch_status, content FROM human_review_recommendations WHERE id = $1 AND review_id = $2 AND kind = 'patch'`,
		rid, v.ID).Scan(&status, &content); err != nil {
		s.fail(w, r, err)
		return
	}
	if status == nil || *status != "approved" {
		s.fail(w, r, httpx.Conflict("only approved patches can be downloaded"))
		return
	}
	var out struct {
		Code string `json:"code"`
	}
	_ = json.Unmarshal(content, &out)
	httpx.Download(w, "text/x-diff; charset=utf-8", fmt.Sprintf("%s-%s.patch", v.Key, rid.String()[:8]))
	_, _ = w.Write([]byte(out.Code))
}

// duplicateCandidates lists other findings of the repository that may be
// the same issue: same file within ten lines, same rule, or same CVE.
func duplicateCandidates(ctx context.Context, q db.Querier, findingID uuid.UUID) ([]map[string]any, error) {
	rows, err := q.Query(ctx, `
	WITH me AS (SELECT * FROM findings WHERE id = $1)
	SELECT o.id, o.title, o.rule_id, o.scanner_keys, o.file_path, o.start_line, o.cwe, o.severity, o.cve, o.package_name, o.status
	FROM me JOIN findings o ON o.repository_id = me.repository_id AND o.id <> me.id
	WHERE (o.file_path = me.file_path AND me.file_path <> '' AND (me.start_line IS NULL OR o.start_line IS NULL OR abs(o.start_line - me.start_line) <= 10))
	   OR (o.rule_id = me.rule_id AND o.category = me.category)
	   OR (me.cve <> '' AND o.cve = me.cve)
	ORDER BY (o.file_path = me.file_path) DESC, o.last_seen_at DESC LIMIT 15`, findingID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []map[string]any
	for rows.Next() {
		var id uuid.UUID
		var title, rule, file, sev, cve, pkg, status string
		var scanners, cwe []string
		var line *int
		if err := rows.Scan(&id, &title, &rule, &scanners, &file, &line, &cwe, &sev, &cve, &pkg, &status); err != nil {
			return nil, err
		}
		out = append(out, map[string]any{"id": id, "title": title, "rule_id": rule, "scanners": scanners, "file_path": file, "start_line": line,
			"cwe": cwe, "severity": sev, "cve": cve, "package": pkg, "status": status})
	}
	return out, rows.Err()
}
