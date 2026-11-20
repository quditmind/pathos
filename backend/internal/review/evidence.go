package review

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"path"
	"slices"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"pathos/internal/audit"
	"pathos/internal/authz"
	"pathos/internal/platform/db"
	"pathos/internal/platform/httpx"
)

// Evidence is one evidence record.
type Evidence struct {
	ID             uuid.UUID  `json:"id"`
	EvidenceKey    string     `json:"evidence_key"`
	FindingID      uuid.UUID  `json:"finding_id"`
	Round          int        `json:"round"`
	Type           string     `json:"evidence_type"`
	Classification string     `json:"classification"`
	Description    string     `json:"description"`
	Comments       string     `json:"comments"`
	FileName       string     `json:"file_name"`
	ContentType    string     `json:"content_type"`
	SizeBytes      int64      `json:"size_bytes"`
	SHA256         string     `json:"sha256"`
	IsFile         bool       `json:"is_file"`
	Text           *string    `json:"text,omitempty"`
	UploadedBy     uuid.UUID  `json:"uploaded_by"`
	UploadedByName string     `json:"uploaded_by_name"`
	CreatedAt      time.Time  `json:"created_at"`
	DeletedAt      *time.Time `json:"deleted_at"`
	DeletedByName  *string    `json:"deleted_by_name"`
	DeleteReason   string     `json:"delete_reason"`
}

// allowedUploads maps file extensions to the content type PATHOS serves
// and the sniffed type the content must match ("text" = UTF-8 text).
// Active content (HTML, SVG, scripts, archives, executables) is refused.
var allowedUploads = map[string]struct{ serve, sniff string }{
	".png":  {"image/png", "image/png"},
	".jpg":  {"image/jpeg", "image/jpeg"},
	".jpeg": {"image/jpeg", "image/jpeg"},
	".gif":  {"image/gif", "image/gif"},
	".webp": {"image/webp", "image/webp"},
	".pdf":  {"application/pdf", "application/pdf"},
	".txt":  {"text/plain; charset=utf-8", "text"},
	".log":  {"text/plain; charset=utf-8", "text"},
	".md":   {"text/plain; charset=utf-8", "text"},
	".csv":  {"text/csv; charset=utf-8", "text"},
	".json": {"application/json", "text"},
	".har":  {"application/json", "text"},
	".http": {"text/plain; charset=utf-8", "text"},
	".docx": {"application/vnd.openxmlformats-officedocument.wordprocessingml.document", "application/zip"},
	".xlsx": {"application/vnd.openxmlformats-officedocument.spreadsheetml.sheet", "application/zip"},
}

// AllowedExtensions lists accepted upload extensions.
func AllowedExtensions() []string {
	out := make([]string, 0, len(allowedUploads))
	for k := range allowedUploads {
		out = append(out, k)
	}
	slices.Sort(out)
	return out
}

// cleanFileName keeps a safe display name.
func cleanFileName(name string) string {
	name = path.Base(strings.ReplaceAll(name, "\\", "/"))
	var b strings.Builder
	for _, r := range name {
		if r < 0x20 || r == 0x7f || strings.ContainsRune(`"<>|:*?`, r) {
			continue
		}
		b.WriteRune(r)
	}
	out := strings.TrimSpace(b.String())
	if len(out) > 200 {
		ext := path.Ext(out)
		out = out[:200-len(ext)] + ext
	}
	if out == "" || out == "." || out == "/" {
		out = "evidence"
	}
	return out
}

// CheckUpload validates a file by extension and content (magic bytes).
func CheckUpload(name string, head []byte) (serveType string, err error) {
	ext := strings.ToLower(path.Ext(name))
	a, ok := allowedUploads[ext]
	if !ok {
		return "", fmt.Errorf("files of type %q are not accepted; allowed: %s", ext, strings.Join(AllowedExtensions(), ", "))
	}
	if a.sniff == "text" {
		if bytes.IndexByte(head, 0) >= 0 || !utf8.Valid(trimPartialRune(head)) {
			return "", errors.New("the file is not UTF-8 text")
		}
		return a.serve, nil
	}
	if got := http.DetectContentType(head); !strings.HasPrefix(got, a.sniff) {
		return "", fmt.Errorf("the file content does not match its %s extension", ext)
	}
	return a.serve, nil
}

// trimPartialRune drops an incomplete UTF-8 sequence at the end of a prefix.
func trimPartialRune(b []byte) []byte {
	for i := 0; i < 3 && len(b) > 0; i++ {
		if utf8.Valid(b) {
			return b
		}
		b = b[:len(b)-1]
	}
	return b
}

func evidenceKey(orgID, reviewID, id uuid.UUID) string {
	return fmt.Sprintf("evidence/%s/%s/%s", orgID, reviewID, id)
}

func (s *Service) uploadEvidence(w http.ResponseWriter, r *http.Request) {
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
	if err := requireEditable(v); err != nil {
		s.fail(w, r, err)
		return
	}
	if err := s.requireAssessor(ctx, s.DB, p, v); err != nil {
		s.fail(w, r, err)
		return
	}
	st, err := loadSettings(ctx, s.DB, p.OrganizationID)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	limit := int64(st.EvidenceMaxMB) << 20
	mt, _, _ := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if mt != "multipart/form-data" {
		s.fail(w, r, httpx.E(http.StatusUnsupportedMediaType, "unsupported_media_type", "send evidence as multipart/form-data"))
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, limit+256<<10)
	mr, err := r.MultipartReader()
	if err != nil {
		s.fail(w, r, httpx.BadRequest("invalid multipart body"))
		return
	}
	form := map[string]string{}
	var fileName, serveType, sum string
	var size int64
	var tmp *bytes.Buffer
	for {
		part, err := mr.NextPart()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			var mbe *http.MaxBytesError
			if errors.As(err, &mbe) {
				s.fail(w, r, httpx.E(http.StatusRequestEntityTooLarge, "too_large", fmt.Sprintf("evidence files are limited to %d MB", st.EvidenceMaxMB)))
				return
			}
			s.fail(w, r, httpx.BadRequest("invalid multipart body"))
			return
		}
		name := part.FormName()
		if name == "file" && part.FileName() != "" {
			if tmp != nil {
				s.fail(w, r, httpx.BadRequest("upload one file per evidence item"))
				return
			}
			fileName = cleanFileName(part.FileName())
			tmp = &bytes.Buffer{}
			h := sha256.New()
			n, err := io.Copy(io.MultiWriter(tmp, h), io.LimitReader(part, limit+1))
			if err != nil {
				var mbe *http.MaxBytesError
				if errors.As(err, &mbe) {
					s.fail(w, r, httpx.E(http.StatusRequestEntityTooLarge, "too_large", fmt.Sprintf("evidence files are limited to %d MB", st.EvidenceMaxMB)))
					return
				}
				s.fail(w, r, httpx.BadRequest("could not read the uploaded file"))
				return
			}
			if n > limit {
				s.fail(w, r, httpx.E(http.StatusRequestEntityTooLarge, "too_large", fmt.Sprintf("evidence files are limited to %d MB", st.EvidenceMaxMB)))
				return
			}
			if n == 0 {
				s.fail(w, r, httpx.BadRequest("the uploaded file is empty"))
				return
			}
			size, sum = n, hex.EncodeToString(h.Sum(nil))
			head := tmp.Bytes()[:min(tmp.Len(), 8192)]
			if serveType, err = CheckUpload(fileName, head); err != nil {
				s.fail(w, r, httpx.BadRequest(err.Error()))
				return
			}
			if strings.HasPrefix(serveType, "text/") || serveType == "application/json" {
				if !utf8.Valid(tmp.Bytes()) || bytes.IndexByte(tmp.Bytes(), 0) >= 0 {
					s.fail(w, r, httpx.BadRequest("the file is not UTF-8 text"))
					return
				}
			}
			continue
		}
		b, err := io.ReadAll(io.LimitReader(part, 256<<10))
		if err != nil {
			s.fail(w, r, httpx.BadRequest("invalid multipart body"))
			return
		}
		form[name] = string(b)
	}
	typ := form["evidence_type"]
	class := form["classification"]
	if class == "" {
		class = "confidential"
	}
	desc := strings.TrimSpace(form["description"])
	comments := strings.TrimSpace(form["comments"])
	text := form["text"]
	errs := map[string]string{}
	if !slices.Contains(EvidenceTypes, typ) {
		errs["evidence_type"] = "Choose an evidence type."
	}
	if !slices.Contains(EvidenceClassifications, class) {
		errs["classification"] = "Choose a classification."
	}
	if desc == "" || len(desc) > 2000 {
		errs["description"] = "A description (1-2000 characters) is required."
	}
	if len(comments) > 4000 {
		errs["comments"] = "Comments are limited to 4000 characters."
	}
	switch {
	case tmp == nil && strings.TrimSpace(text) == "":
		errs["file"] = "Attach a file or paste the evidence as text."
	case tmp != nil && text != "":
		errs["file"] = "Attach a file or paste text, not both."
	case tmp == nil && (len(text) > 200000 || !utf8.ValidString(text) || strings.ContainsRune(text, 0)):
		errs["text"] = "Text evidence is limited to 200,000 characters of UTF-8 text."
	}
	if tmp != nil && s.Evidence == nil {
		errs["file"] = "File uploads are not available: no encrypted object store is configured. Paste the evidence as text instead."
	}
	if len(errs) > 0 {
		s.fail(w, r, fieldErrors(errs))
		return
	}
	eid := uuid.Must(uuid.NewV7())
	var objKey *string
	if tmp != nil {
		k := evidenceKey(p.OrganizationID, v.ID, eid)
		if _, err := s.Evidence.Put(ctx, k, bytes.NewReader(tmp.Bytes())); err != nil {
			s.fail(w, r, err)
			return
		}
		objKey = &k
	} else {
		b := []byte(text)
		h := sha256.Sum256(b)
		size, sum, serveType = int64(len(b)), hex.EncodeToString(h[:]), "text/plain; charset=utf-8"
	}
	var textContent *string
	if tmp == nil {
		textContent = &text
	}
	var out Evidence
	err = db.InTx(ctx, s.DB, func(tx pgx.Tx) error {
		v, err := s.load(ctx, tx, p, id, true)
		if err != nil {
			return err
		}
		if err := requireEditable(v); err != nil {
			return err
		}
		var key string
		if err := tx.QueryRow(ctx, `INSERT INTO human_review_evidence (id, organization_id, review_id, finding_id, round, evidence_type, classification,
			description, comments, file_name, content_type, size_bytes, sha256, object_key, text_content, uploaded_by)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16) RETURNING evidence_key`,
			eid, v.OrgID, v.ID, v.FindingID, v.Round, typ, class, desc, comments, fileName, serveType, size, sum, objKey, textContent, p.UserID).Scan(&key); err != nil {
			return err
		}
		meta := map[string]any{"evidence_id": eid, "evidence_key": key, "type": typ, "file_name": fileName, "sha256": sum, "size": size}
		if err := hist(ctx, tx, v, &p.UserID, "evidence.upload", "evidence", nil, meta, desc); err != nil {
			return err
		}
		if err := s.audit(ctx, tx, p, "evidence_upload", v, meta); err != nil {
			return err
		}
		list, err := listEvidence(ctx, tx, v.ID, &eid)
		if err == nil && len(list) == 1 {
			out = list[0]
		}
		return err
	})
	if err != nil {
		if objKey != nil {
			_ = s.Evidence.Delete(ctx, *objKey)
		}
		s.fail(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusCreated, out)
}

func listEvidence(ctx context.Context, q db.Querier, reviewID uuid.UUID, only *uuid.UUID) ([]Evidence, error) {
	rows, err := q.Query(ctx, `SELECT e.id, e.evidence_key, e.finding_id, e.round, e.evidence_type, e.classification, e.description, e.comments,
		e.file_name, e.content_type, e.size_bytes, e.sha256, e.object_key IS NOT NULL, CASE WHEN e.deleted_at IS NULL THEN e.text_content END,
		e.uploaded_by, COALESCE(NULLIF(u.display_name, ''), u.email), e.created_at, e.deleted_at, COALESCE(NULLIF(du.display_name, ''), du.email),
		e.delete_reason
		FROM human_review_evidence e JOIN users u ON u.id = e.uploaded_by LEFT JOIN users du ON du.id = e.deleted_by
		WHERE e.review_id = $1 AND ($2::uuid IS NULL OR e.id = $2) ORDER BY e.created_at, e.id`, reviewID, only)
	if err != nil {
		return nil, err
	}
	out, err := pgx.CollectRows(rows, pgx.RowToStructByPos[Evidence])
	if out == nil {
		out = []Evidence{}
	}
	return out, err
}

func (s *Service) listEvidence(w http.ResponseWriter, r *http.Request) {
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
	out, err := listEvidence(ctx, s.DB, v.ID, nil)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"items": out, "uploads_enabled": s.Evidence != nil, "allowed_extensions": AllowedExtensions()})
}

// downloadEvidence serves evidence content. Nothing uploaded is ever
// rendered as active content: files are sent with a sandboxing CSP and
// nosniff, and everything except images is an attachment.
func (s *Service) downloadEvidence(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	p := s.Principal(ctx)
	id, err := pathUUID(r, "id")
	if err != nil {
		s.fail(w, r, err)
		return
	}
	eid, err := pathUUID(r, "eid")
	if err != nil {
		s.fail(w, r, err)
		return
	}
	v, err := s.load(ctx, s.DB, p, id, false)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	var name, ct string
	var key, text *string
	var deleted *time.Time
	if err := s.DB.QueryRow(ctx, `SELECT file_name, content_type, object_key, text_content, deleted_at FROM human_review_evidence WHERE id = $1 AND review_id = $2`,
		eid, v.ID).Scan(&name, &ct, &key, &text, &deleted); err != nil {
		s.fail(w, r, err)
		return
	}
	if deleted != nil {
		s.fail(w, r, httpx.E(http.StatusGone, "gone", "this evidence was deleted"))
		return
	}
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Content-Security-Policy", "default-src 'none'; sandbox")
	w.Header().Set("Cache-Control", "private, no-store")
	if text != nil {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.Header().Set("Content-Disposition", mime.FormatMediaType("attachment", map[string]string{"filename": "evidence.txt"}))
		httpx.StampHeaders(w, time.Now())
		_, _ = io.WriteString(w, *text)
		return
	}
	if key == nil || s.Evidence == nil {
		s.fail(w, r, httpx.E(http.StatusServiceUnavailable, "unavailable", "the evidence store is not configured"))
		return
	}
	rc, err := s.Evidence.Open(ctx, *key)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	defer rc.Close()
	// Read fully first: integrity errors surface at the end of the stream.
	data, err := io.ReadAll(io.LimitReader(rc, 101<<20))
	if err != nil {
		s.fail(w, r, err)
		return
	}
	disp := "attachment"
	if strings.HasPrefix(ct, "image/") && r.URL.Query().Get("inline") == "1" {
		disp = "inline"
	}
	w.Header().Set("Content-Type", ct)
	w.Header().Set("Content-Disposition", mime.FormatMediaType(disp, map[string]string{"filename": name}))
	httpx.StampHeaders(w, time.Now())
	_ = audit.Write(ctx, s.DB, audit.Entry{OrganizationID: p.OrganizationID, ActorID: &p.UserID, ActorEmail: p.Email,
		Action: "human_review.evidence_download", TargetType: "human_review", TargetID: v.ID.String(), Metadata: map[string]any{"evidence_id": eid}})
	_, _ = w.Write(data)
}

func (s *Service) deleteEvidence(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	p := s.Principal(ctx)
	id, err := pathUUID(r, "id")
	if err != nil {
		s.fail(w, r, err)
		return
	}
	eid, err := pathUUID(r, "eid")
	if err != nil {
		s.fail(w, r, err)
		return
	}
	reason := strings.TrimSpace(r.URL.Query().Get("reason"))
	if len(reason) < 5 || len(reason) > 2000 {
		s.fail(w, r, httpx.E(http.StatusUnprocessableEntity, "validation_failed", "a reason (5-2000 characters) is required to delete evidence"))
		return
	}
	var key *string
	err = db.InTx(ctx, s.DB, func(tx pgx.Tx) error {
		v, err := s.load(ctx, tx, p, id, true)
		if err != nil {
			return err
		}
		if err := requireEditable(v); err != nil {
			return err
		}
		var uploader uuid.UUID
		var ekey string
		var deleted *time.Time
		if err := tx.QueryRow(ctx, `SELECT uploaded_by, evidence_key, object_key, deleted_at FROM human_review_evidence WHERE id = $1 AND review_id = $2 FOR UPDATE`,
			eid, v.ID).Scan(&uploader, &ekey, &key, &deleted); err != nil {
			return err
		}
		if deleted != nil {
			return httpx.Conflict("the evidence is already deleted")
		}
		if uploader != p.UserID && !s.can(ctx, p, authz.PermReviewsAssign, v.RepoID) {
			return httpx.E(http.StatusForbidden, "forbidden", "only the uploader or a review manager can delete evidence")
		}
		if err := s.requireAssessor(ctx, tx, p, v); err != nil && !s.can(ctx, p, authz.PermReviewsAssign, v.RepoID) {
			return err
		}
		// The record stays (immutable trail); the content is removed.
		if _, err := tx.Exec(ctx, `UPDATE human_review_evidence SET deleted_at = now(), deleted_by = $2, delete_reason = $3, text_content = NULL,
			object_key = NULL WHERE id = $1`, eid, p.UserID, reason); err != nil {
			return err
		}
		meta := map[string]any{"evidence_id": eid, "evidence_key": ekey}
		if err := hist(ctx, tx, v, &p.UserID, "evidence.delete", "evidence", meta, nil, reason); err != nil {
			return err
		}
		return s.audit(ctx, tx, p, "evidence_delete", v, map[string]any{"evidence_id": eid, "evidence_key": ekey, "reason": reason})
	})
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if key != nil && s.Evidence != nil {
		if err := s.Evidence.Delete(context.WithoutCancel(ctx), *key); err != nil {
			s.Log.Warn("evidence object not deleted", "key", *key, "err", err)
		}
	}
	w.WriteHeader(http.StatusNoContent)
}
