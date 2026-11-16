package repos

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"pathos/internal/audit"
	"pathos/internal/authz"
	"pathos/internal/ingest"
	"pathos/internal/platform/db"
	"pathos/internal/platform/httpx"
)

// uploadTTL is how long an unfinished or unused upload is kept.
const uploadTTL = 24 * time.Hour

// maxOpenUploads bounds concurrent upload sessions per user.
const maxOpenUploads = 50

func (s *Service) registerUploads(mux *http.ServeMux) {
	mux.HandleFunc("POST /api/v1/source-uploads", s.createUpload)
	mux.HandleFunc("GET /api/v1/source-uploads/{id}", s.getUpload)
	mux.HandleFunc("PUT /api/v1/source-uploads/{id}/parts/{n}", s.putUploadPart)
	mux.HandleFunc("POST /api/v1/source-uploads/{id}/complete", s.completeUpload)
	mux.HandleFunc("DELETE /api/v1/source-uploads/{id}", s.deleteUpload)
	mux.HandleFunc("GET /api/v1/repositories/{id}/snapshots", s.listSnapshots)
}

// SourceUpload is the API form of an upload session.
type SourceUpload struct {
	ID            uuid.UUID `json:"id"`
	Filename      string    `json:"filename"`
	Format        string    `json:"format"`
	Size          int64     `json:"size"`
	SHA256        string    `json:"sha256"`
	ChunkSize     int       `json:"chunk_size"`
	Status        string    `json:"status"`
	ReceivedParts []int     `json:"received_parts"`
	ReceivedBytes int64     `json:"received_bytes"`
	ExpiresAt     time.Time `json:"expires_at"`
	createdBy     uuid.UUID
}

func (u SourceUpload) parts() int { return int((u.Size + int64(u.ChunkSize) - 1) / int64(u.ChunkSize)) }

func (u SourceUpload) partSize(n int) int64 {
	if n < u.parts()-1 {
		return int64(u.ChunkSize)
	}
	return u.Size - int64(n)*int64(u.ChunkSize)
}

var sha256Re = regexp.MustCompile(`^[0-9a-f]{64}$`)

// uploadFormat derives the archive format from the file name.
func uploadFormat(name string) (string, bool) {
	l := strings.ToLower(name)
	switch {
	case strings.HasSuffix(l, ".zip"):
		return "zip", true
	case strings.HasSuffix(l, ".tar.gz"), strings.HasSuffix(l, ".tgz"):
		return "tar.gz", true
	case strings.HasSuffix(l, ".tar"):
		return "tar", true
	}
	return "", false
}

func partKey(orgID, uploadID uuid.UUID, n int) string {
	return fmt.Sprintf("uploads/%s/%s/%06d", orgID, uploadID, n)
}

func snapshotKey(orgID, snapshotID uuid.UUID) string {
	return fmt.Sprintf("snapshots/%s/%s.tar.gz", orgID, snapshotID)
}

func (s *Service) loadUpload(ctx context.Context, q db.Querier, orgID, id uuid.UUID) (SourceUpload, error) {
	var u SourceUpload
	err := q.QueryRow(ctx, `SELECT u.id, u.filename, u.format, u.declared_size, u.declared_sha256, u.chunk_size,
		CASE WHEN u.status IN ('uploading', 'complete') AND u.expires_at < now() THEN 'expired' ELSE u.status END, u.expires_at, u.created_by,
		COALESCE(array_agg(p.part_number ORDER BY p.part_number) FILTER (WHERE p.part_number IS NOT NULL), '{}'),
		COALESCE(sum(p.size_bytes), 0)
		FROM source_uploads u LEFT JOIN source_upload_parts p ON p.upload_id = u.id
		WHERE u.organization_id = $1 AND u.id = $2 GROUP BY u.id`, orgID, id).
		Scan(&u.ID, &u.Filename, &u.Format, &u.Size, &u.SHA256, &u.ChunkSize, &u.Status, &u.ExpiresAt, &u.createdBy, &u.ReceivedParts, &u.ReceivedBytes)
	if errors.Is(err, pgx.ErrNoRows) {
		return u, errNotFound
	}
	return u, err
}

// ownUpload loads an upload of the calling user (uploads are private to
// their uploader until imported).
func (s *Service) ownUpload(r *http.Request) (*authz.Principal, SourceUpload, error) {
	p := s.Principal(r.Context())
	if s.Sources == nil {
		return p, SourceUpload{}, httpx.E(http.StatusServiceUnavailable, "uploads_unavailable", "local uploads are not configured on this server")
	}
	id, err := pathID(r)
	if err != nil {
		return p, SourceUpload{}, err
	}
	u, err := s.loadUpload(r.Context(), s.DB, p.OrganizationID, id)
	if err != nil {
		return p, u, err
	}
	if u.createdBy != p.UserID {
		return p, u, errNotFound
	}
	return p, u, nil
}

type createUploadRequest struct {
	Filename string `json:"filename"`
	Size     int64  `json:"size"`
	SHA256   string `json:"sha256"`
}

func (s *Service) createUpload(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	p := s.Principal(ctx)
	if !p.HasAnywhere(authz.PermReposManage) {
		s.fail(w, r, authz.ErrForbidden)
		return
	}
	if s.Sources == nil {
		s.fail(w, r, httpx.E(http.StatusServiceUnavailable, "uploads_unavailable", "local uploads are not configured on this server"))
		return
	}
	var req createUploadRequest
	if err := httpx.DecodeJSON(w, r, &req); err != nil {
		s.fail(w, r, err)
		return
	}
	name := filepath.Base(strings.ReplaceAll(strings.TrimSpace(req.Filename), "\\", "/"))
	if name == "" || name == "." || len(name) > 255 || strings.ContainsAny(name, "\x00\r\n") {
		s.fail(w, r, httpx.BadRequest("invalid file name"))
		return
	}
	format, ok := uploadFormat(name)
	if !ok {
		s.fail(w, r, httpx.BadRequest("only .zip, .tar, .tar.gz and .tgz archives are accepted"))
		return
	}
	if req.Size <= 0 || req.Size > s.Limits.UploadMaxBytes {
		s.fail(w, r, httpx.E(http.StatusRequestEntityTooLarge, "too_large",
			fmt.Sprintf("archives must be between 1 byte and %d MB", s.Limits.UploadMaxBytes>>20)))
		return
	}
	sum := strings.ToLower(strings.TrimSpace(req.SHA256))
	if !sha256Re.MatchString(sum) {
		s.fail(w, r, httpx.BadRequest("sha256 must be the hex SHA-256 of the file"))
		return
	}
	var open int
	if err := s.DB.QueryRow(ctx, `SELECT count(*) FROM source_uploads WHERE created_by = $1 AND status IN ('uploading', 'complete') AND expires_at > now()`,
		p.UserID).Scan(&open); err != nil {
		s.fail(w, r, err)
		return
	}
	if open >= maxOpenUploads {
		s.fail(w, r, httpx.E(http.StatusTooManyRequests, "too_many_uploads", "finish or cancel your open uploads first"))
		return
	}
	id := uuid.Must(uuid.NewV7())
	if _, err := s.DB.Exec(ctx, `INSERT INTO source_uploads (id, organization_id, created_by, filename, format, declared_size, declared_sha256,
		chunk_size, expires_at) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`,
		id, p.OrganizationID, p.UserID, name, format, req.Size, sum, uploadChunkSize, time.Now().Add(uploadTTL)); err != nil {
		s.fail(w, r, err)
		return
	}
	u, err := s.loadUpload(ctx, s.DB, p.OrganizationID, id)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusCreated, u)
}

func (s *Service) getUpload(w http.ResponseWriter, r *http.Request) {
	_, u, err := s.ownUpload(r)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, u)
}

func (s *Service) putUploadPart(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	p, u, err := s.ownUpload(r)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if u.Status != "uploading" {
		s.fail(w, r, httpx.Conflict("the upload is "+u.Status))
		return
	}
	n, err := strconv.Atoi(r.PathValue("n"))
	if err != nil || n < 0 || n >= u.parts() {
		s.fail(w, r, httpx.BadRequest(fmt.Sprintf("part must be between 0 and %d", u.parts()-1)))
		return
	}
	want := strings.ToLower(r.Header.Get("X-Content-SHA256"))
	if !sha256Re.MatchString(want) {
		s.fail(w, r, httpx.BadRequest("X-Content-SHA256 header with the part's hex SHA-256 is required"))
		return
	}
	size := u.partSize(n)
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, size))
	if err != nil {
		s.fail(w, r, httpx.E(http.StatusRequestEntityTooLarge, "too_large", fmt.Sprintf("part %d must be exactly %d bytes", n, size)))
		return
	}
	if int64(len(body)) != size {
		s.fail(w, r, httpx.BadRequest(fmt.Sprintf("part %d must be exactly %d bytes, got %d", n, size, len(body))))
		return
	}
	got := sha256.Sum256(body)
	if subtle.ConstantTimeCompare([]byte(hex.EncodeToString(got[:])), []byte(want)) != 1 {
		s.fail(w, r, httpx.E(http.StatusUnprocessableEntity, "checksum_mismatch", "the part does not match its SHA-256; resend it"))
		return
	}
	key := partKey(p.OrganizationID, u.ID, n)
	if _, err := s.Sources.Put(ctx, key, bytes.NewReader(body)); err != nil {
		s.fail(w, r, err)
		return
	}
	if _, err := s.DB.Exec(ctx, `INSERT INTO source_upload_parts (upload_id, part_number, size_bytes, sha256, object_key)
		VALUES ($1, $2, $3, $4, $5) ON CONFLICT (upload_id, part_number) DO UPDATE SET size_bytes = EXCLUDED.size_bytes,
		sha256 = EXCLUDED.sha256, object_key = EXCLUDED.object_key, created_at = now()`, u.ID, n, size, want, key); err != nil {
		s.fail(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"part": n, "size": size})
}

func (s *Service) completeUpload(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	p, u, err := s.ownUpload(r)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if u.Status == "complete" {
		httpx.WriteJSON(w, http.StatusOK, u)
		return
	}
	if u.Status != "uploading" {
		s.fail(w, r, httpx.Conflict("the upload is "+u.Status))
		return
	}
	if len(u.ReceivedParts) != u.parts() || u.ReceivedBytes != u.Size {
		missing := []int{}
		for i := range u.parts() {
			if !slices.Contains(u.ReceivedParts, i) {
				missing = append(missing, i)
			}
		}
		e := httpx.Conflict(fmt.Sprintf("%d of %d parts are missing", len(missing), u.parts()))
		e.Details = map[string]any{"missing_parts": missing}
		s.fail(w, r, e)
		return
	}
	if _, err := s.DB.Exec(ctx, `UPDATE source_uploads SET status = 'complete', completed_at = now() WHERE id = $1 AND status = 'uploading'`, u.ID); err != nil {
		s.fail(w, r, err)
		return
	}
	_ = audit.Write(ctx, s.DB, audit.Entry{OrganizationID: p.OrganizationID, ActorID: &p.UserID, ActorEmail: p.Email,
		Action: "source_upload.complete", TargetType: "source_upload", TargetID: u.ID.String(),
		Metadata: map[string]any{"filename": u.Filename, "size": u.Size, "sha256": u.SHA256}})
	u, err = s.loadUpload(ctx, s.DB, p.OrganizationID, u.ID)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, u)
}

func (s *Service) deleteUpload(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	p, u, err := s.ownUpload(r)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if u.Status == "consumed" {
		s.fail(w, r, httpx.Conflict("the upload was already imported"))
		return
	}
	var active bool
	_ = s.DB.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM repository_import_items WHERE source_ref->>'upload_id' = $1
		AND status NOT IN ('failed', 'cancelled', 'completed'))`, u.ID.String()).Scan(&active)
	if active {
		s.fail(w, r, httpx.Conflict("the upload is being imported; cancel the import first"))
		return
	}
	if err := s.discardUpload(ctx, p.OrganizationID, u.ID, "cancelled"); err != nil {
		s.fail(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// discardUpload deletes an upload's parts and marks it with status.
func (s *Service) discardUpload(ctx context.Context, orgID, id uuid.UUID, status string) error {
	rows, err := s.DB.Query(ctx, `SELECT object_key FROM source_upload_parts WHERE upload_id = $1`, id)
	if err != nil {
		return err
	}
	keys, err := pgx.CollectRows(rows, pgx.RowTo[string])
	if err != nil {
		return err
	}
	if s.Sources != nil && len(keys) > 0 {
		if err := s.Sources.Delete(ctx, keys...); err != nil {
			return err
		}
	}
	_, err = s.DB.Exec(ctx, `WITH d AS (DELETE FROM source_upload_parts WHERE upload_id = $2)
		UPDATE source_uploads SET status = $3 WHERE organization_id = $1 AND id = $2`, orgID, id, status)
	return err
}

// CleanupUploads removes expired uploads (jobs role, hourly).
func (s *Service) CleanupUploads(ctx context.Context) {
	rows, err := s.DB.Query(ctx, `SELECT organization_id, id FROM source_uploads u
		WHERE status IN ('uploading', 'complete') AND expires_at < now()
		  AND NOT EXISTS (SELECT 1 FROM repository_import_items i WHERE i.source_ref->>'upload_id' = u.id::text
		                  AND i.status NOT IN ('failed', 'cancelled', 'completed'))
		LIMIT 500`)
	if err != nil {
		s.Log.Error("upload cleanup", "err", err)
		return
	}
	type pair struct{ org, id uuid.UUID }
	list, err := pgx.CollectRows(rows, func(r pgx.CollectableRow) (pair, error) {
		var p pair
		return p, r.Scan(&p.org, &p.id)
	})
	if err != nil {
		s.Log.Error("upload cleanup", "err", err)
		return
	}
	for _, u := range list {
		if err := s.discardUpload(ctx, u.org, u.id, "expired"); err != nil {
			s.Log.Warn("upload cleanup failed", "upload_id", u.id, "err", err)
		}
	}
	if len(list) > 0 {
		s.Log.Info("expired uploads removed", "count", len(list))
	}
}

// checkUploadItem validates an upload for import by p. It returns the
// default display name, a duplicate repository (same archive), a message
// and whether the problem blocks the import.
func (s *Service) checkUploadItem(ctx context.Context, p *authz.Principal, uploadID uuid.UUID, target *uuid.UUID) (string, *uuid.UUID, string, bool) {
	u, err := s.loadUpload(ctx, s.DB, p.OrganizationID, uploadID)
	if err != nil || u.createdBy != p.UserID {
		return "", nil, "unknown upload", true
	}
	name := u.Filename
	for _, ext := range []string{".tar.gz", ".tgz", ".zip", ".tar"} {
		if strings.HasSuffix(strings.ToLower(name), ext) {
			name = name[:len(name)-len(ext)]
			break
		}
	}
	if u.Status != "complete" {
		return name, nil, "the upload of " + u.Filename + " is " + u.Status, true
	}
	if target != nil {
		var src string
		err := s.DB.QueryRow(ctx, `SELECT source_type FROM repositories WHERE organization_id = $1 AND id = $2 AND archived_at IS NULL`,
			p.OrganizationID, *target).Scan(&src)
		if err != nil || src != "upload" {
			return name, nil, "the target repository does not exist or was not uploaded", true
		}
		if err := s.requireRepo(ctx, p, authz.PermReposManage, *target); err != nil {
			return name, nil, "you need repos.manage on the target repository", true
		}
	}
	var dup uuid.UUID
	if err := s.DB.QueryRow(ctx, `SELECT repository_id FROM source_snapshots WHERE organization_id = $1 AND archive_sha256 = $2
		AND repository_id IS NOT NULL ORDER BY created_at DESC LIMIT 1`, p.OrganizationID, u.SHA256).Scan(&dup); err == nil {
		return name, &dup, "an identical archive was already imported", true
	}
	return name, nil, "", false
}

// countingHash counts and hashes what passes through.
type countingHash struct {
	n int64
	h interface {
		io.Writer
		Sum([]byte) []byte
	}
}

func (c *countingHash) Write(p []byte) (int, error) {
	c.n += int64(len(p))
	return c.h.Write(p)
}

// processUpload validates, scans and normalizes an uploaded archive into an
// encrypted snapshot and registers it.
func (s *Service) processUpload(ctx context.Context, it importItem, owner string) (importResult, error) {
	var res importResult
	if s.Sources == nil {
		return res, permanent("uploads_unavailable", "local uploads are not configured on this server")
	}
	if it.Ref.UploadID == nil {
		return res, permanent("invalid_item", "import item has no upload")
	}
	u, err := s.loadUpload(ctx, s.DB, it.OrgID, *it.Ref.UploadID)
	if err != nil {
		return res, permanent("upload_missing", "the upload no longer exists")
	}
	if u.Status != "complete" {
		return res, permanent("upload_incomplete", "the upload is "+u.Status)
	}
	if len(u.ReceivedParts) != u.parts() {
		return res, permanent("upload_incomplete", "parts of the upload are missing")
	}
	if !it.AllowDuplicate {
		var dup uuid.UUID
		if err := s.DB.QueryRow(ctx, `SELECT repository_id FROM source_snapshots WHERE organization_id = $1 AND archive_sha256 = $2
			AND repository_id IS NOT NULL LIMIT 1`, it.OrgID, u.SHA256).Scan(&dup); err == nil {
			res.RepositoryID = &dup
			return res, attention("duplicate", "an identical archive was already imported; retry with \"import anyway\" to keep a second copy")
		}
	}

	// 1. Reassemble and verify the archive in a private temporary file.
	if err := s.stage(ctx, it, owner, StatusImporting, 15, "Verifying archive checksum"); err != nil {
		return res, err
	}
	workDir := s.Limits.WorkDir
	if workDir == "" {
		workDir = os.TempDir()
	}
	if err := os.MkdirAll(workDir, 0o700); err != nil {
		return res, err
	}
	f, err := os.CreateTemp(workDir, "pathos-import-*")
	if err != nil {
		return res, err
	}
	defer func() {
		_ = f.Close()
		_ = os.Remove(f.Name())
	}()
	whole := sha256.New()
	for n := range u.parts() {
		if err := ctx.Err(); err != nil {
			return res, err
		}
		var key, partSum string
		if err := s.DB.QueryRow(ctx, `SELECT object_key, sha256 FROM source_upload_parts WHERE upload_id = $1 AND part_number = $2`,
			u.ID, n).Scan(&key, &partSum); err != nil {
			return res, permanent("upload_incomplete", fmt.Sprintf("part %d is missing", n))
		}
		rc, err := s.Sources.Open(ctx, key)
		if err != nil {
			return res, &importError{Code: "storage_unavailable", Msg: "could not read the uploaded data", Transient: true}
		}
		ph := sha256.New()
		_, err = io.Copy(io.MultiWriter(f, whole, ph), rc)
		_ = rc.Close()
		if err != nil {
			return res, permanent("upload_corrupt", "stored upload data failed its integrity check")
		}
		if hex.EncodeToString(ph.Sum(nil)) != partSum {
			return res, permanent("checksum_mismatch", fmt.Sprintf("part %d does not match its checksum", n))
		}
	}
	if hex.EncodeToString(whole.Sum(nil)) != u.SHA256 {
		return res, permanent("checksum_mismatch", "the archive does not match the SHA-256 computed by the browser")
	}

	// 2. Malware scan (clamd), when configured.
	malware, engine := "not_configured", ""
	if s.Limits.ClamAVAddress != "" {
		if err := s.stage(ctx, it, owner, StatusImporting, 30, "Scanning for malware"); err != nil {
			return res, err
		}
		if _, err := f.Seek(0, io.SeekStart); err != nil {
			return res, err
		}
		v, err := ingest.ClamAV{Address: s.Limits.ClamAVAddress, Timeout: 10 * time.Minute}.Scan(ctx, f)
		switch {
		case err != nil && s.Limits.ClamAVRequired:
			return res, &importError{Code: "malware_scanner_unavailable", Msg: "the malware scanner is unavailable: " + truncate(err.Error(), 200), Transient: true}
		case err != nil:
			malware, engine = "unavailable", truncate(err.Error(), 200)
			s.Log.Warn("malware scan unavailable; continuing (PATHOS_CLAMAV_REQUIRED=false)", "err", err)
		case !v.Clean:
			_ = audit.Write(ctx, s.DB, audit.Entry{OrganizationID: it.OrgID, ActorID: &it.RequestedBy, Action: "source_upload.malware_detected",
				Outcome: "failure", TargetType: "source_upload", TargetID: u.ID.String(),
				Metadata: map[string]any{"filename": u.Filename, "signature": v.Signature, "engine": v.Engine}})
			_ = s.discardUpload(context.WithoutCancel(ctx), it.OrgID, u.ID, "cancelled")
			return res, permanent("malware_detected", "the archive was rejected by the malware scanner ("+v.Signature+")")
		default:
			malware, engine = "clean", v.Engine
		}
	}

	// 3. Normalize into an encrypted snapshot (nothing is extracted to disk
	// and nothing is executed).
	if err := s.stage(ctx, it, owner, StatusImporting, 45, "Validating and normalizing archive"); err != nil {
		return res, err
	}
	head := make([]byte, 1024)
	hn, _ := f.ReadAt(head, 0)
	format, err := ingest.DetectFormat(head[:hn], u.Filename)
	if err != nil {
		return res, permanent("archive_rejected", "unsupported or corrupt archive: "+err.Error())
	}
	snapID := uuid.Must(uuid.NewV7())
	key := snapshotKey(it.OrgID, snapID)
	pr, pw := io.Pipe()
	snapHash := &countingHash{h: sha256.New()}
	var result ingest.Result
	normErr := make(chan error, 1)
	go func() {
		lim := ingest.Limits{MaxFiles: s.Limits.MaxFiles, MaxTotalBytes: s.Limits.MaxExtractedBytes, MaxFileBytes: s.Limits.MaxFileBytes}
		var err error
		result, err = ingest.Normalize(ctx, f, format, u.Size, io.MultiWriter(pw, snapHash), lim)
		pw.CloseWithError(err)
		normErr <- err
	}()
	_, putErr := s.Sources.Put(ctx, key, pr)
	_ = pr.CloseWithError(putErr)
	nerr := <-normErr
	if nerr != nil || putErr != nil {
		_ = s.Sources.Delete(context.WithoutCancel(ctx), key)
		if code := ingest.CodeOf(nerr); code != "" {
			return res, permanent("archive_rejected", fmt.Sprintf("%s: %s", code, nerr.Error()))
		}
		if nerr != nil {
			return res, nerr
		}
		return res, &importError{Code: "storage_unavailable", Msg: "could not store the snapshot", Transient: true}
	}
	snapSum := hex.EncodeToString(snapHash.h.Sum(nil))
	cleanup := func() { _ = s.Sources.Delete(context.WithoutCancel(ctx), key) }

	// 4. Register.
	if err := s.stage(ctx, it, owner, StatusRegistering, 80, "Registering asset"); err != nil {
		cleanup()
		return res, err
	}
	target := it.Ref.TargetRepositoryID
	if target == nil {
		if err := s.registerChecks(ctx, &it); err != nil {
			cleanup()
			return res, err
		}
	} else {
		p, err := s.requester(ctx, it)
		if err != nil || s.requireRepo(ctx, p, authz.PermReposManage, *target) != nil {
			cleanup()
			return res, attention("permission_denied", "the requesting user no longer has repos.manage on the target repository")
		}
	}
	langs := result.Languages
	if langs == nil {
		langs = map[string]int64{}
	}
	techs := topLanguages(langs, 5)
	manifests := result.Manifests
	if manifests == nil {
		manifests = []string{}
	}
	repoID := uuid.Must(uuid.NewV7())
	resultKind := "imported"
	err = db.InTx(ctx, s.DB, func(tx pgx.Tx) error {
		if target != nil {
			repoID, resultKind = *target, "snapshot_added"
			if _, err := tx.Exec(ctx, `SELECT 1 FROM repositories WHERE id = $1 FOR UPDATE`, repoID); err != nil {
				return err
			}
		} else {
			name := it.Values.DisplayName
			if name == "" {
				name = it.Name
			}
			if _, err := tx.Exec(ctx, `INSERT INTO repositories (id, organization_id, scm_connection_id, source_type, external_id, full_name, name,
				url, clone_url, visibility, technologies, imported_by)
				VALUES ($1, $2, NULL, 'upload', $6, $3, $3, '', '', 'private', $4, $5)`,
				repoID, it.OrgID, truncate(name, 200), techs, it.RequestedBy, repoID.String()); err != nil {
				return err
			}
			if err := writeValues(ctx, tx, it.OrgID, repoID, it.RequestedBy, &it.Values); err != nil {
				return err
			}
		}
		var prevSnap string
		_ = tx.QueryRow(ctx, `SELECT COALESCE(s.snapshot_sha256, '') FROM repositories r LEFT JOIN source_snapshots s ON s.id = r.current_snapshot_id
			WHERE r.id = $1`, repoID).Scan(&prevSnap)
		if _, err := tx.Exec(ctx, `INSERT INTO source_snapshots (id, organization_id, repository_id, object_key, archive_filename, archive_sha256,
			archive_size, snapshot_sha256, snapshot_size, uncompressed_bytes, file_count, languages, manifests, skipped, malware_scan,
			malware_engine, created_by, import_item_id)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18)`,
			snapID, it.OrgID, repoID, key, u.Filename, u.SHA256, u.Size, snapSum, snapHash.n, result.UncompressedBytes, result.Files,
			langs, manifests, result.Skipped, malware, engine, it.RequestedBy, it.ID); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `UPDATE repositories SET current_snapshot_id = $2, size_bytes = $3, file_count = $4, languages = $5,
			technologies = $6, latest_commit_sha = '', latest_commit_at = now(), last_pushed_at = now(),
			last_sync_at = now(), last_sync_ok_at = now(), sync_status = 'ok', sync_error = '', updated_at = now()
			WHERE id = $1`, repoID, snapID, result.UncompressedBytes, result.Files, langs, techs); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `INSERT INTO repository_sync_runs (id, organization_id, repository_id, trigger, status, previous_commit_sha,
			commit_sha, changed, triggered_by) VALUES ($1, $2, $3, 'upload', 'ok', $4, $5, true, $6)`,
			uuid.Must(uuid.NewV7()), it.OrgID, repoID, prevSnap, snapSum, it.RequestedBy); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `UPDATE source_uploads SET status = 'consumed' WHERE id = $1`, u.ID); err != nil {
			return err
		}
		action := "repository.import"
		if target != nil {
			action = "repository.snapshot_add"
		}
		return audit.Write(ctx, tx, audit.Entry{OrganizationID: it.OrgID, ActorID: &it.RequestedBy, Action: action,
			TargetType: "repository", TargetID: repoID.String(),
			Metadata: map[string]any{"import_job_id": it.JobID, "source": "upload", "filename": u.Filename, "archive_sha256": u.SHA256,
				"snapshot_id": snapID, "snapshot_sha256": snapSum, "files": result.Files, "skipped": result.Skipped,
				"malware_scan": malware, "metadata": it.Values}})
	})
	if err != nil {
		cleanup()
		if db.IsUniqueViolation(err) {
			return res, permanent("name_clash", "another asset already uses this asset name")
		}
		if db.IsForeignKeyViolation(err) {
			return res, attention("validation_failed", "a referenced owner, team, unit, region or tag was deleted; edit and import again")
		}
		return res, err
	}
	// The verified snapshot replaces the staged parts.
	if err := s.discardUpload(context.WithoutCancel(ctx), it.OrgID, u.ID, "consumed"); err != nil {
		s.Log.Warn("staged upload parts not removed; the hourly cleanup will retry", "upload_id", u.ID, "err", err)
	}
	return importResult{Result: resultKind, RepositoryID: &repoID, SnapshotID: &snapID}, nil
}

// topLanguages returns up to n languages by size.
func topLanguages(langs map[string]int64, n int) []string {
	names := make([]string, 0, len(langs))
	for k := range langs {
		names = append(names, k)
	}
	slices.SortFunc(names, func(a, b string) int {
		if langs[a] != langs[b] {
			if langs[a] > langs[b] {
				return -1
			}
			return 1
		}
		return strings.Compare(a, b)
	})
	if len(names) > n {
		names = names[:n]
	}
	return names
}

// SnapshotView is the API form of a source snapshot (frontend SourceSnapshot).
type SnapshotView struct {
	SnapshotSummary
	ArchiveSize   int64            `json:"archive_size"`
	SnapshotSize  int64            `json:"snapshot_size"`
	Languages     map[string]int64 `json:"languages"`
	Manifests     []string         `json:"manifests"`
	Skipped       map[string]int   `json:"skipped"`
	MalwareEngine string           `json:"malware_engine"`
	CreatedBy     *UserRef         `json:"created_by"`
}

func (s *Service) listSnapshots(w http.ResponseWriter, r *http.Request) {
	p, repo, err := s.loadRepoFor(r, authz.PermReposRead)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	rows, err := s.DB.Query(r.Context(), `
		SELECT s.id, s.created_at, s.archive_filename, s.archive_sha256, s.snapshot_sha256, s.file_count, s.uncompressed_bytes, s.malware_scan,
		       s.archive_size, s.snapshot_size, s.languages, s.manifests, s.skipped, s.malware_engine,
		       (SELECT `+userJSON+` FROM users u WHERE u.id = s.created_by)
		FROM source_snapshots s WHERE s.organization_id = $1 AND s.repository_id = $2 ORDER BY s.created_at DESC LIMIT 100`,
		p.OrganizationID, repo.ID)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	items, err := pgx.CollectRows(rows, func(row pgx.CollectableRow) (SnapshotView, error) {
		var v SnapshotView
		var by []byte
		if err := row.Scan(&v.ID, &v.CreatedAt, &v.ArchiveFilename, &v.ArchiveSHA256, &v.SnapshotSHA256, &v.FileCount, &v.UncompressedBytes,
			&v.MalwareScan, &v.ArchiveSize, &v.SnapshotSize, &v.Languages, &v.Manifests, &v.Skipped, &v.MalwareEngine, &by); err != nil {
			return v, err
		}
		return v, jsonPtr(by, &v.CreatedBy)
	})
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if items == nil {
		items = []SnapshotView{}
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"items": items})
}

// OpenSnapshot returns a decrypted snapshot stream for the scan worker API,
// with its expected SHA-256.
func (s *Service) OpenSnapshot(ctx context.Context, orgID, snapshotID uuid.UUID) (io.ReadCloser, string, int64, error) {
	if s.Sources == nil {
		return nil, "", 0, errors.New("source store not configured")
	}
	var key, sum string
	var size int64
	if err := s.DB.QueryRow(ctx, `SELECT object_key, snapshot_sha256, snapshot_size FROM source_snapshots WHERE organization_id = $1 AND id = $2`,
		orgID, snapshotID).Scan(&key, &sum, &size); err != nil {
		return nil, "", 0, err
	}
	rc, err := s.Sources.Open(ctx, key)
	return rc, sum, size, err
}
