package repos

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"net/http"

	"github.com/google/uuid"

	"pathos/internal/audit"
	"pathos/internal/platform/httpx"
	"pathos/internal/scm"
	"pathos/internal/secrets"
)

const maxWebhookBody = 5 << 20

// webhookConn loads a connection by ID without an organization context
// (webhooks are unauthenticated until the signature is verified).
func (s *Service) webhookConn(ctx context.Context, r *http.Request, providers ...string) (Connection, []byte, error) {
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		return Connection{}, nil, httpx.ErrNotFound
	}
	c, err := s.scanConn(s.DB.QueryRow(ctx, `SELECT `+connCols+` FROM scm_connections c WHERE c.id = $1 AND c.archived_at IS NULL`, id))
	if err != nil {
		return c, nil, httpx.ErrNotFound
	}
	ok := false
	for _, p := range providers {
		ok = ok || c.Provider == p
	}
	if !ok {
		return c, nil, httpx.ErrNotFound
	}
	secret, err := s.Secrets.Reveal(ctx, s.DB, c.orgID, c.webhookSecretID, secrets.KindWebhook)
	return c, secret, err
}

func (s *Service) githubWebhook(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	c, secret, err := s.webhookConn(ctx, r, scm.GitHub, scm.GitHubEnterprise)
	if err != nil {
		httpx.WriteError(w, r, s.Log, err)
		return
	}
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxWebhookBody))
	if err != nil {
		httpx.WriteError(w, r, s.Log, httpx.E(http.StatusRequestEntityTooLarge, "too_large", "payload too large"))
		return
	}
	if err := scm.VerifyGitHubSignature(secret, body, r.Header.Get("X-Hub-Signature-256")); err != nil {
		s.rejectWebhook(ctx, w, r, c)
		return
	}
	ev, err := scm.ParseGitHubEvent(r.Header.Get("X-GitHub-Event"), body)
	if err != nil {
		httpx.WriteError(w, r, s.Log, httpx.BadRequest(err.Error()))
		return
	}
	s.recordDelivery(ctx, w, r, c, r.Header.Get("X-GitHub-Delivery"), ev, body)
}

func (s *Service) azureWebhook(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	c, secret, err := s.webhookConn(ctx, r, scm.AzureDevOps, scm.AzureDevOpsServer)
	if err != nil {
		httpx.WriteError(w, r, s.Log, err)
		return
	}
	if err := scm.VerifyAzureBasicAuth(secret, r.Header.Get("Authorization")); err != nil {
		s.rejectWebhook(ctx, w, r, c)
		return
	}
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxWebhookBody))
	if err != nil {
		httpx.WriteError(w, r, s.Log, httpx.E(http.StatusRequestEntityTooLarge, "too_large", "payload too large"))
		return
	}
	ev, deliveryID, err := scm.ParseAzureEvent(body)
	if err != nil {
		httpx.WriteError(w, r, s.Log, httpx.BadRequest(err.Error()))
		return
	}
	s.recordDelivery(ctx, w, r, c, deliveryID, ev, body)
}

func (s *Service) rejectWebhook(ctx context.Context, w http.ResponseWriter, r *http.Request, c Connection) {
	_ = audit.Write(ctx, s.DB, audit.Entry{OrganizationID: c.orgID, Action: "webhook.rejected", Outcome: audit.Denied,
		TargetType: "scm_connection", TargetID: c.ID.String(), Metadata: map[string]any{"reason": "invalid signature"}})
	httpx.WriteError(w, r, s.Log, httpx.E(http.StatusUnauthorized, "invalid_signature", "webhook signature verification failed"))
}

// recordDelivery stores a verified delivery once (replays are ignored).
func (s *Service) recordDelivery(ctx context.Context, w http.ResponseWriter, r *http.Request, c Connection, deliveryID string, ev scm.WebhookEvent, body []byte) {
	if deliveryID == "" || len(deliveryID) > 200 {
		sum := sha256.Sum256(body)
		deliveryID = "sha256:" + hex.EncodeToString(sum[:])
	}
	var repoID *uuid.UUID
	status := "received"
	if ev.ExternalID != "" && ev.Kind != "ping" {
		var id uuid.UUID
		err := s.DB.QueryRow(ctx, `SELECT id FROM repositories WHERE scm_connection_id = $1 AND external_id = $2 AND archived_at IS NULL`,
			c.ID, ev.ExternalID).Scan(&id)
		if err == nil {
			repoID = &id
		} else {
			status = "unknown_repository"
		}
	}
	sum := sha256.Sum256(body)
	tag, err := s.DB.Exec(ctx, `
		INSERT INTO webhook_deliveries (id, organization_id, scm_connection_id, delivery_id, event, repository_id, ref,
		  commit_sha, pull_request, payload_sha256, status)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, NULLIF($9, 0), $10, $11)
		ON CONFLICT (scm_connection_id, delivery_id) DO NOTHING`,
		uuid.Must(uuid.NewV7()), c.orgID, c.ID, deliveryID, ev.Kind, repoID, truncate(ev.Ref, 255), truncate(ev.CommitSHA, 64),
		ev.PullRequest, hex.EncodeToString(sum[:]), status)
	if err != nil {
		httpx.WriteError(w, r, s.Log, err)
		return
	}
	if tag.RowsAffected() == 0 {
		httpx.WriteJSON(w, http.StatusOK, map[string]string{"status": "duplicate"})
		return
	}
	if repoID != nil && (ev.Kind == "push" || ev.Kind == "pull_request" || ev.Kind == "merge") && s.OnEvent != nil {
		s.OnEvent(ctx, c.orgID, *repoID, ev)
	}
	httpx.WriteJSON(w, http.StatusAccepted, map[string]string{"status": status, "event": ev.Kind})
}

