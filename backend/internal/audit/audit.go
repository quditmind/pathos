// Package audit writes the append-only audit log. Every state-changing
// operation records an entry in the same transaction as the change.
package audit

import (
	"context"
	"encoding/json"
	"net/netip"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"pathos/internal/platform/db"
)

// Outcome values.
const (
	Success = "success"
	Denied  = "denied"
	Failure = "failure"
)

// Entry is one audit record.
type Entry struct {
	OrganizationID uuid.UUID
	ActorID        *uuid.UUID
	ActorEmail     string
	Action         string // e.g. "user.deactivate"
	TargetType     string
	TargetID       string
	Outcome        string
	IP             string
	UserAgent      string
	RequestID      string
	Metadata       map[string]any
}

// Record is a stored entry as returned by List.
type Record struct {
	ID         uuid.UUID      `json:"id"`
	ActorID    *uuid.UUID     `json:"actor_id"`
	ActorEmail string         `json:"actor_email"`
	Action     string         `json:"action"`
	TargetType string         `json:"target_type"`
	TargetID   string         `json:"target_id"`
	Outcome    string         `json:"outcome"`
	IP         *string        `json:"ip"`
	UserAgent  string         `json:"user_agent"`
	RequestID  string         `json:"request_id"`
	Metadata   map[string]any `json:"metadata"`
	CreatedAt  time.Time      `json:"created_at"`
}

// Meta carries request attributes for audit entries.
type Meta struct {
	IP        string
	UserAgent string
	RequestID string
}

type metaKey struct{}

// WithMeta stores request metadata in ctx.
func WithMeta(ctx context.Context, m Meta) context.Context {
	return context.WithValue(ctx, metaKey{}, m)
}

// MetaFrom returns request metadata from ctx.
func MetaFrom(ctx context.Context) Meta { m, _ := ctx.Value(metaKey{}).(Meta); return m }

// Write inserts e using q (normally the transaction of the change itself).
func Write(ctx context.Context, q db.Querier, e Entry) error {
	m := MetaFrom(ctx)
	if e.IP == "" {
		e.IP = m.IP
	}
	if e.UserAgent == "" {
		e.UserAgent = m.UserAgent
	}
	if e.RequestID == "" {
		e.RequestID = m.RequestID
	}
	if e.Outcome == "" {
		e.Outcome = Success
	}
	if e.Metadata == nil {
		e.Metadata = map[string]any{}
	}
	md, err := json.Marshal(e.Metadata)
	if err != nil {
		return err
	}
	var ip *string
	if a, err := netip.ParseAddr(e.IP); err == nil {
		s := a.String()
		ip = &s
	}
	if len(e.UserAgent) > 512 {
		e.UserAgent = e.UserAgent[:512]
	}
	_, err = q.Exec(ctx, `
		INSERT INTO audit_logs (id, organization_id, actor_id, actor_email, action, target_type, target_id,
		                        outcome, ip, user_agent, request_id, metadata)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9::inet, $10, $11, $12)`,
		uuid.Must(uuid.NewV7()), e.OrganizationID, e.ActorID, e.ActorEmail, e.Action, e.TargetType, e.TargetID,
		e.Outcome, ip, e.UserAgent, e.RequestID, md)
	return err
}

// ListParams filters the audit log.
type ListParams struct {
	OrganizationID uuid.UUID
	Action         string
	ActorID        *uuid.UUID
	TargetType     string
	TargetID       string
	Outcome        string
	Before         *time.Time // cursor: created_at of the last row seen
	BeforeID       *uuid.UUID
	Limit          int
}

// List returns entries newest first.
func List(ctx context.Context, q db.Querier, p ListParams) ([]Record, error) {
	if p.Limit <= 0 || p.Limit > 200 {
		p.Limit = 50
	}
	rows, err := q.Query(ctx, `
		SELECT id, actor_id, actor_email, action, target_type, target_id, outcome,
		       host(ip), user_agent, request_id, metadata, created_at
		FROM audit_logs
		WHERE organization_id = $1
		  AND ($2 = '' OR action = $2 OR action LIKE $2 || '.%')
		  AND ($3::uuid IS NULL OR actor_id = $3)
		  AND ($4 = '' OR target_type = $4)
		  AND ($5 = '' OR target_id = $5)
		  AND ($6::timestamptz IS NULL OR (created_at, id) < ($6, $7::uuid))
		  AND ($9 = '' OR outcome = $9)
		ORDER BY created_at DESC, id DESC
		LIMIT $8`,
		p.OrganizationID, p.Action, p.ActorID, p.TargetType, p.TargetID, p.Before, p.BeforeID, p.Limit, p.Outcome)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, func(r pgx.CollectableRow) (Record, error) {
		var rec Record
		err := r.Scan(&rec.ID, &rec.ActorID, &rec.ActorEmail, &rec.Action, &rec.TargetType, &rec.TargetID,
			&rec.Outcome, &rec.IP, &rec.UserAgent, &rec.RequestID, &rec.Metadata, &rec.CreatedAt)
		return rec, err
	})
}
