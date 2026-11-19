package notify

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"pathos/internal/platform/db"
	"pathos/internal/platform/logging"
	"pathos/internal/secrets"
)

// Recipients is the stored recipient specification of a rule.
type Recipients struct {
	Roles   []string    `json:"roles"`
	Users   []uuid.UUID `json:"users"`
	Emails  []string    `json:"emails"`
	Dynamic []string    `json:"dynamic"`
}

// normalized returns r with empty lists instead of nil (stable JSON).
func (r Recipients) normalized() Recipients {
	if r.Roles == nil {
		r.Roles = []string{}
	}
	if r.Users == nil {
		r.Users = []uuid.UUID{}
	}
	if r.Emails == nil {
		r.Emails = []string{}
	}
	if r.Dynamic == nil {
		r.Dynamic = []string{}
	}
	return r
}

type rule struct {
	ID          uuid.UUID
	MinSeverity *string
	ScopeType   string
	ScopeID     *uuid.UUID
	Recipients  Recipients
	Email       bool
	InApp       bool
}

type recipient struct {
	UserID *uuid.UUID
	Email  string
}

// Dispatcher turns events into deliveries and sends email.
type Dispatcher struct {
	Pool    *pgxpool.Pool
	Secrets *secrets.Store
	Sender  Sender
	BaseURL string
	Log     *slog.Logger
}

// Run processes the outbox until ctx ends.
func (d *Dispatcher) Run(ctx context.Context) {
	tick := time.NewTicker(10 * time.Second)
	defer tick.Stop()
	sla := time.NewTicker(5 * time.Minute)
	defer sla.Stop()
	d.step(ctx, true)
	for {
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
			d.step(ctx, false)
		case <-sla.C:
			d.step(ctx, true)
		}
	}
}

func (d *Dispatcher) step(ctx context.Context, detect bool) {
	if detect {
		if n, err := DetectSLABreaches(ctx, d.Pool); err != nil {
			d.Log.Error("SLA breach detection failed", "err", err, "error_code", "PTH-MON-1002")
		} else if n > 0 {
			d.Log.Info("SLA breaches detected", "events", n)
		}
	}
	if n, err := d.DispatchEvents(ctx); err != nil {
		d.Log.Error("notification dispatch failed", "err", err, "error_code", "PTH-MON-1003")
	} else if n > 0 {
		d.Log.Debug("notification events dispatched", "count", n)
	}
	if sent, failed, err := d.SendWebhooks(ctx); err != nil {
		d.Log.Error("webhook delivery failed", "err", err, "error_code", "PTH-SYNC-1005")
	} else if sent+failed > 0 {
		d.Log.Info("webhook delivery", "sent", sent, "failed", failed)
	}
	if sent, failed, err := d.SendPending(ctx); err != nil {
		d.Log.Error("email delivery failed", "err", err, "error_code", "PTH-CONN-1325")
	} else if sent+failed > 0 {
		d.Log.Info("email delivery", "sent", sent, "failed", failed)
	}
}

// DetectSLABreaches emits one finding.sla_breached event per repository for
// findings that crossed their deadline since the last notice.
func DetectSLABreaches(ctx context.Context, pool *pgxpool.Pool) (int, error) {
	tag, err := pool.Exec(ctx, `
		WITH b AS (
		  UPDATE findings SET sla_breach_notified_at = now()
		  WHERE status IN ('open', 'in_progress', 'needs_review') AND sla_due_at < now()
		    AND (sla_breach_notified_at IS NULL OR sla_breach_notified_at < sla_due_at)
		  RETURNING id, organization_id, repository_id, severity)
		INSERT INTO notification_events (organization_id, event_key, repository_id, severity, payload)
		SELECT organization_id, 'finding.sla_breached', repository_id,
		       (array_agg(severity ORDER BY CASE severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2 WHEN 'low' THEN 3 ELSE 4 END))[1],
		       jsonb_build_object('finding_ids', jsonb_agg(id), 'count', count(*))
		FROM b GROUP BY organization_id, repository_id`)
	if err != nil {
		return 0, err
	}
	return int(tag.RowsAffected()), nil
}

// DispatchEvents processes up to 100 pending events.
func (d *Dispatcher) DispatchEvents(ctx context.Context) (int, error) {
	n := 0
	for range 100 {
		done, err := d.dispatchOne(ctx)
		if err != nil {
			return n, err
		}
		if !done {
			break
		}
		n++
	}
	return n, nil
}

func (d *Dispatcher) dispatchOne(ctx context.Context) (bool, error) {
	found := false
	err := db.InTx(ctx, d.Pool, func(tx pgx.Tx) error {
		var ev eventRow
		var payload []byte
		err := tx.QueryRow(ctx, `
			SELECT id, organization_id, event_key, repository_id, severity, subject_id, payload, created_at
			FROM notification_events WHERE processed_at IS NULL
			ORDER BY created_at LIMIT 1 FOR UPDATE SKIP LOCKED`).
			Scan(&ev.ID, &ev.OrgID, &ev.Key, &ev.Repository, &ev.Severity, &ev.SubjectID, &payload, &ev.CreatedAt)
		if errors.Is(err, pgx.ErrNoRows) {
			return nil
		}
		if err != nil {
			return err
		}
		found = true
		_ = json.Unmarshal(payload, &ev.Payload)
		if err := enqueueWebhooks(ctx, tx, ev); err != nil {
			return err
		}
		n, derr := d.deliver(ctx, tx, ev)
		msg := ""
		if derr != nil {
			// A bad event must not block the queue: record and move on.
			msg = derr.Error()
			d.Log.Warn("notification event not delivered", "event", ev.Key, "event_id", ev.ID, "err", derr)
		}
		_, err = tx.Exec(ctx, `UPDATE notification_events SET processed_at = now(), error = $2,
			payload = payload || jsonb_build_object('deliveries', $3::int) WHERE id = $1`, ev.ID, msg, n)
		return err
	})
	return found, err
}

// matchingRules returns enabled rules for the event whose severity and
// scope filters match.
func matchingRules(ctx context.Context, q db.Querier, ev eventRow) ([]rule, error) {
	rows, err := q.Query(ctx, `
		SELECT r.id, r.min_severity, r.scope_type, r.scope_id, r.recipients, r.email, r.in_app
		FROM notification_rules r
		WHERE r.organization_id = $1 AND r.event_key = $2 AND r.enabled
		  AND (r.scope_type = 'organization' OR ($3::uuid IS NOT NULL AND EXISTS (
		    SELECT 1 FROM repositories repo WHERE repo.id = $3 AND (
		      (r.scope_type = 'repository' AND r.scope_id = repo.id)
		      OR (r.scope_type = 'region' AND r.scope_id = (SELECT region_id FROM countries WHERE id = repo.country_id))
		      OR (r.scope_type = 'business_unit' AND r.scope_id IN (
		        WITH RECURSIVE up AS (SELECT id, parent_id FROM business_units WHERE id = repo.business_unit_id
		          UNION ALL SELECT b.id, b.parent_id FROM business_units b JOIN up ON b.id = up.parent_id)
		        SELECT id FROM up))))))
		ORDER BY r.created_at`, ev.OrgID, ev.Key, ev.Repository)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []rule
	for rows.Next() {
		var r rule
		var rec []byte
		if err := rows.Scan(&r.ID, &r.MinSeverity, &r.ScopeType, &r.ScopeID, &rec, &r.Email, &r.InApp); err != nil {
			return nil, err
		}
		_ = json.Unmarshal(rec, &r.Recipients)
		if r.MinSeverity != nil && ev.Severity != nil && severityRank[*ev.Severity] > severityRank[*r.MinSeverity] {
			continue
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// usersCoveringRepo returns active users holding one of roles (or, with
// perm, any role carrying perm) at a scope that covers repo. Without a
// repository only organization-wide assignments count.
func usersCovering(ctx context.Context, q db.Querier, orgID uuid.UUID, repo *uuid.UUID, roles []string, perm string) ([]recipient, error) {
	rows, err := q.Query(ctx, `
		WITH target AS (SELECT r.id, r.business_unit_id, c.region_id FROM repositories r
		                LEFT JOIN countries c ON c.id = r.country_id WHERE r.id = $2),
		     bus AS (WITH RECURSIVE up AS (SELECT id, parent_id FROM business_units WHERE id = (SELECT business_unit_id FROM target)
		              UNION ALL SELECT b.id, b.parent_id FROM business_units b JOIN up ON b.id = up.parent_id) SELECT id FROM up)
		SELECT DISTINCT u.id, u.email
		FROM role_assignments ra
		JOIN roles ro ON ro.id = ra.role_id
		JOIN users u ON u.id = ra.user_id AND u.status = 'active'
		WHERE ra.organization_id = $1
		  AND (ro.key = ANY($3) OR ($4 <> '' AND EXISTS (SELECT 1 FROM role_permissions rp WHERE rp.role_id = ro.id AND rp.permission_key = $4)))
		  AND (ra.scope_type = 'organization'
		       OR (ra.scope_type = 'repository' AND ra.scope_id = $2)
		       OR (ra.scope_type = 'business_unit' AND ra.scope_id IN (SELECT id FROM bus))
		       OR (ra.scope_type = 'region' AND ra.scope_id = (SELECT region_id FROM target)))`,
		orgID, repo, roles, perm)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, func(row pgx.CollectableRow) (recipient, error) {
		var id uuid.UUID
		var r recipient
		err := row.Scan(&id, &r.Email)
		r.UserID = &id
		return r, err
	})
}

func activeUsers(ctx context.Context, q db.Querier, orgID uuid.UUID, ids []uuid.UUID) ([]recipient, error) {
	if len(ids) == 0 {
		return nil, nil
	}
	rows, err := q.Query(ctx, `SELECT id, email FROM users WHERE organization_id = $1 AND id = ANY($2) AND status = 'active'`, orgID, ids)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, func(row pgx.CollectableRow) (recipient, error) {
		var id uuid.UUID
		var r recipient
		err := row.Scan(&id, &r.Email)
		r.UserID = &id
		return r, err
	})
}

// resolve expands a rule's recipients for one event.
func resolve(ctx context.Context, q db.Querier, ev eventRow, data *Data, rc Recipients) ([]recipient, error) {
	var out []recipient
	add := func(rs []recipient, err error) error {
		out = append(out, rs...)
		return err
	}
	if len(rc.Roles) > 0 {
		if err := add(usersCovering(ctx, q, ev.OrgID, ev.Repository, rc.Roles, "")); err != nil {
			return nil, err
		}
	}
	if err := add(activeUsers(ctx, q, ev.OrgID, rc.Users)); err != nil {
		return nil, err
	}
	for _, e := range rc.Emails {
		out = append(out, recipient{Email: e})
	}
	for _, dyn := range rc.Dynamic {
		var err error
		switch dyn {
		case "assignee":
			err = add(activeUsers(ctx, q, ev.OrgID, data.assignees))
		case "requester":
			if data.requester != nil {
				err = add(activeUsers(ctx, q, ev.OrgID, []uuid.UUID{*data.requester}))
			}
		case "approvers":
			var rs []recipient
			rs, err = usersCovering(ctx, q, ev.OrgID, ev.Repository, nil, "findings.accept_risk")
			for _, r := range rs {
				if data.requester == nil || *r.UserID != *data.requester {
					out = append(out, r)
				}
			}
		case "independent_reviewers":
			if data.independent != nil {
				err = add(activeUsers(ctx, q, ev.OrgID, []uuid.UUID{*data.independent}))
				break
			}
			var rs []recipient
			rs, err = usersCovering(ctx, q, ev.OrgID, ev.Repository, nil, "reviews.approve")
			for _, r := range rs {
				if data.requester == nil || *r.UserID != *data.requester {
					out = append(out, r)
				}
			}
		case "report_recipients":
			err = add(activeUsers(ctx, q, ev.OrgID, data.reportRecipients))
		case "owners":
			if ev.Repository != nil {
				var ids []uuid.UUID
				// Application owners plus the repository's asset owners.
				rows, qerr := q.Query(ctx, `SELECT unnest(ARRAY[a.owner_user_id, a.security_owner_user_id]) FROM repositories r
					JOIN applications a ON a.id = r.application_id WHERE r.id = $1
					UNION SELECT unnest(ARRAY[r.business_owner_id, r.technical_owner_id, r.application_owner_id]) FROM repositories r WHERE r.id = $1`, *ev.Repository)
				if qerr != nil {
					return nil, qerr
				}
				for rows.Next() {
					var id *uuid.UUID
					if rows.Scan(&id) == nil && id != nil {
						ids = append(ids, *id)
					}
				}
				rows.Close()
				err = add(activeUsers(ctx, q, ev.OrgID, ids))
			}
		}
		if err != nil {
			return nil, err
		}
	}
	return out, nil
}

// template returns the organization's override or the default.
func templateFor(ctx context.Context, q db.Querier, orgID uuid.UUID, key string) (string, string) {
	def, _ := LookupEvent(key)
	subject, body := def.Subject, def.Body
	_ = q.QueryRow(ctx, `SELECT subject, body FROM notification_templates WHERE organization_id = $1 AND event_key = $2`, orgID, key).
		Scan(&subject, &body)
	return subject, body
}

func (d *Dispatcher) deliver(ctx context.Context, tx pgx.Tx, ev eventRow) (int, error) {
	rules, err := matchingRules(ctx, tx, ev)
	if err != nil || len(rules) == 0 {
		return 0, err
	}
	data, err := load(ctx, tx, ev, d.BaseURL)
	if err != nil {
		return 0, err
	}
	subjectT, bodyT := templateFor(ctx, tx, ev.OrgID, ev.Key)
	subject, body, err := Render(subjectT, bodyT, data)
	if err != nil {
		// A broken custom template falls back to the default rather than
		// losing the notification.
		def, _ := LookupEvent(ev.Key)
		if subject, body, err = Render(def.Subject, def.Body, data); err != nil {
			return 0, err
		}
		body += "\n\n(The organization's custom template for this event failed to render; the default was used.)"
	}
	link := strings.TrimPrefix(data.Link, d.BaseURL)
	n := 0
	for _, r := range rules {
		rs, err := resolve(ctx, tx, ev, data, r.Recipients)
		if err != nil {
			return n, err
		}
		for _, rc := range rs {
			if r.InApp && rc.UserID != nil {
				tag, err := tx.Exec(ctx, `
					INSERT INTO notifications (organization_id, event_id, rule_id, event_key, channel, user_id, email, subject, body, link, status, sent_at)
					VALUES ($1, $2, $3, $4, 'in_app', $5, '', $6, $7, $8, 'sent', now()) ON CONFLICT DO NOTHING`,
					ev.OrgID, ev.ID, r.ID, ev.Key, rc.UserID, subject, body, link)
				if err != nil {
					return n, err
				}
				n += int(tag.RowsAffected())
			}
			if r.Email && rc.Email != "" {
				tag, err := tx.Exec(ctx, `
					INSERT INTO notifications (organization_id, event_id, rule_id, event_key, channel, user_id, email, subject, body, link)
					VALUES ($1, $2, $3, $4, 'email', $5, lower($6), $7, $8, $9) ON CONFLICT DO NOTHING`,
					ev.OrgID, ev.ID, r.ID, ev.Key, rc.UserID, rc.Email, subject, body, link)
				if err != nil {
					return n, err
				}
				n += int(tag.RowsAffected())
			}
		}
	}
	return n, nil
}

// LoadSMTP returns the organization's SMTP settings, or nil when disabled.
func LoadSMTP(ctx context.Context, q db.Querier, store *secrets.Store, orgID uuid.UUID) (*SMTPConfig, error) {
	var cfg SMTPConfig
	var enabled bool
	var secretID *uuid.UUID
	err := q.QueryRow(ctx, `SELECT enabled, host, port, tls_mode, username, secret_id, from_address, from_name
		FROM smtp_settings WHERE organization_id = $1`, orgID).
		Scan(&enabled, &cfg.Host, &cfg.Port, &cfg.TLSMode, &cfg.Username, &secretID, &cfg.FromAddress, &cfg.FromName)
	if errors.Is(err, pgx.ErrNoRows) || (err == nil && !enabled) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if secretID != nil {
		pw, err := store.Reveal(ctx, q, orgID, *secretID, secrets.KindSMTP)
		if err != nil {
			return nil, fmt.Errorf("reveal SMTP password: %w", err)
		}
		cfg.Password = string(pw)
	}
	return &cfg, nil
}

// backoff after the nth failed attempt.
var backoff = []time.Duration{time.Minute, 5 * time.Minute, 30 * time.Minute, 2 * time.Hour}

// MaxAttempts before an email is marked failed.
const MaxAttempts = 5

type pending struct {
	ID       uuid.UUID
	OrgID    uuid.UUID
	Email    string
	Subject  string
	Body     string
	Event    string
	Attempts int
}

// SendPending claims due emails (a five-minute claim prevents double
// delivery across replicas without holding a transaction during I/O) and
// sends them.
func (d *Dispatcher) SendPending(ctx context.Context) (sent, failed int, err error) {
	rows, err := d.Pool.Query(ctx, `
		UPDATE notifications SET next_attempt_at = now() + interval '5 minutes', attempts = attempts + 1
		WHERE id IN (SELECT id FROM notifications WHERE status = 'pending' AND channel = 'email' AND next_attempt_at <= now()
		             ORDER BY next_attempt_at LIMIT 25 FOR UPDATE SKIP LOCKED)
		RETURNING id, organization_id, email, subject, body, event_key, attempts`)
	if err != nil {
		return 0, 0, err
	}
	batch, err := pgx.CollectRows(rows, pgx.RowToStructByPos[pending])
	if err != nil || len(batch) == 0 {
		return 0, 0, err
	}
	cfgs := map[uuid.UUID]*SMTPConfig{}
	for _, p := range batch {
		cfg, ok := cfgs[p.OrgID]
		if !ok {
			if cfg, err = LoadSMTP(ctx, d.Pool, d.Secrets, p.OrgID); err != nil {
				return sent, failed, err
			}
			cfgs[p.OrgID] = cfg
		}
		if cfg == nil {
			_, err = d.Pool.Exec(ctx, `UPDATE notifications SET status = 'suppressed', last_error = 'email delivery is not configured' WHERE id = $1`, p.ID)
			if err != nil {
				return sent, failed, err
			}
			continue
		}
		serr := d.Sender.Send(ctx, *cfg, Message{To: p.Email, Subject: p.Subject, Body: p.Body, Event: p.Event})
		if serr == nil {
			sent++
			_, err = d.Pool.Exec(ctx, `UPDATE notifications SET status = 'sent', sent_at = now(), last_error = '' WHERE id = $1`, p.ID)
		} else {
			failed++
			msg := redactErr(serr, cfg.Password)
			if p.Attempts >= MaxAttempts {
				d.Log.Warn("notification e-mail failed after all attempts", "notification_id", p.ID, "err", msg, "error_code", "PTH-CONN-1325")
				_, err = d.Pool.Exec(ctx, `UPDATE notifications SET status = 'failed', last_error = $2 WHERE id = $1`, p.ID, msg)
			} else {
				wait := backoff[min(p.Attempts-1, len(backoff)-1)]
				_, err = d.Pool.Exec(ctx, `UPDATE notifications SET last_error = $2, next_attempt_at = now() + $3::interval WHERE id = $1`,
					p.ID, msg, wait.String())
			}
		}
		if err != nil {
			return sent, failed, err
		}
		if ctx.Err() != nil {
			break
		}
	}
	return sent, failed, nil
}

// redactErr keeps delivery errors safe to show administrators.
func redactErr(err error, password string) string {
	s := err.Error()
	if password != "" {
		s = strings.ReplaceAll(s, password, "[REDACTED]")
	}
	s = logging.RedactString(s)
	if len(s) > 500 {
		s = s[:500]
	}
	return s
}
