package scans

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"pathos/internal/audit"
	"pathos/internal/authz"
	"pathos/internal/platform/db"
	"pathos/internal/platform/httpx"
)

// Manifest tools on scan targets: a target's config may name tools of
// family worker images or operator plugins (TargetConfig.Tools). A tool
// that contacts the target (network: target) needs the target's
// authorization statement; an intrusive tool also needs the target's
// "intrusive testing authorized" flag. Both are checked when the scan is
// queued; workers skip intrusive tools of a target whose flag is not set.

// toolRequirement is what running a tool for a target requires.
type toolRequirement struct {
	Key       string
	Name      string
	Targets   []string
	Network   string
	Intrusive bool
}

// toolRequirements reads the catalog rows of keys, made stricter by what
// online workers advertise (the strictest declaration wins).
func toolRequirements(ctx context.Context, q db.Querier, orgID uuid.UUID, keys []string) (map[string]toolRequirement, error) {
	out := map[string]toolRequirement{}
	if len(keys) == 0 {
		return out, nil
	}
	rows, err := q.Query(ctx, `SELECT key, name, targets, network, intrusive FROM scanner_catalog WHERE key = ANY($1)`, keys)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var r toolRequirement
		if err := rows.Scan(&r.Key, &r.Name, &r.Targets, &r.Network, &r.Intrusive); err != nil {
			rows.Close()
			return nil, err
		}
		out[r.Key] = r
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}
	online, _, err := onlineTools(ctx, q, orgID)
	if err != nil {
		return nil, err
	}
	for k, r := range out {
		if o := online[k]; o != nil && o.Manifest != nil {
			if len(o.Manifest.Targets) > 0 {
				r.Targets = o.Manifest.Targets
			}
			r.Intrusive = r.Intrusive || o.Manifest.Intrusive
			if o.Manifest.Network == "target" {
				r.Network = "target"
			}
			out[k] = r
		}
	}
	return out, nil
}

// toolScansKind reports whether a tool with manifest targets scans a scan
// target of kind.
func toolScansKind(targets []string, kind string) bool {
	for _, t := range targets {
		switch {
		case kind == t && (t == "image" || t == "url" || t == "api"),
			kind == "api" && t == "url",
			kind == "artifact" && (t == "binary" || t == "mobile-app" || t == "model"),
			kind == "mobile-app" && t == "mobile-app",
			kind == "llm-endpoint" && t == "llm-endpoint":
			return true
		}
	}
	return false
}

// validateTargetTools checks the tools of a target of kind; with
// authorization set it also checks that the target's authorizations allow
// them (when a scan is queued).
func validateTargetTools(ctx context.Context, q db.Querier, orgID uuid.UUID, kind string, tools []string, authorization *targetAuthorization) error {
	if len(tools) == 0 {
		return nil
	}
	reqs, err := toolRequirements(ctx, q, orgID, tools)
	if err != nil {
		return err
	}
	for _, k := range tools {
		r, ok := reqs[k]
		if !ok {
			return httpx.BadRequest(fmt.Sprintf("tool %s is not known: a worker that provides it must have registered", k))
		}
		if !toolScansKind(r.Targets, kind) {
			return httpx.BadRequest(fmt.Sprintf("%s does not scan %s targets", r.Name, kind))
		}
		if authorization == nil {
			continue
		}
		if r.Network == "target" && authorization.authorizedAt == nil {
			return fmt.Errorf("%w: %s sends requests to the target, and testing it has not been authorized", ErrScanPrerequisite, r.Name)
		}
		if r.Intrusive && authorization.intrusiveAt == nil {
			return fmt.Errorf("%w: %s is intrusive, and intrusive testing of this target has not been authorized", ErrScanPrerequisite, r.Name)
		}
	}
	return nil
}

type targetAuthorization struct {
	authorizedAt, intrusiveAt *time.Time
}

// checkTargetTools runs validateTargetTools for a scan of a stored target.
func checkTargetTools(ctx context.Context, q db.Querier, orgID, targetID uuid.UUID, kind string) error {
	var cfgRaw []byte
	var auth targetAuthorization
	if err := q.QueryRow(ctx, `SELECT config, authorized_at, intrusive_authorized_at FROM scan_targets WHERE organization_id = $1 AND id = $2`,
		orgID, targetID).Scan(&cfgRaw, &auth.authorizedAt, &auth.intrusiveAt); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return errNotFound
		}
		return err
	}
	var cfg TargetConfig
	_ = json.Unmarshal(cfgRaw, &cfg)
	err := validateTargetTools(ctx, q, orgID, kind, cfg.Tools, &auth)
	var he *httpx.Error
	if errors.As(err, &he) {
		return fmt.Errorf("%w: %s", ErrScanPrerequisite, he.Message)
	}
	return err
}

// setIntrusive records or withdraws the intrusive testing authorization of
// a target (audited separately from other changes).
func (s *Service) setIntrusive(ctx context.Context, tx pgx.Tx, p *authz.Principal, id uuid.UUID, on bool, note, reference string) error {
	var err error
	if on {
		_, err = tx.Exec(ctx, `UPDATE scan_targets SET intrusive_authorized_by = $2, intrusive_authorized_at = now(),
			intrusive_authorization_note = $3, updated_at = now() WHERE id = $1`, id, p.UserID, note)
	} else {
		_, err = tx.Exec(ctx, `UPDATE scan_targets SET intrusive_authorized_by = NULL, intrusive_authorized_at = NULL,
			intrusive_authorization_note = '', updated_at = now() WHERE id = $1`, id)
	}
	if err != nil {
		if db.IsCheckViolation(err) {
			return httpx.BadRequest("intrusive testing can be authorized only for an authorized web application, API or LLM endpoint target")
		}
		return err
	}
	action := "scan_target.intrusive_revoke"
	if on {
		action = "scan_target.intrusive_authorize"
	}
	meta := map[string]any{"reference": reference}
	if on {
		meta["note"] = note
	}
	return audit.Write(ctx, tx, audit.Entry{OrganizationID: p.OrganizationID, ActorID: &p.UserID, ActorEmail: p.Email,
		Action: action, TargetType: "scan_target", TargetID: id.String(), Metadata: meta})
}
