package notify

import (
	"context"
	"encoding/json"
	"os"
	"strconv"
	"strings"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"pathos/internal/platform/db"
	"pathos/internal/secrets"
)

type systemRule struct {
	key, name, event string
	minSeverity      string
	rc               Recipients
}

// systemRules are seeded once per organization. Administrators may edit or
// disable them; they are never recreated after deletion is refused.
var systemRules = []systemRule{
	{"critical_findings", "New critical findings", "findings.new", "critical",
		Recipients{Roles: []string{"security_manager"}, Dynamic: []string{"owners"}}},
	{"scan_failed", "Scan failures", "scan.failed", "",
		Recipients{Roles: []string{"platform_admin", "security_manager"}}},
	{"sla_breached", "SLA breaches", "finding.sla_breached", "",
		Recipients{Roles: []string{"security_manager"}, Dynamic: []string{"assignee"}}},
	{"assigned", "Assigned to me", "finding.assigned", "",
		Recipients{Dynamic: []string{"assignee"}}},
	{"risk_requested", "Risk acceptance approvals", "risk.requested", "",
		Recipients{Dynamic: []string{"approvers"}}},
	{"risk_decided", "Risk acceptance decisions", "risk.decided", "",
		Recipients{Dynamic: []string{"requester"}}},
	{"schedule_missed", "Missed scan schedules", "schedule.missed", "",
		Recipients{Roles: []string{"super_admin", "platform_admin"}}},
	{"repository_sync_failed", "Repository sync failures", "repository.sync_failed", "",
		Recipients{Roles: []string{"super_admin", "platform_admin"}, Dynamic: []string{"owners"}}},
	{"import_failed", "Failed repository imports", "import.failed", "",
		Recipients{Dynamic: []string{"requester"}}},
	{"schedule_completed", "Scheduled scans completed", "schedule.completed", "",
		Recipients{Dynamic: []string{"requester"}}},
	{"schedule_failed", "Scheduled scans failed", "schedule.failed", "",
		Recipients{Dynamic: []string{"requester"}}},
	{"worker_offline", "Offline scan workers", "worker.offline", "",
		Recipients{Roles: []string{"super_admin", "platform_admin"}}},
	{"review_assigned", "Human Eye reviews assigned to me", "review.assigned", "",
		Recipients{Dynamic: []string{"assignee"}}},
	{"review_independent_requested", "Independent reviews requested", "review.independent_requested", "",
		Recipients{Dynamic: []string{"independent_reviewers"}}},
	{"review_independent_decided", "Independent review outcomes", "review.independent_decided", "",
		Recipients{Dynamic: []string{"requester"}}},
	{"review_overdue", "Overdue Human Eye reviews", "review.overdue", "",
		Recipients{Dynamic: []string{"assignee"}}},
}

// EnsureDefaults seeds built-in rules and, on first run, SMTP settings from
// the environment (PATHOS_SMTP_*; the same variables Keycloak uses). After
// that, settings are managed in the UI and the environment is ignored.
func EnsureDefaults(ctx context.Context, pool *pgxpool.Pool, store *secrets.Store, orgID uuid.UUID) error {
	return db.InTx(ctx, pool, func(tx pgx.Tx) error {
		for _, r := range systemRules {
			rec, _ := json.Marshal(r.rc.normalized())
			var sev *string
			if r.minSeverity != "" {
				sev = &r.minSeverity
			}
			if _, err := tx.Exec(ctx, `
				INSERT INTO notification_rules (id, organization_id, name, event_key, min_severity, recipients, system_key)
				VALUES ($1, $2, $3, $4, $5, $6, $7) ON CONFLICT (organization_id, system_key) DO NOTHING`,
				uuid.Must(uuid.NewV7()), orgID, r.name, r.event, sev, rec, r.key); err != nil {
				return err
			}
		}
		var exists bool
		if err := tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM smtp_settings WHERE organization_id = $1)`, orgID).Scan(&exists); err != nil || exists {
			return err
		}
		host := strings.TrimSpace(os.Getenv("PATHOS_SMTP_HOST"))
		if host == "" {
			return nil
		}
		port, err := strconv.Atoi(os.Getenv("PATHOS_SMTP_PORT"))
		if err != nil || port < 1 || port > 65535 {
			port = 587
		}
		mode := "none"
		if strings.EqualFold(os.Getenv("PATHOS_SMTP_STARTTLS"), "true") {
			mode = "starttls"
		}
		if strings.EqualFold(os.Getenv("PATHOS_SMTP_SSL"), "true") {
			mode = "tls"
		}
		from := strings.TrimSpace(os.Getenv("PATHOS_SMTP_FROM"))
		user := ""
		if strings.EqualFold(os.Getenv("PATHOS_SMTP_AUTH"), "true") {
			user = strings.TrimSpace(os.Getenv("PATHOS_SMTP_USER"))
		}
		var secretID *uuid.UUID
		if pw := os.Getenv("PATHOS_SMTP_PASSWORD"); user != "" && pw != "" && store != nil {
			id, err := store.Create(ctx, tx, orgID, secrets.KindSMTP, "smtp", []byte(pw), nil)
			if err != nil {
				return err
			}
			secretID = &id
		}
		enabled := ValidateHost(host) == nil && ValidateAddress(from) == nil && !(user != "" && mode == "none")
		_, err = tx.Exec(ctx, `INSERT INTO smtp_settings (organization_id, enabled, host, port, tls_mode, username, secret_id, from_address)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`, orgID, enabled, host, port, mode, user, secretID, from)
		return err
	})
}
