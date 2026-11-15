package identity

import (
	"context"
	"log/slog"
	"net/http"
	"net/url"
	"slices"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// MFAStatus describes a user's second factor in the identity provider.
type MFAStatus struct {
	// Configured: the user has an authenticator (TOTP) and is asked for it at
	// every sign-in.
	Configured bool `json:"configured"`
	// Pending: enrolment is required at the next sign-in.
	Pending bool `json:"pending"`
}

// MFAManager is implemented by providers that can report and require MFA.
type MFAManager interface {
	MFAStatus(ctx context.Context, subject string) (MFAStatus, error)
	// RequireMFA makes the user enrol an authenticator at the next sign-in
	// unless one is configured or enrolment is already pending. It reports
	// whether anything changed (idempotent).
	RequireMFA(ctx context.Context, subject string) (bool, error)
}

const configureTOTP = "CONFIGURE_TOTP"

type kcUser struct {
	RequiredActions []string `json:"requiredActions"`
}

type kcCredential struct {
	Type string `json:"type"`
}

func (k *KeycloakProvisioner) userState(ctx context.Context, subject string) (kcUser, MFAStatus, error) {
	var u kcUser
	var st MFAStatus
	if _, err := k.do(ctx, http.MethodGet, k.admin("/users/"+url.PathEscape(subject)), nil, &u); err != nil {
		return u, st, err
	}
	var creds []kcCredential
	if _, err := k.do(ctx, http.MethodGet, k.admin("/users/"+url.PathEscape(subject)+"/credentials"), nil, &creds); err != nil {
		return u, st, err
	}
	st.Configured = slices.ContainsFunc(creds, func(c kcCredential) bool { return c.Type == "otp" })
	st.Pending = slices.Contains(u.RequiredActions, configureTOTP)
	return u, st, nil
}

// MFAStatus implements MFAManager.
func (k *KeycloakProvisioner) MFAStatus(ctx context.Context, subject string) (MFAStatus, error) {
	_, st, err := k.userState(ctx, subject)
	return st, err
}

// RequireMFA implements MFAManager. Existing required actions are kept.
func (k *KeycloakProvisioner) RequireMFA(ctx context.Context, subject string) (bool, error) {
	u, st, err := k.userState(ctx, subject)
	if err != nil || st.Configured || st.Pending {
		return false, err
	}
	actions := append(slices.Clone(u.RequiredActions), configureTOTP)
	_, err = k.do(ctx, http.MethodPut, k.admin("/users/"+url.PathEscape(subject)), map[string]any{"requiredActions": actions}, nil)
	return err == nil, err
}

// EnforceMFA requires MFA for every active or invited user linked to the
// identity provider. Safe to run repeatedly and on several replicas. It
// returns how many users were newly required to enrol.
func EnforceMFA(ctx context.Context, pool *pgxpool.Pool, m MFAManager, log *slog.Logger) (int, error) {
	rows, err := pool.Query(ctx, `SELECT id, keycloak_subject FROM users
		WHERE status IN ('active', 'invited') AND keycloak_subject IS NOT NULL`)
	if err != nil {
		return 0, err
	}
	type u struct {
		id  uuid.UUID
		sub string
	}
	users, err := pgx.CollectRows(rows, func(r pgx.CollectableRow) (u, error) {
		var x u
		return x, r.Scan(&x.id, &x.sub)
	})
	if err != nil {
		return 0, err
	}
	n := 0
	for _, x := range users {
		changed, err := m.RequireMFA(ctx, x.sub)
		if err != nil {
			// One unreachable account must not stop enforcement for the rest.
			log.Warn("MFA enforcement failed for user", "user_id", x.id, "err", err)
			continue
		}
		if changed {
			n++
		}
	}
	return n, nil
}
