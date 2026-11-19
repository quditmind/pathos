// Package secrets stores credentials (SCM tokens, AI keys, MCP and SMTP
// credentials) envelope-encrypted in PostgreSQL. Plaintext never leaves
// this package except to the caller that needs to use the credential.
package secrets

import (
	"bytes"
	"context"
	"errors"
	"regexp"
	"strings"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"pathos/internal/platform/crypto"
	"pathos/internal/platform/db"
)

// Kinds are stored separately so one class of credential cannot be
// substituted for another (the kind is bound into the AAD).
const (
	KindSCM     = "scm"
	KindAI      = "ai"
	KindMCP     = "mcp"
	KindSMTP    = "smtp"
	KindWebhook = "webhook"
	KindWorker  = "worker"
	// KindIntegration: outbound webhook URLs and signing secrets, ticketing
	// credentials.
	KindIntegration = "integration"
)

var ErrNotFound = errors.New("secret not found")

// AAD binds a ciphertext to its secret ID and kind.
func AAD(kind string, id uuid.UUID) []byte {
	return append([]byte("pathos:secret:"+kind+":"), id[:]...)
}

type Store struct {
	Keys *crypto.Keyring
	// Refs resolves secret references ("vault:<mount>/<path>#<key>") at
	// use time (internal/vault). nil: references cannot be resolved.
	Refs RefResolver
}

// RefResolver resolves an external secret reference for an organization.
// Implementations must not persist the value.
type RefResolver interface {
	Resolve(ctx context.Context, orgID uuid.UUID, ref string) ([]byte, error)
}

// ErrRefUnavailable means a stored credential is a reference but no
// resolver is configured.
var ErrRefUnavailable = errors.New("secret is an external reference but no Vault/OpenBao connection is available")

// refKinds may hold references: connector credentials an administrator
// enters. PATHOS-generated secrets (webhook signing secrets, worker tokens)
// never do.
var refKinds = map[string]bool{KindSCM: true, KindAI: true, KindMCP: true, KindSMTP: true, KindIntegration: true, "scan_target": true}

// IsReference reports whether a plaintext is a Vault/OpenBao reference.
func IsReference(plain []byte) bool {
	return bytes.HasPrefix(plain, []byte("vault:")) && refRe.Match(bytes.TrimSpace(plain))
}

var refRe = regexp.MustCompile(`^vault:[A-Za-z0-9_.-]{1,64}/[A-Za-z0-9_.\-/]{1,512}#[A-Za-z0-9_.-]{1,128}$`)

// Create encrypts and stores a new secret, returning its ID.
func (s *Store) Create(ctx context.Context, q db.Querier, orgID uuid.UUID, kind, name string, plaintext []byte, by *uuid.UUID) (uuid.UUID, error) {
	id := uuid.Must(uuid.NewV7())
	sealed, err := s.Keys.Seal(plaintext, AAD(kind, id))
	if err != nil {
		return uuid.Nil, err
	}
	_, err = q.Exec(ctx, `
		INSERT INTO secrets (id, organization_id, kind, name, ciphertext, wrapped_dek, key_version, created_by)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`,
		id, orgID, kind, name, sealed.Ciphertext, sealed.WrappedDEK, sealed.KeyVersion, by)
	return id, err
}

// Update replaces a secret's value with a fresh DEK.
func (s *Store) Update(ctx context.Context, q db.Querier, orgID, id uuid.UUID, kind string, plaintext []byte) error {
	sealed, err := s.Keys.Seal(plaintext, AAD(kind, id))
	if err != nil {
		return err
	}
	tag, err := q.Exec(ctx, `
		UPDATE secrets SET ciphertext = $4, wrapped_dek = $5, key_version = $6, updated_at = now()
		WHERE organization_id = $1 AND id = $2 AND kind = $3`,
		orgID, id, kind, sealed.Ciphertext, sealed.WrappedDEK, sealed.KeyVersion)
	if err == nil && tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return err
}

// Reveal decrypts a secret. kind must match the stored kind.
func (s *Store) Reveal(ctx context.Context, q db.Querier, orgID, id uuid.UUID, kind string) ([]byte, error) {
	var sealed crypto.Sealed
	err := q.QueryRow(ctx, `SELECT ciphertext, wrapped_dek, key_version FROM secrets
		WHERE organization_id = $1 AND id = $2 AND kind = $3`, orgID, id, kind).
		Scan(&sealed.Ciphertext, &sealed.WrappedDEK, &sealed.KeyVersion)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	plain, err := s.Keys.Open(sealed, AAD(kind, id))
	if err != nil || !refKinds[kind] || !IsReference(plain) {
		return plain, err
	}
	// An external reference: resolved now, never stored or cached.
	if s.Refs == nil {
		return nil, ErrRefUnavailable
	}
	return s.Refs.Resolve(ctx, orgID, string(bytes.TrimSpace(plain)))
}

// ResolveValue resolves one field of a multi-part credential (for example
// the token inside a user name + token JSON credential) when it is a
// reference; other values are returned unchanged.
func (s *Store) ResolveValue(ctx context.Context, orgID uuid.UUID, value string) (string, error) {
	if !IsReference([]byte(value)) {
		return value, nil
	}
	if s.Refs == nil {
		return "", ErrRefUnavailable
	}
	b, err := s.Refs.Resolve(ctx, orgID, strings.TrimSpace(value))
	return string(b), err
}

// RevealStored decrypts a secret without resolving references (to show
// whether a credential is a reference, or to edit one).
func (s *Store) RevealStored(ctx context.Context, q db.Querier, orgID, id uuid.UUID, kind string) ([]byte, error) {
	var sealed crypto.Sealed
	err := q.QueryRow(ctx, `SELECT ciphertext, wrapped_dek, key_version FROM secrets
		WHERE organization_id = $1 AND id = $2 AND kind = $3`, orgID, id, kind).
		Scan(&sealed.Ciphertext, &sealed.WrappedDEK, &sealed.KeyVersion)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	return s.Keys.Open(sealed, AAD(kind, id))
}

// Delete removes a secret.
func (s *Store) Delete(ctx context.Context, q db.Querier, orgID, id uuid.UUID) error {
	_, err := q.Exec(ctx, `DELETE FROM secrets WHERE organization_id = $1 AND id = $2`, orgID, id)
	return err
}

// RewrapAll re-wraps every DEK not under the current master key. It returns
// the number of secrets updated.
func (s *Store) RewrapAll(ctx context.Context, tx pgx.Tx) (int, error) {
	cur := s.Keys.CurrentVersion()
	rows, err := tx.Query(ctx, `SELECT id, kind, ciphertext, wrapped_dek, key_version FROM secrets WHERE key_version <> $1 FOR UPDATE`, cur)
	if err != nil {
		return 0, err
	}
	type row struct {
		id   uuid.UUID
		kind string
		s    crypto.Sealed
	}
	all, err := pgx.CollectRows(rows, func(r pgx.CollectableRow) (row, error) {
		var x row
		err := r.Scan(&x.id, &x.kind, &x.s.Ciphertext, &x.s.WrappedDEK, &x.s.KeyVersion)
		return x, err
	})
	if err != nil {
		return 0, err
	}
	for _, r := range all {
		ns, err := s.Keys.Rewrap(r.s, AAD(r.kind, r.id))
		if err != nil {
			return 0, errors.Join(errors.New("secret "+r.id.String()+": is its key version listed in PATHOS_MASTER_KEYS_PREVIOUS?"), err)
		}
		if _, err := tx.Exec(ctx, `UPDATE secrets SET wrapped_dek = $2, key_version = $3, rotated_at = now() WHERE id = $1`,
			r.id, ns.WrappedDEK, ns.KeyVersion); err != nil {
			return 0, err
		}
	}
	return len(all), nil
}
