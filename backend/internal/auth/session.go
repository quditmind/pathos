// Package auth implements the backend-for-frontend OIDC login against
// Keycloak, server-side sessions in Redis and CSRF protection.
//
// The browser only ever holds an opaque, HttpOnly session cookie. OIDC
// tokens never reach JavaScript.
package auth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"
)

var ErrNoSession = errors.New("no session")

// Session is server-side session state.
type Session struct {
	UserID     uuid.UUID `json:"uid"`
	OrgID      uuid.UUID `json:"oid"`
	CSRF       string    `json:"csrf"`
	IDToken    string    `json:"idt,omitempty"` // used only as id_token_hint at logout
	CreatedAt  time.Time `json:"cat"`
	AbsExpiry  time.Time `json:"exp"`
	LastSeenAt time.Time `json:"lsa"`
}

// SessionStore keeps sessions in Redis keyed by the SHA-256 of the cookie
// value, so a Redis dump does not expose usable session tokens.
type SessionStore struct {
	R           redis.UniversalClient
	IdleTTL     time.Duration
	AbsoluteTTL time.Duration
	Now         func() time.Time
}

func (s *SessionStore) now() time.Time {
	if s.Now != nil {
		return s.Now()
	}
	return time.Now()
}

// RandomToken returns n random bytes, base64url-encoded.
func RandomToken(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

func hashToken(t string) string {
	h := sha256.Sum256([]byte(t))
	return hex.EncodeToString(h[:])
}

func sessKey(hash string) string        { return "pathos:sess:" + hash }
func userSessKey(u uuid.UUID) string    { return "pathos:user_sess:" + u.String() }

// Create stores a new session and returns the cookie token.
func (s *SessionStore) Create(ctx context.Context, userID, orgID uuid.UUID, idToken string) (string, *Session, error) {
	token := RandomToken(32)
	now := s.now()
	sess := &Session{
		UserID: userID, OrgID: orgID, CSRF: RandomToken(32), IDToken: idToken,
		CreatedAt: now, AbsExpiry: now.Add(s.AbsoluteTTL), LastSeenAt: now,
	}
	b, err := json.Marshal(sess)
	if err != nil {
		return "", nil, err
	}
	h := hashToken(token)
	pipe := s.R.TxPipeline()
	pipe.Set(ctx, sessKey(h), b, s.IdleTTL)
	pipe.SAdd(ctx, userSessKey(userID), h)
	pipe.Expire(ctx, userSessKey(userID), s.AbsoluteTTL)
	_, err = pipe.Exec(ctx)
	return token, sess, err
}

// Get loads a session and slides its idle expiry.
func (s *SessionStore) Get(ctx context.Context, token string) (*Session, error) {
	if token == "" || len(token) > 128 {
		return nil, ErrNoSession
	}
	h := hashToken(token)
	b, err := s.R.Get(ctx, sessKey(h)).Bytes()
	if errors.Is(err, redis.Nil) {
		return nil, ErrNoSession
	}
	if err != nil {
		return nil, err
	}
	var sess Session
	if err := json.Unmarshal(b, &sess); err != nil {
		return nil, ErrNoSession
	}
	now := s.now()
	if !now.Before(sess.AbsExpiry) {
		_ = s.R.Del(ctx, sessKey(h)).Err()
		return nil, ErrNoSession
	}
	// Slide idle expiry at most once a minute to limit writes.
	if now.Sub(sess.LastSeenAt) > time.Minute {
		sess.LastSeenAt = now
		ttl := min(s.IdleTTL, sess.AbsExpiry.Sub(now))
		if nb, err := json.Marshal(sess); err == nil {
			_ = s.R.Set(ctx, sessKey(h), nb, ttl).Err()
		}
	}
	return &sess, nil
}

// Delete removes one session.
func (s *SessionStore) Delete(ctx context.Context, token string, userID uuid.UUID) error {
	h := hashToken(token)
	pipe := s.R.TxPipeline()
	pipe.Del(ctx, sessKey(h))
	pipe.SRem(ctx, userSessKey(userID), h)
	_, err := pipe.Exec(ctx)
	return err
}

// RevokeUser deletes every session of a user (used on deactivation).
func (s *SessionStore) RevokeUser(ctx context.Context, userID uuid.UUID) (int, error) {
	hashes, err := s.R.SMembers(ctx, userSessKey(userID)).Result()
	if err != nil {
		return 0, err
	}
	keys := make([]string, 0, len(hashes)+1)
	for _, h := range hashes {
		keys = append(keys, sessKey(h))
	}
	keys = append(keys, userSessKey(userID))
	n, err := s.R.Del(ctx, keys...).Result()
	if n > 0 {
		n-- // do not count the index set itself
	}
	return int(n), err
}

// loginFlow is the short-lived state of an in-progress OIDC login.
type loginFlow struct {
	Verifier string `json:"v"`
	Nonce    string `json:"n"`
	ReturnTo string `json:"r"`
}

func flowKey(state string) string { return "pathos:oidc:" + hashToken(state) }

func (s *SessionStore) putFlow(ctx context.Context, state string, f loginFlow) error {
	b, _ := json.Marshal(f)
	return s.R.Set(ctx, flowKey(state), b, 10*time.Minute).Err()
}

// takeFlow fetches and deletes a login flow (single use).
func (s *SessionStore) takeFlow(ctx context.Context, state string) (loginFlow, error) {
	var f loginFlow
	b, err := s.R.GetDel(ctx, flowKey(state)).Bytes()
	if errors.Is(err, redis.Nil) {
		return f, ErrNoSession
	}
	if err != nil {
		return f, err
	}
	err = json.Unmarshal(b, &f)
	return f, err
}
