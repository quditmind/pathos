package rea

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"pathos/internal/platform/db"
	"pathos/internal/platform/httpx"
	"pathos/internal/scans"
)

// Error codes (catalogue: internal/platform/diag/catalogue_rea.go).
const (
	CodeUntrusted         = "PTH-REA-1001"
	CodeNoWorker          = "PTH-REA-1002"
	CodeSandboxFailed     = "PTH-REA-1003"
	CodeTimedOut          = "PTH-REA-1004"
	CodeInvalidDoc        = "PTH-REA-1005"
	CodeNotArtifact       = "PTH-REA-1006"
	CodeAuthDisabled      = "PTH-REA-1007"
	CodeNoSourceSnapshot  = "PTH-REA-1008"
	CodeStoreFailed       = "PTH-REA-1009"
	CodeCodeWithheld      = "PTH-REA-1010"
	CodeNotReady          = "PTH-REA-1011"
	CodeArtifactMismatch  = "PTH-REA-1012"
	PolicyOwnBuildsOrAuth = "own_builds_or_authorized"
	PolicyOwnBuildsOnly   = "own_builds_only"
)

// Tools are the analysis tools of the static tier, in display order.
var Tools = []ToolInfo{
	{Key: "radare2", Name: "radare2", License: "LGPL-3.0-only", Purpose: "Binary triage: format, sections, imports, exports, symbols, strings, call graph"},
	{Key: "binwalk", Name: "binwalk", License: "MIT", Purpose: "Firmware: embedded file systems and archives, extraction"},
	{Key: "ghidra", Name: "Ghidra (headless)", License: "Apache-2.0", Purpose: "Decompiler: pseudo-C, cross-references, call graph", Optional: true},
	{Key: "jadx", Name: "Jadx", License: "Apache-2.0", Purpose: "Android: DEX and APK decompiler", Optional: true},
	{Key: "ilspy", Name: "ILSpy (ilspycmd)", License: "MIT", Purpose: ".NET assembly decompiler", Optional: true},
}

// ToolInfo is a tool of GET /rea/tools.
type ToolInfo struct {
	Key       string `json:"key"`
	Name      string `json:"name"`
	License   string `json:"license"`
	Purpose   string `json:"purpose"`
	Optional  bool   `json:"optional"`
	Installed bool   `json:"installed"`
	Version   string `json:"version"`
	Enabled   bool   `json:"enabled"`
}

func toolKeys() []string {
	out := make([]string, len(Tools))
	for i, t := range Tools {
		out[i] = t.Key
	}
	return out
}

// Settings are an organization's reverse-engineering settings.
type Settings struct {
	EnabledTools     []string   `json:"enabled_tools"`
	MemoryMB         int        `json:"memory_mb"`
	TimeoutMinutes   int        `json:"timeout_minutes"`
	InputPolicy      string     `json:"input_policy"`
	DecompiledCodeAI string     `json:"decompiled_code_ai"`
	AISendCode       bool       `json:"ai_send_code_allowed"`
	UpdatedAt        *time.Time `json:"updated_at,omitempty"`
}

// DefaultSettings apply without a stored row.
func DefaultSettings() Settings {
	return Settings{EnabledTools: []string{"radare2", "binwalk"}, MemoryMB: 4096, TimeoutMinutes: 30,
		InputPolicy: PolicyOwnBuildsOrAuth, DecompiledCodeAI: "none"}
}

func loadSettings(ctx context.Context, q db.Querier, orgID uuid.UUID) (Settings, error) {
	st := DefaultSettings()
	var at time.Time
	err := q.QueryRow(ctx, `SELECT enabled_tools, memory_mb, timeout_minutes, input_policy, decompiled_code_ai, updated_at
		FROM rea_settings WHERE organization_id = $1`, orgID).Scan(&st.EnabledTools, &st.MemoryMB, &st.TimeoutMinutes, &st.InputPolicy,
		&st.DecompiledCodeAI, &at)
	switch {
	case errors.Is(err, pgx.ErrNoRows):
	case err != nil:
		return st, err
	default:
		st.UpdatedAt = &at
	}
	st.AISendCode, _, err = aiCodePolicy(ctx, q, orgID)
	return st, err
}

// aiCodePolicy reads the default AI configuration: whether it may receive
// code (send_code_context) and whether its provider is self-hosted.
func aiCodePolicy(ctx context.Context, q db.Querier, orgID uuid.UUID) (sendCode, local bool, err error) {
	var kind string
	err = q.QueryRow(ctx, `SELECT v.send_code_context, p.kind FROM ai_configurations c
		JOIN ai_configuration_versions v ON v.id = c.current_version_id JOIN ai_providers p ON p.id = v.provider_id
		WHERE c.organization_id = $1 AND c.is_default AND c.archived_at IS NULL`, orgID).Scan(&sendCode, &kind)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, false, nil
	}
	return sendCode, kind == "self_hosted", err
}

// DecompiledCodeAllowed decides whether decompiled code may be sent to an
// AI provider of the given kind: never with "none" (the default); only
// self-hosted providers with "local"; with "cloud" any provider, but only
// while the AI configuration allows sending code. No M10 feature sends
// decompiled code to a model; this is the rule every future one must use.
func DecompiledCodeAllowed(st Settings, providerKind string) error {
	switch {
	case st.DecompiledCodeAI == "none" || st.DecompiledCodeAI == "":
		return withheld("the reverse-engineering setting allows no AI model to see decompiled code")
	case providerKind == "self_hosted":
		return nil
	case st.DecompiledCodeAI == "local":
		return withheld("only a self-hosted (local) model may see decompiled code")
	case !st.AISendCode:
		return withheld("cloud models may see decompiled code only while the AI configuration allows sending code")
	}
	return nil
}

func withheld(msg string) error {
	return httpx.E(http.StatusUnprocessableEntity, "rea_code_withheld", msg).WithDiag(CodeCodeWithheld)
}

// validate checks settings sent by an administrator.
func (st *Settings) validate(sendCode bool) error {
	bad := func(msg string) error { return httpx.E(http.StatusUnprocessableEntity, "invalid_request", msg) }
	var tools []string
	for _, t := range st.EnabledTools {
		t = strings.TrimSpace(t)
		if !slices.Contains(toolKeys(), t) {
			return bad("unknown tool " + t)
		}
		if !slices.Contains(tools, t) {
			tools = append(tools, t)
		}
	}
	if len(tools) == 0 {
		return bad("enable at least one tool")
	}
	st.EnabledTools = tools
	switch {
	case st.MemoryMB < 512 || st.MemoryMB > 16384:
		return bad("memory_mb must be between 512 and 16384")
	case st.TimeoutMinutes < 5 || st.TimeoutMinutes > 230:
		return bad("timeout_minutes must be between 5 and 230 (an execution is limited to 4 hours)")
	case st.InputPolicy != PolicyOwnBuildsOrAuth && st.InputPolicy != PolicyOwnBuildsOnly:
		return bad("input_policy must be own_builds_or_authorized or own_builds_only")
	case !slices.Contains([]string{"none", "local", "cloud"}, st.DecompiledCodeAI):
		return bad("decompiled_code_ai must be none, local or cloud")
	case st.DecompiledCodeAI == "cloud" && !sendCode:
		return withheld("cloud models may see decompiled code only when the default AI configuration allows sending code (AI settings → send code context)")
	}
	return nil
}

// Trust is the input-policy evaluation of an artifact.
type Trust struct {
	// Status: trusted (own build: verified signature or provenance),
	// authorized (explicit per-artifact authorisation) or untrusted.
	Status        string         `json:"status"`
	Basis         string         `json:"basis"`
	Reason        string         `json:"reason"`
	Signature     *SignatureInfo `json:"signature"`
	Provenance    *ProvInfo      `json:"provenance"`
	Authorization *AuthInfo      `json:"authorization"`
	// AuthorizationAllowed: the input policy permits authorising this
	// artifact.
	AuthorizationAllowed bool `json:"authorization_allowed"`
}

// SignatureInfo is the newest signature verification.
type SignatureInfo struct {
	Status     string    `json:"status"`
	Mode       string    `json:"mode"`
	VerifiedAt time.Time `json:"verified_at"`
}

// ProvInfo is the provenance attestation state.
type ProvInfo struct {
	Status     string     `json:"status"` // verified | mismatch | unverified | missing | invalid | error
	Commit     string     `json:"commit,omitempty"`
	Builder    string     `json:"builder,omitempty"`
	SourceRepo string     `json:"source_repository,omitempty"`
	VerifiedAt *time.Time `json:"verified_at,omitempty"`
}

// AuthInfo is an active authorisation.
type AuthInfo struct {
	ID                 uuid.UUID `json:"id"`
	Reason             string    `json:"reason"`
	AuthorizedBy       *string   `json:"authorized_by"`
	AuthorizedByEmail  string    `json:"authorized_by_email"`
	CreatedAt          time.Time `json:"created_at"`
	ArtifactSHA256     string    `json:"artifact_sha256"`
	authorizedByUserID *uuid.UUID
}

// artifactRow is an artifact target as the input policy sees it.
type artifactRow struct {
	ID, RepoID uuid.UUID
	AppID      *uuid.UUID
	Kind       string
	Name       string
	FileName   string
	SHA256     string
	Size       int64
	Provenance *string
	CreatedAt  time.Time
	RepoName   string
	Enabled    bool
}

// evaluate applies the input policy to an artifact target. It reads only
// verification evidence PATHOS recorded itself: the newest
// signature_verifications row of the target (written from the worker's
// cosign check), the stored provenance statement when that check verified
// it (and only if it names this artifact's SHA-256), and active
// authorisations bound to the same SHA-256.
func evaluate(ctx context.Context, q db.Querier, orgID uuid.UUID, a artifactRow, policy string) (Trust, error) {
	t := Trust{Status: "untrusted", AuthorizationAllowed: policy == PolicyOwnBuildsOrAuth}
	var sv struct {
		status, mode, att string
		at                time.Time
	}
	err := q.QueryRow(ctx, `SELECT status, mode, attestation_status, created_at FROM signature_verifications
		WHERE organization_id = $1 AND scan_target_id = $2 ORDER BY created_at DESC, id DESC LIMIT 1`, orgID, a.ID).
		Scan(&sv.status, &sv.mode, &sv.att, &sv.at)
	switch {
	case errors.Is(err, pgx.ErrNoRows):
	case err != nil:
		return t, err
	default:
		t.Signature = &SignatureInfo{Status: sv.status, Mode: sv.mode, VerifiedAt: sv.at}
	}
	sigOK := t.Signature != nil && t.Signature.Status == "verified" && (t.Signature.Mode == "key" || t.Signature.Mode == "keyless")
	provOK := false
	if a.Provenance != nil {
		p := &ProvInfo{Status: "unverified"}
		if t.Signature != nil && sv.att != "" {
			p.Status = sv.att
		}
		if pr, err := scans.ParseProvenance(*a.Provenance); err == nil {
			p.Builder, p.SourceRepo = pr.Builder, pr.SourceRepo
			if p.Status == "verified" {
				if pr.HasSubject(a.SHA256) {
					p.Commit, p.VerifiedAt, provOK = pr.Commit, &sv.at, true
				} else {
					p.Status = "mismatch"
				}
			}
		} else if p.Status == "verified" {
			p.Status = "invalid"
		}
		t.Provenance = p
	}
	switch {
	case provOK:
		t.Status, t.Basis, t.Reason = "trusted", "provenance", "SLSA provenance verified for this artifact"
		return t, nil
	case sigOK:
		t.Status, t.Basis, t.Reason = "trusted", "signature", "signature verified ("+t.Signature.Mode+")"
		return t, nil
	}
	var au AuthInfo
	var by *string
	err = q.QueryRow(ctx, `SELECT a.id, a.reason, a.authorized_by, COALESCE(NULLIF(u.display_name, ''), u.email), COALESCE(u.email, ''),
		a.created_at, a.artifact_sha256
		FROM rea_authorizations a LEFT JOIN users u ON u.id = a.authorized_by
		WHERE a.organization_id = $1 AND a.target_id = $2 AND a.revoked_at IS NULL`, orgID, a.ID).
		Scan(&au.ID, &au.Reason, &au.authorizedByUserID, &by, &au.AuthorizedByEmail, &au.CreatedAt, &au.ArtifactSHA256)
	switch {
	case errors.Is(err, pgx.ErrNoRows):
	case err != nil:
		return t, err
	default:
		au.AuthorizedBy = by
		t.Authorization = &au
	}
	switch {
	case t.Authorization != nil && policy == PolicyOwnBuildsOrAuth && au.ArtifactSHA256 == a.SHA256:
		t.Status, t.Basis, t.Reason = "authorized", "authorization", "authorised as an untrusted artifact: "+au.Reason
	case t.Authorization != nil && au.ArtifactSHA256 != a.SHA256:
		t.Reason = "the authorisation was given for another file (" + au.ArtifactSHA256[:12] + ")"
	case t.Authorization != nil:
		t.Reason = "the input policy (own builds only) ignores authorisations"
	case t.Provenance != nil && t.Provenance.Status == "mismatch":
		t.Reason = "the provenance attestation does not name this artifact"
	case t.Signature == nil:
		t.Reason = "no signature or provenance verification is recorded for this artifact"
	default:
		t.Reason = "signature " + t.Signature.Status + ", provenance not verified"
	}
	return t, nil
}

// trustJSON is the stored copy of an evaluation (rea_analyses.trust_detail).
func trustJSON(t Trust) []byte {
	b, _ := json.Marshal(t)
	if len(b) > 15000 {
		b, _ = json.Marshal(map[string]any{"status": t.Status, "basis": t.Basis, "reason": t.Reason})
	}
	return b
}
