package scans

import (
	"context"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"pathos/internal/scanners"
)

// SignatureConfig is a target's Sigstore verification policy (cosign).
type SignatureConfig struct {
	// Mode: "" (off), key (a public key) or keyless (Fulcio certificate
	// identity and OIDC issuer, Rekor transparency log).
	Mode           string `json:"mode"`
	PublicKey      string `json:"public_key,omitempty"`
	Identity       string `json:"identity,omitempty"`
	IdentityRegexp string `json:"identity_regexp,omitempty"`
	Issuer         string `json:"issuer,omitempty"`
	// Require: a missing or invalid signature (or required attestation)
	// creates a finding and fails the security gate.
	Require bool `json:"require,omitempty"`
	// Attestation is an in-toto predicate type verified as well (images).
	Attestation string `json:"attestation,omitempty"`
	// IgnoreTlog: do not require a transparency log entry (key-based
	// signatures that were never uploaded to Rekor).
	IgnoreTlog bool `json:"ignore_tlog,omitempty"`
}

// SignatureVerification is the latest verification evidence of a target.
type SignatureVerification struct {
	Status            string          `json:"status"`
	Mode              string          `json:"mode"`
	Required          bool            `json:"required"`
	AttestationStatus string          `json:"attestation_status"`
	Details           json.RawMessage `json:"details"`
	ScanJobID         *uuid.UUID      `json:"scan_job_id"`
	VerifiedAt        time.Time       `json:"verified_at"`
}

// AttestationTypes are the predicate types cosign verify-attestation
// accepts by name.
var AttestationTypes = []string{"slsaprovenance", "slsaprovenance02", "slsaprovenance1", "spdx", "spdxjson", "cyclonedx", "vuln", "openvex", "link"}

const maxSignatureMaterial = 65536

var oidcIssuerRe = regexp.MustCompile(`^https://[A-Za-z0-9.-]+(:\d{1,5})?(/[\w./~-]*)?$`)

func validSignatureConfig(c *SignatureConfig) error {
	if c == nil {
		return nil
	}
	c.PublicKey = strings.TrimSpace(c.PublicKey)
	c.Identity, c.IdentityRegexp, c.Issuer = strings.TrimSpace(c.Identity), strings.TrimSpace(c.IdentityRegexp), strings.TrimSpace(c.Issuer)
	switch c.Mode {
	case "":
		*c = SignatureConfig{}
		return nil
	case "key":
		if len(c.PublicKey) > 4096 {
			return errors.New("the public key is limited to 4096 characters")
		}
		block, _ := pem.Decode([]byte(c.PublicKey))
		if block == nil || block.Type != "PUBLIC KEY" {
			return errors.New("enter the cosign public key in PEM format (-----BEGIN PUBLIC KEY-----)")
		}
		if _, err := x509.ParsePKIXPublicKey(block.Bytes); err != nil {
			return errors.New("the public key could not be parsed")
		}
		c.Identity, c.IdentityRegexp, c.Issuer = "", "", ""
	case "keyless":
		if !oidcIssuerRe.MatchString(c.Issuer) || len(c.Issuer) > 300 {
			return errors.New("keyless verification needs the OIDC issuer URL (e.g. https://token.actions.githubusercontent.com)")
		}
		if (c.Identity == "") == (c.IdentityRegexp == "") {
			return errors.New("keyless verification needs either the certificate identity or an identity regular expression")
		}
		if len(c.Identity) > 500 || len(c.IdentityRegexp) > 500 || strings.ContainsAny(c.Identity+c.IdentityRegexp, "\r\n\x00") {
			return errors.New("the certificate identity is limited to 500 characters on one line")
		}
		if c.IdentityRegexp != "" {
			if _, err := regexp.Compile(c.IdentityRegexp); err != nil {
				return errors.New("the identity regular expression is invalid")
			}
		}
		c.PublicKey = ""
	default:
		return errors.New("signature mode must be key or keyless")
	}
	if c.Attestation != "" && !slices.Contains(AttestationTypes, c.Attestation) {
		return errors.New("attestation must be one of " + strings.Join(AttestationTypes, ", "))
	}
	return nil
}

// validSignatureMaterial accepts a Sigstore bundle (JSON) or a base64
// signature.
func validSignatureMaterial(v string) error {
	v = strings.TrimSpace(v)
	if v == "" {
		return nil
	}
	if len(v) > maxSignatureMaterial {
		return errors.New("the signature or bundle is limited to 64 KiB")
	}
	if strings.HasPrefix(v, "{") {
		var b struct {
			MediaType string `json:"mediaType"`
		}
		if json.Unmarshal([]byte(v), &b) != nil {
			return errors.New("the Sigstore bundle is not valid JSON")
		}
		return nil
	}
	if _, err := base64.StdEncoding.DecodeString(v); err != nil {
		return errors.New("upload a base64 signature (cosign sign-blob --output-signature) or a Sigstore bundle (JSON)")
	}
	return nil
}

// signatureAudit is the policy as recorded in the audit log.
func signatureAudit(c *SignatureConfig) map[string]any {
	if c == nil || c.Mode == "" {
		return map[string]any{"mode": "off"}
	}
	m := map[string]any{"mode": c.Mode, "require": c.Require, "attestation": c.Attestation, "ignore_tlog": c.IgnoreTlog}
	if c.Mode == "keyless" {
		m["identity"], m["identity_regexp"], m["issuer"] = c.Identity, c.IdentityRegexp, c.Issuer
	}
	return m
}

// targetScannerKeys are the scanners a target runs: cosign only with a
// verification policy, Nuclei for declared endpoints only when enabled.
func targetScannerKeys(kind string, cfg TargetConfig) []string {
	var out []string
	for _, k := range scanners.TargetScanners[kind] {
		switch {
		case k == scanners.Cosign && (cfg.Signature == nil || cfg.Signature.Mode == ""):
			continue
		case kind == "endpoints" && k == scanners.Nuclei && !cfg.Nuclei:
			continue
		}
		out = append(out, k)
	}
	if out == nil {
		out = []string{}
	}
	return out
}

// recordSignature stores the verification evidence of a cosign result.
func recordSignature(ctx context.Context, tx pgx.Tx, orgID, jobID uuid.UUID, targetID *uuid.UUID, raw []byte) error {
	if targetID == nil {
		return nil
	}
	rep, err := scanners.ParseSignatureReport(raw)
	if err != nil {
		return nil // the result itself records the parse failure
	}
	att := ""
	if rep.Attestation != nil {
		att = rep.Attestation.Status
	}
	details, _ := json.Marshal(map[string]any{"subject": rep.Subject, "detail": rep.Detail, "offline": rep.Offline,
		"signatures": rep.Signatures, "attestation": rep.Attestation})
	if len(details) > 60000 {
		details = []byte(`{"truncated":true}`)
	}
	_, err = tx.Exec(ctx, `INSERT INTO signature_verifications (id, organization_id, scan_target_id, scan_job_id, status, mode, required,
		attestation_status, details) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`,
		uuid.Must(uuid.NewV7()), orgID, *targetID, jobID, rep.Status, rep.Mode, rep.Required, att, details)
	return err
}

// signatureGateFailed reports whether a job's target requires a signature
// (or attestation) that was not verified.
func signatureGateFailed(ctx context.Context, tx pgx.Tx, jobID uuid.UUID) (bool, error) {
	var failed bool
	err := tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM signature_verifications WHERE scan_job_id = $1 AND required
		AND (status <> 'verified' OR attestation_status IN ('missing', 'invalid', 'error')))`, jobID).Scan(&failed)
	return failed, err
}
