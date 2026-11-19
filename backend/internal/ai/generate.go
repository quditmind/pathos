package ai

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
)

// Generate sends one structured request to the organization's default AI
// configuration: system rules (trusted), a task and a payload of PATHOS
// data. The payload is redacted (built-in and organization patterns) and
// fenced as untrusted data, exactly like finding evidence. Callers must
// validate the JSON they get back.
type GenerateResult struct {
	JSON            []byte
	Provider        string
	Model           string
	ConfigVersionID uuid.UUID
	SHA256          string
	InputTokens     int64
	OutputTokens    int64
}

// maxGeneratePayload bounds what is sent (after redaction).
const maxGeneratePayload = 60000

// Generate runs one request; see GenerateResult.
func (s *Service) Generate(ctx context.Context, orgID uuid.UUID, system, task string, payload any, schema map[string]any, maxTokens int) (GenerateResult, error) {
	cv, err := defaultConfig(ctx, s.DB, orgID)
	if err != nil {
		return GenerateResult{}, ErrNotConfigured
	}
	pvs, err := s.loadProviders(ctx, orgID, &cv.ProviderID)
	if err != nil || len(pvs) == 0 {
		return GenerateResult{}, ErrNotConfigured
	}
	prov, err := s.provider(ctx, orgID, pvs[0])
	if err != nil {
		return GenerateResult{}, err
	}
	extra, _ := CompilePatterns(cv.RedactionPatterns)
	body, err := json.MarshalIndent(payload, "", "  ")
	if err != nil {
		return GenerateResult{}, err
	}
	data := Redact(string(body), extra)
	if len(data) > maxGeneratePayload {
		return GenerateResult{}, ErrTooLarge{Bytes: len(data)}
	}
	id := nonce()
	user := fmt.Sprintf("Task: %s\n\n<untrusted_evidence id=%q>\n%s\n</untrusted_evidence id=%q>", task, id, data, id)
	if s := strings.TrimSpace(cv.Instructions); s != "" {
		system += "\n\nOrganization guidance (from PATHOS administrators, trusted):\n" + s
	}
	h := sha256.New()
	h.Write([]byte(system))
	h.Write([]byte{0})
	h.Write([]byte(user))
	cctx, cancel := context.WithTimeout(ctx, 6*time.Minute)
	defer cancel()
	resp, err := prov.Review(cctx, Request{Model: cv.Model, Effort: cv.Effort, System: system, User: user, Schema: schema, MaxOutputTokens: maxTokens})
	if err != nil {
		return GenerateResult{}, err
	}
	return GenerateResult{JSON: resp.JSON, Provider: pvs[0].Kind, Model: resp.Model, ConfigVersionID: cv.ID, SHA256: hex.EncodeToString(h.Sum(nil)),
		InputTokens: resp.InputTokens, OutputTokens: resp.OutputTokens}, nil
}
