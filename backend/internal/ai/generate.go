package ai

import (
	"context"
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
	// EvidenceID is the AI evidence record of the call.
	EvidenceID uuid.UUID
}

// maxGeneratePayload bounds what is sent (after redaction).
const maxGeneratePayload = 60000

// Generate runs one request for aiTask (TaskAnalyst, TaskReport) with the
// task's configuration (model per task); see GenerateResult. The call
// writes an AI evidence record (subject from WithSubject).
func (s *Service) Generate(ctx context.Context, orgID uuid.UUID, aiTask, system, task string, payload any, schema map[string]any, maxTokens int) (GenerateResult, error) {
	rc, err := s.resolve(ctx, orgID, aiTask)
	if err != nil {
		return GenerateResult{}, err
	}
	cv := rc.CV
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
	op := map[string]string{TaskAnalyst: "analyst_answer", TaskReport: "report_narrative"}[aiTask]
	if op == "" {
		op = "generate"
	}
	cctx, cancel := context.WithTimeout(ctx, 6*time.Minute)
	defer cancel()
	resp, _, eid, err := s.invoke(cctx, orgID, rc, callSpec{Task: aiTask, Operation: op, Template: "generate@1", System: system, User: user,
		Schema: schema, Effort: cv.Effort, MaxTokens: maxTokens, Subject: subjectFrom(ctx, aiTask), Review: ReviewNotRequired})
	if err != nil {
		return GenerateResult{EvidenceID: eid}, err
	}
	return GenerateResult{JSON: resp.JSON, Provider: rc.PV.Kind, Model: resp.Model, ConfigVersionID: cv.ID, SHA256: sha256Hex(system, user),
		InputTokens: resp.InputTokens, OutputTokens: resp.OutputTokens, EvidenceID: eid}, nil
}
