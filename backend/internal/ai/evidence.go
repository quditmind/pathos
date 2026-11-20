package ai

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"pathos/internal/platform/crypto"
	"pathos/internal/platform/db"
	"pathos/internal/platform/logging"
)

// AI evidence records (PATHOS 3.0 M7, ADR-008). Every call PATHOS makes to
// a model goes through Service.invoke, which writes one
// ai_evidence_records row whatever the outcome: the subject, the task and
// template, the model and provider, the parameters, the SHA-256 of exactly
// what was sent and received, the validated reasoning steps, conclusion
// and confidence, and (envelope-encrypted, until the retention ends) the
// redacted prompt and response, so the decision can be shown and replayed.
// evidence_test.go fails when a provider call bypasses invoke.

// Tasks: each has its own AI configuration (model per task).
const (
	TaskFindingValidation = "finding_validation"
	TaskFixProposal       = "fix_proposal"
	TaskTroubleshooting   = "troubleshooting"
	TaskThreatSuggestion  = "threat_suggestion"
	TaskCorrelation       = "correlation"
	TaskAnalyst           = "analyst"
	TaskReport            = "report"
	TaskGraphInference    = "graph_inference"
)

// TaskInfo describes a task in the model-per-task settings.
type TaskInfo struct {
	Key   string `json:"task"`
	Label string `json:"label"`
	// CodeBearing tasks send source code or code structure; without an
	// assignment they use a self-hosted (local) configuration when one
	// exists.
	CodeBearing bool   `json:"code_bearing"`
	Description string `json:"description"`
}

// Tasks lists every task, in display order.
var Tasks = []TaskInfo{
	{TaskFindingValidation, "Triage and review", true, "AI review of findings (automatic and on request) and Human Eye assistance"},
	{TaskFixProposal, "Fix proposals", true, "AI-proposed code fixes, verified by a worker before a pull request"},
	{TaskTroubleshooting, "Troubleshooting", true, "AI help on PATHOS error codes"},
	{TaskThreatSuggestion, "Threat suggestions", true, "AI-suggested threats for a threat model draft"},
	{TaskCorrelation, "Correlation", true, "AI explanation and priority of a finding's cross-phase correlation"},
	{TaskAnalyst, "Analyst chat", false, "AI Security Analyst answers"},
	{TaskReport, "Report narratives", false, "Narratives of AI reports"},
	{TaskGraphInference, "Graph inference", true, "Reserved: AI-inferred CodeGraph edges"},
}

// TaskByKey returns the task's description.
func TaskByKey(key string) (TaskInfo, bool) {
	for _, t := range Tasks {
		if t.Key == key {
			return t, true
		}
	}
	return TaskInfo{}, false
}

// Provider locations.
const (
	LocationLocal = "local"
	LocationCloud = "cloud"
	LocationUser  = "user"
)

// Location returns where a provider kind runs.
func Location(kind string) string {
	switch kind {
	case SelfHosted:
		return LocationLocal
	case "mcp":
		return LocationUser
	}
	return LocationCloud
}

// Determinism says whether a provider kind can repeat an answer, and why.
func Determinism(kind string) (bool, string) {
	switch Location(kind) {
	case LocationLocal:
		return true, "Self-hosted model called with temperature 0 and a fixed seed: the same model file and server return the same answer for the same prompt (servers that ignore the seed may still vary)."
	case LocationUser:
		return false, "Produced by a person's own assistant outside PATHOS: PATHOS holds the conclusion but not the prompt, so it cannot be replayed."
	}
	return false, "Hosted model: the provider samples and can change the model behind the same name, so a replay can differ; the replay is compared, never assumed equal."
}

// Subject is what an AI call is about. Callers outside this package set it
// with WithSubject before calling Assist, Generate, ProposeFix or
// Troubleshoot.
type Subject struct {
	Kind string
	ID   *uuid.UUID
	// FindingID ties the record to a finding (deleted with it).
	FindingID *uuid.UUID
	// Related holds references (ids and keys) only.
	Related     map[string]any
	RequestedBy *uuid.UUID
}

type subjectKey struct{}

// WithSubject attaches the subject of the next AI calls to ctx.
func WithSubject(ctx context.Context, s Subject) context.Context {
	return context.WithValue(ctx, subjectKey{}, s)
}

func subjectFrom(ctx context.Context, task string) Subject {
	s, _ := ctx.Value(subjectKey{}).(Subject)
	if s.Kind == "" {
		s.Kind = map[string]string{TaskFindingValidation: "finding", TaskFixProposal: "finding", TaskCorrelation: "finding",
			TaskTroubleshooting: "error", TaskAnalyst: "conversation", TaskReport: "report", TaskThreatSuggestion: "threat_model",
			TaskGraphInference: "codegraph_edge"}[task]
	}
	if s.Kind == "finding" && s.FindingID == nil {
		s.FindingID = s.ID
	}
	return s
}

// interpretation is the record's view of a validated answer.
type interpretation struct {
	Steps      []string
	Conclusion string
	Verdict    string
	Confidence *float64
}

// Review decisions.
const (
	ReviewPending     = "pending"
	ReviewAccepted    = "accepted"
	ReviewRejected    = "rejected"
	ReviewNotRequired = "not_required"
)

// callSpec is one model call.
type callSpec struct {
	Task      string
	Operation string
	// Template is the prompt template key and version (interpreters).
	Template  string
	System    string
	User      string
	Schema    map[string]any
	Effort    string
	MaxTokens int
	// SentCode: the prompt contains source code. Refused for a cloud model
	// whose configuration does not allow sending code.
	SentCode bool
	Subject  Subject
	// Review is the record's initial review decision (pending for
	// conclusions that propose a decision).
	Review   string
	ParentID *uuid.UUID
	ReplayOf *uuid.UUID
	// Comparison is set on a replay.
	Comparison map[string]any
	// compare computes Comparison from the replay's answer.
	compare func(Response, interpretation) map[string]any
}

// payload is the encrypted part of a record.
type payload struct {
	System   string         `json:"system"`
	User     string         `json:"user"`
	Schema   map[string]any `json:"schema"`
	Response string         `json:"response"`
	Request  struct {
		Effort    string `json:"effort"`
		MaxTokens int    `json:"max_output_tokens"`
	} `json:"request"`
}

func payloadAAD(id uuid.UUID) []byte { return append([]byte("pathos:ai-evidence:"), id[:]...) }

func shaHex(b []byte) string {
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

// ErrCodeToCloud means the call needs source code and the configuration
// it uses does not allow sending code.
var ErrCodeToCloud = fmt.Errorf("%w (a cloud model only receives code when an administrator allows it)", ErrCodeNotAllowed)

// interpreters turn a raw answer into the record's view, per template
// (also used by replay).
var interpreters = map[string]func([]byte) (interpretation, error){
	"finding_validation@1": func(raw []byte) (interpretation, error) {
		out, err := Validate(raw)
		if err != nil {
			return interpretation{}, err
		}
		c := out.Confidence
		return interpretation{Steps: out.Evidence, Conclusion: out.Verdict + ": " + out.Rationale, Verdict: out.Verdict, Confidence: &c}, nil
	},
	"assist@1": func(raw []byte) (interpretation, error) {
		out, err := ValidateAssist(raw)
		if err != nil {
			return interpretation{}, err
		}
		return interpretation{Steps: out.Points, Conclusion: out.Summary, Verdict: "suggested"}, nil
	},
	"fix_proposal@1": func(raw []byte) (interpretation, error) {
		out, err := ValidateFix(raw)
		if err != nil {
			return interpretation{}, err
		}
		return interpretation{Steps: diffFiles(out.Diff), Conclusion: out.Summary, Verdict: "proposed"}, nil
	},
	"troubleshooting@1": func(raw []byte) (interpretation, error) {
		out, err := ValidateTroubleshoot(raw)
		if err != nil {
			return interpretation{}, err
		}
		return interpretation{Steps: out.Actions, Conclusion: out.LikelyCause, Verdict: "answered"}, nil
	},
	"generate@1":          interpretGeneric,
	"threat_suggestion@1": interpretThreats,
	"correlation@1":       interpretCorrelation,
}

func diffFiles(d string) []string {
	var out []string
	for _, l := range strings.Split(d, "\n") {
		if p, ok := strings.CutPrefix(l, "+++ b/"); ok && len(out) < 20 {
			out = append(out, "changes "+strings.TrimSpace(p))
		}
	}
	return out
}

// interpretGeneric reads a JSON object answer (analyst answers, report
// narratives): the first known text field is the conclusion and string
// arrays are the steps.
func interpretGeneric(raw []byte) (interpretation, error) {
	var obj map[string]any
	if err := json.Unmarshal(raw, &obj); err != nil {
		return interpretation{}, fmt.Errorf("ai: invalid answer: %w", err)
	}
	var in interpretation
	for _, k := range []string{"answer", "summary", "executive_summary", "narrative", "overview"} {
		if v, ok := obj[k].(string); ok && strings.TrimSpace(v) != "" {
			in.Conclusion = clip(v, 8000)
			break
		}
	}
	for _, k := range []string{"key_points", "points", "risks", "recommendations", "follow_up_questions", "priorities"} {
		if arr, ok := obj[k].([]any); ok {
			for _, x := range arr {
				if s, ok := x.(string); ok && len(in.Steps) < 30 {
					in.Steps = append(in.Steps, clip(s, 2000))
				}
			}
		}
	}
	if in.Conclusion == "" {
		in.Conclusion = clip(string(raw), 2000)
	}
	in.Verdict = "answered"
	return in, nil
}

// errorCode returns the PTH code recorded for a failed call.
func errorCode(err error) string {
	if errors.Is(err, ErrCodeNotAllowed) {
		return "PTH-AI-1101"
	}
	return DiagCode(err)
}

// invoke calls the model of rc and writes the evidence record. The record
// is written for every outcome (refused, failed, invalid output,
// succeeded); when it cannot be written the call fails, so no AI result
// exists without its record.
func (s *Service) invoke(ctx context.Context, orgID uuid.UUID, rc resolved, spec callSpec) (Response, interpretation, uuid.UUID, error) {
	interp := interpreters[spec.Template]
	if interp == nil {
		return Response{}, interpretation{}, uuid.Nil, fmt.Errorf("ai: unknown prompt template %q", spec.Template)
	}
	id := uuid.Must(uuid.NewV7())
	det, _ := Determinism(rc.PV.Kind)
	req := Request{Model: rc.CV.Model, Effort: spec.Effort, System: spec.System, User: spec.User, Schema: spec.Schema, MaxOutputTokens: spec.MaxTokens}
	params := map[string]any{"effort": spec.Effort, "max_output_tokens": spec.MaxTokens, "configuration_version": rc.CV.Version,
		"configuration_id": rc.ConfigurationID, "selected_by": rc.Source}
	if rc.Location == LocationLocal {
		zero, seed := 0.0, 0
		req.Temperature, req.Seed = &zero, &seed
		params["temperature"], params["seed"] = 0, 0
	} else {
		params["temperature"] = "provider default"
	}
	rec := recordRow{ID: id, OrgID: orgID, Spec: spec, RC: rc, Params: params, Deterministic: det,
		InputSHA: sha256Hex(spec.System, spec.User)}
	// Code is only sent where the configuration allows it (for a cloud
	// model this is the administrator's explicit permission). Callers
	// leave code out when it is not allowed; a call that needs code is
	// refused and recorded.
	if spec.SentCode && !rc.CV.SendCodeContext {
		rec.Status, rec.ErrorCode, rec.Error = "disabled", "PTH-AI-1101", "source code may not be sent with this AI configuration ("+rc.Location+" model; send code context is off)"
		if err := s.writeRecord(ctx, rec, nil); err != nil {
			return Response{}, interpretation{}, uuid.Nil, err
		}
		return Response{}, interpretation{}, id, ErrCodeToCloud
	}
	resp, err := rc.Prov.Review(ctx, req)
	pl := &payload{System: spec.System, User: spec.User, Schema: spec.Schema}
	pl.Request.Effort, pl.Request.MaxTokens = spec.Effort, spec.MaxTokens
	if err != nil {
		rec.Status, rec.ErrorCode, rec.Error = "failed", errorCode(err), logging.RedactString(err.Error())
		if werr := s.writeRecord(ctx, rec, pl); werr != nil {
			return resp, interpretation{}, uuid.Nil, werr
		}
		return resp, interpretation{}, id, err
	}
	rec.Resp = resp
	pl.Response = string(resp.JSON)
	in, verr := interp(resp.JSON)
	if spec.compare != nil {
		rec.Spec.Comparison = spec.compare(resp, in)
	}
	if verr != nil {
		rec.Status, rec.ErrorCode, rec.Error = "invalid_output", "PTH-AI-1006", logging.RedactString(verr.Error())
		if werr := s.writeRecord(ctx, rec, pl); werr != nil {
			return resp, in, uuid.Nil, werr
		}
		return resp, in, id, verr
	}
	rec.Status, rec.Interp = "succeeded", in
	if err := s.writeRecord(ctx, rec, pl); err != nil {
		return resp, in, uuid.Nil, err
	}
	return resp, in, id, nil
}

type recordRow struct {
	ID            uuid.UUID
	OrgID         uuid.UUID
	Spec          callSpec
	RC            resolved
	Params        map[string]any
	Deterministic bool
	InputSHA      string
	Resp          Response
	Interp        interpretation
	Status        string
	ErrorCode     string
	Error         string
}

// writeRecord inserts the record and, when the organization keeps
// payloads, its encrypted payload.
func (s *Service) writeRecord(ctx context.Context, r recordRow, pl *payload) error {
	st := LoadEvidenceSettings(ctx, s.DB, r.OrgID)
	review := r.Spec.Review
	if review == "" || r.Status != "succeeded" {
		if r.Status != "succeeded" {
			review = ReviewNotRequired
		} else {
			review = ReviewPending
		}
	}
	steps := r.Interp.Steps
	if steps == nil {
		steps = []string{}
	}
	stepsJSON, _ := json.Marshal(steps)
	related := r.Spec.Subject.Related
	if related == nil {
		related = map[string]any{}
	}
	relJSON, _ := json.Marshal(related)
	paramsJSON, _ := json.Marshal(r.Params)
	var cmp []byte
	if r.Spec.Comparison != nil {
		cmp, _ = json.Marshal(r.Spec.Comparison)
	}
	var cvID *uuid.UUID
	if r.RC.CV.ID != uuid.Nil {
		v := r.RC.CV.ID
		cvID = &v
	}
	var respSHA string
	if len(r.Resp.JSON) > 0 {
		respSHA = shaHex(r.Resp.JSON)
	}
	keep := pl != nil && st.StorePayloads && s.Secrets != nil && s.Secrets.Keys != nil
	var expires *time.Time
	if keep {
		e := time.Now().Add(time.Duration(st.RetentionDays) * 24 * time.Hour)
		expires = &e
	}
	provider := r.RC.PV.Kind
	if provider == "" {
		provider = "unknown"
	}
	var sealed *crypto.Sealed
	var size int
	if keep {
		body, _ := json.Marshal(pl)
		sl, err := s.Secrets.Keys.Seal(body, payloadAAD(r.ID))
		if err != nil {
			return fmt.Errorf("ai: the evidence payload could not be encrypted: %w", err)
		}
		sealed, size = &sl, len(body)
	}
	err := db.InTx(ctx, s.DB, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `INSERT INTO ai_evidence_records (id, organization_id, task, operation, subject_kind, subject_id, finding_id, related,
			parent_id, config_version_id, provider, provider_location, model, model_reported, prompt_template, parameters, deterministic, sent_code,
			input_sha256, response_sha256, steps, conclusion, verdict, confidence, status, error_code, error, input_tokens, output_tokens,
			review_decision, replay_of, comparison, payload_expires_at, requested_by)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, $20, $21, $22, $23, $24, $25, $26, $27,
			$28, $29, $30, $31, $32, $33, $34)`,
			r.ID, r.OrgID, r.Spec.Task, r.Spec.Operation, r.Spec.Subject.Kind, r.Spec.Subject.ID, r.Spec.Subject.FindingID, relJSON,
			r.Spec.ParentID, cvID, provider, r.RC.Location, truncate(r.RC.CV.Model, 200), truncate(r.Resp.Model, 200), r.Spec.Template, paramsJSON,
			r.Deterministic, r.Spec.SentCode, r.InputSHA, respSHA, stepsJSON, clip(r.Interp.Conclusion, 7900), truncate(r.Interp.Verdict, 32),
			r.Interp.Confidence, r.Status, r.ErrorCode, truncate(r.Error, 1000), r.Resp.InputTokens, r.Resp.OutputTokens, review,
			r.Spec.ReplayOf, cmp, expires, r.Spec.Subject.RequestedBy); err != nil {
			return err
		}
		if sealed == nil {
			return nil
		}
		_, err := tx.Exec(ctx, `INSERT INTO ai_evidence_payloads (record_id, organization_id, ciphertext, wrapped_dek, key_version, size_bytes)
			VALUES ($1, $2, $3, $4, $5, $6)`, r.ID, r.OrgID, sealed.Ciphertext, sealed.WrappedDEK, sealed.KeyVersion, size)
		return err
	})
	if err != nil {
		return fmt.Errorf("ai: the evidence record could not be written: %w", err)
	}
	return nil
}
