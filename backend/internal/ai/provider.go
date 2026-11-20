// Package ai implements AI-assisted finding review: provider adapters
// (Anthropic, OpenAI, xAI), evidence redaction, prompt-injection-resistant
// prompt assembly, strict output validation and the review pipeline.
//
// AI is never on the critical path: when no provider is configured or a
// call fails, findings stay pending and scanning continues.
package ai

import (
	"context"
	"errors"
	"net/http"
)

// Provider kinds.
const (
	Anthropic = "anthropic"
	OpenAI    = "openai"
	XAI       = "xai"
	// SelfHosted is any OpenAI-compatible server run by the organization
	// (Ollama, vLLM, LM Studio, llama.cpp server). The key is optional.
	SelfHosted = "self_hosted"
)

// Request is one review call.
type Request struct {
	Model string
	// Effort is a provider-neutral depth hint: low | medium | high.
	Effort string
	// System is the static instruction block (cacheable).
	System string
	// User carries the fenced, redacted evidence.
	User string
	// Schema is the JSON schema the output must follow.
	Schema map[string]any
	// MaxOutputTokens bounds the response.
	MaxOutputTokens int
	// Temperature and Seed make an answer repeatable where the provider
	// honours them (self-hosted servers); nil leaves the provider default.
	Temperature *float64
	Seed        *int
}

// Response is the raw provider result before validation.
type Response struct {
	JSON         []byte
	Model        string // model version reported by the provider
	InputTokens  int64
	OutputTokens int64
	CacheReadTok int64
}

// Provider is implemented per vendor. The review pipeline never imports a
// vendor package directly.
type Provider interface {
	Kind() string
	Review(ctx context.Context, req Request) (Response, error)
	// Validate checks credentials with a minimal request.
	Validate(ctx context.Context, model string) error
}

var (
	// ErrRefused means the provider declined to answer (safety refusal).
	ErrRefused = errors.New("ai: the provider declined to review this finding")
	// ErrRateLimited is retryable.
	ErrRateLimited = errors.New("ai: provider rate limit reached")
	// ErrAuth means the API key was rejected.
	ErrAuth = errors.New("ai: provider rejected the API key")
	// ErrTruncated means the output hit the token limit.
	ErrTruncated = errors.New("ai: response truncated at the output token limit")
)

// Config builds a provider.
type Config struct {
	Kind    string
	APIKey  string
	BaseURL string // optional override (gateway / regional endpoint)
	HTTP    *http.Client
}

// New returns a provider for cfg.
func New(cfg Config) (Provider, error) {
	if cfg.APIKey == "" && cfg.Kind != SelfHosted {
		return nil, errors.New("ai: API key required")
	}
	switch cfg.Kind {
	case SelfHosted:
		if cfg.BaseURL == "" {
			return nil, errors.New("ai: a base URL is required for a self-hosted provider")
		}
		return &chatCompletions{cfg: cfg, kind: SelfHosted}, nil
	case Anthropic:
		return newAnthropic(cfg), nil
	case OpenAI:
		if cfg.BaseURL == "" {
			cfg.BaseURL = "https://api.openai.com/v1"
		}
		return &chatCompletions{cfg: cfg, kind: OpenAI}, nil
	case XAI:
		if cfg.BaseURL == "" {
			cfg.BaseURL = "https://api.x.ai/v1"
		}
		return &chatCompletions{cfg: cfg, kind: XAI}, nil
	}
	return nil, errors.New("ai: unknown provider " + cfg.Kind)
}

// DefaultModel returns the suggested model for a provider. Only Anthropic
// has a built-in default; OpenAI and xAI models must be chosen explicitly
// because their catalogs change independently of PATHOS releases.
func DefaultModel(kind string) string {
	if kind == Anthropic {
		return "claude-opus-5-5"
	}
	return ""
}
