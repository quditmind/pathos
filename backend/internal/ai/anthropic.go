package ai

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/anthropics/anthropic-sdk-go/v2"
	"github.com/anthropics/anthropic-sdk-go/v2/option"
)

// anthropicProvider calls the Claude Messages API through the official SDK.
type anthropicProvider struct {
	client anthropic.Client
}

func newAnthropic(cfg Config) *anthropicProvider {
	opts := []option.RequestOption{option.WithAPIKey(cfg.APIKey), option.WithMaxRetries(2)}
	if cfg.BaseURL != "" {
		opts = append(opts, option.WithBaseURL(cfg.BaseURL))
	}
	if cfg.HTTP != nil {
		opts = append(opts, option.WithHTTPClient(cfg.HTTP))
	}
	return &anthropicProvider{client: anthropic.NewClient(opts...)}
}

func (a *anthropicProvider) Kind() string { return Anthropic }

func effortOf(e string) anthropic.BetaOutputConfigEffort {
	switch e {
	case "low":
		return anthropic.BetaOutputConfigEffortLow
	case "high":
		return anthropic.BetaOutputConfigEffortHigh
	default:
		return anthropic.BetaOutputConfigEffortMedium
	}
}

func (a *anthropicProvider) Review(ctx context.Context, req Request) (Response, error) {
	if req.Model == "" {
		req.Model = DefaultModel(Anthropic)
	}
	if req.MaxOutputTokens == 0 {
		req.MaxOutputTokens = 16000
	}
	schema, err := json.Marshal(req.Schema)
	if err != nil {
		return Response{}, err
	}
	params := anthropic.BetaMessageNewParams{
		Model:     anthropic.Model(req.Model),
		MaxTokens: int64(req.MaxOutputTokens),
		// The static instructions are cached; per-finding evidence follows.
		System: []anthropic.BetaTextBlockParam{{
			Text:         req.System,
			CacheControl: anthropic.NewBetaCacheControlEphemeralParam(),
		}},
		Messages: []anthropic.BetaMessageParam{
			anthropic.NewBetaUserMessage(anthropic.NewBetaTextBlock(req.User)),
		},
		OutputConfig: anthropic.BetaOutputConfigParam{
			Effort: effortOf(req.Effort),
			Format: anthropic.BetaJSONOutputFormatParam{Schema: json.RawMessage(schema)},
		},
	}
	// Opt into server-side refusal fallbacks on models that support them:
	// a policy decline is re-served by Anthropic's recommended model.
	if supportsFallbacks(req.Model) {
		params.Betas = []anthropic.AnthropicBeta{anthropic.AnthropicBetaServerSideFallback2026_07_01}
		params.Fallbacks = anthropic.BetaFallbacksParamOfDefault()
	}
	msg, err := a.client.Beta.Messages.New(ctx, params)
	if err != nil {
		return Response{}, mapAnthropicError(err)
	}
	switch msg.StopReason {
	case anthropic.BetaStopReasonRefusal:
		return Response{}, ErrRefused
	case anthropic.BetaStopReasonMaxTokens:
		return Response{}, ErrTruncated
	}
	var text strings.Builder
	for _, block := range msg.Content {
		if t, ok := block.AsAny().(anthropic.BetaTextBlock); ok {
			text.WriteString(t.Text)
		}
	}
	return Response{
		JSON: []byte(text.String()), Model: string(msg.Model),
		InputTokens: msg.Usage.InputTokens, OutputTokens: msg.Usage.OutputTokens,
		CacheReadTok: msg.Usage.CacheReadInputTokens,
	}, nil
}

func supportsFallbacks(model string) bool {
	switch model {
	case "claude-opus-5-5", "claude-opus-5", "claude-fable-5-2", "claude-fable-5-1", "claude-sonnet-5-5":
		return true
	}
	return false
}

func mapAnthropicError(err error) error {
	var apierr *anthropic.Error
	if errors.As(err, &apierr) {
		switch apierr.StatusCode {
		case http.StatusUnauthorized, http.StatusForbidden:
			return ErrAuth
		case http.StatusTooManyRequests, 529:
			return ErrRateLimited
		case http.StatusBadRequest, http.StatusNotFound:
			// Do not echo request bodies; the status and type are enough.
			return fmt.Errorf("ai: Anthropic rejected the request (%d): check the model name and configuration", apierr.StatusCode)
		}
		return fmt.Errorf("ai: Anthropic API error %d", apierr.StatusCode)
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return fmt.Errorf("ai: request timed out")
	}
	return fmt.Errorf("ai: Anthropic request failed: %w", err)
}

func (a *anthropicProvider) Validate(ctx context.Context, model string) error {
	if model == "" {
		model = DefaultModel(Anthropic)
	}
	_, err := a.client.Beta.Messages.New(ctx, anthropic.BetaMessageNewParams{
		Model:        anthropic.Model(model),
		MaxTokens:    16,
		Messages:     []anthropic.BetaMessageParam{anthropic.NewBetaUserMessage(anthropic.NewBetaTextBlock("Reply with OK."))},
		OutputConfig: anthropic.BetaOutputConfigParam{Effort: anthropic.BetaOutputConfigEffortLow},
	})
	if err != nil {
		return mapAnthropicError(err)
	}
	return nil
}
