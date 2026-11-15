package ai

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// chatCompletions implements Provider for OpenAI and xAI, which share the
// Chat Completions wire format with strict JSON-schema response formats.
type chatCompletions struct {
	cfg  Config
	kind string
}

func (c *chatCompletions) Kind() string { return c.kind }

func (c *chatCompletions) client() *http.Client {
	if c.cfg.HTTP != nil {
		return c.cfg.HTTP
	}
	return &http.Client{Timeout: 3 * time.Minute}
}

type ccMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

func (c *chatCompletions) post(ctx context.Context, body any, out any) error {
	b, err := json.Marshal(body)
	if err != nil {
		return err
	}
	var lastErr error
	for attempt := 0; attempt < 3; attempt++ {
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimRight(c.cfg.BaseURL, "/")+"/chat/completions", bytes.NewReader(b))
		if err != nil {
			return err
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer "+c.cfg.APIKey)
		resp, err := c.client().Do(req)
		if err != nil {
			return fmt.Errorf("ai: %s request failed: %w", c.kind, err)
		}
		data, _ := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
		resp.Body.Close()
		switch {
		case resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden:
			return ErrAuth
		case resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode >= 500:
			lastErr = ErrRateLimited
			if resp.StatusCode >= 500 {
				lastErr = fmt.Errorf("ai: %s server error %d", c.kind, resp.StatusCode)
			}
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(time.Duration(1<<attempt) * time.Second):
			}
			continue
		case resp.StatusCode >= 300:
			return fmt.Errorf("ai: %s rejected the request (%d): check the model name and configuration", c.kind, resp.StatusCode)
		}
		return json.Unmarshal(data, out)
	}
	return lastErr
}

type ccResponse struct {
	Model   string `json:"model"`
	Choices []struct {
		FinishReason string `json:"finish_reason"`
		Message      struct {
			Content *string `json:"content"`
			Refusal *string `json:"refusal"`
		} `json:"message"`
	} `json:"choices"`
	Usage struct {
		PromptTokens     int64 `json:"prompt_tokens"`
		CompletionTokens int64 `json:"completion_tokens"`
	} `json:"usage"`
}

func (c *chatCompletions) Review(ctx context.Context, req Request) (Response, error) {
	if req.Model == "" {
		return Response{}, errors.New("ai: a model must be configured for " + c.kind)
	}
	body := map[string]any{
		"model": req.Model,
		"messages": []ccMessage{
			{Role: "system", Content: req.System},
			{Role: "user", Content: req.User},
		},
		"response_format": map[string]any{
			"type": "json_schema",
			"json_schema": map[string]any{"name": "finding_review", "strict": true, "schema": req.Schema},
		},
	}
	if req.MaxOutputTokens > 0 {
		body["max_completion_tokens"] = req.MaxOutputTokens
	}
	var out ccResponse
	if err := c.post(ctx, body, &out); err != nil {
		return Response{}, err
	}
	if len(out.Choices) == 0 {
		return Response{}, fmt.Errorf("ai: %s returned no choices", c.kind)
	}
	ch := out.Choices[0]
	if ch.Message.Refusal != nil && *ch.Message.Refusal != "" {
		return Response{}, ErrRefused
	}
	if ch.FinishReason == "length" {
		return Response{}, ErrTruncated
	}
	if ch.Message.Content == nil {
		return Response{}, fmt.Errorf("ai: %s returned an empty message", c.kind)
	}
	return Response{JSON: []byte(*ch.Message.Content), Model: out.Model,
		InputTokens: out.Usage.PromptTokens, OutputTokens: out.Usage.CompletionTokens}, nil
}

func (c *chatCompletions) Validate(ctx context.Context, model string) error {
	if model == "" {
		return errors.New("ai: a model must be configured for " + c.kind)
	}
	var out ccResponse
	return c.post(ctx, map[string]any{
		"model": model, "max_completion_tokens": 16,
		"messages": []ccMessage{{Role: "user", Content: "Reply with OK."}},
	}, &out)
}
