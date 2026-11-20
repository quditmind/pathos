package ai

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestSelfHostedRequestShape(t *testing.T) {
	var got map[string]any
	var auth string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/missing/chat/completions" {
			http.NotFound(w, r)
			return
		}
		auth = r.Header.Get("Authorization")
		_ = json.NewDecoder(r.Body).Decode(&got)
		_, _ = w.Write([]byte(`{"model":"qwen2.5-coder:7b","choices":[{"finish_reason":"stop","message":{"content":"{\"verdict\":\"true_positive\"}"}}],
			"usage":{"prompt_tokens":10,"completion_tokens":5}}`))
	}))
	defer srv.Close()

	if _, err := New(Config{Kind: SelfHosted}); err == nil {
		t.Fatal("a base URL is required")
	}
	if _, err := New(Config{Kind: OpenAI, BaseURL: srv.URL}); err == nil {
		t.Fatal("cloud providers still need a key")
	}
	p, err := New(Config{Kind: SelfHosted, BaseURL: srv.URL + "/v1"})
	if err != nil {
		t.Fatal(err)
	}
	resp, err := p.Review(context.Background(), Request{Model: "qwen2.5-coder:7b", System: "s", User: "u", Schema: map[string]any{"type": "object"}, MaxOutputTokens: 900})
	if err != nil {
		t.Fatal(err)
	}
	if auth != "" {
		t.Errorf("no Authorization header without a key, got %q", auth)
	}
	if got["max_tokens"] != float64(900) || got["max_completion_tokens"] != nil || got["temperature"] != float64(0) {
		t.Errorf("self-hosted request fields: %v", got)
	}
	if rf, _ := got["response_format"].(map[string]any); rf["type"] != "json_schema" {
		t.Errorf("structured output must be requested: %v", got["response_format"])
	}
	if resp.Model != "qwen2.5-coder:7b" || resp.OutputTokens != 5 {
		t.Errorf("response: %+v", resp)
	}

	// Without a limit in the request (finding reviews), a bounded default is
	// sent: a small local model otherwise generates until its context is full.
	got = nil
	if _, err := p.Review(context.Background(), Request{Model: "m", System: "s", User: "u", Schema: map[string]any{"type": "object"}}); err != nil {
		t.Fatal(err)
	}
	if got["max_tokens"] != float64(defaultSelfHostedOutputTokens) {
		t.Errorf("self-hosted default output limit: %v", got["max_tokens"])
	}
	oai, _ := New(Config{Kind: OpenAI, BaseURL: srv.URL + "/v1", APIKey: "k"})
	got = nil
	if _, err := oai.Review(context.Background(), Request{Model: "m", System: "s", User: "u", Schema: map[string]any{"type": "object"}}); err != nil {
		t.Fatal(err)
	}
	if got["max_completion_tokens"] != float64(defaultOutputTokens) || got["max_tokens"] != nil {
		t.Errorf("OpenAI default output limit: %v", got)
	}

	withKey, _ := New(Config{Kind: SelfHosted, BaseURL: srv.URL + "/v1", APIKey: "local-secret"})
	_ = withKey.Validate(context.Background(), "m")
	if auth != "Bearer local-secret" {
		t.Errorf("optional key should be sent when set, got %q", auth)
	}

	bad, _ := New(Config{Kind: SelfHosted, BaseURL: srv.URL + "/v1/missing"})
	if err := bad.Validate(context.Background(), "m"); err == nil || !strings.Contains(err.Error(), "ollama pull") {
		t.Errorf("404 should explain base URL / model pull: %v", err)
	}
}
