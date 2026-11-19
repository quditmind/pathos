package ai

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/anthropics/anthropic-sdk-go/v2"
	"github.com/google/uuid"
)

// ModelLister lists the models a credential can use. It is the Connectors
// health check of an AI provider: it proves reachability and the key
// without generating tokens (no cost).
type ModelLister interface {
	Models(ctx context.Context) (int, error)
}

// Models implements ModelLister (GET {base}/models, OpenAI-compatible).
func (c *chatCompletions) Models(ctx context.Context) (int, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimRight(c.cfg.BaseURL, "/")+"/models", nil)
	if err != nil {
		return 0, errors.New("ai: invalid base URL")
	}
	req.Header.Set("Accept", "application/json")
	if c.cfg.APIKey != "" {
		req.Header.Set("Authorization", "Bearer "+c.cfg.APIKey)
	}
	resp, err := c.client().Do(req)
	if err != nil {
		var ue *url.Error
		if errors.As(err, &ue) {
			err = ue.Err
		}
		return 0, fmt.Errorf("ai: %s request failed: %w", c.kind, err)
	}
	defer resp.Body.Close()
	switch {
	case resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden:
		return 0, ErrAuth
	case resp.StatusCode == http.StatusTooManyRequests:
		return 0, ErrRateLimited
	case resp.StatusCode != http.StatusOK:
		return 0, &ProviderStatusError{Status: resp.StatusCode, Kind: c.kind}
	}
	var out struct {
		Data []json.RawMessage `json:"data"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 8<<20)).Decode(&out); err != nil {
		return 0, fmt.Errorf("ai: %s returned an unreadable model list", c.kind)
	}
	return len(out.Data), nil
}

// Models implements ModelLister (Models API, first page).
func (a *anthropicProvider) Models(ctx context.Context) (int, error) {
	page, err := a.client.Models.List(ctx, anthropic.ModelListParams{Limit: anthropic.Int(100)})
	if err != nil {
		var apierr *anthropic.Error
		if errors.As(err, &apierr) && apierr.StatusCode != http.StatusUnauthorized && apierr.StatusCode != http.StatusForbidden &&
			apierr.StatusCode != http.StatusTooManyRequests && apierr.StatusCode != 529 {
			return 0, &ProviderStatusError{Status: apierr.StatusCode, Kind: Anthropic}
		}
		return 0, mapAnthropicError(err)
	}
	return len(page.Data), nil
}

// ProviderStatusError is an unexpected HTTP status of a provider.
type ProviderStatusError struct {
	Status int
	Kind   string
}

func (e *ProviderStatusError) Error() string {
	if e.Kind == SelfHosted && e.Status == http.StatusNotFound {
		return "ai: the self-hosted server returned 404 for /models: check the base URL (it usually ends in /v1)"
	}
	return fmt.Sprintf("ai: %s answered HTTP %d", e.Kind, e.Status)
}

// ListModels runs the model-list check of a configured provider (the
// Connectors health check). It returns the number of models listed.
func (s *Service) ListModels(ctx context.Context, orgID, id uuid.UUID) (int, error) {
	pvs, err := s.loadProviders(ctx, orgID, &id)
	if err != nil {
		return 0, err
	}
	if len(pvs) == 0 {
		return 0, ErrNotConfigured
	}
	prov, err := s.provider(ctx, orgID, pvs[0])
	if err != nil {
		return 0, err
	}
	ml, ok := prov.(ModelLister)
	if !ok {
		return 0, errors.New("ai: this provider cannot list models")
	}
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	return ml.Models(ctx)
}
