-- Local / self-hosted AI and single-person installs.
--   * ai_providers.kind 'self_hosted': any OpenAI-compatible server (Ollama,
--     vLLM, LM Studio, llama.cpp). The API key is optional.
--   * ai_configuration_versions.allow_self_approval: lets the person who
--     submitted an interactive (MCP) review approve it. Off by default;
--     meant for one-person installations. Versioned like the rest of the
--     configuration, so enabling it is part of the change history.

-- +goose Up
ALTER TABLE ai_providers DROP CONSTRAINT IF EXISTS ai_providers_kind_check;
ALTER TABLE ai_providers ADD CONSTRAINT ai_providers_kind_check CHECK (kind IN ('anthropic', 'openai', 'xai', 'self_hosted'));
ALTER TABLE ai_providers ALTER COLUMN secret_id DROP NOT NULL;
ALTER TABLE ai_providers ADD CONSTRAINT ai_providers_key_ck CHECK (kind = 'self_hosted' OR secret_id IS NOT NULL);
ALTER TABLE ai_configuration_versions ADD COLUMN allow_self_approval boolean NOT NULL DEFAULT false;

-- +goose Down
ALTER TABLE ai_configuration_versions DROP COLUMN IF EXISTS allow_self_approval;
ALTER TABLE ai_providers DROP CONSTRAINT IF EXISTS ai_providers_key_ck;
DELETE FROM ai_providers WHERE kind = 'self_hosted';
ALTER TABLE ai_providers ALTER COLUMN secret_id SET NOT NULL;
ALTER TABLE ai_providers DROP CONSTRAINT IF EXISTS ai_providers_kind_check;
ALTER TABLE ai_providers ADD CONSTRAINT ai_providers_kind_check CHECK (kind IN ('anthropic', 'openai', 'xai'));
