package worker

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"pathos/internal/scanners"
)

func TestAIBOM(t *testing.T) {
	src := t.TempDir()
	write := func(rel, body string) {
		p := filepath.Join(src, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write("requirements.txt", "torch==2.5.1\nopenai>=1.40.0\nrequests==2.32.0\n# transformers==4.0\n-r other.txt\n")
	write("pyproject.toml", "[project]\ndependencies = [\"langchain-core>=0.3\", \"numpy\"]\n")
	write("web/package.json", `{"dependencies": {"@anthropic-ai/sdk": "^0.30.1", "react": "18.3.1"}, "devDependencies": {"ai": "4.0.0"}}`)
	write("svc/go.mod", "module example.com/svc\n\ngo 1.24\n\nrequire (\n\tgithub.com/sashabaranov/go-openai v1.36.0\n\tgithub.com/google/uuid v1.6.0\n)\n")
	write("models/classifier/model.safetensors", "safetensors-bytes")
	write("data/cache.pkl", "not a model") // pickles count only in model directories
	write("app/infer.py", "from transformers import AutoModel\nm = AutoModel.from_pretrained(\"meta-llama/Llama-3.1-8B\")\n"+
		"import openai\nclient = openai.OpenAI(base_url=\"https://api.openai.com/v1\")\nclient.chat.completions.create(model=\"gpt-4o-mini\", messages=[])\n")
	write("app/claude.ts", "import Anthropic from '@anthropic-ai/sdk';\nconst r = await c.messages.create({model: 'claude-sonnet-4-5'});\n")
	write("node_modules/openai/package.json", `{"dependencies": {"torch": "1"}}`) // third-party code is skipped
	out := filepath.Join(t.TempDir(), "aibom.json")
	tool := nativeTools(Config{Version: "2.0.0"})[scanners.AIBOM]
	if s, err := tool.Run(context.Background(), RunInput{Src: src, Out: out}); err != nil || s != "" {
		t.Fatalf("run: %q %v", s, err)
	}
	if s, _ := tool.Run(context.Background(), RunInput{Src: src, Out: out, Target: &JobTarget{Kind: "artifact"}}); s == "" {
		t.Error("targets are skipped")
	}
	raw, _ := os.ReadFile(out)
	var doc struct {
		BOMFormat, SpecVersion string
		Components             []struct {
			Type, Name, Group, Version, PURL string
			BOMRef                           string `json:"bom-ref"`
			Hashes                           []struct{ Alg, Content string }
			Properties                       []struct{ Name, Value string }
		}
		Services []struct {
			Name     string
			Provider struct{ Name string }
		}
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	if doc.BOMFormat != "CycloneDX" || doc.SpecVersion != "1.6" {
		t.Fatalf("document: %s %s", doc.BOMFormat, doc.SpecVersion)
	}
	got := map[string]string{}
	evidence := map[string][]string{}
	for _, c := range doc.Components {
		id := strings.TrimPrefix(strings.Join([]string{c.Group, c.Name}, "/"), "/")
		got[id] = c.Type + " " + c.Version + " " + c.PURL
		for _, p := range c.Properties {
			if p.Name == "pathos:evidence" {
				evidence[id] = append(evidence[id], p.Value)
			}
		}
		if c.Type == "machine-learning-model" && c.Name == "models/classifier/model.safetensors" &&
			(len(c.Hashes) != 1 || c.Hashes[0].Alg != "SHA-256" || len(c.Hashes[0].Content) != 64) {
			t.Errorf("model hash: %+v", c)
		}
	}
	want := map[string]string{
		"torch":                               "framework 2.5.1 pkg:pypi/torch@2.5.1",
		"openai":                              "library  pkg:pypi/openai",
		"langchain-core":                      "framework  pkg:pypi/langchain-core",
		"@anthropic-ai/sdk":                   "library  pkg:npm/%40anthropic-ai/sdk",
		"ai":                                  "framework 4.0.0 pkg:npm/ai@4.0.0",
		"github.com/sashabaranov/go-openai":   "library v1.36.0 pkg:golang/github.com/sashabaranov/go-openai@v1.36.0",
		"models/classifier/model.safetensors": "machine-learning-model  ",
		"meta-llama/Llama-3.1-8B":             "machine-learning-model  pkg:huggingface/meta-llama/Llama-3.1-8B",
		"OpenAI/gpt-4o-mini":                  "machine-learning-model  ",
		"Anthropic/claude-sonnet-4-5":         "machine-learning-model  ",
	}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("%s: %q, want %q", k, got[k], v)
		}
	}
	for _, k := range []string{"requests", "numpy", "react", "github.com/google/uuid", "data/cache.pkl", "transformers"} {
		if _, ok := got[k]; ok {
			t.Errorf("%s is not an AI component", k)
		}
	}
	if !slices.Contains(evidence["openai"], "requirements.txt") || !slices.Contains(evidence["meta-llama/Llama-3.1-8B"], "app/infer.py") {
		t.Errorf("evidence: %v", evidence)
	}
	var services []string
	for _, s := range doc.Services {
		services = append(services, s.Provider.Name+": "+s.Name)
	}
	slices.Sort(services)
	if !slices.Equal(services, []string{"Anthropic: Anthropic API", "OpenAI: OpenAI API"}) {
		t.Errorf("services: %v", services)
	}
	// The AI-BOM is an inventory, not findings.
	if fs, err := scanners.Parse(scanners.AIBOM, raw); err != nil || len(fs) != 0 {
		t.Errorf("parse: %v %v", fs, err)
	}
}
