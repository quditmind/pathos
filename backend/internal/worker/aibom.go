package worker

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"os"
	"path"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

// The AI-BOM (scanner ai-bom) inventories the AI parts of a repository and
// writes them as a CycloneDX 1.6 SBOM:
//
//   - AI and ML frameworks and LLM SDKs declared as dependencies
//     (requirements files, pyproject.toml, Pipfile, setup.py, package.json,
//     go.mod, pom.xml, build.gradle): components of type "framework"
//     (PyTorch, TensorFlow, LangChain, ...) or "library" (provider SDKs);
//   - model files by format (safetensors, GGUF, ONNX, PyTorch, Keras,
//     TensorFlow Lite, Core ML, pickled scikit-learn models in model
//     directories): "machine-learning-model" components with their SHA-256;
//   - Hugging Face model references in code (from_pretrained, pipeline,
//     hf_hub_download, SentenceTransformer): "machine-learning-model"
//     components with a pkg:huggingface purl, and hosted model names
//     (gpt-*, claude-*, gemini-*, ...);
//   - LLM APIs the code calls (provider endpoints and SDK imports):
//     CycloneDX services.
//
// Every entry lists the files it was found in (property pathos:evidence).
// It reads files only; nothing is executed. The API stores the entries as
// SBOM components of the repository (source "aibom").

const (
	aibomMaxFiles      = 50000
	aibomMaxTextBytes  = 2 << 20
	aibomMaxHashBytes  = 512 << 20
	aibomMaxComponents = 5000
	aibomMaxEvidence   = 10
)

// aiPackage is a known AI package: its display name, CycloneDX component
// type (framework or library) and, for SDKs, the provider whose API it
// calls.
type aiPackage struct {
	Name, Type, Provider string
}

// aiPackages by ecosystem (purl type) and lowercase package name.
var aiPackages = map[string]map[string]aiPackage{
	"pypi": {
		"torch": {"PyTorch", "framework", ""}, "tensorflow": {"TensorFlow", "framework", ""}, "tensorflow-cpu": {"TensorFlow", "framework", ""},
		"keras": {"Keras", "framework", ""}, "jax": {"JAX", "framework", ""}, "flax": {"Flax", "framework", ""},
		"scikit-learn": {"scikit-learn", "framework", ""}, "xgboost": {"XGBoost", "framework", ""}, "lightgbm": {"LightGBM", "framework", ""},
		"transformers": {"Hugging Face Transformers", "framework", ""}, "diffusers": {"Hugging Face Diffusers", "framework", ""},
		"sentence-transformers": {"Sentence Transformers", "framework", ""}, "huggingface-hub": {"Hugging Face Hub client", "library", "Hugging Face"},
		"accelerate": {"Hugging Face Accelerate", "framework", ""}, "peft": {"PEFT", "framework", ""}, "datasets": {"Hugging Face Datasets", "library", ""},
		"onnx": {"ONNX", "framework", ""}, "onnxruntime": {"ONNX Runtime", "framework", ""}, "vllm": {"vLLM", "framework", ""},
		"llama-cpp-python": {"llama.cpp (Python)", "framework", ""}, "langchain": {"LangChain", "framework", ""},
		"langchain-core": {"LangChain", "framework", ""}, "langchain-community": {"LangChain", "framework", ""}, "langgraph": {"LangGraph", "framework", ""},
		"llama-index": {"LlamaIndex", "framework", ""}, "llama-index-core": {"LlamaIndex", "framework", ""}, "haystack-ai": {"Haystack", "framework", ""},
		"semantic-kernel": {"Semantic Kernel", "framework", ""}, "dspy": {"DSPy", "framework", ""}, "crewai": {"CrewAI", "framework", ""},
		"autogen-agentchat": {"AutoGen", "framework", ""}, "litellm": {"LiteLLM", "library", ""}, "guidance": {"Guidance", "framework", ""},
		"openai": {"OpenAI Python SDK", "library", "OpenAI"}, "anthropic": {"Anthropic Python SDK", "library", "Anthropic"},
		"google-generativeai": {"Google Generative AI SDK", "library", "Google"}, "google-genai": {"Google Gen AI SDK", "library", "Google"},
		"cohere": {"Cohere Python SDK", "library", "Cohere"}, "mistralai": {"Mistral AI SDK", "library", "Mistral AI"},
		"groq": {"Groq SDK", "library", "Groq"}, "together": {"Together AI SDK", "library", "Together AI"}, "replicate": {"Replicate SDK", "library", "Replicate"},
		"ollama": {"Ollama Python client", "library", "Ollama"}, "langchain-openai": {"LangChain OpenAI", "library", "OpenAI"},
		"langchain-anthropic": {"LangChain Anthropic", "library", "Anthropic"}, "modelscan": {"ModelScan", "library", ""},
		"mlflow": {"MLflow", "framework", ""}, "ultralytics": {"Ultralytics YOLO", "framework", ""},
	},
	"npm": {
		"openai": {"OpenAI Node SDK", "library", "OpenAI"}, "@anthropic-ai/sdk": {"Anthropic TypeScript SDK", "library", "Anthropic"},
		"@google/generative-ai": {"Google Generative AI SDK", "library", "Google"}, "@google/genai": {"Google Gen AI SDK", "library", "Google"},
		"cohere-ai": {"Cohere SDK", "library", "Cohere"}, "@mistralai/mistralai": {"Mistral AI SDK", "library", "Mistral AI"},
		"groq-sdk": {"Groq SDK", "library", "Groq"}, "ollama": {"Ollama JS client", "library", "Ollama"},
		"langchain": {"LangChain.js", "framework", ""}, "@langchain/core": {"LangChain.js", "framework", ""}, "@langchain/openai": {"LangChain.js OpenAI", "library", "OpenAI"},
		"llamaindex": {"LlamaIndex.TS", "framework", ""}, "ai": {"Vercel AI SDK", "framework", ""}, "@ai-sdk/openai": {"Vercel AI SDK OpenAI provider", "library", "OpenAI"},
		"@ai-sdk/anthropic": {"Vercel AI SDK Anthropic provider", "library", "Anthropic"}, "@tensorflow/tfjs": {"TensorFlow.js", "framework", ""},
		"@tensorflow/tfjs-node": {"TensorFlow.js", "framework", ""}, "onnxruntime-node": {"ONNX Runtime", "framework", ""}, "onnxruntime-web": {"ONNX Runtime", "framework", ""},
		"@huggingface/inference": {"Hugging Face Inference client", "library", "Hugging Face"}, "@huggingface/transformers": {"Transformers.js", "framework", ""},
		"@xenova/transformers": {"Transformers.js", "framework", ""},
	},
	"golang": {
		"github.com/sashabaranov/go-openai": {"go-openai", "library", "OpenAI"}, "github.com/openai/openai-go": {"OpenAI Go SDK", "library", "OpenAI"},
		"github.com/anthropics/anthropic-sdk-go": {"Anthropic Go SDK", "library", "Anthropic"}, "github.com/tmc/langchaingo": {"LangChainGo", "framework", ""},
		"google.golang.org/genai": {"Google Gen AI Go SDK", "library", "Google"}, "github.com/google/generative-ai-go": {"Google Generative AI Go SDK", "library", "Google"},
		"github.com/ollama/ollama": {"Ollama", "library", "Ollama"}, "github.com/yalue/onnxruntime_go": {"ONNX Runtime (Go)", "framework", ""},
		"github.com/cohere-ai/cohere-go/v2": {"Cohere Go SDK", "library", "Cohere"},
	},
	"maven": {
		"dev.langchain4j:langchain4j": {"LangChain4j", "framework", ""}, "dev.langchain4j:langchain4j-open-ai": {"LangChain4j OpenAI", "library", "OpenAI"},
		"ai.djl:api": {"Deep Java Library", "framework", ""}, "org.deeplearning4j:deeplearning4j-core": {"Deeplearning4j", "framework", ""},
		"com.openai:openai-java": {"OpenAI Java SDK", "library", "OpenAI"}, "com.anthropic:anthropic-java": {"Anthropic Java SDK", "library", "Anthropic"},
		"org.springframework.ai:spring-ai-core": {"Spring AI", "framework", ""}, "com.microsoft.onnxruntime:onnxruntime": {"ONNX Runtime", "framework", ""},
	},
}

// llmEndpoints are provider API hosts; code that names one calls that API.
var llmEndpoints = []struct{ Host, Provider, Name string }{
	{"api.openai.com", "OpenAI", "OpenAI API"},
	{"openai.azure.com", "Microsoft", "Azure OpenAI Service"},
	{"api.anthropic.com", "Anthropic", "Anthropic API"},
	{"generativelanguage.googleapis.com", "Google", "Gemini API"},
	{"aiplatform.googleapis.com", "Google", "Vertex AI API"},
	{"bedrock-runtime", "Amazon Web Services", "Amazon Bedrock Runtime API"},
	{"api.mistral.ai", "Mistral AI", "Mistral AI API"},
	{"api.cohere.ai", "Cohere", "Cohere API"},
	{"api.cohere.com", "Cohere", "Cohere API"},
	{"api.groq.com", "Groq", "Groq API"},
	{"api.together.xyz", "Together AI", "Together AI API"},
	{"api.deepseek.com", "DeepSeek", "DeepSeek API"},
	{"api.x.ai", "xAI", "xAI API"},
	{"api.perplexity.ai", "Perplexity", "Perplexity API"},
	{"api-inference.huggingface.co", "Hugging Face", "Hugging Face Inference API"},
	{"router.huggingface.co", "Hugging Face", "Hugging Face Inference Providers"},
	{"openrouter.ai/api", "OpenRouter", "OpenRouter API"},
	{"api.replicate.com", "Replicate", "Replicate API"},
}

// modelFormats maps model file extensions to their format.
var modelFormats = map[string]string{
	".safetensors": "safetensors", ".gguf": "GGUF", ".ggml": "GGML", ".onnx": "ONNX", ".pt": "PyTorch", ".pth": "PyTorch",
	".ckpt": "checkpoint", ".h5": "Keras/HDF5", ".keras": "Keras", ".tflite": "TensorFlow Lite", ".mlmodel": "Core ML",
	".pb": "TensorFlow", ".joblib": "joblib", ".pkl": "pickle", ".pickle": "pickle", ".npz": "NumPy", ".llamafile": "llamafile",
}

var (
	hfRefRe = regexp.MustCompile(`(?:from_pretrained|hf_hub_download|snapshot_download|SentenceTransformer|AutoModel\w*\.from_pretrained|pipeline)\s*\(` +
		`[^)]{0,200}?["']([A-Za-z0-9][\w.-]{0,95}/[A-Za-z0-9][\w.-]{0,95})["']`)
	hostedModelRe = regexp.MustCompile(`["'` + "`" + `]((?:gpt-(?:3\.5|4|4o|4\.1|5)[\w.-]*)|(?:o[134](?:-mini|-preview|-pro)?)|(?:claude-[a-z0-9][\w.-]{2,60})|` +
		`(?:gemini-[0-9][\w.-]{1,60})|(?:mistral-(?:large|medium|small|tiny)[\w.-]*)|(?:command-r[\w.+-]*)|(?:text-embedding-[\w.-]+))["'` + "`" + `]`)
	// Only an exact pin (==) is recorded as the version; ranges are not.
	reqLineRe         = regexp.MustCompile(`^\s*([A-Za-z0-9][A-Za-z0-9._-]*)\s*(?:\[[^\]]*\])?\s*(?:===?\s*([0-9][^\s,;#]*))?`)
	quotedDepRe       = regexp.MustCompile(`["']([A-Za-z0-9][A-Za-z0-9._-]*)\s*(?:\[[^\]]*\])?\s*(?:===?\s*([0-9][^"',;\s]*))?[^"']*["']`)
	pipfileRe         = regexp.MustCompile(`^\s*"?([A-Za-z0-9][A-Za-z0-9._-]*)"?\s*=\s*(?:"(?:==)?([0-9][^"]*)"|"\*"|\{)`)
	npmExactVersionRe = regexp.MustCompile(`^[0-9]+\.[0-9]+\.[0-9]+[\w.+-]*$`)
	goRequireRe       = regexp.MustCompile(`^\s*(?:require\s+)?([a-z0-9.-]+\.[a-z]{2,}/[\w./-]+)\s+(v[0-9][\w.+-]*)`)
	mavenDepRe        = regexp.MustCompile(`(?s)<groupId>\s*([\w.-]+)\s*</groupId>\s*<artifactId>\s*([\w.-]+)\s*</artifactId>(?:\s*<version>\s*([\w.${}-]+)\s*</version>)?`)
	gradleDepRe       = regexp.MustCompile(`["']([\w.-]+):([\w.-]+)(?::([\w.-]+))?["']`)
	sdkImportRe       = regexp.MustCompile(`(?m)^\s*(?:from|import)\s+(openai|anthropic|cohere|mistralai|groq|google\.generativeai|google\.genai|ollama)\b|` +
		`require\(\s*["'](openai|@anthropic-ai/sdk|cohere-ai|@google/generative-ai|@mistralai/mistralai)["']\s*\)|` +
		`from\s+["'](openai|@anthropic-ai/sdk|cohere-ai|@google/generative-ai|@google/genai|@mistralai/mistralai)["']`)
)

// sdkImportProvider maps an imported SDK module to its provider API.
var sdkImportProvider = map[string]string{
	"openai": "OpenAI", "anthropic": "Anthropic", "@anthropic-ai/sdk": "Anthropic", "cohere": "Cohere", "cohere-ai": "Cohere",
	"mistralai": "Mistral AI", "@mistralai/mistralai": "Mistral AI", "groq": "Groq", "google.generativeai": "Google", "google.genai": "Google",
	"@google/generative-ai": "Google", "@google/genai": "Google", "ollama": "Ollama",
}

// providerAPI is the service recorded for a provider found through its SDK.
var providerAPI = map[string]string{
	"OpenAI": "OpenAI API", "Anthropic": "Anthropic API", "Cohere": "Cohere API", "Mistral AI": "Mistral AI API", "Groq": "Groq API",
	"Google": "Gemini API", "Ollama": "Ollama API (self-hosted)", "Hugging Face": "Hugging Face Inference API", "Together AI": "Together AI API",
	"Replicate": "Replicate API",
}

type cdxProperty struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

type cdxHash struct {
	Alg     string `json:"alg"`
	Content string `json:"content"`
}

type cdxComponent struct {
	Type       string        `json:"type"`
	BOMRef     string        `json:"bom-ref"`
	Group      string        `json:"group,omitempty"`
	Name       string        `json:"name"`
	Version    string        `json:"version,omitempty"`
	PURL       string        `json:"purl,omitempty"`
	Hashes     []cdxHash     `json:"hashes,omitempty"`
	Properties []cdxProperty `json:"properties,omitempty"`
}

type cdxService struct {
	BOMRef   string `json:"bom-ref"`
	Provider *struct {
		Name string `json:"name"`
	} `json:"provider,omitempty"`
	Name       string        `json:"name"`
	Endpoints  []string      `json:"endpoints,omitempty"`
	Properties []cdxProperty `json:"properties,omitempty"`
}

// aiBOM accumulates components and services with their evidence.
type aiBOM struct {
	comps    map[string]*cdxComponent
	evidence map[string][]string
	services map[string]*cdxService
	files    int
	skipped  int
}

func (b *aiBOM) addEvidence(ref, rel string) {
	ev := b.evidence[ref]
	for _, e := range ev {
		if e == rel {
			return
		}
	}
	if len(ev) < aibomMaxEvidence {
		b.evidence[ref] = append(ev, rel)
	}
}

func (b *aiBOM) component(c cdxComponent, rel string) {
	if cur, ok := b.comps[c.BOMRef]; ok {
		if cur.Version == "" && c.Version != "" {
			cur.Version = c.Version
			cur.PURL = c.PURL
		}
		b.addEvidence(c.BOMRef, rel)
		return
	}
	if len(b.comps) >= aibomMaxComponents {
		return
	}
	cc := c
	b.comps[c.BOMRef] = &cc
	b.addEvidence(c.BOMRef, rel)
}

func (b *aiBOM) service(provider, name, endpoint, rel string) {
	ref := "aibom:service:" + strings.ToLower(strings.ReplaceAll(name, " ", "-"))
	sv, ok := b.services[ref]
	if !ok {
		if len(b.services) >= 200 {
			return
		}
		sv = &cdxService{BOMRef: ref, Name: name}
		sv.Provider = &struct {
			Name string `json:"name"`
		}{provider}
		b.services[ref] = sv
	}
	if endpoint != "" && len(sv.Endpoints) < 10 {
		found := false
		for _, e := range sv.Endpoints {
			found = found || e == endpoint
		}
		if !found {
			sv.Endpoints = append(sv.Endpoints, endpoint)
		}
	}
	b.addEvidence(ref, rel)
}

// dependency records a declared dependency when it is a known AI package.
func (b *aiBOM) dependency(eco, name, version, rel string) {
	key := strings.ToLower(name)
	if eco == "pypi" {
		key = strings.NewReplacer("_", "-", ".", "-").Replace(key)
	}
	p, ok := aiPackages[eco][key]
	if !ok || p.Type == "" {
		return
	}
	purl := "pkg:" + eco + "/" + key
	if eco == "maven" {
		purl = "pkg:maven/" + strings.Replace(key, ":", "/", 1)
	}
	if eco == "npm" && strings.HasPrefix(key, "@") {
		purl = "pkg:npm/%40" + strings.TrimPrefix(key, "@")
	}
	if version != "" {
		purl += "@" + version
	}
	props := []cdxProperty{{"pathos:ai:display-name", p.Name}}
	if p.Provider != "" {
		props = append(props, cdxProperty{"pathos:ai:provider", p.Provider})
	}
	b.component(cdxComponent{Type: p.Type, BOMRef: "aibom:" + eco + ":" + key, Name: key, Version: version, PURL: purl, Properties: props}, rel)
	if p.Provider != "" && providerAPI[p.Provider] != "" {
		b.service(p.Provider, providerAPI[p.Provider], "", rel)
	}
}

// aibomSkipDir reports directories of third-party code and build output.
func aibomSkipDir(name string) bool {
	switch name {
	case ".git", "node_modules", "vendor", ".venv", "venv", "site-packages", "__pycache__", "dist", "build", ".tox", ".mypy_cache", "target":
		return true
	}
	return false
}

// runAIBOM writes the AI-BOM of src to out.
func runAIBOM(ctx context.Context, src, out, version string) error {
	b := &aiBOM{comps: map[string]*cdxComponent{}, evidence: map[string][]string{}, services: map[string]*cdxService{}}
	root, err := os.OpenRoot(src)
	if err != nil {
		return err
	}
	defer root.Close()
	_, err = walkFiles(ctx, src, func(rel string, size int64) error {
		for _, part := range strings.Split(path.Dir(rel), "/") {
			if aibomSkipDir(part) {
				return nil
			}
		}
		if b.files >= aibomMaxFiles {
			b.skipped++
			return nil
		}
		b.files++
		base := path.Base(rel)
		lower := strings.ToLower(base)
		if format, ok := modelFormats[path.Ext(lower)]; ok && modelFile(rel, lower) {
			b.modelFile(root, rel, format, size)
			return nil
		}
		if size > aibomMaxTextBytes {
			return nil
		}
		switch {
		case lower == "go.mod", lower == "package.json", lower == "pyproject.toml", lower == "pipfile", lower == "setup.py", lower == "setup.cfg",
			lower == "pom.xml", lower == "build.gradle", lower == "build.gradle.kts", lower == "environment.yml",
			strings.HasPrefix(lower, "requirements") && (strings.HasSuffix(lower, ".txt") || strings.HasSuffix(lower, ".in")):
			b.manifest(root, rel, lower)
		case sourceFile(lower):
			b.source(root, rel)
		}
		return nil
	})
	if err != nil {
		return err
	}
	return writeAIBOM(out, b, version)
}

// modelFile: pickles, NumPy archives and checkpoints are common data files;
// they count as models only in a directory or file named like one.
func modelFile(rel, lower string) bool {
	switch path.Ext(lower) {
	case ".pkl", ".pickle", ".npz", ".joblib", ".ckpt", ".pb", ".h5":
		l := strings.ToLower(rel)
		if path.Ext(lower) == ".pb" && lower == "saved_model.pb" {
			return true
		}
		return strings.Contains(l, "model") || strings.Contains(l, "weights") || strings.Contains(l, "checkpoint")
	}
	return true
}

func sourceFile(lower string) bool {
	switch path.Ext(lower) {
	case ".py", ".ipynb", ".js", ".mjs", ".cjs", ".ts", ".tsx", ".jsx", ".go", ".java", ".kt", ".rb", ".cs", ".php", ".rs", ".swift",
		".yaml", ".yml", ".toml", ".json", ".env.example":
		return true
	}
	return false
}

func (b *aiBOM) modelFile(root *os.Root, rel, format string, size int64) {
	c := cdxComponent{Type: "machine-learning-model", BOMRef: "aibom:file:" + rel, Name: rel,
		Properties: []cdxProperty{{"pathos:ai:model-format", format}, {"pathos:ai:size-bytes", itoa64(size)}}}
	if size <= aibomMaxHashBytes {
		if f, err := openIn(root, rel); err == nil {
			h := sha256.New()
			if _, err := io.Copy(h, f); err == nil {
				c.Hashes = []cdxHash{{Alg: "SHA-256", Content: hex.EncodeToString(h.Sum(nil))}}
			}
			_ = f.Close()
		}
	}
	b.component(c, rel)
}

func readSmall(root *os.Root, rel string) []byte {
	f, err := openIn(root, rel)
	if err != nil {
		return nil
	}
	defer f.Close()
	data, _ := io.ReadAll(io.LimitReader(f, aibomMaxTextBytes))
	return data
}

// manifest reads a dependency manifest.
func (b *aiBOM) manifest(root *os.Root, rel, lower string) {
	data := readSmall(root, rel)
	if data == nil {
		return
	}
	switch {
	case lower == "package.json":
		var pkg map[string]json.RawMessage
		if json.Unmarshal(data, &pkg) != nil {
			return
		}
		for _, k := range []string{"dependencies", "devDependencies", "optionalDependencies", "peerDependencies"} {
			var deps map[string]string
			if json.Unmarshal(pkg[k], &deps) != nil {
				continue
			}
			for n, v := range deps {
				if !npmExactVersionRe.MatchString(v) {
					v = "" // a range, tag or URL: the resolved version is in the lockfile
				}
				b.dependency("npm", n, v, rel)
			}
		}
	case lower == "go.mod":
		sc := bufio.NewScanner(strings.NewReader(string(data)))
		for sc.Scan() {
			if m := goRequireRe.FindStringSubmatch(sc.Text()); m != nil {
				b.dependency("golang", m[1], m[2], rel)
			}
		}
	case lower == "pom.xml":
		for _, m := range mavenDepRe.FindAllStringSubmatch(string(data), -1) {
			v := m[3]
			if strings.Contains(v, "$") {
				v = ""
			}
			b.dependency("maven", m[1]+":"+m[2], v, rel)
		}
	case strings.HasPrefix(lower, "build.gradle"):
		for _, m := range gradleDepRe.FindAllStringSubmatch(string(data), -1) {
			b.dependency("maven", m[1]+":"+m[2], m[3], rel)
		}
	case strings.HasPrefix(lower, "requirements"):
		sc := bufio.NewScanner(strings.NewReader(string(data)))
		for sc.Scan() {
			line := sc.Text()
			if strings.HasPrefix(strings.TrimSpace(line), "-") || strings.HasPrefix(strings.TrimSpace(line), "#") {
				continue
			}
			if m := reqLineRe.FindStringSubmatch(line); m != nil {
				b.dependency("pypi", m[1], m[2], rel)
			}
		}
	case lower == "pipfile":
		sc := bufio.NewScanner(strings.NewReader(string(data)))
		for sc.Scan() {
			if m := pipfileRe.FindStringSubmatch(sc.Text()); m != nil {
				b.dependency("pypi", m[1], m[2], rel)
			}
		}
	default: // pyproject.toml, setup.py, setup.cfg, environment.yml
		for _, m := range quotedDepRe.FindAllStringSubmatch(string(data), -1) {
			b.dependency("pypi", m[1], m[2], rel)
		}
		if lower == "setup.cfg" || lower == "environment.yml" {
			sc := bufio.NewScanner(strings.NewReader(string(data)))
			for sc.Scan() {
				line := strings.TrimLeft(strings.TrimSpace(sc.Text()), "- ")
				if m := reqLineRe.FindStringSubmatch(line); m != nil && strings.TrimSpace(line) != "" {
					b.dependency("pypi", m[1], m[2], rel)
				}
			}
		}
	}
}

// source looks for model references and LLM API calls in a source file.
func (b *aiBOM) source(root *os.Root, rel string) {
	data := readSmall(root, rel)
	if data == nil {
		return
	}
	text := string(data)
	for _, m := range hfRefRe.FindAllStringSubmatch(text, 50) {
		id := m[1]
		if strings.HasPrefix(id, ".") || strings.Contains(id, "..") {
			continue // a local path, not a hub reference
		}
		org, name, _ := strings.Cut(id, "/")
		b.component(cdxComponent{Type: "machine-learning-model", BOMRef: "aibom:huggingface:" + strings.ToLower(id), Group: org, Name: name,
			PURL: "pkg:huggingface/" + strings.ToLower(org) + "/" + name, Properties: []cdxProperty{{"pathos:ai:source", "Hugging Face Hub"}}}, rel)
	}
	for _, m := range hostedModelRe.FindAllStringSubmatch(text, 50) {
		id := m[1]
		provider := hostedProvider(id)
		b.component(cdxComponent{Type: "machine-learning-model", BOMRef: "aibom:hosted:" + strings.ToLower(id), Group: provider, Name: id,
			Properties: []cdxProperty{{"pathos:ai:source", "hosted model (" + provider + ")"}}}, rel)
	}
	lower := strings.ToLower(text)
	for _, e := range llmEndpoints {
		if strings.Contains(lower, e.Host) {
			b.service(e.Provider, e.Name, "https://"+e.Host, rel)
		}
	}
	for _, m := range sdkImportRe.FindAllStringSubmatch(text, 20) {
		mod := firstNonEmptyStr(m[1], m[2], m[3])
		if p := sdkImportProvider[mod]; p != "" {
			b.service(p, providerAPI[p], "", rel)
		}
	}
}

func hostedProvider(id string) string {
	switch {
	case strings.HasPrefix(id, "claude-"):
		return "Anthropic"
	case strings.HasPrefix(id, "gemini-"):
		return "Google"
	case strings.HasPrefix(id, "mistral-"):
		return "Mistral AI"
	case strings.HasPrefix(id, "command-r"):
		return "Cohere"
	}
	return "OpenAI"
}

func itoa64(n int64) string { return strconv.FormatInt(n, 10) }

// writeAIBOM writes the CycloneDX document.
func writeAIBOM(out string, b *aiBOM, version string) error {
	doc := map[string]any{
		"bomFormat": "CycloneDX", "specVersion": "1.6", "version": 1,
		"metadata": map[string]any{
			"timestamp": time.Now().UTC().Format(time.RFC3339),
			"tools":     map[string]any{"components": []map[string]string{{"type": "application", "name": "pathos-ai-bom", "version": version}}},
			"properties": []cdxProperty{{"pathos:ai-bom:files-read", itoa64(int64(b.files))},
				{"pathos:ai-bom:files-skipped", itoa64(int64(b.skipped))}},
		},
	}
	comps := make([]cdxComponent, 0, len(b.comps))
	for ref, c := range b.comps {
		for _, e := range b.evidence[ref] {
			c.Properties = append(c.Properties, cdxProperty{"pathos:evidence", e})
		}
		comps = append(comps, *c)
	}
	sort.Slice(comps, func(i, j int) bool { return comps[i].BOMRef < comps[j].BOMRef })
	svcs := make([]cdxService, 0, len(b.services))
	for ref, sv := range b.services {
		for _, e := range b.evidence[ref] {
			sv.Properties = append(sv.Properties, cdxProperty{"pathos:evidence", e})
		}
		svcs = append(svcs, *sv)
	}
	sort.Slice(svcs, func(i, j int) bool { return svcs[i].BOMRef < svcs[j].BOMRef })
	doc["components"], doc["services"] = comps, svcs
	raw, err := json.Marshal(doc)
	if err != nil {
		return err
	}
	return os.WriteFile(out, raw, 0o600)
}
