package scanners

// worker-ai (workers/ai): model files (ModelScan) and red-teaming of LLM
// endpoint targets (garak, promptfoo). The AI-BOM is built into every
// worker (pure Go, like licensecheck).

// AIBOM is the built-in AI bill of materials: AI frameworks, model files,
// model references and LLM API usage in a repository, recorded as SBOM
// components (CycloneDX types framework, library, machine-learning-model;
// LLM APIs as services). It produces no findings.
const AIBOM = "ai-bom"

func init() {
	llm := func(sc *Scanner) {
		sc.AdapterAvailable, sc.TargetOnly, sc.Targets = true, true, []string{"llm-endpoint"}
	}
	Catalog = append(Catalog,
		s("modelscan", "ModelScan", "ai", "Apache-2.0", "use", "ai", available,
			func(sc *Scanner) { sc.Targets = []string{"repository", "model"} }, format("json"), home("https://github.com/protectai/modelscan"),
			note("worker-ai image (tool manifest): unsafe operators in serialised models (pickle, PyTorch, Keras, TensorFlow) in repositories and uploaded model artifacts")),
		s("garak", "garak", "ai", "Apache-2.0", "use", "ai", llm, intrusive, format("jsonl"), home("https://github.com/NVIDIA/garak"),
			note("worker-ai image (tool manifest): LLM red-teaming probes (prompt injection, jailbreaks, encoding, markdown exfiltration) against an authorized LLM endpoint target; intrusive")),
		s("promptfoo", "promptfoo", "ai", "MIT", "use", "ai", llm, intrusive, format("json"), home("https://github.com/promptfoo/promptfoo"),
			note("worker-ai image (tool manifest): PATHOS red-team test suite (prompt injection, system prompt and secret disclosure, harmful instructions) run with promptfoo eval against an authorized LLM endpoint target; remote generation and telemetry off")),
	)
	Builtins = append(Builtins, Scanner{Key: AIBOM, Name: "AI-BOM (AI frameworks, models and LLM APIs)", Category: "sbom", License: "Apache-2.0",
		Decision: "use", Family: "core", Network: "none", AdapterAvailable: true, OutputFormat: "cyclonedx-json",
		Homepage: "https://github.com/quditmind/pathos", Targets: []string{"repository"},
		Notes: "Built into the worker: AI and ML frameworks, LLM SDKs, model files, Hugging Face model references and LLM API endpoints, recorded as SBOM components; opt-in per scan profile"})
	mbafAddScanTypeTools("ai", "modelscan", "garak", "promptfoo", AIBOM)
	mbafAddScanTypeTools("sbom", AIBOM)
}
