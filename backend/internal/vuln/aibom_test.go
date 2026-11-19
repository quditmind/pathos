package vuln

import "testing"

func TestParseAIBOM(t *testing.T) {
	raw := []byte(`{"bomFormat": "CycloneDX", "specVersion": "1.6", "components": [
	  {"type": "framework", "bom-ref": "aibom:pypi:torch", "name": "torch", "version": "2.5.1", "purl": "pkg:pypi/torch@2.5.1"},
	  {"type": "machine-learning-model", "bom-ref": "aibom:huggingface:meta-llama/llama-3.1-8b", "group": "meta-llama", "name": "Llama-3.1-8B",
	   "purl": "pkg:huggingface/meta-llama/Llama-3.1-8B"},
	  {"type": "machine-learning-model", "bom-ref": "aibom:file:models/m.onnx", "name": "models/m.onnx"}],
	  "services": [{"bom-ref": "aibom:service:openai-api", "name": "OpenAI API", "provider": {"name": "OpenAI"}},
	               {"bom-ref": "aibom:service:x", "name": ""}]}`)
	comps, err := ParseAIBOM(raw)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]string{}
	for _, c := range comps {
		got[c.Name] = c.Type + "|" + c.Version + "|" + c.PURL + "|" + c.Ref
		if c.Licenses == nil {
			t.Errorf("%s: licences must be an empty list", c.Name)
		}
	}
	want := map[string]string{
		"torch":                   "framework|2.5.1|pkg:pypi/torch@2.5.1|aibom:pypi:torch",
		"meta-llama/Llama-3.1-8B": "machine-learning-model||pkg:huggingface/meta-llama/Llama-3.1-8B|aibom:huggingface:meta-llama/llama-3.1-8b",
		"models/m.onnx":           "machine-learning-model|||aibom:file:models/m.onnx",
		"OpenAI API":              "service|||aibom:service:openai-api",
	}
	if len(got) != len(want) {
		t.Errorf("components: %v", got)
	}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("%s: %q, want %q", k, got[k], v)
		}
	}
	if _, err := ParseAIBOM([]byte(`{"bomFormat": "SPDX"}`)); err == nil {
		t.Error("not a CycloneDX document")
	}
}
