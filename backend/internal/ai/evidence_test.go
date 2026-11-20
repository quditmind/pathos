package ai

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"testing"
)

// callSite is a function that calls a model or writes an evidence record.
type callSite struct{ file, fn string }

func (c callSite) String() string { return c.file + ":" + c.fn }

// scanBackend parses every non-test Go file of the backend and reports
// the functions that (1) call a provider's Review (a model call), (2) call
// Service.invoke and (3) call Service.writeRecord.
func scanBackend(t *testing.T) (reviews, invokes, writes []callSite) {
	t.Helper()
	root := "../.."
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if name := d.Name(); name == "testdata" || name == "node_modules" || name == "test" {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		f, err := parser.ParseFile(token.NewFileSet(), path, nil, parser.SkipObjectResolution)
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(root, path)
		for _, decl := range f.Decls {
			fd, ok := decl.(*ast.FuncDecl)
			if !ok || fd.Body == nil {
				continue
			}
			name := fd.Name.Name
			if fd.Recv != nil && len(fd.Recv.List) > 0 {
				if st, ok := fd.Recv.List[0].Type.(*ast.StarExpr); ok {
					if id, ok := st.X.(*ast.Ident); ok {
						name = id.Name + "." + name
					}
				}
			}
			ast.Inspect(fd.Body, func(n ast.Node) bool {
				call, ok := n.(*ast.CallExpr)
				if !ok {
					return true
				}
				sel, ok := call.Fun.(*ast.SelectorExpr)
				if !ok {
					return true
				}
				site := callSite{filepath.ToSlash(rel), name}
				switch {
				// Provider.Review(ctx, Request): the only way PATHOS asks a
				// model for an answer.
				case sel.Sel.Name == "Review" && len(call.Args) == 2:
					reviews = append(reviews, site)
				case sel.Sel.Name == "invoke" && len(call.Args) == 4:
					invokes = append(invokes, site)
				case sel.Sel.Name == "writeRecord" && len(call.Args) == 3:
					writes = append(writes, site)
				}
				return true
			})
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return reviews, invokes, writes
}

func names(cs []callSite) []string {
	out := []string{}
	for _, c := range cs {
		if s := c.String(); !slices.Contains(out, s) {
			out = append(out, s)
		}
	}
	sort.Strings(out)
	return out
}

// TestEveryModelCallWritesAnEvidenceRecord enumerates the AI call sites of
// the backend and fails when one does not write an AI evidence record:
// every provider Review call must be inside Service.invoke (which writes
// the record for every outcome), and every caller of invoke or writeRecord
// must be a known path exercised by the integration test
// (test/integration/ai_evidence_test.go, aiEvidenceCallPaths).
func TestEveryModelCallWritesAnEvidenceRecord(t *testing.T) {
	reviews, invokes, writes := scanBackend(t)
	if got := names(reviews); !slices.Equal(got, []string{"internal/ai/evidence.go:Service.invoke"}) {
		t.Fatalf("a model is called outside Service.invoke, so no evidence record would be written: %v", got)
	}
	// The known AI call paths (functions that call invoke) and the records
	// written without a model call (an MCP review a person produced with
	// their own assistant; the per-item records of threat suggestions).
	wantInvokes := []string{
		"internal/ai/assist.go:Service.Assist",
		"internal/ai/correlation.go:Service.ExplainCorrelation",
		"internal/ai/evidence_api.go:Service.replayEvidence",
		"internal/ai/fix.go:Service.ProposeFix",
		"internal/ai/generate.go:Service.Generate",
		"internal/ai/service.go:Service.review",
		"internal/ai/suggest.go:Service.SuggestThreats",
		"internal/ai/troubleshoot.go:Service.Troubleshoot",
	}
	wantWrites := []string{
		"internal/ai/evidence.go:Service.invoke",
		"internal/ai/service.go:Service.SubmitInteractive",
		"internal/ai/suggest.go:Service.SuggestThreats",
	}
	if got := names(invokes); !slices.Equal(got, wantInvokes) {
		t.Errorf("AI call paths changed: got %v, want %v; add the new path to this list and to aiEvidenceCallPaths in the integration test", got, wantInvokes)
	}
	if got := names(writes); !slices.Equal(got, wantWrites) {
		t.Errorf("evidence writers changed: got %v, want %v", got, wantWrites)
	}
	// Every path must be exercised by the integration test with a stub
	// provider that checks the record.
	src, err := os.ReadFile("../../test/integration/ai_evidence_test.go")
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range append(wantInvokes, wantWrites...) {
		fn := p[strings.Index(p, ":")+1:]
		if fn == "Service.invoke" {
			continue
		}
		if !strings.Contains(string(src), `"`+fn+`"`) {
			t.Errorf("%s has no record-completeness case in test/integration/ai_evidence_test.go (aiEvidenceCallPaths)", p)
		}
	}
}

func TestDeterminismAndLocation(t *testing.T) {
	if Location(SelfHosted) != LocationLocal || Location(Anthropic) != LocationCloud || Location(OpenAI) != LocationCloud ||
		Location(XAI) != LocationCloud || Location("mcp") != LocationUser {
		t.Fatal("provider locations")
	}
	if d, note := Determinism(SelfHosted); !d || !strings.Contains(note, "temperature 0") {
		t.Errorf("a self-hosted model is called deterministically: %v %q", d, note)
	}
	for _, k := range []string{Anthropic, OpenAI, XAI} {
		if d, note := Determinism(k); d || !strings.Contains(note, "cannot") && !strings.Contains(note, "can differ") {
			t.Errorf("%s must say it cannot promise the same answer: %v %q", k, d, note)
		}
	}
	if d, _ := Determinism("mcp"); d {
		t.Error("an external review is not replayable")
	}
}

func TestInterpreters(t *testing.T) {
	cases := map[string]struct {
		raw     string
		verdict string
		steps   int
	}{
		"finding_validation@1": {`{"verdict":"false_positive","confidence":0.8,"suggested_severity":"low","rationale":"constant","remediation":"","evidence_cited":["line 3"]}`, FalsePositive, 1},
		"assist@1":             {`{"summary":"s","points":["a","b"],"references":[],"code":""}`, "suggested", 2},
		"fix_proposal@1":       {`{"summary":"fix","diff":"--- a/x.py\n+++ b/x.py\n@@ -1 +1 @@\n-a\n+b\n"}`, "proposed", 1},
		"troubleshooting@1":    {`{"likely_cause":"c","probable_causes":[],"actions":["do"],"verify":[]}`, "answered", 1},
		"generate@1":           {`{"answer":"42","cited_findings":[],"follow_up_questions":["why?"]}`, "answered", 1},
		"correlation@1":        {`{"priority":"high","exploitability":"not_exploitable","confidence":0.6,"explanation":"unreachable","reasoning":["no route"]}`, NotExploitable, 1},
		"threat_suggestion@1":  {`{"threats":[{"title":"t","description":"d","category":"spoofing","severity":"high","confidence":0.5,"element_keys":["k"],"mitigation":"m","reasoning":["r"]}]}`, "suggested", 1},
	}
	for tmpl, c := range cases {
		in, err := interpreters[tmpl]([]byte(c.raw))
		if err != nil {
			t.Errorf("%s: %v", tmpl, err)
			continue
		}
		if in.Verdict != c.verdict || len(in.Steps) != c.steps || in.Conclusion == "" {
			t.Errorf("%s: %+v", tmpl, in)
		}
		if _, err := interpreters[tmpl]([]byte(`{"unexpected":true}`)); err == nil && tmpl != "generate@1" {
			t.Errorf("%s accepts output outside the schema", tmpl)
		}
	}
	if len(interpreters) != len(cases) {
		t.Errorf("every template needs a case: %d templates, %d cases", len(interpreters), len(cases))
	}
}

func TestReplayComparison(t *testing.T) {
	c := 0.9
	orig := EvidenceRecord{Verdict: FalsePositive, Conclusion: "false_positive: constant", Steps: []string{"line 3"}, ResponseSHA256: shaHex([]byte(`{"a":1}`)),
		Deterministic: true, ModelReported: "m1", Confidence: &c}
	same := compare(orig, Response{JSON: []byte(`{"a":1}`), Model: "m1"}, interpretation{Verdict: FalsePositive, Conclusion: "x", Steps: []string{"line 3"}})
	if same["same_conclusion"] != true || same["identical_response"] != true || same["model_changed"] != false {
		t.Errorf("same answer: %v", same)
	}
	diff := compare(orig, Response{JSON: []byte(`{"a":2}`), Model: "m2"}, interpretation{Verdict: TruePositive, Steps: []string{"line 4"}})
	if diff["same_conclusion"] != false || diff["identical_response"] != false || diff["model_changed"] != true ||
		len(diff["steps_added"].([]string)) != 1 || len(diff["steps_removed"].([]string)) != 1 {
		t.Errorf("different answer: %v", diff)
	}
}

func TestTasksCodeBearingDefaults(t *testing.T) {
	code := map[string]bool{}
	for _, task := range Tasks {
		code[task.Key] = task.CodeBearing
	}
	for _, k := range []string{TaskFindingValidation, TaskFixProposal, TaskThreatSuggestion, TaskTroubleshooting, TaskCorrelation, TaskGraphInference} {
		if !code[k] {
			t.Errorf("%s carries code and must default to a local model", k)
		}
	}
	if code[TaskAnalyst] || code[TaskReport] {
		t.Error("analyst and report tasks send metadata only")
	}
}
