import { afterEach, describe, expect, it, vi } from "vitest";
import { screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { jsonResponse, mockApi, renderApp } from "@/test/harness";
import type { AIConfiguration } from "@/api/types";
import { AIEvidencePanel } from "./AIEvidencePanel";
import { AIEvidencePage } from "./AIEvidencePage";
import { CorrelationSection } from "./CorrelationSection";
import { ModelPerTask } from "./ModelPerTask";
import type { Correlation, EvidenceRecord, TaskAssignment } from "./evidence";
import { ThreatModelView } from "@/features/threatmodels/ThreatModelPage";
import type { ThreatModel } from "@/features/threatmodels/api";

// Example data for tests only (labelled): no real finding, model or person.
const F1 = "0190c000-0000-7000-8000-000000000f01";
const M1 = "0190c000-0000-7000-8000-0000000000a1";
const meta = (flags: Record<string, boolean>) => () => ({ product: "PATHOS", vendor: "Quditmind", version: "3.0.0-test", feature_flags: flags });

const rec = (over: Partial<EvidenceRecord> = {}): EvidenceRecord => ({
  id: "r1",
  task: "finding_validation",
  task_label: "Triage and review",
  operation: "ai_review",
  subject_kind: "finding",
  subject_id: F1,
  finding_id: F1,
  related: { findings: [F1] },
  parent_id: null,
  config_version_id: "cv1",
  provider: "self_hosted",
  provider_location: "local",
  model: "example-local-model",
  model_reported: "example-local-model",
  model_digest: "",
  prompt_template: "finding_validation@1",
  parameters: { temperature: 0 },
  deterministic: true,
  determinism_note: "Self-hosted model called with temperature 0 and a fixed seed.",
  sent_code: true,
  input_sha256: "a".repeat(64),
  response_sha256: "b".repeat(64),
  steps: ["line 10: eval(x)"],
  conclusion: "false_positive: the input is a constant",
  verdict: "false_positive",
  confidence: 0.82,
  status: "succeeded",
  error_code: "",
  error: "",
  input_tokens: 1,
  output_tokens: 1,
  review_decision: "pending",
  reviewer_id: null,
  reviewer_name: null,
  reviewed_at: null,
  review_note: "",
  replay_of: null,
  comparison: null,
  payload_expires_at: null,
  payload_purged_at: null,
  payload_available: true,
  requested_by: null,
  requested_by_name: null,
  created_at: "2026-11-20T10:00:00Z",
  label: "ai_inferred",
  confirmed: false,
  proposes_suppression: true,
  replayable: true,
  can_review: true,
  ...over,
});

afterEach(() => vi.unstubAllGlobals());

describe("AIEvidencePanel", () => {
  it("is hidden when the flag is off", async () => {
    mockApi({ "GET /api/v1/meta": meta({ ai_intelligence: false }) });
    const { container } = renderApp(<AIEvidencePanel findingId={F1} />, { permissions: ["ai.evidence_read"] });
    await new Promise((r) => setTimeout(r, 20));
    expect(container.querySelector("[aria-label='AI evidence']")).toBeNull();
  });

  it("labels a conclusion AI-inferred until a person accepts it, and says it only proposes a suppression", async () => {
    const { calls } = mockApi({
      "GET /api/v1/meta": meta({ ai_intelligence: true }),
      "GET /api/v1/ai/evidence": (u) => ({ items: [rec()], next_cursor: "", filter: u.searchParams.get("finding_id") }),
      "POST /api/v1/ai/evidence/r1/review": () => rec({ review_decision: "accepted", reviewer_name: "Ada", confirmed: true, can_review: false }),
    });
    renderApp(<AIEvidencePanel findingId={F1} />, { permissions: ["ai.evidence_read"] });
    const card = await screen.findByTestId("ai-evidence-record");
    expect(within(card).getByText(/AI-inferred · awaiting a decision/)).toBeInTheDocument();
    expect(within(card).getByRole("note")).toHaveTextContent("Proposal only: a person decides in triage or Human Eye");
    expect(within(card).getByText("Local model")).toBeInTheDocument();
    expect(calls.find((c) => c.path === "/api/v1/ai/evidence")?.url.searchParams.get("finding_id")).toBe(F1);
    await userEvent.type(within(card).getByLabelText("Decision note"), "checked");
    await userEvent.click(within(card).getByRole("button", { name: /Accept/ }));
    await waitFor(() => expect(calls.find((c) => c.method === "POST")?.body).toEqual({ decision: "accepted", note: "checked" }));
  });

  it("shows confirmation once accepted", async () => {
    mockApi({
      "GET /api/v1/meta": meta({ ai_intelligence: true }),
      "GET /api/v1/ai/evidence": () => ({ items: [rec({ review_decision: "accepted", reviewer_name: "Ada", confirmed: true, can_review: false })], next_cursor: "" }),
    });
    renderApp(<AIEvidencePanel threatId="t1" />, { permissions: ["ai.evidence_read"] });
    expect(await screen.findByText("AI-inferred · confirmed by Ada")).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: /Accept/ })).toBeNull();
  });

  it("Reproduce shows the comparison; an unavailable replay says why", async () => {
    mockApi({
      "GET /api/v1/meta": meta({ ai_intelligence: true }),
      "GET /api/v1/ai/evidence": () => ({
        items: [rec(), rec({ id: "r2", replayable: false, replay_unavailable: "the redacted prompt was deleted at the end of the retention period" })],
        next_cursor: "",
      }),
      "POST /api/v1/ai/evidence/r1/replay": () =>
        jsonResponse(
          {
            record: rec({ id: "r3", operation: "replay" }),
            original: rec(),
            comparison: {
              same_conclusion: false, same_verdict: false, identical_response: false, original_verdict: "false_positive", replay_verdict: "true_positive",
              original_conclusion: "a", replay_conclusion: "true_positive: reachable", steps_added: ["route reaches eval"], steps_removed: [],
              original_model: "m1", replay_model: "m2", model_changed: true, deterministic: false,
              determinism_note: "Hosted model: the replay is compared, never assumed equal.", original_confidence: 0.8, replay_confidence: 0.6,
            },
          },
          201,
        ),
    });
    renderApp(<AIEvidencePanel findingId={F1} />, { permissions: ["ai.evidence_read"] });
    expect(await screen.findByText(/Reproduce unavailable: the redacted prompt was deleted/)).toBeInTheDocument();
    await userEvent.click(screen.getByRole("button", { name: /Reproduce/ }));
    const cmp = await screen.findByTestId("replay-comparison");
    expect(cmp).toHaveTextContent("Same conclusionno");
    expect(cmp).toHaveTextContent("m1 → m2");
    expect(cmp).toHaveTextContent("route reaches eval");
    expect(cmp).toHaveTextContent("never assumed equal");
  });
});

describe("AIEvidencePage", () => {
  it("explains a disabled module", async () => {
    mockApi({ "GET /api/v1/meta": meta({}) });
    renderApp(<AIEvidencePage />, { permissions: ["ai.evidence_read"] });
    expect(await screen.findByText("AI security intelligence is not enabled")).toBeInTheDocument();
  });

  it("lists records and filters them", async () => {
    const { calls } = mockApi({
      "GET /api/v1/meta": meta({ ai_intelligence: true }),
      "GET /api/v1/ai/evidence": (u) =>
        u.searchParams.get("task") === "correlation"
          ? { items: [rec({ id: "c1", task: "correlation", task_label: "Correlation", conclusion: "priority low" })], next_cursor: "" }
          : { items: [rec()], next_cursor: "" },
    });
    renderApp(<AIEvidencePage />, { permissions: ["ai.evidence_read"] });
    expect(await screen.findByText("false_positive: the input is a constant")).toBeInTheDocument();
    await userEvent.selectOptions(screen.getByRole("combobox", { name: "Task" }), "correlation");
    expect(await screen.findByText("priority low")).toBeInTheDocument();
    expect(calls.some((c) => c.url.searchParams.get("task") === "correlation")).toBe(true);
  });
});

describe("ModelPerTask", () => {
  const items: TaskAssignment[] = [
    {
      task: "fix_proposal", label: "Fix proposals", code_bearing: true, description: "AI-proposed code fixes", configuration_id: null,
      effective: { configuration_id: "c-local", configuration_name: "Local", provider_kind: "self_hosted", location: "local", model: "example-local-model", send_code_context: true, source: "local_default" },
    },
    {
      task: "analyst", label: "Analyst chat", code_bearing: false, description: "Answers", configuration_id: null,
      effective: { configuration_id: "c-cloud", configuration_name: "Cloud", provider_kind: "anthropic", location: "cloud", model: "example-cloud-model", send_code_context: false, source: "default" },
      warning: "",
    },
  ];
  const configs = [
    { id: "c-local", name: "Local", is_default: false, used_today: 0, current: { model: "example-local-model" } },
    { id: "c-cloud", name: "Cloud", is_default: true, used_today: 0, current: { model: "example-cloud-model" } },
  ] as unknown as AIConfiguration[];

  it("saves only the changed assignments", async () => {
    const { calls } = mockApi({
      "GET /api/v1/meta": meta({ ai_intelligence: true }),
      "GET /api/v1/ai/task-assignments": () => ({ items, evidence: { retention_days: 180, store_payloads: true, updated_at: null } }),
      "PUT /api/v1/ai/task-assignments": () => ({ items, evidence: { retention_days: 180, store_payloads: true, updated_at: null } }),
    });
    renderApp(<ModelPerTask configs={configs} />, { permissions: ["ai.configure"] });
    expect(await screen.findByText("automatic: local model for code · code allowed")).toBeInTheDocument();
    expect(screen.getByText("carries code")).toBeInTheDocument();
    await userEvent.selectOptions(screen.getByRole("combobox", { name: "Configuration for Fix proposals" }), "c-cloud");
    await userEvent.click(screen.getByRole("button", { name: "Save assignments" }));
    await waitFor(() => expect(calls.find((c) => c.method === "PUT")?.body).toEqual({ assignments: { fix_proposal: "c-cloud" } }));
    expect(screen.getByLabelText(/Keep prompts and responses for/)).toHaveValue(180);
  });
});

describe("CorrelationSection", () => {
  const corr: Correlation = {
    finding: { id: F1, title: "eval", severity: "high", status: "open", file_path: "internal/store/store.go", start_line: 38, package_name: "" },
    deterministic: true,
    codegraph: { snapshot_id: "s1", snapshot_status: "ready", nodes: [{ key: "fn:AddProduct", type: "function", label: "AddProduct", file_path: "internal/store/store.go", start_line: 30, end_line: 50, match: "location", evidence: "verified" }], edges: [] },
    threats: [],
    threats_note: "threat modelling is not enabled",
    components: [],
    runtime: { status: "running", exposed: true, privileged: false, alert: false, context: null, evidence: "observed" },
    related_findings: [],
  };

  it("shows the deterministic join and an AI explanation that leaves the finding unchanged", async () => {
    mockApi({
      "GET /api/v1/meta": meta({ ai_intelligence: true }),
      [`GET /api/v1/findings/${F1}/correlation`]: () => corr,
      [`POST /api/v1/findings/${F1}/correlation/explain`]: () => ({
        correlation: corr, evidence_record_id: "r9", label: "ai_inferred", review_decision: "pending", provider_location: "local", model: "m",
        proposes_suppression: true, note: "",
        explanation: { priority: "low", exploitability: "not_exploitable", confidence: 0.7, explanation: "No route reaches the code.", reasoning: ["no route"] },
      }),
    });
    renderApp(<CorrelationSection findingId={F1} />, { permissions: ["findings.read", "ai.review"] });
    expect(await screen.findByText("AddProduct")).toBeInTheDocument();
    expect(screen.getByText("verified")).toBeInTheDocument();
    expect(screen.getByText("observed")).toBeInTheDocument();
    expect(screen.getByText("threat modelling is not enabled")).toBeInTheDocument();
    await userEvent.click(screen.getByRole("button", { name: /Explain with AI/ }));
    const ex = await screen.findByTestId("correlation-explanation");
    expect(ex).toHaveTextContent("AI-inferred");
    expect(ex).toHaveTextContent("The finding is unchanged");
  });
});

describe("AI threat suggestions", () => {
  const model: ThreatModel = {
    id: M1, lineage_id: M1, version: 1, status: "draft", application_id: "app", application_name: "Example app (fixture)", repository_id: null,
    title: "Example model", summary: "", method: "stride", created_at: "2026-11-20T10:00:00Z", updated_at: "2026-11-20T10:00:00Z",
    counts: { total: 1, open: 1, mitigated: 0, accepted: 0, not_applicable: 0, unverified: 0, without_mitigation: 0, ai_pending: 2 },
    can_edit: true, can_approve: false,
  } as ThreatModel;

  it("offers Suggest threats on a draft and shows the pending count", async () => {
    const { calls } = mockApi({
      "GET /api/v1/meta": meta({ ai_intelligence: true, threat_models: true }),
      [`GET /api/v1/threat-models/${M1}`]: () => ({ model, elements: [], versions: [] }),
      [`GET /api/v1/threat-models/${M1}/threats`]: () => ({ items: [] }),
      [`POST /api/v1/threat-models/${M1}/suggest`]: () => ({ items: [{ id: "t9", title: "x" }], evidence_record_id: "r1", dropped: 0, model: "m", label: "AI-inferred", note: "" }),
    });
    renderApp(<ThreatModelView modelId={M1} tab="threats" onNavigate={() => undefined} />, { permissions: ["threats.read", "threats.manage", "ai.review"] });
    expect(await screen.findByText(/2 AI-suggested threat\(s\) await a person's decision/)).toBeInTheDocument();
    await userEvent.click(screen.getByRole("button", { name: /Suggest threats with AI/ }));
    await waitFor(() => expect(calls.some((c) => c.method === "POST" && c.path.endsWith("/suggest"))).toBe(true));
  });

  it("hides Suggest without ai.review", async () => {
    mockApi({
      "GET /api/v1/meta": meta({ ai_intelligence: true, threat_models: true }),
      [`GET /api/v1/threat-models/${M1}`]: () => ({ model, elements: [], versions: [] }),
      [`GET /api/v1/threat-models/${M1}/threats`]: () => ({ items: [] }),
    });
    renderApp(<ThreatModelView modelId={M1} tab="threats" onNavigate={() => undefined} />, { permissions: ["threats.read", "threats.manage"] });
    expect(await screen.findByRole("button", { name: /Submit for review/ })).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: /Suggest threats with AI/ })).toBeNull();
  });
});
