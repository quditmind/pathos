import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { mockApi, renderApp } from "@/test/harness";
import { mockReactFlowDom } from "@/components/graph/testing";
import { approveBlockedReason, diagramDetail, evidenceLabel, patchProblem, type Threat, type ThreatModel } from "./api";
import { ThreatModelsPage } from "./ThreatModelsPage";
import { ApprovalPanel, ThreatModelView } from "./ThreatModelPage";
import { ThreatModelPanel } from "./ThreatModelPanel";
import { emptyThreatFilters, filterThreats, ThreatsTable } from "./threats";
import { validateThreatModelSearch } from "./search";
import { parseElementKeys } from "./dialogs";

// Example data for tests only (labelled): no real application or model.
const APP = "0190b000-0000-7000-8000-000000000001";
const M1 = "0190b000-0000-7000-8000-0000000000a1";
const AUTHOR = "0190b000-0000-7000-8000-0000000000b1";
const meta = (on: boolean) => () => ({ product: "PATHOS", vendor: "Quditmind", version: "3.0.0-test", feature_flags: { threat_models: on } });

const model = (over: Partial<ThreatModel> = {}): ThreatModel => ({
  id: M1,
  lineage_id: M1,
  version: 1,
  status: "draft",
  application_id: APP,
  application_name: "Example shop (fixture)",
  repository_id: null,
  title: "Example shop threat model",
  summary: "",
  method: "stride",
  created_by: { id: AUTHOR, name: "Author" },
  created_at: "2026-11-20T10:00:00Z",
  updated_at: "2026-11-20T10:00:00Z",
  counts: { total: 3, open: 2, mitigated: 1, accepted: 0, not_applicable: 0, by_severity: { high: 1, medium: 1 }, unverified: 1, without_mitigation: 0 },
  can_edit: true,
  can_approve: false,
  ...over,
});

const threat = (id: string, over: Partial<Threat> = {}): Threat => ({
  id,
  threat_model_id: M1,
  title: `Threat ${id}`,
  description: "",
  category: "spoofing",
  method: "rule",
  rule_id: "TM-S-001",
  rule_version: "1",
  evidence_type: "verified",
  severity: "high",
  confidence: 0.6,
  status: "open",
  mitigation: "Require authentication.",
  change_state: "new",
  ...over,
});

const threats = [
  threat("t1"),
  threat("t2", { category: "tampering", severity: "medium", rule_id: "TM-T-001", change_state: "changed" }),
  threat("t3", { method: "imported", evidence_type: "unverified", severity: "low", rule_id: "", change_state: "", status: "mitigated" }),
];

beforeEach(mockReactFlowDom);
afterEach(() => vi.unstubAllGlobals());

describe("threat model helpers", () => {
  it("labels evidence per rule 5", () => {
    expect(evidenceLabel({ evidence_type: "verified", method: "rule" })).toBe("verified");
    expect(evidenceLabel({ evidence_type: "observed", method: "attack_path" })).toBe("observed");
    expect(evidenceLabel({ evidence_type: "unverified", method: "imported" })).toBe("imported, unverified");
    expect(evidenceLabel({ evidence_type: "unverified", method: "manual" })).toBe("manual, unverified");
    expect(evidenceLabel({ evidence_type: "unverified", method: "manual", label: "server label" })).toBe("server label");
  });

  it("requires a reason for severity or status changes", () => {
    const cur = { severity: "high" as const, status: "open" as const };
    expect(patchProblem({ severity: "low" }, cur)).toMatch(/reason/);
    expect(patchProblem({ status: "accepted", reason: "  " }, cur)).toMatch(/reason/);
    expect(patchProblem({ status: "accepted", reason: "Behind the VPN" }, cur)).toBeUndefined();
    expect(patchProblem({ mitigation: "x" }, cur)).toBeUndefined();
  });

  it("explains why the author cannot approve", () => {
    const m = model({ status: "in_review", submitted_by: { id: "other", name: "Other" }, can_approve: true });
    expect(approveBlockedReason(m, AUTHOR, true)).toMatch(/someone else/);
    expect(approveBlockedReason(m, "reviewer", false)).toMatch(/threats.approve/);
    expect(approveBlockedReason(m, "reviewer", true)).toBeUndefined();
    expect(approveBlockedReason(model(), "reviewer", true)).toMatch(/in review/);
  });

  it("filters and sorts threats", () => {
    expect(filterThreats(threats, { ...emptyThreatFilters, category: "tampering" }).map((t) => t.id)).toEqual(["t2"]);
    expect(filterThreats(threats, { ...emptyThreatFilters, change_state: "new" }).map((t) => t.id)).toEqual(["t1"]);
    expect(filterThreats(threats, { ...emptyThreatFilters, method: "imported" }).map((t) => t.id)).toEqual(["t3"]);
    expect(filterThreats(threats, emptyThreatFilters).map((t) => t.severity)).toEqual(["high", "medium", "low"]);
  });

  it("validates the URL state and parses element keys", () => {
    expect(validateThreatModelSearch({ tab: "diagram", threat: "nope!" })).toEqual({ tab: "diagram", threat: undefined });
    expect(parseElementKeys(`${APP} route:GET /x\nds:redis`, "r1")).toEqual([
      { repository_id: APP, key: "route:GET /x" },
      { repository_id: "r1", key: "ds:redis" },
    ]);
  });

  it("lists an element's threats in the diagram inspector", () => {
    const g = { nodes: [{ id: "n1", type: "route" as const, label: "GET /x", layer: "api" as const, attrs: { element_id: "e1" } }], edges: [] };
    const d = diagramDetail(g, [threat("t1", { elements: [{ id: "e1", kind: "process", name: "GET /x" }] }), threat("t2")], M1, "n1");
    expect(d.findings?.map((f) => f.id)).toEqual(["t1"]);
    expect(d.findings?.[0]?.href).toBe(`/threat-models/${M1}?tab=threats&threat=t1`);
  });
});

describe("ThreatModelsPage", () => {
  it("shows the feature-disabled state while the flag is off", async () => {
    mockApi({ "GET /api/v1/meta": meta(false) });
    renderApp(<ThreatModelsPage />, { permissions: ["threats.read"] });
    expect(await screen.findByText("Threat models is not enabled")).toBeInTheDocument();
  });

  it("shows the empty state with create and import for managers", async () => {
    mockApi({ "GET /api/v1/meta": meta(true), "GET /api/v1/threat-models": () => ({ items: [] }), "GET /api/v1/applications": () => ({ items: [] }) });
    renderApp(<ThreatModelsPage />, { permissions: ["threats.read", "threats.manage"] });
    expect(await screen.findByText("No threat models yet")).toBeInTheDocument();
    expect(screen.getAllByRole("button", { name: /New threat model/ }).length).toBeGreaterThan(0);
  });

  it("lists models without management actions for readers", async () => {
    mockApi({ "GET /api/v1/meta": meta(true), "GET /api/v1/threat-models": () => ({ items: [model()] }), "GET /api/v1/applications": () => ({ items: [] }) });
    renderApp(<ThreatModelsPage />, { permissions: ["threats.read"] });
    expect(await screen.findByRole("link", { name: "Example shop threat model" })).toBeInTheDocument();
    expect(screen.getByTestId("model-row")).toHaveTextContent("Draft");
    expect(screen.queryByRole("button", { name: /New threat model/ })).toBeNull();
  });

  it("shows an error panel when the list fails", async () => {
    mockApi({
      "GET /api/v1/meta": meta(true),
      "GET /api/v1/threat-models": () => new Response(JSON.stringify({ error: { code: "internal", message: "boom" } }), { status: 500 }),
      "GET /api/v1/applications": () => ({ items: [] }),
    });
    renderApp(<ThreatModelsPage />, { permissions: ["threats.read"] });
    expect(await screen.findByText(/Could not load the threat models/)).toBeInTheDocument();
  });
});

describe("threats table", () => {
  it("filters by category and shows evidence labels", async () => {
    renderApp(<ThreatsTable threats={threats} onOpen={() => undefined} />);
    expect(await screen.findAllByTestId("threat-row")).toHaveLength(3);
    expect(screen.getByText("imported, unverified")).toBeInTheDocument();
    await userEvent.selectOptions(screen.getByRole("combobox", { name: "Category" }), "tampering");
    expect(screen.getAllByTestId("threat-row")).toHaveLength(1);
    expect(screen.getByText("1 of 3 threats")).toBeInTheDocument();
  });
});

describe("ThreatModelView", () => {
  const routes = (m: ThreatModel) => ({
    "GET /api/v1/meta": meta(true),
    [`GET /api/v1/threat-models/${M1}`]: () => ({ model: m, elements: [], versions: [] }),
    [`GET /api/v1/threat-models/${M1}/threats`]: () => ({ items: threats }),
  });

  it("renders the threats with summary and draft actions", async () => {
    mockApi(routes(model()));
    renderApp(<ThreatModelView modelId={M1} tab="threats" onNavigate={() => undefined} />, { permissions: ["threats.read", "threats.manage"] });
    expect(await screen.findByRole("button", { name: /Submit for review/ })).toBeInTheDocument();
    expect(await screen.findAllByTestId("threat-row")).toHaveLength(3);
    expect(screen.getByLabelText("Threat model summary")).toHaveTextContent("Unverified1");
  });

  it("lets another person with threats.approve approve", async () => {
    const m = model({ status: "in_review", can_edit: false, can_approve: true, submitted_by: { id: AUTHOR, name: "Author" } });
    mockApi(routes(m));
    renderApp(<ApprovalPanel model={m} />, { permissions: ["threats.read", "threats.approve"] });
    expect(await screen.findByRole("button", { name: "Approve" })).toBeEnabled();
    expect(screen.queryByTestId("approve-blocked")).toBeNull();
  });

  it("blocks the author in the approval panel", async () => {
    const m = model({ status: "in_review", created_by: { id: "u1", name: "Ada" } });
    mockApi({ "GET /api/v1/meta": meta(true) });
    renderApp(<ApprovalPanel model={m} />, { permissions: ["threats.approve"] });
    expect(await screen.findByTestId("approve-blocked")).toHaveTextContent(/someone else/);
    expect(screen.getByRole("button", { name: "Approve" })).toBeDisabled();
  });

  it("requires a note to request changes", async () => {
    const m = model({ status: "in_review", created_by: { id: "other", name: "Other" }, can_approve: true });
    const { calls } = mockApi({ "GET /api/v1/meta": meta(true), [`POST /api/v1/threat-models/${M1}/reject`]: () => m });
    renderApp(<ApprovalPanel model={m} />, { permissions: ["threats.approve"] });
    await userEvent.click(await screen.findByRole("button", { name: "Request changes" }));
    expect(screen.getByRole("alert")).toHaveTextContent(/note is required/);
    expect(calls.some((c) => c.method === "POST")).toBe(false);
    await userEvent.type(screen.getByLabelText(/Note/), "Add the payment flow");
    await userEvent.click(screen.getByRole("button", { name: "Request changes" }));
    await waitFor(() => expect(calls.find((c) => c.method === "POST")?.body).toEqual({ note: "Add the payment flow", decision: "changes_requested" }));
  });

  it("refuses a status change without a reason in the threat detail", async () => {
    const { calls } = mockApi({
      ...routes(model()),
      "GET /api/v1/threats/t1": () => ({ threat: threat("t1", { evidence: { nodes: [{ id: "n1", key: "route:GET /x", type: "route", label: "GET /x", file: "a.go", line: 3 }], absent: ["no authentication function"] } }), events: [] }),
    });
    renderApp(<ThreatModelView modelId={M1} tab="threats" threat="t1" onNavigate={() => undefined} />, { permissions: ["threats.read", "threats.manage"] });
    const detail = await screen.findByTestId("threat-detail");
    expect(within(detail).getByRole("link", { name: "GET /x" })).toHaveAttribute("href", expect.stringContaining(`/codegraph/${APP}`));
    expect(within(detail).getByText("no authentication function")).toBeInTheDocument();
    await userEvent.selectOptions(within(detail).getByLabelText("Status"), "accepted");
    await userEvent.click(within(detail).getByRole("button", { name: "Save changes" }));
    expect(within(detail).getByRole("alert")).toHaveTextContent(/reason/);
    expect(calls.some((c) => c.method === "PATCH")).toBe(false);
  });
});

describe("ThreatModelPanel", () => {
  it("shows the feature-disabled state while the flag is off", async () => {
    mockApi({ "GET /api/v1/meta": meta(false) });
    renderApp(<ThreatModelPanel applicationId={APP} />);
    expect(await screen.findByText("Threat models is not enabled")).toBeInTheDocument();
  });

  it("offers to create a model when the application has none", async () => {
    mockApi({ "GET /api/v1/meta": meta(true), "GET /api/v1/threat-models": () => ({ items: [] }) });
    renderApp(<ThreatModelPanel applicationId={APP} />, { permissions: ["threats.manage"] });
    expect(await screen.findByText("No threat model yet")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: /Create threat model/ })).toBeInTheDocument();
  });

  it("summarises the model and its top open threats", async () => {
    mockApi({
      "GET /api/v1/meta": meta(true),
      "GET /api/v1/threat-models": () => ({ items: [model()] }),
      [`GET /api/v1/threat-models/${M1}/threats`]: () => ({ items: threats }),
    });
    renderApp(<ThreatModelPanel applicationId={APP} />, { permissions: ["threats.read"] });
    const list = await screen.findByRole("list", { name: "Top open threats" });
    expect(within(list).getAllByRole("listitem")).toHaveLength(2);
    expect(screen.getByText("1 unverified")).toBeInTheDocument();
  });
});
