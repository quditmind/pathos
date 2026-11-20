import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { jsonResponse, mockApi, renderApp } from "@/test/harness";
import { mockReactFlowDom } from "@/components/graph/testing";
import { hideToolNames, kindOf, refText, sanitiseGraph, threatCategoryFor, type Analysis, type Artifact, type Draft, type ReaSettings } from "./api";
import { ArtifactsPage } from "./ArtifactsPage";
import { AnalysisView } from "./AnalysisPage";
import { ReaSettingsPage, settingsProblem } from "./SettingsPage";
import { validateReaAnalysisSearch } from "./search";

// Example data for tests only (labelled): no real artifact, repository or build.
const T1 = "0190c000-0000-7000-8000-000000000001";
const T2 = "0190c000-0000-7000-8000-000000000002";
const AN = "0190c000-0000-7000-8000-0000000000a1";
const APP = "0190c000-0000-7000-8000-0000000000b1";
const meta = (on: boolean) => () => ({ product: "PATHOS", vendor: "Quditmind", version: "3.0.0-test", feature_flags: { reverse_engineering: on } });

const artifact = (over: Partial<Artifact> = {}): Artifact => ({
  target_id: T1,
  name: "example-server (fixture)",
  file_name: "server",
  sha256: "ab".repeat(32),
  size: 2048,
  kind: "artifact",
  repository_id: "r1",
  repository_name: "example/repo",
  created_at: "2026-11-20T10:00:00Z",
  trust: { status: "trusted", basis: "signature", signature: { status: "verified", mode: "key" } },
  last_analysis: null,
  ...over,
});

const settings = (over: Partial<ReaSettings> = {}): ReaSettings => ({
  enabled_tools: ["radare2", "binwalk"],
  memory_mb: 4096,
  timeout_minutes: 30,
  input_policy: "own_builds_or_authorized",
  decompiled_code_ai: "none",
  ai_send_code_allowed: false,
  ...over,
});

const analysis = (over: Partial<Analysis> = {}): Analysis => ({
  id: AN,
  target_id: T1,
  artifact_name: "example-server (fixture)",
  artifact_sha256: "ab".repeat(32),
  repository_id: "r1",
  repository_name: "example/repo",
  application_id: APP,
  status: "ready",
  trust_basis: "provenance",
  commit_sha: "a41c9e2aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
  commit_source: "provenance",
  format: "elf",
  arch: "x86",
  language: "go",
  tools: { radare2: { version: "6.2.6", status: "succeeded" }, binwalk: { status: "skipped", detail: "binwalk: not firmware" } },
  created_at: "2026-11-20T10:00:00Z",
  ...over,
});

const draft = (over: Partial<Draft> = {}): Draft => ({
  id: "d1",
  title: "Profiling handlers shipped in the binary",
  description: "The binary registers /debug/pprof/ handlers that the API inventory does not list.",
  severity: "medium",
  status: "proposed",
  label: "proposal",
  evidence: [
    { evidence: "verified", kind: "binary", ref: "0x6a3f20", detail: "radare2: string reference" },
    { evidence: "verified", kind: "file_line", ref: "cmd/server/main.go:7", detail: "blank import" },
  ],
  application_id: APP,
  created_at: "2026-11-20T10:00:00Z",
  ...over,
});

beforeEach(mockReactFlowDom);
afterEach(() => vi.unstubAllGlobals());

describe("reverse-engineering helpers", () => {
  it("names the kind of analysis, never the tool (rule 3)", () => {
    expect(kindOf("radare2")).toBe("Binary triage");
    expect(kindOf("ghidra")).toBe("Decompiler");
    expect(kindOf("binwalk")).toBe("Firmware extraction");
    expect(kindOf("jadx")).toBe("Android decompiler");
    expect(kindOf("ilspy")).toBe(".NET decompiler");
    expect(hideToolNames("radare2: call at 0x10; Ghidra too")).toBe("Binary triage: call at 0x10; Decompiler too");
    expect(refText({ evidence: "verified", kind: "binary", ref: "0x6a3f20", detail: "radare2: call" })).toBe("offset 0x6a3f20 (Binary triage: call)");
    const g = sanitiseGraph({
      nodes: [{ id: "n", type: "binary_function", label: "main.main", layer: "code", attrs: { tool: "radare2" } }],
      edges: [{ id: "e", source: "n", target: "n", type: "calls", evidence: "verified", evidence_refs: [{ kind: "binary", ref: "0x1", detail: "radare2: call" }] }],
    });
    expect(g.nodes[0]!.attrs!.tool).toBe("Binary triage");
    expect(g.edges[0]!.evidence_refs[0]!.detail).toBe("Binary triage: call");
  });

  it("validates the URL state and picks a threat category", () => {
    expect(validateReaAnalysisSearch({ tab: "diff", fn: "bad id!" })).toEqual({ tab: "diff", fn: undefined, node: undefined });
    expect(validateReaAnalysisSearch({ tab: "nope" }).tab).toBeUndefined();
    expect(threatCategoryFor({ title: "os/exec.Command only in binary", description: "" })).toBe("elevation_of_privilege");
    expect(threatCategoryFor(draft())).toBe("information_disclosure");
  });

  it("validates the settings form", () => {
    expect(settingsProblem(settings(), false)).toBeUndefined();
    expect(settingsProblem(settings({ memory_mb: 100 }), false)).toMatch(/Memory/);
    expect(settingsProblem(settings({ enabled_tools: [] }), false)).toMatch(/at least one/);
    expect(settingsProblem(settings({ decompiled_code_ai: "cloud" }), false)).toMatch(/Cloud/);
    expect(settingsProblem(settings({ decompiled_code_ai: "cloud" }), true)).toBeUndefined();
  });
});

describe("ArtifactsPage", () => {
  it("shows the feature-disabled state while the flag is off", async () => {
    mockApi({ "GET /api/v1/meta": meta(false) });
    renderApp(<ArtifactsPage />, { permissions: ["findings.read"] });
    expect(await screen.findByText("Reverse engineering is not enabled")).toBeInTheDocument();
  });

  it("lists artifacts with trust badges; untrusted ones cannot be analysed and need a reasoned authorisation", async () => {
    const api = mockApi({
      "GET /api/v1/meta": meta(true),
      "GET /api/v1/rea/settings": () => settings(),
      "GET /api/v1/rea/artifacts": () => ({
        artifacts: [
          artifact(),
          artifact({ target_id: T2, name: "vendor-blob (fixture)", trust: { status: "untrusted", basis: "", reason: "no verified signature or provenance" } }),
        ],
      }),
      [`POST /api/v1/rea/artifacts/${T2}/authorizations`]: () => jsonResponse({ id: "z1", reason: "x", created_at: "2026-11-20T10:00:00Z" }, 201),
    });
    renderApp(<ArtifactsPage />, { permissions: ["findings.read", "scans.run", "rea.run", "rea.authorize"] });
    const rows = await screen.findAllByTestId("artifact-row");
    expect(rows).toHaveLength(2);
    expect(within(rows[0]!).getByTestId("trust-badge")).toHaveTextContent("Trusted · verified signature");
    expect(within(rows[1]!).getByTestId("trust-badge")).toHaveTextContent("Untrusted · refused by default");
    expect(within(rows[0]!).getByRole("button", { name: /Analyse/ })).toBeEnabled();
    expect(within(rows[1]!).getByRole("button", { name: /Analyse/ })).toBeDisabled();

    await userEvent.click(within(rows[1]!).getByRole("button", { name: /Authorise untrusted artifact/ }));
    const dialog = await screen.findByRole("dialog");
    expect(within(dialog).getByText(/cannot tie this artifact to your own builds/)).toBeInTheDocument();
    const confirm = within(dialog).getByRole("button", { name: "Authorise this artifact" });
    expect(confirm).toBeDisabled();
    await userEvent.type(within(dialog).getByRole("textbox", { name: "Reason" }), "short");
    expect(confirm).toBeDisabled();
    await userEvent.type(within(dialog).getByRole("textbox", { name: "Reason" }), " vendor firmware, ticket SEC-1");
    expect(confirm).toBeEnabled();
    await userEvent.click(confirm);
    await waitFor(() => expect(api.calls.some((c) => c.method === "POST" && c.path.endsWith(`/${T2}/authorizations`))).toBe(true));
    expect(api.calls.find((c) => c.method === "POST")!.body).toEqual({ reason: "short vendor firmware, ticket SEC-1" });
  });

  it("disables authorisation when the input policy is own builds only", async () => {
    mockApi({
      "GET /api/v1/meta": meta(true),
      "GET /api/v1/rea/settings": () => settings({ input_policy: "own_builds_only" }),
      "GET /api/v1/rea/artifacts": () => ({ artifacts: [artifact({ trust: { status: "untrusted", basis: "" } })] }),
    });
    renderApp(<ArtifactsPage />, { permissions: ["findings.read", "rea.authorize"] });
    const btn = await screen.findByRole("button", { name: /Authorise untrusted artifact/ });
    await waitFor(() => expect(btn).toBeDisabled());
  });

  it("shows the authorisation reason of an authorised artifact", async () => {
    mockApi({
      "GET /api/v1/meta": meta(true),
      "GET /api/v1/rea/settings": () => settings(),
      "GET /api/v1/rea/artifacts": () => ({
        artifacts: [artifact({ trust: { status: "authorized", basis: "authorization", authorization: { id: "z", reason: "Vendor blob for audit", authorized_by_email: "ada@example.com", created_at: "2026-11-20T10:00:00Z" } } })],
      }),
    });
    renderApp(<ArtifactsPage />, { permissions: ["findings.read"] });
    expect(await screen.findByText(/Vendor blob for audit/)).toBeInTheDocument();
    expect(screen.getByTestId("trust-badge")).toHaveTextContent("Authorised untrusted artifact");
  });
});

describe("AnalysisView", () => {
  const routes = () => ({
    [`GET /api/v1/rea/analyses/${AN}/functions`]: () => ({
      items: [
        { node_id: "f1", key: "fn:0x1", name: "net/http/pprof.Index", match: "binary_only", sensitive: true, offset: 0x6a3f20, tool: "radare2" },
        { node_id: "f2", key: "fn:0x2", name: "main.CreatePayment", match: "matched", source: { file: "cmd/server/main.go", line: 20 } },
      ],
      total: 2,
    }),
    [`GET /api/v1/rea/analyses/${AN}/functions/f1`]: () => ({
      function: { node_id: "f1", key: "fn:0x1", name: "net/http/pprof.Index", match: "binary_only", sensitive: true, offset: 0x6a3f20 },
      code: { tool: "radare2", kind: "disassembly", text: "push rbp" },
      callers: [],
      callees: [],
      strings: [{ node_id: "s1", value: "[REDACTED:token]", redacted: true }],
      evidence: [{ evidence: "verified", kind: "binary", ref: "0x6a3f20", detail: "radare2: function start" }],
    }),
    [`GET /api/v1/rea/analyses/${AN}/strings`]: () => ({
      items: [
        { node_id: "s1", value: "[REDACTED:aws]", redacted: true, kind: "secret", offset: 16 },
        { node_id: "s2", value: "/debug/pprof/", kind: "route", offset: 32 },
      ],
      total: 2,
    }),
    [`GET /api/v1/rea/analyses/${AN}/imports`]: () => ({ items: [{ node_id: "i1", name: "net/http/pprof", kind: "package", sensitive: true }], total: 1 }),
    [`GET /api/v1/rea/analyses/${AN}/diff`]: () => ({
      status: "ready",
      commit_sha: "a41c9e2aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
      commit_source: "provenance",
      counts: { binary_only: 1, source_only: 0, matched: 5 },
      items: [
        {
          id: "x1",
          side: "binary_only",
          kind: "route",
          name: "/debug/pprof/",
          sensitive: true,
          sensitive_reason: "Profiling handlers expose memory contents",
          evidence: [{ evidence: "verified", kind: "binary", ref: "0x20", detail: "radare2: string" }],
        },
      ],
      total: 1,
    }),
    [`GET /api/v1/rea/analyses/${AN}/drafts`]: () => ({ drafts: [draft()] }),
    [`POST /api/v1/rea/drafts/d1/create-finding`]: () => ({ finding_id: "fid" }),
  });

  it("renders the functions tab with match badges and labels disassembly honestly", async () => {
    mockApi(routes());
    renderApp(<AnalysisView analysis={analysis()} counts={{ functions: 2 }} search={{ fn: "f1" }} onNavigate={() => undefined} />, { permissions: ["findings.read"] });
    expect((await screen.findAllByRole("tab")).map((t) => t.textContent)).toEqual(["Functions", "Call graph", "Strings & imports", "Runtime behaviour", "Source ↔ binary", "History"]);
    const rows = await screen.findAllByTestId("function-row");
    expect(rows[0]).toHaveTextContent("Only in binary");
    expect(rows[0]).toHaveTextContent("Sensitive");
    expect(rows[1]).toHaveTextContent("Matched");
    const detail = await screen.findByTestId("function-detail");
    expect(within(detail).getByText(/^Disassembly · Binary triage/)).toBeInTheDocument();
    expect(within(detail).queryByText(/Decompiled/)).toBeNull();
    expect(within(detail).getByText("Redacted secret")).toBeInTheDocument();
    // Rule 3: no tool names in the workspace.
    expect(document.body.textContent).not.toMatch(/radare2|ghidra|binwalk|jadx|ilspy/i);
  });

  it("shows redacted strings as redacted and imports", async () => {
    mockApi(routes());
    renderApp(<AnalysisView analysis={analysis()} counts={{}} search={{ tab: "strings" }} onNavigate={() => undefined} />, { permissions: ["findings.read"] });
    const rows = await screen.findAllByTestId("string-row");
    expect(rows[0]).toHaveTextContent("Redacted secret");
    expect(rows[0]).not.toHaveTextContent("REDACTED:aws");
    expect(rows[1]).toHaveTextContent("/debug/pprof/");
    expect(await screen.findByTestId("import-row")).toHaveTextContent("net/http/pprof");
  });

  it("renders the call graph with the shared graph component and switches binary views", async () => {
    const api = mockApi({
      [`GET /api/v1/rea/analyses/${AN}/graph`]: () => ({
        nodes: [
          { id: "n1", type: "binary_function", label: "main.main", layer: "code", attrs: { tool: "radare2" } },
          { id: "n2", type: "import", label: "net/http/pprof", layer: "dependency" },
        ],
        edges: [{ id: "e1", source: "n1", target: "n2", type: "calls", evidence: "verified", evidence_refs: [{ kind: "binary", ref: "0x401000", detail: "radare2: call" }] }],
        aggregated: [],
        truncated: false,
      }),
    });
    renderApp(<AnalysisView analysis={analysis()} counts={{}} search={{ tab: "call-graph" }} onNavigate={() => undefined} />, { permissions: ["findings.read"] });
    expect(await screen.findByRole("button", { name: /^main\.main, Binary function/ })).toBeInTheDocument();
    expect(api.calls.find((c) => c.path.endsWith("/graph"))!.url.searchParams.get("view")).toBe("binary_call_graph");
    await userEvent.click(screen.getByRole("button", { name: "Layout" }));
    await waitFor(() => expect(api.calls.filter((c) => c.path.endsWith("/graph")).map((c) => c.url.searchParams.get("view"))).toContain("binary_layout"));
  });

  it("shows the sandbox notice on Runtime behaviour, with no data", async () => {
    mockApi({});
    renderApp(<AnalysisView analysis={analysis()} counts={{}} search={{ tab: "runtime" }} onNavigate={() => undefined} />);
    expect(await screen.findByText("Sandbox tier arrives after 3.0")).toBeInTheDocument();
  });

  it("asks for the analysis to finish before showing results", async () => {
    mockApi({});
    renderApp(<AnalysisView analysis={analysis({ status: "running" })} counts={{}} search={{}} onNavigate={() => undefined} />);
    expect(await screen.findByText(/Functions appear when the analysis has finished/)).toBeInTheDocument();
  });

  it("shows the source ↔ binary diff with evidence, and drafts as proposals that need confirmation", async () => {
    const api = mockApi(routes());
    renderApp(<AnalysisView analysis={analysis()} counts={{}} search={{ tab: "diff" }} onNavigate={() => undefined} />, {
      permissions: ["findings.read", "findings.triage", "threats.manage"],
    });
    const row = await screen.findByTestId("diff-row");
    expect(row).toHaveTextContent("/debug/pprof/");
    expect(row).toHaveTextContent("Only in binary");
    expect(row).toHaveTextContent("offset 0x20 (Binary triage: string)");
    expect(screen.getByTestId("diff-commit")).toHaveTextContent("verified provenance");
    const card = await screen.findByTestId("draft-card");
    expect(within(card).getByText("Proposal · needs human review")).toBeInTheDocument();
    expect(within(card).getByText(/cmd\/server\/main.go:7/)).toBeInTheDocument();
    await userEvent.click(within(card).getByRole("button", { name: "Create finding" }));
    // Nothing is created until the confirmation.
    expect(api.calls.some((c) => c.method === "POST")).toBe(false);
    const dialog = await screen.findByRole("dialog");
    expect(within(dialog).getByText(/never as confirmed/)).toBeInTheDocument();
    await userEvent.click(within(dialog).getByRole("button", { name: "Create finding" }));
    await waitFor(() => expect(api.calls.some((c) => c.method === "POST" && c.path === "/api/v1/rea/drafts/d1/create-finding")).toBe(true));
  });

  it("explains a missing source snapshot", async () => {
    mockApi({
      ...routes(),
      [`GET /api/v1/rea/analyses/${AN}/diff`]: () => ({ status: "no_source_snapshot", commit_sha: "a41c9e2aaaa", counts: {}, items: [], total: 0 }),
      [`GET /api/v1/codegraph/applications/${APP}/snapshots`]: () => ({ snapshots: [] }),
    });
    renderApp(<AnalysisView analysis={analysis()} counts={{}} search={{ tab: "diff" }} onNavigate={() => undefined} />, { permissions: ["findings.read", "rea.run"] });
    expect(await screen.findByText(/no CodeGraph snapshot of commit a41c9e2aaaa/)).toBeInTheDocument();
    expect(screen.getByRole("combobox", { name: "CodeGraph snapshot" })).toBeInTheDocument();
  });
});

describe("ReaSettingsPage", () => {
  const tools = () => ({
    worker_online: true,
    tools: [
      { key: "radare2", name: "radare2", license: "LGPL-3.0", purpose: "Binary triage", installed: true, version: "6.2.6", enabled: true, optional: false },
      { key: "ghidra", name: "Ghidra (headless)", license: "Apache-2.0", purpose: "Decompiler", installed: false, enabled: false, optional: true },
    ],
  });

  it("disables cloud models without the AI allow-code setting and saves", async () => {
    const api = mockApi({ "GET /api/v1/meta": meta(true), "GET /api/v1/rea/settings": () => settings(), "GET /api/v1/rea/tools": tools, "PUT /api/v1/rea/settings": () => settings({ memory_mb: 2048 }) });
    renderApp(<ReaSettingsPage />, { permissions: ["scanners.read", "scanners.manage"] });
    expect(await screen.findByRole("radio", { name: "Local and cloud models" })).toBeDisabled();
    expect(screen.getByRole("radio", { name: "No AI model (default)" })).toBeChecked();
    expect(screen.getByRole("link", { name: "AI settings" })).toHaveAttribute("href", "/admin/ai");
    expect(await screen.findAllByTestId("rea-tool-row")).toHaveLength(2);
    expect(screen.getByText("Not in the image")).toBeInTheDocument();
    const mem = screen.getByRole("spinbutton", { name: "Memory per analysis (MB)" });
    await userEvent.clear(mem);
    await userEvent.type(mem, "2048");
    await userEvent.click(screen.getByRole("button", { name: "Save" }));
    await waitFor(() => expect(api.calls.some((c) => c.method === "PUT")).toBe(true));
    expect(api.calls.find((c) => c.method === "PUT")!.body).toMatchObject({ memory_mb: 2048, decompiled_code_ai: "none", input_policy: "own_builds_or_authorized" });
  });

  it("allows cloud models when the AI settings allow sending code", async () => {
    mockApi({ "GET /api/v1/meta": meta(true), "GET /api/v1/rea/settings": () => settings({ ai_send_code_allowed: true }), "GET /api/v1/rea/tools": tools });
    renderApp(<ReaSettingsPage />, { permissions: ["scanners.read", "scanners.manage"] });
    expect(await screen.findByRole("radio", { name: "Local and cloud models" })).toBeEnabled();
  });

  it("is read-only without scanners.manage", async () => {
    mockApi({ "GET /api/v1/meta": meta(true), "GET /api/v1/rea/settings": () => settings(), "GET /api/v1/rea/tools": tools });
    renderApp(<ReaSettingsPage />, { permissions: ["scanners.read"] });
    expect(await screen.findByText(/needs the scanners.manage permission/)).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Save" })).toBeNull();
  });
});
