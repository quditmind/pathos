import { afterEach, describe, expect, it, vi } from "vitest";
import { fireEvent, screen, waitFor, within } from "@testing-library/react";
import { jsonResponse, mockApi, renderApp } from "@/test/harness";
import type { Decision, GateException, ItemDetail, RemediationItem } from "./api";
import { RemediationPage } from "./RemediationPage";
import { RemediationItemPage } from "./ItemDetailPage";
import { GatesPage } from "./GatesPage";
import { ExceptionsPage } from "./ExceptionsPage";
import { RemediationPanel } from "./RemediationPanel";

afterEach(() => vi.unstubAllGlobals());

// Example data for tests only (labelled fixtures).
const meta = (on: boolean) => () => ({ product: "PATHOS", vendor: "Quditmind", version: "dev", feature_flags: { remediation_workspace: on } });

const item: RemediationItem = {
  id: "i1", title: "SQL injection in orders API", kind: "code_fix", status: "in_progress", priority: "high",
  repository_id: "r1", repository_name: "acme/payments", application_id: null, application_name: "",
  owner_id: null, owner_email: "", due_at: "2026-12-01T00:00:00Z", due_source: "sla", overdue: false, root_cause: "",
  finding_count: 1, open_finding_count: 1, top_severity: "high", affected_files: ["api/orders.go"],
  fix_pull_request: null, last_verification: null, created_at: "2026-11-18T00:00:00Z", updated_at: "2026-11-18T00:00:00Z", closed_at: null,
};
const item2: RemediationItem = { ...item, id: "i2", title: "Upgrade lodash", kind: "dependency_upgrade", overdue: true, owner_email: "bob@example.com", owner_id: "u2" };

const detail = (over: Partial<ItemDetail> = {}): ItemDetail => ({
  ...item,
  findings: [{ id: "f1", title: "SQL injection", severity: "high", status: "open", category: "sast", rule_id: "sqli", file_path: "api/orders.go", start_line: 42, scanner_keys: ["opengrep"] }],
  guidance: [
    { source: "verified_ai_fix", evidence: "verified", title: "Verified AI fix", text: "Use a parameterised query." },
    { source: "ai_review", evidence: "ai_inferred", title: "AI review", text: "Bind the order id." },
  ],
  fix_prs: [],
  verifications: [],
  can_verify: true,
  verify_unavailable_reason: "",
  ...over,
});

describe("remediation workspace", () => {
  it("shows the feature-disabled state while the flag is off", async () => {
    mockApi({ "GET /api/v1/meta": meta(false), "GET /api/v1/remediation/items": () => jsonResponse({ error: { code: "feature_disabled", error_code: "PTH-PLAT-1007", message: "off" } }, 404) });
    renderApp(<RemediationPage />, { permissions: ["remediation.read"], path: "/remediation" });
    expect(await screen.findByText(/is not enabled/)).toBeInTheDocument();
    expect(screen.getByText("remediation_workspace")).toBeInTheDocument();
  });

  it("names the missing permission", async () => {
    mockApi({ "GET /api/v1/meta": meta(true), "GET /api/v1/remediation/items": () => ({ items: [] }), "GET /api/v1/remediation/views": () => ({ items: [] }) });
    renderApp(<RemediationPage />, { permissions: ["findings.read"], path: "/remediation" });
    expect(await screen.findByText("remediation.read")).toBeInTheDocument();
  });

  it("lists items, sends filters to the server and bulk-assigns after confirmation", async () => {
    const api = mockApi({
      "GET /api/v1/meta": meta(true),
      "GET /api/v1/remediation/items": () => ({ items: [item, item2], next_cursor: null }),
      "GET /api/v1/remediation/views": () => ({ items: [{ id: "v1", name: "My overdue", filters: { overdue: "true" }, shared: false, owner_email: "ada@example.com", created_at: "" }] }),
      "POST /api/v1/remediation/items/bulk": () => ({ updated: 2 }),
    });
    renderApp(<RemediationPage />, { permissions: ["remediation.read", "remediation.manage"], path: "/remediation" });
    expect(await screen.findByText("SQL injection in orders API")).toBeInTheDocument();
    expect(screen.getByText("Overdue")).toBeInTheDocument();
    expect(screen.getByText("bob@example.com")).toBeInTheDocument();

    fireEvent.change(screen.getByLabelText("Status"), { target: { value: "in_progress" } });
    await waitFor(() => expect(api.calls.some((c) => c.path === "/api/v1/remediation/items" && c.url.searchParams.get("status") === "in_progress")).toBe(true));

    fireEvent.click(await screen.findByRole("button", { name: "My overdue" }));
    await waitFor(() => expect(api.calls.some((c) => c.path === "/api/v1/remediation/items" && c.url.searchParams.get("overdue") === "true")).toBe(true));

    fireEvent.click(await screen.findByLabelText("Select all items on this page"));
    const bar = await screen.findByRole("region", { name: "Bulk actions" });
    fireEvent.click(within(bar).getByRole("button", { name: /Assign to me/ }));
    // Nothing is sent before confirmation.
    expect(api.calls.some((c) => c.path === "/api/v1/remediation/items/bulk")).toBe(false);
    fireEvent.click(await screen.findByRole("button", { name: "Apply" }));
    await waitFor(() => {
      const call = api.calls.find((c) => c.method === "POST" && c.path === "/api/v1/remediation/items/bulk");
      expect(call?.body).toEqual({ ids: ["i1", "i2"], owner_id: "u1" });
    });
  });

  it("hides bulk selection without remediation.manage and explains the empty state", async () => {
    mockApi({ "GET /api/v1/meta": meta(true), "GET /api/v1/remediation/items": () => ({ items: [] }), "GET /api/v1/remediation/views": () => ({ items: [] }) });
    renderApp(<RemediationPage />, { permissions: ["remediation.read"], path: "/remediation" });
    expect(await screen.findByText("No remediation items yet")).toBeInTheDocument();
    expect(screen.queryByLabelText("Select all items on this page")).not.toBeInTheDocument();
  });
});

describe("remediation item", () => {
  it("labels guidance evidence and queues a verification after confirmation", async () => {
    const api = mockApi({
      "GET /api/v1/meta": meta(true),
      "GET /api/v1/remediation/items/i1": () => detail(),
      "POST /api/v1/remediation/items/i1/verify": () => ({ id: "ver1", status: "queued" }),
    });
    renderApp(<RemediationItemPage id="i1" />, { permissions: ["remediation.read", "remediation.manage"], path: "/remediation/items/i1" });
    expect(await screen.findByText("Verified AI fix")).toBeInTheDocument();
    expect(screen.getByText("Verified")).toBeInTheDocument();
    expect(screen.getByText("AI-inferred")).toBeInTheDocument();
    const btn = screen.getByRole("button", { name: /Verify fix/ });
    expect(btn).toBeEnabled();
    fireEvent.click(btn);
    fireEvent.click(await screen.findByRole("button", { name: "Queue rescan" }));
    await waitFor(() => expect(api.calls.some((c) => c.method === "POST" && c.path === "/api/v1/remediation/items/i1/verify")).toBe(true));
  });

  it("lets the item's owner verify without remediation.manage, and refuses other readers", async () => {
    mockApi({
      "GET /api/v1/meta": meta(true),
      "GET /api/v1/remediation/items/i1": () => ({ ...detail(), can_request_verification: true }),
    });
    const { unmount } = renderApp(<RemediationItemPage id="i1" />, { permissions: ["remediation.read"], path: "/remediation/items/i1" });
    expect(await screen.findByRole("button", { name: /Verify fix/ })).toBeEnabled();
    unmount();
    mockApi({
      "GET /api/v1/meta": meta(true),
      "GET /api/v1/remediation/items/i1": () => ({ ...detail(), can_request_verification: false }),
    });
    renderApp(<RemediationItemPage id="i1" />, { permissions: ["remediation.read"], path: "/remediation/items/i1" });
    const btn = await screen.findByRole("button", { name: /Verify fix/ });
    expect(btn).toBeDisabled();
    expect(btn).toHaveAttribute("title", expect.stringContaining("item's owner"));
  });

  it("disables Verify fix with the reason, and shows before/after evidence and regressions", async () => {
    mockApi({
      "GET /api/v1/meta": meta(true),
      "GET /api/v1/remediation/items/i1": () =>
        detail({
          can_verify: false,
          verify_unavailable_reason: "The finding comes only from an imported report.",
          verifications: [
            {
              id: "ver1", item_id: "i1", status: "completed", result: "regressed", trigger: "fix_pr_merged", scanner_key: "opengrep", scanner_version: "1.0",
              files: ["api/orders.go"], before: { scan_job_id: "11111111-aaaa", commit: "abcdef1234567890", result_count: 2 },
              after: { scan_job_id: null, commit: "1234567890abcdef", result_count: 1 },
              findings: [{ finding_id: "f1aaaaaa-1", status_before: "open", status_after: "fixed", reproduced: true, removed: true }],
              regressions: [{ rule_id: "xss", file: "api/orders.go", line: 7, title: "Reflected XSS" }],
              failure_reason: "", requested_by_email: "", created_at: "2026-11-19T00:00:00Z", finished_at: "2026-11-19T00:05:00Z",
            },
          ],
        }),
    });
    renderApp(<RemediationItemPage id="i1" />, { permissions: ["remediation.read", "remediation.manage"], path: "/remediation/items/i1" });
    expect(await screen.findByRole("button", { name: /Verify fix/ })).toBeDisabled();
    expect(screen.getByTestId("verify-reason")).toHaveTextContent("imported report");
    const v = screen.getByTestId("verification");
    expect(within(v).getByText("Regression found")).toBeInTheDocument();
    expect(within(v).getByText(/Fix PR merged/)).toBeInTheDocument();
    expect(within(v).getByText(/xss at api\/orders.go:7/)).toBeInTheDocument();
    expect(within(v).getByText(/reported before, gone after/)).toBeInTheDocument();
    // Rule 3: the tool name is not shown.
    expect(within(v).queryByText(/opengrep/)).not.toBeInTheDocument();
  });
});

const decision = (over: Partial<Decision> = {}): Decision => ({
  id: "d1", stage: "ci", outcome: "block", repository_id: "r1", repository_name: "acme/payments", application_id: null, scan_job_id: "s1",
  commit_sha: "0123456789abcdef", pull_request: null,
  gates: [{ id: "g1", name: "No criticals in CI", mode: "block", matched: true, count: 2, effect: "block", policy: { id: "p1", name: "Critical findings", version: 3 } }],
  policy_ids: ["p1"], reasons: [{ code: "policy_matched", message: "Policy Critical findings matched 2 finding(s)", gate_id: "g1", policy_id: "p1", count: 2 }],
  evidence: { scope: "new", by_severity: { critical: 2 }, finding_ids: [], scan_job_id: "s1" }, exceptions: [], requested_by_email: "ci@example.com",
  created_at: "2026-11-19T00:00:00Z", docs_url: "", ...over,
});

describe("gates and decisions", () => {
  it("filters the decision log by stage and outcome and shows reasons and policies", async () => {
    const api = mockApi({
      "GET /api/v1/meta": meta(true),
      "GET /api/v1/gates": () => ({
        items: [
          { id: "g1", name: "No criticals in CI", stage: "ci", mode: "block", allow_exceptions: true, application_id: null, repository_id: null, enabled: true, managed: false, policy: { id: "p1", name: "Critical findings", version: 3, enabled: true }, created_at: "", updated_at: "" },
          { id: "g2", name: "Pull request gate: acme/payments", stage: "pull_request", mode: "block", allow_exceptions: true, application_id: null, repository_id: "r1", repository_name: "acme/payments", enabled: true, managed: true, policy: { id: "p2", name: "PR gate acme/payments", version: 1, enabled: true }, created_at: "", updated_at: "" },
        ],
      }),
      "GET /api/v1/gates/decisions": () => ({ items: [decision(), decision({ id: "d2", outcome: "pass", reasons: [{ code: "no_gate_configured", message: "No gate configured for this stage" }], gates: [], policy_ids: [] })] }),
    });
    renderApp(<GatesPage />, { permissions: ["remediation.read", "remediation.manage", "gates.manage"], path: "/remediation/gates?decision=d1" });
    expect(await screen.findByText("No criticals in CI")).toBeInTheDocument();
    expect(screen.getByText("Managed by the repository's pull request settings")).toBeInTheDocument();
    // The managed gate cannot be edited here.
    expect(screen.queryByRole("button", { name: "Edit Pull request gate: acme/payments" })).not.toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Edit No criticals in CI" })).toBeInTheDocument();
    const d = await screen.findByTestId("decision-detail");
    expect(within(d).getByText("Policy Critical findings matched 2 finding(s)")).toBeInTheDocument();
    expect(within(d).getByRole("button", { name: "Request exception" })).toBeInTheDocument();

    fireEvent.change(screen.getByLabelText("Stage"), { target: { value: "deploy" } });
    fireEvent.change(screen.getByLabelText("Decision"), { target: { value: "block" } });
    await waitFor(() =>
      expect(api.calls.some((c) => c.path === "/api/v1/gates/decisions" && c.url.searchParams.get("stage") === "deploy" && c.url.searchParams.get("outcome") === "block")).toBe(true),
    );
  });

  it("explains a gate cannot exist without a policy", async () => {
    mockApi({
      "GET /api/v1/meta": meta(true),
      "GET /api/v1/gates": () => ({ items: [] }),
      "GET /api/v1/gates/decisions": () => ({ items: [] }),
      "GET /api/v1/security-policies": () => ({ items: [] }),
    });
    renderApp(<GatesPage />, { permissions: ["remediation.read", "gates.manage"], path: "/remediation/gates" });
    expect(await screen.findByText("No gates configured")).toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: /Add gate/ }));
    expect(await screen.findByText(/a gate cannot exist without a policy/)).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Save gate" })).toBeDisabled();
  });
});

const exc = (over: Partial<GateException> = {}): GateException => ({
  id: "x1", gate_id: "g1", gate_name: "No criticals in CI", decision_id: "d1", kind: "exception", scope: { repository_id: "r1", commit_sha: "0123456789abcdef" },
  reason: "Compensating WAF rule until the fix ships", status: "requested", requested_by_email: "bob@example.com", decided_by_email: "", decision_note: "",
  expires_at: "2026-11-26T00:00:00Z", created_at: "2026-11-19T00:00:00Z", decided_at: null, can_decide: true, ...over,
});

describe("exceptions and approvals", () => {
  it("lets an approver approve another person's request", async () => {
    const api = mockApi({
      "GET /api/v1/meta": meta(true),
      "GET /api/v1/gate-exceptions": () => ({ items: [exc()] }),
      "POST /api/v1/gate-exceptions/x1/approve": () => exc({ status: "approved" }),
    });
    renderApp(<ExceptionsPage />, { permissions: ["remediation.read", "gates.approve_exception"], path: "/remediation/exceptions" });
    fireEvent.click(await screen.findByRole("button", { name: "Approve" }));
    const dialog = await screen.findByRole("dialog");
    fireEvent.click(within(dialog).getByRole("button", { name: "Approve" }));
    await waitFor(() => expect(api.calls.some((c) => c.method === "POST" && c.path === "/api/v1/gate-exceptions/x1/approve")).toBe(true));
  });

  it("disables approval for the requester and explains why", async () => {
    mockApi({ "GET /api/v1/meta": meta(true), "GET /api/v1/gate-exceptions": () => ({ items: [exc({ requested_by_email: "ada@example.com", can_decide: false })] }) });
    renderApp(<ExceptionsPage />, { permissions: ["remediation.read", "gates.approve_exception"], path: "/remediation/exceptions" });
    expect(await screen.findByRole("button", { name: "Approve" })).toBeDisabled();
    expect(screen.getByRole("button", { name: "Reject" })).toBeDisabled();
    expect(screen.getByText("You requested this; someone else must decide it.")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Revoke" })).toBeInTheDocument();
  });
});

describe("application profile Remediation tab", () => {
  it("lists the application's items and links to the workspace filtered to it", async () => {
    const api = mockApi({
      "GET /api/v1/meta": meta(true),
      "GET /api/v1/remediation/items": () => ({ items: [{ ...item, application_id: "a1" }, { ...item2, application_id: "a1" }], next_cursor: null }),
    });
    renderApp(<RemediationPanel applicationId="a1" />, { permissions: ["remediation.read"] });
    expect(await screen.findByRole("link", { name: "SQL injection in orders API" })).toHaveAttribute("href", "/remediation/items/i1");
    const summary = screen.getByLabelText("Remediation summary");
    expect(summary).toHaveTextContent("2 open");
    expect(summary).toHaveTextContent("1 overdue");
    expect(summary).toHaveTextContent("1 unassigned");
    expect(screen.getByRole("link", { name: /Open in the remediation workspace/ })).toHaveAttribute("href", "/remediation?application_id=a1");
    expect(api.calls.find((c) => c.path === "/api/v1/remediation/items")?.url.searchParams.get("application_id")).toBe("a1");
  });

  it("shows the feature-disabled state and the missing permission without calling the API", async () => {
    const api = mockApi({ "GET /api/v1/meta": meta(false) });
    const { unmount } = renderApp(<RemediationPanel applicationId="a1" />, { permissions: ["remediation.read"] });
    expect(await screen.findByText(/is not enabled/)).toBeInTheDocument();
    unmount();
    mockApi({ "GET /api/v1/meta": meta(true) });
    renderApp(<RemediationPanel applicationId="a1" />, { permissions: ["findings.read"] });
    expect(await screen.findByText("remediation.read")).toBeInTheDocument();
    expect(api.calls.some((c) => c.path === "/api/v1/remediation/items")).toBe(false);
  });
});
