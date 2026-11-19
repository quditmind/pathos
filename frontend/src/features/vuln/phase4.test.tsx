import { afterEach, describe, expect, it, vi } from "vitest";
import { fireEvent, screen, waitFor, within } from "@testing-library/react";
import { mockApi, renderApp, me } from "@/test/harness";
import { SuppressionRulesPage, type SuppressionRule } from "./SuppressionRulesPage";
import { RelatedFindings } from "./RelatedFindings";
import { AttackPathsPage } from "@/features/posture/AttackPathsPage";

afterEach(() => vi.unstubAllGlobals());

const rule = (over: Partial<SuppressionRule>): SuppressionRule => ({
  id: "s1", name: "Generated code", scope_type: "repository", scope_id: "r1", scope_name: "acme/api", match_rule_id: "", match_path: "gen/*",
  match_package: "", match_cve: "", match_scanner: "", match_category: "sast", decision: "false_positive",
  justification: "Generated from the OpenAPI schema and never deployed", expires_at: "2027-02-01T00:00:00Z", status: "pending",
  requested_by: "Ada", requested_by_id: "someone-else", requested_at: "2026-11-17T10:00:00Z", decided_by: null, decided_at: null,
  decision_note: "", findings: 0, ...over,
});

describe("suppression rules", () => {
  it("lets another person approve, and only the proposer withdraw", async () => {
    const self = me(["findings.read", "findings.triage", "findings.accept_risk"]).user.id;
    const api = mockApi({
      "GET /api/v1/suppression-rules": () => ({ items: [rule({}), rule({ id: "s2", name: "Mine", requested_by_id: self }), rule({ id: "s3", name: "Active", status: "active", findings: 4 })] }),
      "POST /api/v1/suppression-rules/s1/approve": () => ({ rule: rule({ status: "active" }), findings_changed: 3 }),
    });
    renderApp(<SuppressionRulesPage />, { permissions: ["findings.read", "findings.triage", "findings.accept_risk"] });
    const other = (await screen.findByText("Generated code")).closest("tr")!;
    expect(within(other).getByText("path gen/* · type sast")).toBeInTheDocument();
    const mine = screen.getByText("Mine").closest("tr")!;
    expect(within(mine).queryByRole("button", { name: "Approve" })).toBeNull();
    expect(within(mine).getByText("awaiting another approver")).toBeInTheDocument();
    expect(within(screen.getByText("Active").closest("tr")!).getByRole("button", { name: "Revoke" })).toBeInTheDocument();
    fireEvent.click(within(other).getByRole("button", { name: "Approve" }));
    await waitFor(() => expect(api.calls.some((c) => c.method === "POST" && c.path === "/api/v1/suppression-rules/s1/approve")).toBe(true));
  });

  it("needs a specific criterion and a justification before proposing", async () => {
    mockApi({ "GET /api/v1/suppression-rules": () => ({ items: [] }), "GET /api/v1/applications": () => ({ items: [] }) });
    renderApp(<SuppressionRulesPage />, { permissions: ["findings.read", "findings.triage"] });
    fireEvent.click(await screen.findByRole("button", { name: /Propose rule/ }));
    fireEvent.change(screen.getByLabelText("Name"), { target: { value: "x" } });
    fireEvent.change(screen.getByLabelText("Scope"), { target: { value: "organization" } });
    const submit = screen.getByRole("button", { name: "Propose rule" });
    expect(submit).toBeDisabled();
    fireEvent.change(screen.getByLabelText(/^CVE/), { target: { value: "CVE-2021-44906" } });
    fireEvent.change(screen.getByLabelText(/Justification/), { target: { value: "too short" } });
    expect(submit).toBeDisabled();
    fireEvent.change(screen.getByLabelText(/Justification/), { target: { value: "The advisory does not affect our usage of the package" } });
    expect(submit).toBeEnabled();
  });
});

describe("related findings", () => {
  it("shows other tools at the same place and other repositories", async () => {
    mockApi({
      "GET /api/v1/findings/f1/related": () => ({
        cve: "CVE-2021-44906", other_repositories: 2,
        items: [{ id: "f2", relation: "same_location", title: "SQL injection", severity: "high", status: "open", scanner_keys: ["import-sast-semgrep-pro"],
          file_path: "app.js", start_line: 12, scan_target_name: null, risk_score: 60 }],
      }),
    });
    renderApp(<RelatedFindings findingId="f1" />, { permissions: ["findings.read"] });
    expect(await screen.findByText(/Same location, another engine · SAST: deep engines · confirmed by 1 engine · app.js:12/)).toBeInTheDocument();
    expect(screen.getByRole("link", { name: /open in 2 other repositories/ })).toBeInTheDocument();
  });
});

describe("attack paths", () => {
  it("draws each path from the internet to the finding", async () => {
    mockApi({
      "GET /api/v1/posture/attack-paths": () => ({
        counts: { exposed_repository: 1 }, truncated: false,
        items: [{ finding_id: "f1", risk: 91, severity: "high", kev: true, exploit_available: true, entry: "exposed_repository",
          reasons: ["the asset is exposed to the internet and its code uses the vulnerable package", "actively exploited (CISA KEV)"],
          steps: [{ type: "internet", label: "Internet", sub: "https://shop.example" }, { type: "application", label: "Shop" },
            { type: "repository", label: "acme/shop", link: "/repositories?repo=r1" }, { type: "component", label: "lodash@4.17.20", sub: "the code imports or names the package" },
            { type: "finding", label: "Prototype pollution", link: "/findings?finding=f1" }] }],
      }),
    });
    renderApp(<AttackPathsPage />, { permissions: ["findings.read"] });
    expect(await screen.findByText("lodash@4.17.20")).toBeInTheDocument();
    expect(screen.getByText("Internet")).toBeInTheDocument();
    expect(screen.getByText(/actively exploited \(CISA KEV\)/)).toBeInTheDocument();
    expect(screen.getByText(/1 through exposed assets/)).toBeInTheDocument();
  });
});
