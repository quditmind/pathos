import { afterEach, describe, expect, it, vi } from "vitest";
import { fireEvent, screen, waitFor } from "@testing-library/react";
import { mockApi, renderApp } from "@/test/harness";
import { ApplicationVersionsPage } from "./ApplicationVersionsPage";
import { ComponentPoliciesPage } from "./ComponentPoliciesPage";
import { PortfolioPage } from "./PortfolioPage";
import { VexPage } from "./VexPage";
import type { AppVersion, ComponentPolicy, VexSuggestion } from "./api";

afterEach(() => vi.unstubAllGlobals());

const version: AppVersion = {
  id: "v1", application_id: "a1", version: "2.3.1", description: "Spring release", released_at: null, created_by: "Ada",
  created_at: "2026-11-18T10:00:00Z", repository_count: 1, component_count: 2, open_findings: 1,
};

describe("application versions", () => {
  it("lists versions, creates one and shows the frozen snapshot with VEX export links", async () => {
    const api = mockApi({
      "GET /api/v1/applications/a1/versions": () => ({ items: [version], application: { id: "a1", name: "Payments" }, can_manage: true }),
      "POST /api/v1/applications/a1/versions": () => ({ version: { ...version, id: "v2", version: "2.4.0" }, warnings: [] }),
      "GET /api/v1/applications/a1/versions/v1": () => ({
        version, application: { id: "a1", name: "Payments" }, can_manage: true,
        repositories: [{ repository_id: "r1", full_name: "acme/payments", ref: "main", commit_sha: "0123456789abcdef", scan_job_id: "j1" }],
        components: [{ repository_id: "r1", name: "lodash", version: "4.17.20", purl: "pkg:npm/lodash@4.17.20", type: "library", licenses: ["MIT"] }],
        findings: [{ finding_id: "f1", repository_id: "r1", category: "sca", title: "Prototype pollution", severity: "high", cve: "CVE-2021-23337",
          package_name: "lodash", package_version: "4.17.20", fixed_version: "4.17.21", status_at_release: "open", status: "false_positive" }],
      }),
      "GET /api/v1/applications/a1/versions/v2": () => ({ version: { ...version, id: "v2", version: "2.4.0" }, application: { id: "a1", name: "Payments" }, can_manage: true, repositories: [], components: [], findings: [] }),
    });
    renderApp(<ApplicationVersionsPage appId="a1" />, { permissions: ["repos.read", "repos.manage", "findings.export", "findings.triage"] });
    expect(await screen.findByText("Payments: versions")).toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: /New version/ }));
    fireEvent.change(screen.getByLabelText("Version"), { target: { value: "2.4.0" } });
    fireEvent.click(screen.getByRole("button", { name: "Create version" }));
    await waitFor(() => expect(api.calls.some((c) => c.method === "POST" && c.path === "/api/v1/applications/a1/versions" && (c.body as { version: string }).version === "2.4.0")).toBe(true));
    fireEvent.keyDown(document.activeElement ?? document.body, { key: "Escape" });
    await waitFor(() => expect(screen.queryByRole("button", { name: "Create version" })).not.toBeInTheDocument());
    fireEvent.click(screen.getByText("2.3.1"));
    expect(await screen.findByText("Prototype pollution")).toBeInTheDocument();
    expect(screen.getByText("false positive")).toBeInTheDocument();
    expect(screen.getByText("main @ 0123456789ab")).toBeInTheDocument();
    expect(screen.getByRole("link", { name: /OpenVEX/ })).toHaveAttribute("href", "/api/v1/applications/a1/versions/v1/vex?format=openvex");
    expect(screen.getByRole("link", { name: /CycloneDX VEX/ })).toHaveAttribute("href", "/api/v1/applications/a1/versions/v1/vex?format=cyclonedx");
    expect(screen.getByLabelText("Import VEX document")).toBeInTheDocument();
  });

  it("hides management without repos.manage", async () => {
    mockApi({ "GET /api/v1/applications/a1/versions": () => ({ items: [], application: { id: "a1", name: "Payments" }, can_manage: false }) });
    renderApp(<ApplicationVersionsPage appId="a1" />, { permissions: ["repos.read"] });
    expect(await screen.findByText("No versions yet")).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: /New version/ })).not.toBeInTheDocument();
  });
});

const sug = (over: Partial<VexSuggestion>): VexSuggestion => ({
  id: "s1", import_id: "i1", finding_id: "f1", finding_title: "Prototype pollution", finding_status: "open", severity: "high",
  package_name: "lodash", package_version: "4.17.20", repository_id: "r1", repository: "acme/payments", vulnerability: "CVE-2021-23337",
  vex_status: "not_affected", justification: "vulnerable_code_not_in_execute_path", impact_statement: "template() is never called",
  status: "pending", requested_by_id: "u2", requested_by: "Bob", decided_by: "", decided_at: null, decision_note: "",
  created_at: "2026-11-18T10:00:00Z", can_decide: true, ...over,
});

describe("VEX review", () => {
  it("lets another reviewer approve and explains why the importer cannot", async () => {
    const api = mockApi({
      "GET /api/v1/vex-suggestions": () => ({ items: [sug({}), sug({ id: "s2", vex_status: "fixed", can_decide: false, cannot_decide_reason: "You imported this statement; another reviewer must decide it." })] }),
      "GET /api/v1/vex-imports": () => ({ items: [] }),
      "GET /api/v1/repositories": () => ({ items: [], next_cursor: "" }),
      "POST /api/v1/vex-suggestions/s1/approve": () => sug({ status: "approved" }),
    });
    renderApp(<VexPage />, { permissions: ["findings.read", "findings.accept_risk", "findings.triage", "findings.export"] });
    expect((await screen.findAllByText(/template\(\) is never called/)).length).toBe(2);
    expect(screen.getByText("You imported this statement; another reviewer must decide it.")).toBeInTheDocument();
    expect(screen.getByText(/resolved only when a scan no longer detects it/)).toBeInTheDocument();
    const approve = screen.getAllByRole("button", { name: /Approve/ });
    expect(approve).toHaveLength(1);
    fireEvent.change(screen.getByLabelText("Decision note"), { target: { value: "verified" } });
    fireEvent.click(approve[0]!);
    await waitFor(() => expect(api.calls.some((c) => c.method === "POST" && c.path === "/api/v1/vex-suggestions/s1/approve" && (c.body as { note: string }).note === "verified")).toBe(true));
  });
});

describe("portfolio", () => {
  it("searches versions and repositories containing a vulnerability", async () => {
    const api = mockApi({
      "GET /api/v1/portfolio/component-versions": () => ({
        versions: [{ application_id: "a1", application_name: "Payments", version_id: "v1", version: "2.3.1", repository: "acme/payments", component: "log4j-core", component_version: "2.14.1", purl: "", matched_by: "vulnerability" }],
        repositories: [],
      }),
    });
    renderApp(<PortfolioPage />, { permissions: ["sbom.read"] });
    fireEvent.change(await screen.findByLabelText("Vulnerability"), { target: { value: "CVE-2021-44228" } });
    fireEvent.click(screen.getByRole("button", { name: /Search/ }));
    expect(await screen.findByText("Payments")).toBeInTheDocument();
    expect(screen.getByText("No current inventory contains it.")).toBeInTheDocument();
    expect(api.calls.find((c) => c.path === "/api/v1/portfolio/component-versions")!.url.searchParams.get("cve")).toBe("CVE-2021-44228");
  });
});

describe("component policies", () => {
  it("creates a licence policy and shows violations", async () => {
    const pol: ComponentPolicy = { id: "p1", name: "No GPL", description: "", enabled: true, condition_kind: "license", params: { licenses: ["GPL-3.0-only"] },
      violation_state: "fail", created_at: "", updated_at: "", evaluated_at: null, open_violations: 1 };
    const api = mockApi({
      "GET /api/v1/component-policies": () => ({ items: [pol], can_manage: true }),
      "POST /api/v1/component-policies": () => pol,
      "GET /api/v1/component-policy-violations": () => ({ items: [{ id: "x1", policy_id: "p1", policy_name: "No GPL", violation_state: "fail", repository_id: "r1",
        repository: "acme/payments", component: "gpl-thing", component_version: "1.0.0", purl: "", detail: "licence GPL-3.0-only", first_seen_at: "2026-11-18T10:00:00Z", last_seen_at: "", resolved_at: null }] }),
    });
    renderApp(<ComponentPoliciesPage />, { permissions: ["sbom.read", "settings.manage"] });
    expect(await screen.findByText("licence GPL-3.0-only")).toBeInTheDocument();
    expect(screen.getByText(/licence in GPL-3.0-only/)).toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: /New policy/ }));
    fireEvent.change(screen.getByLabelText("Name"), { target: { value: "No AGPL" } });
    fireEvent.change(screen.getByLabelText(/^Licences/), { target: { value: "AGPL-3.0-only, SSPL-1.0" } });
    fireEvent.click(screen.getByRole("button", { name: "Save" }));
    await waitFor(() => {
      const c = api.calls.find((x) => x.method === "POST" && x.path === "/api/v1/component-policies");
      expect(c?.body).toMatchObject({ name: "No AGPL", condition_kind: "license", params: { licenses: ["AGPL-3.0-only", "SSPL-1.0"] } });
    });
  });
});
