import { afterEach, describe, expect, it, vi } from "vitest";
import { fireEvent, screen, waitFor } from "@testing-library/react";
import { mockApi, renderApp } from "@/test/harness";
import { SecurityPolicies, describeConditions, type SecurityPolicy } from "./SecurityPolicies";
import { CompliancePage } from "@/features/compliance/CompliancePage";

afterEach(() => vi.unstubAllGlobals());

const pol: SecurityPolicy = {
  id: "p1", name: "No KEV in production", description: "", enabled: true, version: 2,
  conditions: { kev: true, environments: ["production"] }, actions: { block: true, sla_days: 7 },
  applies_to_pull_requests: true, open_violations: 3, created_by: "ada@acme.test", updated_by: "ada@acme.test",
  updated_at: "2026-11-18T01:00:00Z", evaluated_at: "2026-11-18T01:00:00Z",
};

describe("security policies", () => {
  it("describes conditions in words", () => {
    expect(describeConditions({ min_severity: "high", categories: ["sca"], kev: true })).toBe("severity high or above · Dependencies (SCA) · actively exploited (KEV)");
  });

  it("lists policies with actions and violations, previews and saves a new one", async () => {
    const api = mockApi({
      "GET /api/v1/security-policies": () => ({ items: [pol] }),
      "POST /api/v1/security-policies/preview": () => ({ matching: 4, applies_to_pull_requests: true, sample: [] }),
      "POST /api/v1/security-policies": (_u, init) => ({ ...pol, id: "p2", ...(init.json as object) }),
    });
    renderApp(<SecurityPolicies />, { permissions: ["findings.read", "settings.manage"] });
    expect(await screen.findByText("No KEV in production")).toBeInTheDocument();
    expect(screen.getByText("Blocks gates")).toBeInTheDocument();
    expect(screen.getByText("SLA 7 d")).toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: /New policy/ }));
    fireEvent.change(await screen.findByLabelText("Name"), { target: { value: "Critical secrets" } });
    fireEvent.click(screen.getByLabelText("Secrets"));
    expect(await screen.findByText(/open findings you can see match now/)).toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: "Save policy" }));
    await waitFor(() => expect(api.calls.some((c) => c.method === "POST" && c.path === "/api/v1/security-policies")).toBe(true));
    const body = api.calls.find((c) => c.method === "POST" && c.path === "/api/v1/security-policies")!.body as { name: string; conditions: { categories: string[] } };
    expect(body.name).toBe("Critical secrets");
    expect(body.conditions.categories).toEqual(["secrets"]);
  });

  it("is read-only without settings.manage", async () => {
    mockApi({ "GET /api/v1/security-policies": () => ({ items: [pol] }) });
    renderApp(<SecurityPolicies />, { permissions: ["findings.read"] });
    expect(await screen.findByText("No KEV in production")).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: /New policy/ })).not.toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Edit No KEV in production" })).not.toBeInTheDocument();
  });
});

describe("compliance", () => {
  it("shows frameworks and the failing controls with their findings", async () => {
    mockApi({
      "GET /api/v1/compliance/frameworks": () => ({ note: "", items: [
        { key: "pci_dss_4", name: "PCI DSS", version: "4.0.1", scope_key: "pci_dss", description: "", repositories_in_scope: 2, failing: 1, attention: 0, passing: 9 },
      ] }),
      "GET /api/v1/compliance/frameworks/pci_dss_4": () => ({
        key: "pci_dss_4", name: "PCI DSS", version: "4.0.1", scope_key: "pci_dss", description: "Payment card requirements.", repositories_in_scope: 2, failing: 1, attention: 0, passing: 9,
        controls: [
          { id: "8.6.2", title: "Passwords are not hard-coded", categories: ["secrets"], status: "failing", open_findings: 2, by_severity: { high: 2 }, repositories: 1 },
          { id: "6.4.1", title: "Public-facing web applications are protected", categories: ["dast"], status: "passing", open_findings: 0, by_severity: {}, repositories: 0 },
        ],
      }),
    });
    renderApp(<CompliancePage />, { permissions: ["findings.read"] });
    expect(await screen.findByText("1 failing")).toBeInTheDocument();
    expect(await screen.findByText("Passwords are not hard-coded")).toBeInTheDocument();
    expect(screen.getByText("Failing")).toBeInTheDocument();
    expect(screen.getByText("No open findings")).toBeInTheDocument();
  });
});
