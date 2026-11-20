import { afterEach, describe, expect, it, vi } from "vitest";
import { fireEvent, render, screen, within } from "@testing-library/react";
import { mockApi, renderApp } from "@/test/harness";
import { CompliancePage } from "@/features/compliance/CompliancePage";
import { AIReportsPage } from "@/features/ai/AIReportsPage";
import { humanizeMetric, LifecycleEvidence, lifecycleSections, type LifecycleSection } from "./LifecycleEvidence";

afterEach(() => vi.unstubAllGlobals());

// Example data for tests only (labelled fixtures).
const sections: LifecycleSection[] = [
  { key: "codegraph", title: "CodeGraph", available: true, evidence_label: "verified", evidence: "Counted from the stored CodeGraph snapshots (test fixture).", metrics: { applications_with_snapshots: 2, internet_exposed_routes: 5 } },
  { key: "threat_models", title: "Threat models", available: false, reason: "The threat_models feature is not enabled.", evidence_label: "verified", evidence: "", metrics: {} },
  { key: "remediation", title: "Remediation", available: true, evidence_label: "verified", evidence: "From remediation items.", metrics: {} },
];

describe("lifecycle evidence sections", () => {
  it("humanizes metric keys", () => {
    expect(humanizeMetric("internet_exposed_routes")).toBe("Internet exposed routes");
    expect(humanizeMetric("x")).toBe("X");
  });

  it("drops malformed sections", () => {
    expect(lifecycleSections(undefined)).toEqual([]);
    expect(lifecycleSections([{ key: "gates", title: "Gates", available: true }, null, "x", { title: "no key" }])).toHaveLength(1);
  });

  it("renders evidence, labels, metrics and honest reasons", () => {
    render(<LifecycleEvidence sections={sections} />);
    const cards = screen.getAllByTestId("lifecycle-evidence-section");
    expect(cards).toHaveLength(3);
    expect(within(cards[0]!).getByText("verified")).toBeInTheDocument();
    expect(within(cards[0]!).getByText("Internet exposed routes")).toBeInTheDocument();
    expect(within(cards[0]!).getByText("5")).toBeInTheDocument();
    expect(within(cards[1]!).getByText("The threat_models feature is not enabled.")).toBeInTheDocument();
    expect(within(cards[1]!).queryByText("verified")).toBeNull();
    expect(within(cards[2]!).getByText("No figures recorded yet.")).toBeInTheDocument();
  });

  it("renders nothing without sections", () => {
    const { container } = render(<LifecycleEvidence sections={[]} />);
    expect(container).toBeEmptyDOMElement();
  });
});

const framework = {
  key: "owasp-asvs", name: "OWASP ASVS", version: "4.0.3", scope_key: "", description: "Example framework (test fixture).", repositories_in_scope: 1,
  failing: 0, attention: 0, passing: 1, controls: [], lifecycle_evidence: sections,
};
const compRoutes = {
  "GET /api/v1/compliance/frameworks": () => ({ items: [framework], note: "" }),
  "GET /api/v1/compliance/frameworks/owasp-asvs": () => framework,
};

describe("compliance lifecycle evidence", () => {
  it("shows the sections and the export links with findings.export", async () => {
    mockApi(compRoutes);
    renderApp(<CompliancePage />, { permissions: ["findings.read", "findings.export"], path: "/compliance" });
    expect(await screen.findByRole("region", { name: "Lifecycle evidence" })).toBeInTheDocument();
    expect(screen.getByRole("link", { name: /Export JSON/ })).toHaveAttribute("href", "/api/v1/compliance/frameworks/owasp-asvs/export?format=json");
    expect(screen.getByRole("link", { name: /Export CSV/ })).toHaveAttribute("href", "/api/v1/compliance/frameworks/owasp-asvs/export?format=csv");
  });

  it("hides the export links without findings.export", async () => {
    mockApi(compRoutes);
    renderApp(<CompliancePage />, { permissions: ["findings.read"], path: "/compliance" });
    await screen.findByRole("region", { name: "Lifecycle evidence" });
    expect(screen.queryByRole("link", { name: /Export JSON/ })).toBeNull();
  });
});

describe("technical AI report lifecycle facts", () => {
  it("renders facts.lifecycle for a technical report", async () => {
    const report = { id: "rp1", kind: "technical", scope_type: "organization", title: "Technical report (test fixture)", facts: { open_by_severity: {}, lifecycle: sections }, narrative: null, narrative_error: "", model: "", created_by: "ada@example.com", created_at: "2026-11-20T10:00:00Z" };
    mockApi({
      "GET /api/v1/ai/reports": () => ({ items: [report] }),
      "GET /api/v1/ai/reports/rp1": () => report,
      "GET /api/v1/applications": () => ({ items: [] }),
    });
    renderApp(<AIReportsPage />, { permissions: ["findings.read"] });
    fireEvent.click(await screen.findByRole("button", { name: "Technical report (test fixture)" }));
    expect(await screen.findByRole("region", { name: "Lifecycle evidence" })).toBeInTheDocument();
    expect(screen.getAllByTestId("lifecycle-evidence-section")).toHaveLength(3);
  });
});
