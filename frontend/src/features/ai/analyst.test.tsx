import { afterEach, describe, expect, it, vi } from "vitest";
import { fireEvent, screen, waitFor } from "@testing-library/react";
import { mockApi, renderApp } from "@/test/harness";
import { AnalystPage } from "./AnalystPage";
import { AIReportsPage } from "./AIReportsPage";

afterEach(() => vi.unstubAllGlobals());

const answer = {
  id: "m2", role: "assistant", content: "Fix the **SQL injection** first.\n\n- it is in CISA KEV\n- risk 95", follow_ups: ["Which repositories are exposed?"],
  citations: [{ id: "f1", title: "SQL injection in orders export", severity: "critical" }], context_findings: 12, model: "qwen2.5-coder:3b",
  input_tokens: 900, output_tokens: 80, created_at: "2026-11-18T01:00:00Z",
};

describe("AI Security Analyst", () => {
  it("asks, renders the answer with cited findings and offers follow-ups", async () => {
    const api = mockApi({
      "GET /api/v1/ai/analyst/conversations": () => ({ items: [{ id: "c1", title: "New conversation", created_at: "", updated_at: "2026-11-18T01:00:00Z" }] }),
      "GET /api/v1/ai/analyst/conversations/c1": () => ({ id: "c1", title: "New conversation", created_at: "", updated_at: "", messages: [] }),
      "POST /api/v1/ai/analyst/conversations/c1/messages": () => ({
        messages: [{ ...answer, id: "m1", role: "user", content: "What should we fix first this week?", citations: [], follow_ups: [] }, answer],
      }),
    });
    renderApp(<AnalystPage />, { permissions: ["ai.review", "findings.read"] });
    fireEvent.click(await screen.findByRole("button", { name: "What should we fix first this week?" }));
    expect(await screen.findByText("SQL injection", { selector: "strong" })).toBeInTheDocument();
    expect(screen.getByRole("link", { name: "SQL injection in orders export" })).toBeInTheDocument();
    expect(screen.getByText(/answered from 12 findings/)).toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: "Which repositories are exposed?" }));
    await waitFor(() => expect(api.calls.filter((c) => c.method === "POST").length).toBe(2));
    expect(api.calls.filter((c) => c.method === "POST")[1]!.body).toEqual({ question: "Which repositories are exposed?" });
  });
});

describe("AI reports", () => {
  it("generates a figures-only report when the narrative is off", async () => {
    const api = mockApi({
      "GET /api/v1/ai/reports": () => ({ items: [] }),
      "GET /api/v1/applications": () => ({ items: [] }),
      "POST /api/v1/ai/reports": () => ({ id: "r1", kind: "executive", scope_type: "organization", title: "Executive security summary: Organization", facts: {},
        narrative: null, narrative_error: "", model: "", created_by: "Ada", created_at: "2026-11-18T01:00:00Z" }),
      "GET /api/v1/ai/reports/r1": () => ({ id: "r1", kind: "executive", scope_type: "organization", title: "Executive security summary: Organization",
        facts: { open_by_severity: { critical: 2, high: 1, medium: 0, low: 0 }, open_actively_exploited: 1, mean_days_to_fix: null },
        narrative: null, narrative_error: "", model: "", created_by: "Ada", created_at: "2026-11-18T01:00:00Z" }),
    });
    renderApp(<AIReportsPage />, { permissions: ["findings.read", "ai.review"] });
    fireEvent.click(await screen.findByLabelText("AI narrative"));
    fireEvent.click(screen.getByRole("button", { name: /Generate/ }));
    await waitFor(() => expect(api.calls.some((c) => c.method === "POST")).toBe(true));
    expect(api.calls.find((c) => c.method === "POST")!.body).toMatchObject({ kind: "executive", scope_type: "organization", narrative: false });
    expect(await screen.findByText("2 / 1 / 0 / 0")).toBeInTheDocument();
    expect(screen.getAllByText("not available").length).toBeGreaterThan(0);
  });
});
