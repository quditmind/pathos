import { afterEach, describe, expect, it, vi } from "vitest";
import { fireEvent, screen, waitFor } from "@testing-library/react";
import { mockApi, renderApp } from "@/test/harness";
import { AIPanel } from "./workspace/AIPanel";
import type { Recommendation, ReviewDetail } from "./types";

afterEach(() => vi.unstubAllGlobals());

const d = { id: "rv1", can: { assess: true, ai: true, ai_unavailable_reason: "" }, assessment: { fields: {}, remediation: {} } } as unknown as ReviewDetail;
const rec = (over: Partial<Recommendation>): Recommendation => ({
  id: "r1", kind: "patch", provider: "self_hosted", model: "qwen", transmitted_sha256: "x", requested_by: "u1", requested_by_name: "Ada",
  created_at: "2026-11-18T01:00:00Z", label: "AI suggestion", patch_status: "proposed",
  content: { summary: "Use a parameterized query", points: [], references: [], code: "--- a/app/db.py\n+++ b/app/db.py\n@@ -4 +4 @@\n-cur.execute(q % id)\n+cur.execute(q, (id,))\n" },
  ...over,
});

describe("AI patch proposals", () => {
  it("shows the diff and requires a note to reject; approval is recorded", async () => {
    const api = mockApi({
      "GET /api/v1/human-reviews/rv1/ai": () => ({ items: [rec({})] }),
      "POST /api/v1/human-reviews/rv1/ai/r1/patch-decision": () => new Response(null, { status: 204 }),
    });
    renderApp(<AIPanel d={d} />, { permissions: ["reviews.assess"] });
    expect(await screen.findByLabelText("Proposed patch")).toHaveTextContent("+cur.execute(q, (id,))");
    const reject = screen.getByRole("button", { name: /Reject/ });
    expect(reject).toBeDisabled();
    fireEvent.click(screen.getByRole("button", { name: /Approve patch/ }));
    await waitFor(() => expect(api.calls.some((c) => c.path === "/api/v1/human-reviews/rv1/ai/r1/patch-decision")).toBe(true));
    expect(api.calls.find((c) => c.path.endsWith("patch-decision"))!.body).toMatchObject({ decision: "approved" });
  });

  it("offers approved patches for download only", async () => {
    mockApi({ "GET /api/v1/human-reviews/rv1/ai": () => ({ items: [rec({ patch_status: "approved", patch_decided_by: "Grace" })] }) });
    renderApp(<AIPanel d={d} />, { permissions: ["reviews.assess"] });
    expect(await screen.findByText("Approved by Grace")).toBeInTheDocument();
    expect(screen.getByRole("link", { name: /Download .patch/ })).toHaveAttribute("href", "/api/v1/human-reviews/rv1/ai/r1/patch");
    expect(screen.queryByRole("button", { name: /Approve patch/ })).toBeNull();
  });

  it("offers the new kinds of assistance", async () => {
    mockApi({ "GET /api/v1/human-reviews/rv1/ai": () => ({ items: [] }) });
    renderApp(<AIPanel d={d} />, { permissions: ["reviews.assess"] });
    const select = await screen.findByLabelText("Kind of suggestion");
    for (const label of ["Propose a patch (reviewed by you, never applied)", "Explain the risk score", "Find possible duplicates"]) {
      expect(select).toHaveTextContent(label);
    }
  });
});
