import { describe, expect, it } from "vitest";
import { slaState } from "./LifecyclePanel";
import { needsReason, transitions } from "./api";

const inDays = (d: number) => new Date(Date.now() + d * 86400000).toISOString();

describe("slaState", () => {
  it("is null without a deadline or when closed", () => {
    expect(slaState({ sla_due_at: null, status: "open" })).toBeNull();
    expect(slaState({ sla_due_at: inDays(-3), status: "fixed" })).toBeNull();
  });
  it("flags breached and due-soon findings", () => {
    expect(slaState({ sla_due_at: inDays(-2.5), status: "open" })?.tone).toBe("danger");
    expect(slaState({ sla_due_at: inDays(3), status: "in_progress" })?.tone).toBe("warning");
    expect(slaState({ sla_due_at: inDays(40), status: "open" })?.tone).toBe("neutral");
  });
});

describe("transitions", () => {
  it("never offers accepted_risk directly and requires reasons for closures", () => {
    for (const next of Object.values(transitions)) expect(next).not.toContain("accepted_risk");
    expect(needsReason("false_positive")).toBe(true);
    expect(needsReason("in_progress")).toBe(false);
  });
});
