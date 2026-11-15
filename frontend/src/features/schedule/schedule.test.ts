import { describe, expect, it } from "vitest";
import { describeCron } from "./api";

describe("describeCron", () => {
  it("describes presets and common shapes", () => {
    expect(describeCron("0 2 * * *")).toBe("Daily at 02:00");
    expect(describeCron("30 7 * * 1-5")).toBe("Weekdays at 07:30");
    expect(describeCron("15 4 * * 3")).toBe("Every Wednesday at 04:15");
    expect(describeCron("0 5 15 * *")).toBe("Monthly on day 15 at 05:00");
    expect(describeCron("0 */6 * * *")).toBe("Every 6 hours");
    expect(describeCron("@weekly")).toBe("Weekly (Sunday 00:00)");
  });
  it("falls back to the raw expression", () => {
    expect(describeCron("5,35 1-3 * 1 *")).toBe("5,35 1-3 * 1 *");
  });
});
