import { describe, expect, it } from "vitest";
import { render, screen } from "@testing-library/react";
import { csvEscape, toCsv, type Column } from "./DataTable";
import { formatKpiValue, kpiDelta, KpiCard } from "./KpiCard";
import { splitHref } from "@/lib/utils";
import type { Kpi } from "@/api/types";

describe("CSV export", () => {
  it("quotes and neutralises formulas", () => {
    expect(csvEscape('a,"b"')).toBe('"a,""b"""');
    expect(csvEscape("=HYPERLINK(1)")).toBe("'=HYPERLINK(1)");
    expect(csvEscape("@cmd")).toBe("'@cmd");
    expect(csvEscape(null)).toBe("");
  });
  it("exports only columns with csv accessors", () => {
    const cols: Column<{ a: string }>[] = [
      { id: "a", header: "A", cell: (r) => r.a, csv: (r) => r.a },
      { id: "b", header: "B", cell: () => "x" },
    ];
    expect(toCsv(cols, [{ a: "1" }])).toBe("A\r\n1\r\n");
  });
});

describe("KPI helpers", () => {
  it("formats units", () => {
    expect(formatKpiValue(12.34, "percent")).toMatch(/^12\.3%$/);
    expect(formatKpiValue(4, "days")).toBe("4d");
  });
  it("colours deltas by polarity", () => {
    expect(kpiDelta({ value: 5, previous: 10, polarity: "lower_is_better" })?.tone).toBe("good");
    expect(kpiDelta({ value: 15, previous: 10, polarity: "lower_is_better" })?.tone).toBe("bad");
    expect(kpiDelta({ value: 15, previous: 10, polarity: "neutral" })?.tone).toBe("neutral");
    expect(kpiDelta({ value: 1, previous: 0, polarity: "higher_is_better" })?.pct).toBeNull();
    expect(kpiDelta({ value: 1, previous: null, polarity: "neutral" })).toBeNull();
  });
});

const base: Kpi = {
  key: "open_findings", label: "Open findings", group: "Risk posture", description: "", unit: "count",
  polarity: "lower_is_better", drill: "/findings", status: "not_yet_available", phase: 6, value: null, previous: null,
};

describe("KpiCard", () => {
  it("never shows a number for unavailable KPIs", () => {
    render(<KpiCard kpi={base} period="30 days" />);
    expect(screen.getByText("Not yet available")).toBeInTheDocument();
    expect(screen.getByText(/phase 6/)).toBeInTheDocument();
  });
  it("shows restricted state without a value", () => {
    render(<KpiCard kpi={{ ...base, status: "restricted", value: 3 }} period="30 days" />);
    expect(screen.getByText(/additional permission/)).toBeInTheDocument();
    expect(screen.queryByText("3")).toBeNull();
  });
});

describe("splitHref", () => {
  it("splits path and query", () => {
    expect(splitHref("/admin/audit?outcome=denied")).toEqual({ to: "/admin/audit", search: { outcome: "denied" } });
    expect(splitHref("/")).toEqual({ to: "/", search: {} });
  });
});
