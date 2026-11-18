import { describe, expect, it } from "vitest";
import { categoryLabel, categoryName, FINDING_CATEGORIES } from "./findingCategories";

describe("finding categories", () => {
  it("lists the content-scanning categories with labels", () => {
    for (const c of ["malware", "misconfiguration", "binary", "license"]) {
      expect(FINDING_CATEGORIES).toContain(c);
    }
    for (const c of FINDING_CATEGORIES) {
      expect(categoryLabel[c]).toBeTruthy();
    }
    expect(categoryName("misconfiguration")).toBe("Framework configuration");
    expect(categoryName("binary")).toBe("Binary hardening");
  });

  it("falls back to the raw value for unknown categories", () => {
    expect(categoryName("future")).toBe("future");
  });
});
