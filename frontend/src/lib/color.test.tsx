import { describe, expect, it } from "vitest";
import { render, screen } from "@testing-library/react";
import { TagChip } from "@/components/data/TagChip";
import { chipColors, contrastRatio, hexToRgb, isHexColor } from "./color";

describe("colour helpers", () => {
  it("parses hex colours", () => {
    expect(isHexColor("#1f6feb")).toBe(true);
    expect(isHexColor("blue")).toBe(false);
    expect(hexToRgb("#ff8000")).toEqual([255, 128, 0]);
  });

  it.each(["#1f6feb", "#ffd60a", "#00ff00", "#000000", "#ffffff", "#e5534b", "#7c3aed"])("keeps AA text contrast for %s in both themes", (hex) => {
    const c = chipColors(hex);
    expect(contrastRatio(hexToRgb(c.fgLight), hexToRgb(c.bgLight))).toBeGreaterThanOrEqual(4.5);
    expect(contrastRatio(hexToRgb(c.fgDark), hexToRgb(c.bgDark))).toBeGreaterThanOrEqual(4.5);
  });
});

describe("TagChip", () => {
  it("renders hex colours with a tint and theme-specific readable text", () => {
    render(<TagChip name="Payments" category="Team" color="#ffd60a" />);
    const chip = screen.getByTitle("Team: Payments");
    expect(chip.style.backgroundColor).toBe("rgba(255, 214, 10, 0.14)");
    const fg = chip.style.getPropertyValue("--chip-fg");
    const fgDark = chip.style.getPropertyValue("--chip-fg-dark");
    expect(fg).toMatch(/^#[0-9a-f]{6}$/);
    // Yellow text on white would be unreadable: it must have been darkened.
    expect(fg).not.toBe("#ffd60a");
    expect(fgDark).toMatch(/^#[0-9a-f]{6}$/);
    expect(chip.className).toContain("text-[var(--chip-fg)]");
  });

  it("keeps palette names on the class-based colours", () => {
    render(<TagChip name="Core" color="blue" />);
    const chip = screen.getByTitle("Core");
    expect(chip.className).toContain("text-blue-700");
    expect(chip.style.backgroundColor).toBe("");
  });
});
