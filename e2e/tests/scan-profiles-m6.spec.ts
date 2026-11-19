import type { Page } from "@playwright/test";
import { test, expect } from "./fixtures";

// PATHOS 3.0 M6: Quick / Standard / Comprehensive profiles beside Default,
// kinds of check per profile ("N of 10 tools"), kinds of check on Scan
// coverage, and no catalogued tool name on the Findings and Scans pages.

async function api(page: Page, method: string, path: string, body?: unknown) {
  const me = await (await page.request.get("/api/v1/me")).json();
  const res = await page.request.fetch(path, {
    method,
    headers: { "X-CSRF-Token": me.csrf_token, "Content-Type": "application/json" },
    data: body === undefined ? undefined : JSON.stringify(body),
  });
  return { status: res.status(), json: res.status() === 204 ? null : await res.json() };
}

async function setTiers(page: Page, on: boolean) {
  const r = await api(page, "PUT", "/api/v1/admin/feature-flags", { flags: { scan_profile_tiers: on } });
  expect([200, 204]).toContain(r.status);
}

test("tier profiles appear with the flag and show kinds of check", async ({ page }) => {
  await page.goto("/");
  await setTiers(page, true);
  try {
    await page.goto("/configurations/scan-profiles");
    await expect(page.getByRole("heading", { level: 1, name: "Scan profiles" })).toBeVisible();
    for (const t of ["Quick", "Standard", "Comprehensive"]) await expect(page.getByText(t, { exact: true }).first()).toBeVisible();
    await page.getByText("Standard", { exact: true }).first().click();
    const panel = page.getByTestId("profile-kinds");
    await expect(panel).toBeVisible();
    await expect(panel.getByText("Infrastructure as code", { exact: true })).toBeVisible();
    await expect(panel.getByText(/\d+ of 10 tools/).first()).toBeVisible();
  } finally {
    await setTiers(page, false);
  }
  await page.goto("/configurations/scan-profiles");
  await expect(page.getByRole("heading", { level: 1, name: "Scan profiles" })).toBeVisible();
  await expect(page.getByText("Comprehensive", { exact: true })).toHaveCount(0);
});

test("scan coverage lists the 20 kinds of check", async ({ page }) => {
  await page.goto("/configurations/scan-coverage");
  await expect(page.getByRole("heading", { name: "Kinds of check" })).toBeVisible();
  await expect(page.getByRole("button", { name: "Infrastructure as code tools" })).toBeVisible();
  await expect(page.getByRole("button", { name: "Fuzz testing tools" })).toBeVisible();
});

for (const path of ["/findings", "/scans"]) {
  test(`${path} names kinds of check, not tools`, async ({ page }) => {
    await page.goto(path);
    await expect(page.getByRole("heading", { level: 1 })).toBeVisible();
    await page.waitForLoadState("networkidle");
    const options = await page.locator("option").allTextContents();
    expect(options).toContain("Infrastructure as code");
    const text = (await page.locator("main").innerText()) + "\n" + options.join("\n");
    for (const name of ["Opengrep", "Gitleaks", "Checkov", "Trivy", "Grype", "OSV-Scanner", "Semgrep"]) {
      expect(text, `${name} on ${path}`).not.toMatch(new RegExp(`\\b${name}\\b`));
    }
  });
}
