import { test, expect } from "./fixtures";

// PATHOS 3.0 M1 enterprise shell: brand header and version, Help menu,
// help drawer, Troubleshooting centre, and every old menu URL.

test("brand header shows the version from /api/v1/meta and opens About", async ({ page, request }) => {
  const r = await request.get("/api/v1/meta");
  expect(r.ok()).toBe(true);
  const meta = (await r.json()) as { product: string; vendor: string; version: string };
  expect(meta.product).toBe("PATHOS");
  expect(meta.vendor).toBe("Quditmind");
  await page.goto("/");
  const v = meta.version === "dev" || meta.version.startsWith("v") ? meta.version : `v${meta.version}`;
  const chip = page.getByTestId("version-chip");
  await expect(chip).toHaveText(new RegExp(v.replace(/[.+]/g, "\\$&")));
  await expect(page.getByText("Quditmind", { exact: true }).first()).toBeVisible();
  await chip.click();
  const about = page.getByRole("dialog", { name: "About PATHOS" });
  await expect(about).toBeVisible();
  await expect(about.getByText("Apache License 2.0")).toBeVisible();
  await expect(about.getByText(v, { exact: true }).first()).toBeVisible();
});

test("sign-in page shows the brand and the version", async ({ browser, request }) => {
  const meta = (await (await request.get("/api/v1/meta")).json()) as { version: string };
  const ctx = await browser.newContext({ storageState: { cookies: [], origins: [] }, ignoreHTTPSErrors: true });
  const page = await ctx.newPage();
  await page.goto("/login");
  await expect(page.getByText("Quditmind", { exact: true })).toBeVisible();
  await expect(page.getByTestId("login-version")).toContainText(meta.version);
  await ctx.close();
});

test("F1 opens help for the current page", async ({ page }) => {
  await page.goto("/scans");
  await expect(page.getByRole("heading", { level: 1, name: "Scans" })).toBeVisible();
  await page.keyboard.press("F1");
  const drawer = page.getByRole("dialog", { name: /Help: Running scans/ });
  await expect(drawer).toBeVisible();
  await expect(drawer.locator("article.help-prose h1")).toBeVisible();
  await page.keyboard.press("Escape");
  await expect(drawer).toHaveCount(0);
  await page.keyboard.press("Shift+?");
  await expect(page.getByRole("dialog", { name: /Help: Running scans/ })).toBeVisible();
});

test("Help menu lists every item", async ({ page }) => {
  await page.goto("/");
  await page.getByRole("button", { name: "Help", exact: true }).click();
  for (const name of ["Help for this page", "Help centre", "Troubleshooting centre", "Keyboard shortcuts", /What's new in/, "API reference", "System status", "Report a problem", "About PATHOS"]) {
    await expect(page.getByRole("menuitem", { name })).toBeVisible();
  }
  await page.getByRole("menuitem", { name: "System status" }).click();
  const status = page.getByRole("dialog", { name: "System status" });
  await expect(status.getByText("API", { exact: true })).toBeVisible();
  await expect(status.getByText("Database", { exact: true })).toBeVisible();
});

test("Troubleshooting centre renders and searches", async ({ page }) => {
  await page.goto("/help/troubleshooting");
  await expect(page.getByRole("heading", { level: 1, name: "Troubleshooting centre" })).toBeVisible();
  await expect(page.getByText(/\d+ of \d+ codes?/)).toBeVisible();
  await page.getByRole("searchbox", { name: "Search error codes" }).or(page.getByLabel("Search error codes")).fill("PTH-");
  await page.keyboard.press("Enter");
  await expect(page).toHaveURL(/q=PTH-/);
});

// Every route of the 2.2 sidebar still resolves (prompt §1.1: URLs unchanged).
const oldMenuRoutes = ["/", "/executive", "/reports", "/insights/developers", "/repositories", "/repositories/imports", "/applications", "/runtime", "/posture", "/posture/coverage", "/posture/unmanaged", "/posture/benchmark", "/posture/attack-paths", "/compliance", "/posture/blast-radius", "/posture/graph", "/scans/overview", "/scans", "/scans/schedules", "/scans/compare", "/scans/targets", "/pull-requests", "/scans/imports", "/configurations/scan-profiles", "/configurations/scanners", "/configurations/scan-coverage", "/configurations/custom-rules", "/findings", "/risk", "/suppression-rules", "/sbom", "/portfolio", "/sbom/policies", "/vex", "/human-review", "/human-review/queue", "/human-review/assessments", "/human-review/assignments", "/human-review/reports", "/human-review/configurations", "/ai/analyst", "/ai", "/ai/reports", "/admin/ai", "/admin/ai-usage", "/admin/mcp", "/admin/users", "/admin/organization", "/admin/scm", "/admin/tags", "/admin/assets", "/admin/policies", "/admin/integrations", "/admin/risk-intelligence", "/admin/developer-attribution", "/admin/secret-validation", "/admin/notifications", "/admin/audit"];

for (const path of oldMenuRoutes) {
  test(`old URL ${path} still resolves`, async ({ page }) => {
    await page.goto(path);
    await expect(page).toHaveURL(new RegExp(`${path.replace(/[/]/g, "\\/")}(\\?|$)`));
    await expect(page.locator("main h1").first()).toBeVisible();
    await expect(page.getByText("Page not found")).toHaveCount(0);
    await expect(page.getByText("Something went wrong")).toHaveCount(0);
  });
}
