import { mkdirSync } from "node:fs";
import type { Page } from "@playwright/test";
import { test, expect } from "./fixtures";

// PATHOS 3.0 M9: continuous monitoring (flag `continuous_monitoring`).
//   1. Flag off: the sidebar item stays a disabled roadmap item, the page
//      says how to enable it and the API answers 404 (PTH-PLAT-1007).
//   2. Flag on: the feed (filters reflected in the URL), the architecture
//      drift timeline and the Drift alerts dialog (opened, nothing saved).
//   3. The application profile's Overview shows the Monitoring card with the
//      deep link to /monitoring?application_id=… (needs one application and
//      the `onboarding` flag for the hub; skipped, with the reason, without one).
// Light and dark screenshots of every screen go to
// screenshots/out/monitoring/<name>-<light|dark>.png. The flags are restored
// (continuous_monitoring, onboarding, lifecycle_overview) to their previous
// values afterwards.

const OUT = "screenshots/out/monitoring";
mkdirSync(OUT, { recursive: true });

test.describe.configure({ mode: "serial" });

async function api(page: Page, method: string, path: string, body?: unknown) {
  const me = await (await page.request.get("/api/v1/me")).json();
  const res = await page.request.fetch(path, {
    method,
    headers: { "X-CSRF-Token": me.csrf_token, "Content-Type": "application/json" },
    data: body === undefined ? undefined : JSON.stringify(body),
  });
  return { status: res.status(), json: res.status() === 204 ? null : await res.json().catch(() => null) };
}

async function setFlags(page: Page, flags: Record<string, boolean>) {
  const r = await api(page, "PUT", "/api/v1/admin/feature-flags", { flags });
  expect(r.status, JSON.stringify(r.json)).toBeLessThan(300);
}

async function shot(page: Page, name: string) {
  // The test stack's server version (a build tag) may differ from the bundle's.
  const dismiss = page.getByRole("button", { name: "Dismiss version notice" });
  if (await dismiss.isVisible().catch(() => false)) await dismiss.click();
  const email = page.locator("header [aria-label='User menu']");
  for (const scheme of ["light", "dark"] as const) {
    await page.evaluate((dark) => document.documentElement.classList.toggle("dark", dark), scheme === "dark");
    await page.waitForTimeout(250);
    await page.screenshot({ path: `${OUT}/${name}-${scheme}.png`, fullPage: false, mask: (await email.count()) ? [email] : [] });
  }
  await page.evaluate(() => document.documentElement.classList.remove("dark"));
}

const initial: Record<string, boolean> = {};
test.beforeAll(async ({ browser }) => {
  const page = await browser.newPage();
  const r = await api(page, "GET", "/api/v1/admin/feature-flags");
  for (const name of ["continuous_monitoring", "onboarding", "lifecycle_overview"]) {
    initial[name] = !!(r.json?.items as { name: string; enabled: boolean }[] | undefined)?.find((f) => f.name === name)?.enabled;
  }
  await page.close();
});
test.afterAll(async ({ browser }) => {
  const page = await browser.newPage();
  await setFlags(page, initial);
  await page.close();
});

test("flag off: continuous monitoring looks absent and says how to enable it", async ({ page }) => {
  await setFlags(page, { continuous_monitoring: false });
  await page.goto("/monitoring");
  await expect(page.getByText("Continuous monitoring is not enabled")).toBeVisible();
  await expect(page.getByText("continuous_monitoring", { exact: true })).toBeVisible();
  const nav = page.getByRole("navigation", { name: "Main" });
  await expect(nav.getByRole("link", { name: "Continuous monitoring", exact: true })).toHaveCount(0);
  await expect(nav.getByText("Continuous monitoring").locator("xpath=ancestor-or-self::*[@aria-disabled='true'][1]")).toHaveAttribute("aria-disabled", "true");
  const r = await api(page, "GET", "/api/v1/monitoring/events");
  expect(r.status).toBe(404);
  expect(JSON.stringify(r.json)).toContain("PTH-PLAT-1007");
  await shot(page, "00-feature-disabled");
});

test("flag on: feed, filters in the URL, drift timeline and drift alerts", async ({ page }) => {
  await setFlags(page, { continuous_monitoring: true });
  await page.goto("/");
  const nav = page.getByRole("navigation", { name: "Main" });
  await expect(nav.getByRole("link", { name: "Continuous monitoring", exact: true })).toHaveAttribute("href", "/monitoring");
  await nav.getByRole("link", { name: "Continuous monitoring", exact: true }).click();
  await expect(page.getByRole("heading", { level: 1, name: "Continuous monitoring" })).toBeVisible();
  await expect(page.getByRole("tab", { name: "Feed" })).toHaveAttribute("aria-selected", "true");
  await page.waitForLoadState("networkidle");
  // Either real events or the honest empty state; never an error.
  await expect(page.getByTestId("monitoring-event").first().or(page.getByText("No monitoring events yet"))).toBeVisible();
  await shot(page, "01-feed");

  await page.getByLabel("Time range", { exact: true }).selectOption("7d");
  await expect(page).toHaveURL(/range=7d/);
  await page.getByLabel("Severity", { exact: true }).selectOption("high");
  await expect(page).toHaveURL(/severity=high/);
  await page.waitForLoadState("networkidle");
  await expect(page.getByTestId("monitoring-event").first().or(page.getByText("No events match these filters"))).toBeVisible();
  await shot(page, "02-feed-filtered");

  const types = await api(page, "GET", "/api/v1/monitoring/types");
  expect(types.status).toBe(200);
  expect((types.json?.items as { type: string }[]).map((t) => t.type)).toContain("architecture.drift");

  await page.getByRole("tab", { name: "Architecture drift" }).click();
  await expect(page).toHaveURL(/tab=drift/);
  await page.waitForLoadState("networkidle");
  await expect(page.getByTestId("drift-entry").first().or(page.getByText(/No architecture drift yet|No drift for this selection/))).toBeVisible();
  await shot(page, "03-drift-timeline");
  const entry = page.getByTestId("drift-entry").first();
  if (await entry.count()) {
    await entry.getByRole("button").click();
    await expect(page.getByTestId("drift-detail")).toBeVisible();
    await shot(page, "04-drift-detail");
    await page.keyboard.press("Escape");
  }

  const alerts = page.getByRole("button", { name: /Drift alerts/ });
  await expect(alerts).toBeVisible();
  await alerts.click();
  const dlg = page.getByRole("dialog", { name: "Drift alerts" });
  await expect(dlg.getByLabel("Alert on architecture drift")).toBeVisible();
  const settings = await api(page, "GET", "/api/v1/monitoring/settings");
  expect(settings.status).toBe(200);
  await shot(page, "05-drift-alerts");
  await page.keyboard.press("Escape");
});

test("application profile: the Monitoring card links to the feed filtered to the application", async ({ page }) => {
  const apps = await api(page, "GET", "/api/v1/applications?limit=1");
  const app = (apps.json?.items as { id: string; name: string }[] | undefined)?.[0];
  test.skip(!app, "needs one application (CI has no seeded application)");
  await setFlags(page, { continuous_monitoring: true, onboarding: true });
  await page.goto(`/applications/${app!.id}`);
  const card = page.getByTestId("monitoring-widget");
  await expect(card).toBeVisible();
  await page.waitForLoadState("networkidle");
  await card.scrollIntoViewIfNeeded();
  await shot(page, "06-application-monitoring-card");
  await card.getByRole("link", { name: /Open in Continuous monitoring/ }).click();
  await expect(page).toHaveURL(new RegExp(`/monitoring\\?application_id=${app!.id}`));
  await expect(page.getByLabel("Application", { exact: true })).toHaveValue(app!.id);
  await shot(page, "07-feed-for-application");
});

test("lifecycle overview: no 'arrives in' copy for built modules", async ({ page }) => {
  await setFlags(page, { lifecycle_overview: true });
  await page.goto("/lifecycle");
  await expect(page.getByRole("heading", { level: 1, name: "Lifecycle overview" })).toBeVisible();
  await page.waitForLoadState("networkidle");
  await expect(page.locator("main")).not.toContainText(/arrives in M\d/);
  await shot(page, "08-lifecycle-overview");
});
