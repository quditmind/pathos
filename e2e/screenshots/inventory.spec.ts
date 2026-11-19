import { mkdirSync } from "node:fs";
import type { Page } from "@playwright/test";
import { test, expect } from "@playwright/test";

// Light and dark screenshots of the PATHOS 3.0 M3 screens: onboarding flow,
// application profile (overview, classification), applications with the
// onboarding status, lifecycle overview, tag framework and application
// fields. The application is created through the API for the capture
// (example data, archived afterwards); the signed-in e-mail is masked.
//
//   scripts/e2e.sh --reporter=line --config=screenshots.config.ts screenshots/inventory.spec.ts
//   (PNG files: e2e/screenshots/out/inventory/<name>-<theme>.png)

const OUT = "screenshots/out/inventory";
mkdirSync(OUT, { recursive: true });

async function api(page: Page, method: string, path: string, body?: unknown) {
  const me = await (await page.request.get("/api/v1/me")).json();
  const res = await page.request.fetch(path, {
    method,
    headers: { "X-CSRF-Token": me.csrf_token, "Content-Type": "application/json" },
    data: body === undefined ? undefined : JSON.stringify(body),
  });
  return { status: res.status(), json: res.status() === 204 ? null : await res.json() };
}

async function shot(page: Page, name: string, theme: string) {
  const email = page.locator("header [aria-label='User menu']");
  await page.screenshot({ path: `${OUT}/${name}-${theme}.png`, mask: (await email.count()) ? [email] : [] });
}

test.describe.configure({ mode: "serial" });

let appId = "";

test.beforeAll(async ({ browser }) => {
  const page = await browser.newPage();
  await page.goto("/");
  await api(page, "PUT", "/api/v1/admin/feature-flags", { flags: { onboarding: true, lifecycle_overview: true } });
  const sfx = Date.now().toString(36);
  const app = await api(page, "POST", "/api/v1/applications", { name: `Example Payments ${sfx}`, criticality: "high", description: "Example application (screenshot fixture)" });
  appId = app.json.id;
  await api(page, "PATCH", `/api/v1/applications/${appId}/classification`, {
    languages: ["Go", "TypeScript"], frameworks: ["chi", "React"], runtimes: ["Go", "Node.js"], data_classification: "confidential",
    internet_exposure: "public", compliance_scopes: ["pci_dss"], hosting_region: "europe", application_type: "web_application",
  });
  await page.close();
});

test.afterAll(async ({ browser }) => {
  const page = await browser.newPage();
  await page.goto("/");
  if (appId) await api(page, "POST", `/api/v1/applications/${appId}/archive`);
  await api(page, "PUT", "/api/v1/admin/feature-flags", { flags: { onboarding: false, lifecycle_overview: false } });
  await page.close();
});

for (const theme of ["light", "dark"] as const) {
  test(`M3 screens ${theme}`, async ({ page }) => {
    await page.emulateMedia({ colorScheme: theme, reducedMotion: "reduce" });
    await page.addInitScript((t) => {
      try {
        localStorage.setItem("pathos-theme", t);
      } catch {
        /* ignore */
      }
    }, theme);

    await page.goto("/onboarding");
    await expect(page.getByRole("list", { name: "Onboarding steps" })).toBeVisible();
    await shot(page, "01-onboarding", theme);

    await page.goto(`/applications/${appId}`);
    await expect(page.getByRole("list", { name: "Lifecycle progress" })).toBeVisible();
    await shot(page, "02-profile-overview", theme);

    await page.goto(`/applications/${appId}?tab=classification`);
    await expect(page.getByRole("form", { name: "Classification" })).toBeVisible();
    await shot(page, "03-profile-classification", theme);

    await page.goto("/applications");
    await expect(page.getByRole("heading", { level: 1, name: "Applications" })).toBeVisible();
    await shot(page, "04-applications", theme);

    await page.goto("/lifecycle");
    await expect(page.getByRole("heading", { level: 1, name: "Lifecycle overview" })).toBeVisible();
    await shot(page, "05-lifecycle", theme);

    await page.goto("/admin/tags");
    await expect(page.getByRole("heading", { name: "Automatic tagging rules" })).toBeVisible();
    await page.getByRole("heading", { name: "Automatic tagging rules" }).scrollIntoViewIfNeeded();
    await shot(page, "06-tag-framework", theme);

    await page.goto("/admin/assets");
    await expect(page.getByRole("heading", { name: "Application fields" })).toBeVisible();
    await page.getByRole("heading", { name: "Application fields" }).scrollIntoViewIfNeeded();
    await shot(page, "07-application-fields", theme);
  });
}
