import type { Page } from "@playwright/test";
import { test, expect } from "./fixtures";

// PATHOS 3.0 M3: onboarding flow, application profile hub, application
// classification, tag framework and lifecycle overview. The flags are
// switched on for the test and restored afterwards. Duplicate prevention
// under concurrency is covered by the Go integration tests (it needs SCM
// connections this stack does not have).

async function api(page: Page, method: string, path: string, body?: unknown) {
  const me = await (await page.request.get("/api/v1/me")).json();
  const res = await page.request.fetch(path, {
    method,
    headers: { "X-CSRF-Token": me.csrf_token, "Content-Type": "application/json" },
    data: body === undefined ? undefined : JSON.stringify(body),
  });
  return { status: res.status(), json: res.status() === 204 ? null : await res.json() };
}

async function setFlags(page: Page, flags: Record<string, boolean>) {
  const r = await api(page, "PUT", "/api/v1/admin/feature-flags", { flags });
  expect(r.status, JSON.stringify(r.json)).toBe(200);
}

test.describe.configure({ mode: "serial" });

test("M3 pages are off until their flags are on", async ({ page }) => {
  await page.goto("/");
  await setFlags(page, { onboarding: false, lifecycle_overview: false });
  await page.goto("/onboarding");
  await expect(page.getByText("Application onboarding is not enabled")).toBeVisible();
  await page.goto("/lifecycle");
  await expect(page.getByText("The lifecycle overview is not enabled")).toBeVisible();
  const nav = page.getByRole("navigation", { name: "Main" });
  await expect(nav.getByText("Lifecycle overview").locator("xpath=ancestor::*[@aria-disabled='true'][1]")).toHaveAttribute("title", /arrives in roadmap phase 3/);
  // The API answers PTH-PLAT-1007 (404) while the flag is off.
  const r = await api(page, "GET", "/api/v1/onboarding");
  expect(r.status).toBe(404);
  expect(r.json.error.error_code).toBe("PTH-PLAT-1007");
});

test("profile, classification, tags and lifecycle with the flags on", async ({ page }) => {
  const sfx = Date.now().toString(36);
  await page.goto("/");
  await setFlags(page, { onboarding: true, lifecycle_overview: true });
  try {
    const created = await api(page, "POST", "/api/v1/applications", { name: `E2E Payments ${sfx}`, criticality: "high" });
    expect(created.status).toBe(201);
    const id = created.json.id as string;

    // The single read exists and carries the onboarding status.
    const one = await api(page, "GET", `/api/v1/applications/${id}`);
    expect(one.status).toBe(200);
    expect(one.json.onboarding_status).toBe("complete");

    // Applications: the name links to the profile; ?app= still opens the dialog.
    await page.goto("/applications");
    await page.getByRole("link", { name: `E2E Payments ${sfx}` }).click();
    await expect(page).toHaveURL(new RegExp(`/applications/${id}$`));
    await expect(page.getByRole("heading", { level: 1, name: `E2E Payments ${sfx}` })).toBeVisible();
    await expect(page.getByRole("list", { name: "Lifecycle progress" }).getByRole("listitem")).toHaveCount(9);
    for (const t of ["Threat model", "Remediation"]) {
      await expect(page.getByRole("tab", { name: new RegExp(`^${t}`) })).toHaveAttribute("aria-disabled", "true");
    }
    // CodeGraph (M4) is a live tab: the panel inside checks the codegraph flag.
    await page.getByRole("tab", { name: "CodeGraph" }).click();
    await expect(page).toHaveURL(/tab=codegraph/);
    await expect(page.getByRole("tabpanel", { name: "CodeGraph" })).toBeVisible();
    await page.goto(`/applications?app=${id}`);
    await expect(page.getByRole("dialog", { name: `Edit E2E Payments ${sfx}` })).toBeVisible();

    // Classification & tags: save a field.
    await page.goto(`/applications/${id}?tab=classification`);
    const form = page.getByRole("form", { name: "Classification" });
    await form.getByLabel("Data classification").selectOption({ label: "Confidential" });
    await form.getByLabel("Languages").fill("Go, TypeScript");
    await form.getByRole("button", { name: "Save" }).click();
    await expect(form.getByText("Saved.")).toBeVisible();
    const after = await api(page, "GET", `/api/v1/applications/${id}`);
    expect(after.json.data_classification).toBe("confidential");
    expect(after.json.languages).toEqual(["Go", "TypeScript"]);

    // Tag framework: a classification rule tags the application.
    const cat = await api(page, "POST", "/api/v1/tag-categories", { name: `E2E data ${sfx}` });
    const tag = await api(page, "POST", `/api/v1/tag-categories/${cat.json.id}/tags`, { name: "confidential", color: "amber" });
    const rule = await api(page, "POST", "/api/v1/tag-rules", { name: `E2E rule ${sfx}`, tag_id: tag.json.id, target_type: "application",
      condition: "classification", field: "data_classification", value: "confidential", apply: true });
    expect(rule.status).toBe(201);
    expect(rule.json.applied).toBeGreaterThanOrEqual(1);
    await page.goto("/admin/tags");
    await expect(page.getByRole("heading", { name: "Automatic tagging rules" })).toBeVisible();
    await expect(page.getByText(`E2E rule ${sfx}`)).toBeVisible();
    await expect(page.getByRole("heading", { name: "Tag history" })).toBeVisible();
    await expect(page.getByText(`E2E Payments ${sfx}`).first()).toBeVisible();

    // Lifecycle overview lists the application with its phases.
    await page.goto("/lifecycle");
    await expect(page.getByRole("heading", { level: 1, name: "Lifecycle overview" })).toBeVisible();
    await expect(page.getByRole("link", { name: `E2E Payments ${sfx}`, exact: true })).toBeVisible();

    // Onboarding page: the seven steps; without connections the source picker explains what to do.
    await page.goto("/onboarding");
    await expect(page.getByRole("list", { name: "Onboarding steps" }).getByRole("listitem")).toHaveCount(7);

    // Clean up.
    await api(page, "DELETE", `/api/v1/tag-rules/${rule.json.rule.id}`);
    await api(page, "DELETE", `/api/v1/tag-categories/${cat.json.id}`);
    await api(page, "POST", `/api/v1/applications/${id}/archive`);
  } finally {
    await setFlags(page, { onboarding: false, lifecycle_overview: false });
  }
});
