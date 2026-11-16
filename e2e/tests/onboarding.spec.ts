import type { Page } from "@playwright/test";
import { test, expect } from "./fixtures";
import { strToU8, zipSync } from "./zip";

/** Calls the API from the signed-in page (session cookie + CSRF header). */
async function api(page: Page, method: string, path: string, body?: unknown) {
  const me = await (await page.request.get("/api/v1/me")).json();
  const res = await page.request.fetch(path, {
    method,
    headers: { "X-CSRF-Token": me.csrf_token, "Content-Type": "application/json" },
    data: body === undefined ? undefined : JSON.stringify(body),
  });
  return { status: res.status(), json: res.status() === 204 ? null : await res.json() };
}

/** Picks the first option of a search combobox, optionally after typing. */
async function pick(page: Page, label: string, query = "") {
  const box = page.getByRole("combobox", { name: label });
  await box.click();
  if (query) await box.fill(query);
  const list = page.locator(`#${await box.getAttribute("aria-controls")}`);
  await list.getByRole("option").first().click();
}

for (const [path, heading] of [
  ["/repositories/import", "Import repositories"],
  ["/repositories/imports", /Import history/],
  ["/admin/assets", /Asset settings/],
] as const) {
  test(`page ${path} renders`, async ({ page }) => {
    await page.goto(path);
    await expect(page.getByRole("heading", { name: heading }).first()).toBeVisible();
  });
}

test("local PC onboarding: upload, classify, import in the background, metadata persists", async ({ page }) => {
  const sfx = Date.now().toString(36);
  await page.goto("/");
  const bu = await api(page, "POST", "/api/v1/business-units", { name: `E2E unit ${sfx}` });
  expect(bu.status).toBe(201);

  await page.goto("/repositories/import");
  await page.getByText("Import from Local PC").click();
  await expect(page.getByRole("heading", { name: "Choose source code" })).toBeVisible();
  const archive = zipSync({ [`svc-${sfx}/main.go`]: strToU8("package main\nfunc main() {}\n"), [`svc-${sfx}/go.mod`]: strToU8("module e2e\n") });
  await page.getByLabel("Choose archives").setInputFiles({ name: `svc-${sfx}.zip`, mimeType: "application/zip", buffer: Buffer.from(archive) });
  await expect(page.getByText("Uploaded")).toBeVisible({ timeout: 30_000 });
  const next = () => page.getByRole("button", { name: /^(Next|Check and review)$/ }).click();

  // General
  await next();
  await page.getByLabel("Description").fill("Uploaded by the end-to-end test");
  // Business ownership: required fields block the step until filled.
  await next();
  await next();
  await expect(page.getByText("Business owner is required")).toBeVisible();
  await pick(page, "Business owner");
  await pick(page, "Technical owner");
  await page.getByLabel("Business unit").selectOption({ label: `E2E unit ${sfx}` });
  // Geography: business and hosting regions are separate fields.
  await next();
  await page.getByLabel("Business region").selectOption({ index: 1 });
  await page.getByLabel("Hosting region").selectOption({ label: "Europe" });
  // Classification
  await next();
  await page.getByText("High", { exact: true }).click();
  await page.getByLabel("GDPR").check();
  await page.getByLabel("Data classification").selectOption({ label: "Confidential" });
  await page.getByLabel("Environment").selectOption({ label: "Development" });
  // Tags & colour, Lifecycle
  await next();
  await next();
  await next();
  await expect(page.getByRole("heading", { name: /Review/ }).first()).toBeVisible();
  await page.getByRole("button", { name: /Start import/ }).click();

  // Background job runs in the jobs container; the page polls until done.
  await expect(page).toHaveURL(/\/repositories\/imports\//);
  await expect(page.getByText("Completed").first()).toBeVisible({ timeout: 60_000 });
  const repoLink = page.getByRole("link", { name: "Repository" }).first();
  await expect(repoLink).toBeVisible();

  // Persisted after a full reload, as seen by the API.
  const list = await api(page, "GET", `/api/v1/repositories?q=svc-${sfx}`);
  expect(list.status).toBe(200);
  const repo = list.json.items[0];
  expect(repo.source_type).toBe("upload");
  expect(repo.data_classification).toBe("confidential");
  expect(repo.criticality).toBe("high");
  expect(repo.compliance_scopes).toEqual(["gdpr"]);
  expect(repo.environment).toBe("development");
  expect(repo.hosting_region).toBe("europe");
  expect(repo.business_unit?.name).toBe(`E2E unit ${sfx}`);
  expect(repo.business_owner).not.toBeNull();
  expect(repo.current_snapshot?.file_count).toBe(2);
  await page.goto(`/repositories?repo=${repo.id}`);
  await page.reload();
  await expect(page.getByText("Uploaded by the end-to-end test").first()).toBeVisible();

  // Clean up: archive then delete (also removes the encrypted snapshot).
  expect((await api(page, "POST", `/api/v1/repositories/${repo.id}/archive`)).status).toBe(200);
  expect((await api(page, "DELETE", `/api/v1/repositories/${repo.id}`)).status).toBe(204);
});
