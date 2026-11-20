import { test, expect } from "./fixtures";
import type { APIRequestContext, Page } from "@playwright/test";
import { createHash } from "node:crypto";
import { zipSync } from "./zip";

// PATHOS 3.0 M7 AI security intelligence (flag `ai_intelligence`): the AI
// evidence log behind the flag (roadmap item while off), its filters and
// empty state, the model-per-task and retention settings, and the
// correlation and AI evidence sections of the finding drawer, with light
// and dark screenshots (screenshots/out/ai-evidence, copied to
// ~/.cache/pathos-m7-screens). No AI provider is called: the stack has no
// model configured, so every AI action stays a button (rule: tests never
// make a real AI call; record completeness is covered by the Go
// integration test with stub providers).

async function csrf(request: APIRequestContext) {
  return ((await (await request.get("/api/v1/me")).json()).csrf_token as string) ?? "";
}

async function setFlags(request: APIRequestContext, flags: Record<string, boolean>) {
  const r = await request.fetch("/api/v1/admin/feature-flags", { method: "PUT", data: { flags }, headers: { "X-CSRF-Token": await csrf(request) } });
  expect(r.status(), await r.text()).toBe(200);
}

async function shot(page: Page, name: string) {
  const dismiss = page.getByRole("button", { name: "Dismiss version notice" });
  if (await dismiss.isVisible().catch(() => false)) await dismiss.click();
  for (const scheme of ["light", "dark"] as const) {
    await page.evaluate((dark) => document.documentElement.classList.toggle("dark", dark), scheme === "dark");
    await page.waitForTimeout(200);
    await page.screenshot({ path: `screenshots/out/ai-evidence/${name}-${scheme}.png`, fullPage: false });
  }
  await page.evaluate(() => document.documentElement.classList.remove("dark"));
}

/**
 * A finding to open in the drawer. A stack without findings gets a test
 * repository (uploaded test data) and one finding imported as PATHOS
 * findings JSON, both labelled as test data.
 */
async function someFinding(request: APIRequestContext): Promise<string> {
  const existing = ((await (await request.get("/api/v1/findings?limit=1")).json()).items ?? []) as { id: string }[];
  if (existing.length > 0) return existing[0]!.id;
  const headers = { "X-CSRF-Token": await csrf(request) };
  const archive = Buffer.from(zipSync({ "ai-evidence-e2e/app.py": new TextEncoder().encode("import os\n\ndef run(q):\n    return eval(q)\n") }));
  const sha256 = createHash("sha256").update(archive).digest("hex");
  const up = await request.post("/api/v1/source-uploads", { data: { filename: "ai-evidence-e2e.zip", size: archive.length, sha256 }, headers });
  expect(up.status(), await up.text()).toBe(201);
  const upID = (await up.json()).id as string;
  const part = await request.put(`/api/v1/source-uploads/${upID}/parts/0`, {
    data: archive, headers: { ...headers, "Content-Type": "application/octet-stream", "X-Content-SHA256": sha256 } });
  expect(part.ok(), await part.text()).toBe(true);
  expect((await request.post(`/api/v1/source-uploads/${upID}/complete`, { headers })).status()).toBe(200);
  const me = (await (await request.get("/api/v1/me")).json()).user as { id: string };
  const bu = await (await request.post("/api/v1/business-units", { data: { name: `E2E AI evidence unit ${Date.now().toString(36)}` }, headers })).json();
  const regions = ((await (await request.get("/api/v1/regions")).json()).items ?? []) as { id: string }[];
  const job = await request.post("/api/v1/repository-imports", { headers, data: {
    source: "upload", idempotency_key: `aiev-e2e-${Date.now().toString(36)}`, start_scan: false,
    metadata: { business_owner_id: me.id, technical_owner_id: me.id, business_unit_id: bu.id, business_region_id: regions[0]?.id,
      hosting_region: "europe", criticality: "medium", environment: "test", data_classification: "internal", public_exposure: "no",
      new_application: { name: "E2E AI evidence app (test data)" } },
    items: [{ upload_id: upID, display_name: "ai-evidence-e2e" }] } });
  expect([200, 202], await job.text()).toContain(job.status());
  const jobID = (await job.json()).id as string;
  await expect.poll(async () => (await (await request.get(`/api/v1/repository-imports/${jobID}`)).json()).status, { timeout: 120_000 }).toBe("completed");
  const repos = ((await (await request.get("/api/v1/repositories?q=ai-evidence-e2e")).json()).items ?? []) as { id: string }[];
  expect(repos.length, "test repository").toBeGreaterThan(0);
  const report = JSON.stringify({ tool: "e2e-test-data", findings: [{ rule_id: "e2e.eval", title: "eval() on input (test data)", severity: "high",
    cwe: ["CWE-95"], file_path: "app.py", start_line: 4, fingerprint: "e2e-ai-evidence-1" }] });
  const imp = await request.post("/api/v1/imports/results", { headers, multipart: {
    file: { name: "findings.json", mimeType: "application/json", buffer: Buffer.from(report) }, repository_id: repos[0]!.id, format: "pathos", tool: "E2E test data" } });
  expect([200, 201, 202], await imp.text()).toContain(imp.status());
  let id = "";
  await expect.poll(async () => {
    const items = ((await (await request.get("/api/v1/findings?limit=1")).json()).items ?? []) as { id: string }[];
    id = items[0]?.id ?? "";
    return id;
  }, { timeout: 120_000 }).not.toBe("");
  return id;
}

test.describe.configure({ mode: "serial" });

test("the AI evidence log stays a roadmap item while the flag is off", async ({ page, request }) => {
  await setFlags(request, { ai_intelligence: false });
  await page.goto("/");
  const nav = page.getByRole("navigation", { name: "Main" });
  await expect(nav.getByText("AI evidence log", { exact: true })).toBeVisible();
  await expect(nav.getByRole("link", { name: "AI evidence log", exact: true })).toHaveCount(0);
  expect((await request.get("/api/v1/ai/evidence")).status()).toBe(404);
  await page.goto("/ai/evidence");
  await expect(page.getByText("AI security intelligence is not enabled")).toBeVisible();
  await shot(page, "00-feature-disabled");
});

test("evidence log, model per task, retention and the finding drawer", async ({ page, request }) => {
  await setFlags(request, { ai_intelligence: true });
  await page.goto("/");
  await page.getByRole("navigation", { name: "Main" }).getByRole("link", { name: "AI evidence log", exact: true }).click();
  await expect(page.getByRole("heading", { level: 1, name: "AI evidence log" })).toBeVisible();
  await expect(page.getByRole("combobox", { name: "Task" })).toBeVisible();
  // Records exist only after an AI call; either the table or the empty state.
  await expect(page.getByRole("table").or(page.getByText("No AI evidence yet"))).toBeVisible();
  await page.getByRole("combobox", { name: "Model location" }).selectOption("local");
  await shot(page, "01-evidence-log");

  // AI settings: model per task and retention.
  await page.goto("/admin/ai");
  const section = page.getByRole("region", { name: "Model per task" });
  await expect(section).toBeVisible();
  await expect(section.getByText("Fix proposals")).toBeVisible();
  await expect(section.getByText("carries code").first()).toBeVisible();
  await expect(page.getByLabel(/Keep prompts and responses for/)).toHaveValue(/\d+/);
  await section.scrollIntoViewIfNeeded();
  await shot(page, "02-model-per-task");

  // The finding drawer: correlation (deterministic) and AI evidence.
  const findings = [{ id: await someFinding(request) }];
  await page.goto(`/findings?finding=${findings[0]!.id}`);
  const drawer = page.getByRole("dialog");
  const corr = drawer.getByRole("region", { name: "Correlation" });
  await expect(corr).toBeVisible();
  await expect(corr.getByText("Joined from stored facts, without AI.")).toBeVisible();
  await expect(drawer.getByRole("region", { name: "AI evidence" })).toBeVisible();
  await corr.scrollIntoViewIfNeeded();
  await shot(page, "03-finding-correlation");
  const r = await request.get(`/api/v1/findings/${findings[0]!.id}/correlation`);
  expect(r.status()).toBe(200);
  expect((await r.json()).deterministic).toBe(true);
});
