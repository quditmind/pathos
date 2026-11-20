import { test, expect } from "./fixtures";
import type { APIRequestContext, Page } from "@playwright/test";
import { createHash } from "node:crypto";
import { readdirSync, readFileSync, statSync } from "node:fs";
import { join, relative } from "node:path";
import { zipSync } from "./zip";

// PATHOS 3.0 M5 threat models (flag `threat_models`): the sidebar item behind
// the flag; a repository uploaded from test data (tests/fixtures-data/
// threat-model-repo, a copy of the CodeGraph discovery fixture), its
// CodeGraph built by the real worker-graph, a threat model generated from
// it in the web app, every threat with evidence, method, severity,
// confidence and mitigation, the threat detail, diagram, versions,
// submission and the approval rule, export, and light and dark screenshots
// (screenshots/out/threatmodels, copied to ~/.cache/pathos-m5-screens).

const FIXTURE = "tests/fixtures-data/threat-model-repo";

async function csrf(request: APIRequestContext) {
  return ((await (await request.get("/api/v1/me")).json()).csrf_token as string) ?? "";
}

async function call(request: APIRequestContext, method: string, url: string, data?: unknown) {
  const r = await request.fetch(url, { method, data, headers: { "X-CSRF-Token": await csrf(request) } });
  const text = await r.text();
  let json: any;
  try {
    json = JSON.parse(text);
  } catch {
    json = text;
  }
  return { status: r.status(), json };
}

async function setFlags(request: APIRequestContext, flags: Record<string, boolean>) {
  const r = await call(request, "PUT", "/api/v1/admin/feature-flags", { flags });
  expect(r.status, JSON.stringify(r.json)).toBe(200);
}

function files(dir: string, root = dir, out: Record<string, Uint8Array> = {}) {
  for (const name of readdirSync(dir)) {
    const p = join(dir, name);
    if (statSync(p).isDirectory()) files(p, root, out);
    else out[`threat-model-shop/${relative(root, p)}`] = new Uint8Array(readFileSync(p));
  }
  return out;
}

/** The application holding the uploaded fixture repository (created once). */
async function fixtureApp(request: APIRequestContext): Promise<{ appId: string; repoId: string }> {
  const name = "E2E threat model shop (test data)";
  const apps = ((await (await request.get("/api/v1/applications")).json()).items ?? []) as { id: string; name: string }[];
  let app = apps.find((a) => a.name === name);
  if (!app) {
    const archive = Buffer.from(zipSync(files(FIXTURE)));
    const sha256 = createHash("sha256").update(archive).digest("hex");
    const up = await call(request, "POST", "/api/v1/source-uploads", { filename: "threat-model-shop.zip", size: archive.length, sha256 });
    expect(up.status, JSON.stringify(up.json)).toBe(201);
    const part = await request.put(`/api/v1/source-uploads/${up.json.id}/parts/0`, {
      data: archive, headers: { "X-CSRF-Token": await csrf(request), "Content-Type": "application/octet-stream", "X-Content-SHA256": sha256 },
    });
    expect(part.ok(), await part.text()).toBe(true);
    expect((await call(request, "POST", `/api/v1/source-uploads/${up.json.id}/complete`)).status).toBe(200);
    const me = (await (await request.get("/api/v1/me")).json()).user as { id: string };
    const bu = await call(request, "POST", "/api/v1/business-units", { name: `E2E threat unit ${Date.now().toString(36)}` });
    const regions = ((await (await request.get("/api/v1/regions")).json()).items ?? []) as { id: string }[];
    const job = await call(request, "POST", "/api/v1/repository-imports", {
      source: "upload", idempotency_key: `tm-e2e-${Date.now().toString(36)}`, start_scan: false,
      metadata: { business_owner_id: me.id, technical_owner_id: me.id, business_unit_id: bu.json.id, business_region_id: regions[0]?.id,
        hosting_region: "europe", criticality: "high", environment: "production", data_classification: "confidential",
        public_exposure: "yes", production_url: "https://shop.example.test", public_urls: ["https://shop.example.test"], new_application: { name } },
      items: [{ upload_id: up.json.id, display_name: "threat-model-shop" }],
    });
    expect([200, 202], JSON.stringify(job.json)).toContain(job.status);
    await expect.poll(async () => (await call(request, "GET", `/api/v1/repository-imports/${job.json.id}`)).json.status, { timeout: 120_000 }).toBe("completed");
    const again = ((await (await request.get("/api/v1/applications")).json()).items ?? []) as { id: string; name: string }[];
    app = again.find((a) => a.name === name);
  }
  expect(app, "fixture application").toBeTruthy();
  const repos = ((await (await request.get(`/api/v1/repositories?application_id=${app!.id}`)).json()).items ?? []) as { id: string; application?: { id: string } }[];
  return { appId: app!.id, repoId: repos[0]?.id ?? "" };
}

async function readySnapshot(request: APIRequestContext, appId: string) {
  const base = `/api/v1/codegraph/applications/${appId}`;
  const list = async () => ((await (await request.get(`${base}/snapshots`)).json()).snapshots ?? []) as { id: string; status: string; error?: string }[];
  let snaps = await list();
  if (!snaps.some((s) => s.status === "ready" || s.status === "partial")) {
    if (!snaps.some((s) => s.status === "queued" || s.status === "building")) {
      const r = await call(request, "POST", `${base}/build`, {});
      expect(r.status, JSON.stringify(r.json)).toBe(202);
    }
    await expect
      .poll(async () => {
        snaps = await list();
        const failed = snaps.find((s) => s.status === "failed");
        if (failed && !snaps.some((s) => s.status === "queued" || s.status === "building")) throw new Error(`CodeGraph build failed: ${JSON.stringify(failed)}`);
        return snaps.some((s) => s.status === "ready" || s.status === "partial");
      }, { timeout: 600_000, intervals: [5000] })
      .toBe(true);
  }
}

async function shot(page: Page, name: string) {
  // The test stack's server version (a build tag) differs from the bundle's.
  const dismiss = page.getByRole("button", { name: "Dismiss version notice" });
  if (await dismiss.isVisible().catch(() => false)) await dismiss.click();
  for (const scheme of ["light", "dark"] as const) {
    await page.evaluate((dark) => document.documentElement.classList.toggle("dark", dark), scheme === "dark");
    await page.waitForTimeout(200);
    await page.screenshot({ path: `screenshots/out/threatmodels/${name}-${scheme}.png`, fullPage: false });
  }
  await page.evaluate(() => document.documentElement.classList.remove("dark"));
}

test.describe.configure({ mode: "serial" });

test("Threat models stays a roadmap item while the flag is off", async ({ page, request }) => {
  await setFlags(request, { threat_models: false });
  await page.goto("/");
  const nav = page.getByRole("navigation", { name: "Main" });
  await expect(nav.getByText("Threat models", { exact: true })).toBeVisible();
  await expect(nav.getByRole("link", { name: "Threat models", exact: true })).toHaveCount(0);
  await page.goto("/threat-models");
  await expect(page.getByText(/Threat models is not enabled|not enabled/).first()).toBeVisible();
  expect((await request.get("/api/v1/threat-models")).status()).toBe(404);
  await shot(page, "00-feature-disabled");
});

test("a threat model generated from the CodeGraph: evidence, review and export", async ({ page, request }) => {
  test.setTimeout(900_000);
  await setFlags(request, { codegraph: true, threat_models: true });
  const { appId } = await fixtureApp(request);
  await readySnapshot(request, appId);
  // A model from an earlier run of this test is removed from the list's way by
  // reusing it (one model per application).
  const existing = ((await (await request.get(`/api/v1/threat-models?application_id=${appId}`)).json()).items ?? []) as { id: string }[];

  await page.goto("/");
  await page.getByRole("navigation", { name: "Main" }).getByRole("link", { name: "Threat models", exact: true }).click();
  await expect(page.getByRole("heading", { level: 1, name: "Threat models" })).toBeVisible();
  let modelId = existing[0]?.id;
  if (!modelId) {
    await page.getByRole("button", { name: /New threat model/ }).first().click();
    const dlg = page.getByRole("dialog", { name: "New threat model" });
    await dlg.getByLabel("Application").selectOption(appId);
    await shot(page, "01-new-model-dialog");
    await dlg.getByRole("button", { name: "Create" }).click();
    await expect(page).toHaveURL(/\/threat-models\/[0-9a-f-]{36}/, { timeout: 60_000 });
    modelId = page.url().match(/threat-models\/([0-9a-f-]{36})/)![1];
  } else {
    await page.goto(`/threat-models/${modelId}`);
  }

  // Done when, through the API of the running stack.
  const threats = ((await (await request.get(`/api/v1/threat-models/${modelId}/threats`)).json()).items ?? []) as any[];
  expect(threats.length, "generated threats").toBeGreaterThan(5);
  for (const t of threats) {
    expect(t.rule_id && t.rule_version && ["rule", "attack_path"].includes(t.method), `${t.title}: method`).toBeTruthy();
    expect(["critical", "high", "medium", "low", "info"], `${t.title}: severity`).toContain(t.severity);
    expect(t.severity_reason, `${t.title}: severity reason`).not.toBe("");
    expect(t.confidence > 0 && t.confidence <= 1 && t.confidence_reason !== "", `${t.title}: confidence`).toBe(true);
    expect(t.mitigation.trim(), `${t.title}: mitigation`).not.toBe("");
    expect((t.evidence.nodes?.length ?? 0) + (t.evidence.edges?.length ?? 0), `${t.title}: evidence`).toBeGreaterThan(0);
    for (const e of t.evidence.edges ?? []) expect(e.refs.length, `${t.title}: edge ${e.key}`).toBeGreaterThan(0);
    expect(["verified", "observed"]).toContain(t.evidence_type);
  }

  // Threat table.
  await expect(page.getByRole("tab", { name: "Threats" })).toHaveAttribute("aria-selected", "true");
  const first = threats.find((t) => t.rule_id === "TM-T-001") ?? threats[0];
  await expect(page.getByText(first.title).first()).toBeVisible();
  await expect(page.getByText("verified").first()).toBeVisible();
  await shot(page, "02-threats");

  // Threat detail: evidence with references and links into CodeGraph.
  await page.getByText(first.title).first().click();
  const detail = page.getByRole("dialog", { name: first.title });
  await expect(detail).toBeVisible();
  await expect(detail.getByRole("list", { name: "Evidence edges" })).toBeVisible();
  await expect(detail.getByRole("link", { name: /CodeGraph/ }).first()).toBeVisible();
  await shot(page, "03-threat-detail");
  await page.keyboard.press("Escape");

  // Diagram on the shared graph component, threats overlaid.
  await page.getByRole("tab", { name: "Diagram" }).click();
  const canvas = page.getByTestId("graph-canvas");
  await expect(canvas.locator(".react-flow__node").first()).toBeVisible({ timeout: 30_000 });
  const drawn = await canvas.locator(".pathos-evidence-edge").evaluateAll((els) => els.map((e) => e.getAttribute("data-evidence")));
  expect(drawn.every((e) => e === "verified" || e === "observed")).toBe(true);
  await page.getByRole("button", { name: "Fit", exact: true }).click();
  await page.waitForTimeout(500);
  await canvas.evaluate((el) => el.scrollIntoView({ block: "end" }));
  await shot(page, "04-diagram");

  // Submit for review; the author cannot approve.
  const m = (await (await request.get(`/api/v1/threat-models/${modelId}`)).json()).model;
  if (m.status === "draft") {
    await page.getByRole("tab", { name: "Threats" }).click();
    await page.getByRole("button", { name: /Submit for review/ }).click();
    const confirm = page.getByRole("dialog").getByRole("button", { name: /Submit/ });
    if (await confirm.isVisible({ timeout: 2000 }).catch(() => false)) await confirm.click();
    await expect.poll(async () => (await (await request.get(`/api/v1/threat-models/${modelId}`)).json()).model.status, { timeout: 15_000 }).toBe("in_review");
    await page.reload();
  }
  const approval = page.getByLabel("Approval");
  await expect(approval).toContainText(/another person|you created or submitted|You wrote or submitted/i);
  const self = await call(request, "POST", `/api/v1/threat-models/${modelId}/approve`, {});
  expect(self.status).toBe(409);
  expect(self.json.error.error_code).toBe("PTH-TM-1005");
  await shot(page, "05-in-review-approval");

  // Versions tab.
  await page.getByRole("tab", { name: "Versions" }).click();
  await expect(page.getByText(/submitted/i).first()).toBeVisible();
  await shot(page, "06-versions");

  // Export (PATHOS JSON, Threat Dragon) carry the version stamp.
  for (const f of ["pathos", "threat_dragon", "pytm", "markdown"]) {
    const r = await request.get(`/api/v1/threat-models/${modelId}/export?format=${f}`);
    expect(r.status(), f).toBe(200);
    expect(r.headers()["x-pathos-generated-by"], f).toContain("PATHOS");
  }

  // The list.
  await page.goto("/threat-models");
  await expect(page.getByRole("link", { name: m.title }).first()).toBeVisible();
  await shot(page, "07-list");
});
