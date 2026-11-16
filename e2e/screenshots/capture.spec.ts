import { createHash } from "node:crypto";
import { mkdirSync } from "node:fs";
import type { Locator, Page } from "@playwright/test";
import { test, expect } from "@playwright/test";
import { strToU8, zipSync } from "../tests/zip";

// Captures the Help Center screenshots (docs/user-guide/images) from the
// running stack. Seeds example data ("Payments" business unit, "Payments
// Platform" application, a "Data domain" tag category and a small
// payments-api upload), captures every page the user guide shows, and
// cleans up what it created. The signed-in user's e-mail address is masked
// in every capture.
//
//   scripts/e2e.sh --reporter=line --config=screenshots.config.ts
//   cp e2e/screenshots/out/*.png docs/user-guide/images/

const OUT = "screenshots/out";
mkdirSync(OUT, { recursive: true });

interface Ctx {
  email: string;
  userId: string;
}

async function api(page: Page, method: string, path: string, body?: unknown) {
  const me = await (await page.request.get("/api/v1/me")).json();
  const res = await page.request.fetch(path, {
    method,
    headers: { "X-CSRF-Token": me.csrf_token, "Content-Type": "application/json" },
    data: body === undefined ? undefined : JSON.stringify(body),
  });
  const text = await res.text();
  return { status: res.status(), json: text ? JSON.parse(text) : null };
}

/** Uploads bytes through the resumable upload API (single part). */
async function upload(page: Page, filename: string, bytes: Uint8Array): Promise<string> {
  const me = await (await page.request.get("/api/v1/me")).json();
  const sha = createHash("sha256").update(bytes).digest("hex");
  const s = await api(page, "POST", "/api/v1/source-uploads", { filename, size: bytes.length, sha256: sha });
  expect(s.status).toBe(201);
  const put = await page.request.fetch(`/api/v1/source-uploads/${s.json.id}/parts/0`, {
    method: "PUT",
    headers: { "X-CSRF-Token": me.csrf_token, "Content-Type": "application/octet-stream", "X-Content-SHA256": sha },
    data: Buffer.from(bytes),
  });
  expect(put.status()).toBe(200);
  expect((await api(page, "POST", `/api/v1/source-uploads/${s.json.id}/complete`)).status).toBe(200);
  return s.json.id;
}

/** Picks the first option of a search combobox, optionally after typing. */
async function pick(page: Page, label: string, query = "") {
  const box = page.getByRole("combobox", { name: label });
  await box.click();
  if (query) await box.fill(query);
  const list = page.locator(`#${await box.getAttribute("aria-controls")}`);
  await list.getByRole("option").first().click();
}

/** Selects the first option whose text matches re. */
async function selectMatching(select: Locator, re: RegExp) {
  const opts = await select.locator("option").allTextContents();
  const label = opts.find((o) => re.test(o));
  if (!label) throw new Error(`no option matching ${re}: ${opts.join(", ")}`);
  await select.selectOption({ label });
}

function shooter(page: Page, ctx: Ctx) {
  const masks = () => [page.getByText(ctx.email)];
  return {
    async page(name: string, opts: { height?: number } = {}) {
      if (opts.height) await page.setViewportSize({ width: 1440, height: opts.height });
      await page.waitForTimeout(400);
      await page.screenshot({ path: `${OUT}/${name}.png`, scale: "css", animations: "disabled", mask: masks() });
      if (opts.height) await page.setViewportSize({ width: 1440, height: 900 });
    },
    async el(name: string, loc: Locator, opts: { height?: number } = {}) {
      if (opts.height) await page.setViewportSize({ width: 1440, height: opts.height });
      await page.waitForTimeout(400);
      await loc.screenshot({ path: `${OUT}/${name}.png`, scale: "css", animations: "disabled", mask: masks() });
      if (opts.height) await page.setViewportSize({ width: 1440, height: 900 });
    },
  };
}

test("capture user guide screenshots", async ({ page }) => {
  await page.addInitScript(() => localStorage.setItem("pathos-theme", "light"));
  await page.goto("/");
  const meRes = await (await page.request.get("/api/v1/me")).json();
  const ctx: Ctx = { email: meRes.user.email, userId: meRes.user.id };
  const shot = shooter(page, ctx);
  const main = page.locator("main");
  const created = { bu: "", buCreated: false, category: "", app: "", repos: [] as string[] };

  try {
    // ---------------------------------------------------------------- seed
    const bus = await api(page, "GET", "/api/v1/business-units");
    const existingBu = (bus.json.items ?? bus.json).find((b: { name: string }) => b.name === "Payments");
    if (existingBu) created.bu = existingBu.id;
    else {
      const bu = await api(page, "POST", "/api/v1/business-units", { name: "Payments", description: "Card acquiring and payment processing" });
      expect(bu.status).toBe(201);
      created.bu = bu.json.id;
      created.buCreated = true;
    }
    const cat = await api(page, "POST", "/api/v1/tag-categories", { name: "Data domain", description: "Business data domain of the asset", is_mandatory: false, allow_multiple: false });
    expect(cat.status).toBe(201);
    created.category = cat.json.id;
    for (const [name, color] of [["Payments", "blue"], ["Customer", "teal"]] as const) {
      const t = await api(page, "POST", `/api/v1/tag-categories/${created.category}/tags`, { name, color });
      expect(t.status).toBe(201);
    }

    // ------------------------------------------------- top bar, dashboard
    await page.goto("/");
    await expect(page.getByText("Security posture").first()).toBeVisible();
    await page.waitForLoadState("networkidle");
    await shot.el("help-button", page.locator("header"));
    await shot.page("dashboard");

    // ------------------------------------------------------- applications
    await page.goto("/applications");
    await expect(page.getByRole("heading", { name: "Applications" })).toBeVisible();
    await page.getByRole("button", { name: "New application" }).click();
    const dlg = page.getByRole("dialog");
    await dlg.getByLabel("Name").fill("Payments Platform");
    await dlg.getByLabel("Description").fill("Card payment authorisation, capture and settlement services.");
    await dlg.getByLabel("Business unit").selectOption({ label: "Payments" });
    await dlg.getByLabel("Criticality").selectOption("high");
    const owner = dlg.getByLabel("Owner", { exact: true });
    if (await owner.count()) await selectMatching(owner, /PATHOS/);
    const sec = dlg.getByLabel("Security owner");
    if (await sec.count()) await selectMatching(sec, /PATHOS/);
    await shot.el("application-new", dlg);
    await dlg.getByRole("button", { name: "Create" }).click();
    await expect(dlg).toHaveCount(0);
    const apps = await api(page, "GET", "/api/v1/applications");
    created.app = (apps.json.items ?? apps.json).find((a: { name: string }) => a.name === "Payments Platform").id;

    // ------------------------------------------------------ import landing
    await page.goto("/repositories/import");
    await expect(page.getByText("Import from Local PC")).toBeVisible();
    await page.waitForLoadState("networkidle");
    await shot.page("import-landing");

    // ------------------------------------------------- wizard: local source
    await page.getByText("Import from Local PC").click();
    await expect(page.getByRole("heading", { name: "Choose source code" })).toBeVisible();
    const archive = zipSync({
      "payments-api/README.md": strToU8("# payments-api\n\nCard payment authorisation service (example).\n"),
      "payments-api/go.mod": strToU8("module example.com/payments-api\n\ngo 1.22\n"),
      "payments-api/main.go": strToU8('package main\n\nimport "fmt"\n\nfunc main() { fmt.Println("payments-api") }\n'),
      "payments-api/package.json": strToU8('{\n  "name": "payments-web",\n  "version": "1.0.0",\n  "dependencies": { "lodash": "4.17.15" }\n}\n'),
    });
    await page.getByLabel("Choose archives").setInputFiles({ name: "payments-api.zip", mimeType: "application/zip", buffer: Buffer.from(archive) });
    await expect(page.getByText("Uploaded")).toBeVisible({ timeout: 30_000 });
    const wizard = page.locator("main > *").first();
    await shot.el("wizard-source", wizard);
    const next = () => page.getByRole("button", { name: /^(Next|Check and review)$/ }).click();

    // General
    await next();
    await expect(page.getByRole("heading", { name: "General" })).toBeVisible();
    await page.getByLabel("Description").fill("REST API that authorises and captures card payments.");
    await pick(page, "Select application", "Payments");
    await selectMatching(page.getByLabel("Application type"), /^API$/);
    await page.getByLabel("Business purpose").fill("Processes customer card payments for the web shop.");
    await page.getByRole("textbox", { name: "Staging URL" }).fill("https://staging.payments.example.com");
    await page.getByRole("textbox", { name: "Production URL" }).fill("https://payments.example.com");
    await shot.el("wizard-general", wizard, { height: 1200 });

    // Business ownership
    await next();
    await expect(page.getByRole("heading", { name: "Business ownership" })).toBeVisible();
    await pick(page, "Business owner", "PATHOS");
    await pick(page, "Technical owner", "PATHOS");
    await pick(page, "Application owner", "PATHOS");
    await page.getByLabel("Business unit").selectOption({ label: "Payments" });
    await page.getByLabel("Cost centre").fill("CC-4711");
    await shot.el("wizard-ownership", wizard, { height: 1100 });

    // Geography
    await next();
    await expect(page.getByRole("heading", { name: "Geography" })).toBeVisible();
    await selectMatching(page.getByLabel("Business region"), /Europe|EMEA/);
    await selectMatching(page.getByLabel("Country"), /^Germany$/);
    await selectMatching(page.getByLabel("Hosting region"), /Europe/);
    await selectMatching(page.getByLabel("Data residency region"), /Europe|EMEA/);
    await page.getByLabel("Primary operational location").fill("Frankfurt data centre");
    await shot.el("wizard-geography", wizard, { height: 1100 });

    // Classification
    await next();
    await expect(page.getByRole("heading", { name: "Classification" })).toBeVisible();
    const exposure = page.getByRole("radiogroup", { name: /publicly exposed to the internet/ });
    await exposure.getByRole("radio", { name: /^Yes/ }).check();
    await page.getByRole("textbox", { name: "Public-facing URL 1" }).fill("https://payments.example.com");
    await page.getByRole("button", { name: "Add domain" }).click();
    await page.getByRole("textbox", { name: "Public domain name 1" }).fill("api.payments.example.com");
    await page.getByRole("button", { name: "Add IP address" }).click();
    await page.getByRole("textbox", { name: "Public IP address 1" }).fill("203.0.113.10");
    await page.getByLabel("Exposure notes").fill("Behind the corporate WAF and CDN; confirmed by Dana Owner.");
    await page.getByText("High", { exact: true }).click();
    await selectMatching(page.getByLabel("Data classification"), /Confidential/);
    await selectMatching(page.getByLabel("Environment"), /Production/);
    const pci = page.getByLabel(/PCI/);
    if (await pci.count()) await pci.first().check();
    await page.getByLabel("GDPR").check();
    await shot.el("wizard-classification", wizard, { height: 1500 });

    // Tags & colour
    await next();
    await expect(page.getByRole("heading", { name: "Tags & colour" })).toBeVisible();
    await page.getByRole("button", { name: "Payments", exact: true }).click();
    await page.getByRole("group", { name: "Asset colour" }).getByRole("button").nth(1).click();
    await shot.el("wizard-tags", wizard, { height: 1100 });

    // Lifecycle
    await next();
    await expect(page.getByRole("heading", { name: "Lifecycle" })).toBeVisible();
    await selectMatching(page.getByLabel("Lifecycle status"), /Production|Active|Live/);
    await page.getByLabel("Go-live date").fill("2026-03-01");
    await shot.el("wizard-lifecycle", wizard);

    // Review
    await next();
    await expect(page.getByRole("heading", { name: /Review/ }).first()).toBeVisible();
    await expect(page.getByRole("button", { name: /Start import/ })).toBeEnabled({ timeout: 20_000 });
    await shot.el("wizard-review", wizard, { height: 1700 });
    await page.getByRole("button", { name: /Start import/ }).click();

    // Progress
    await expect(page).toHaveURL(/\/repositories\/imports\//);
    await expect(page.getByText("Completed").first()).toBeVisible({ timeout: 90_000 });
    await expect(page.getByText("Up to date")).toBeVisible({ timeout: 10_000 });
    await shot.page("import-progress");

    const list = await api(page, "GET", "/api/v1/repositories?q=payments-api");
    const repo = list.json.items.find((r: { asset_name: string }) => r.asset_name === "payments-api");
    expect(repo).toBeTruthy();
    created.repos.push(repo.id);

    // ------------------------------------- failed import (rejected archive)
    const evil = zipSync({ "../evil.txt": strToU8("path traversal test\n"), "ok.txt": strToU8("ok\n") });
    const evilUpload = await upload(page, "traversal-sample.zip", evil);
    const settings = (await api(page, "GET", "/api/v1/asset-settings")).json;
    const first = (kind: string) => settings.classifications[kind].find((c: { archived: boolean }) => !c.archived).key;
    const regions = (await api(page, "GET", "/api/v1/regions")).json;
    const regionList = regions.items ?? regions;
    const job = await api(page, "POST", "/api/v1/repository-imports", {
      source: "upload",
      idempotency_key: `docs-${Date.now()}`,
      metadata: {
        business_owner_id: ctx.userId,
        technical_owner_id: ctx.userId,
        business_unit_id: created.bu,
        business_region_id: regionList[0].id,
        criticality: "low",
        data_classification: first("data_classification"),
        environment: first("environment"),
        public_exposure: "unknown",
      },
      items: [{ upload_id: evilUpload, display_name: "traversal-sample", asset_name: "traversal-sample" }],
    });
    expect([201, 202]).toContain(job.status);
    await page.goto(`/repositories/imports/${job.json.id}`);
    await expect(page.getByText("archive_rejected").first()).toBeVisible({ timeout: 90_000 });
    await expect(page.getByText("Up to date")).toBeVisible({ timeout: 10_000 });
    await shot.page("import-failed");

    // ----------------------------------------------------- import history
    await page.goto("/repositories/imports");
    await expect(page.getByRole("heading", { name: /Import history/ }).first()).toBeVisible();
    await page.waitForLoadState("networkidle");
    await shot.page("import-history");

    // -------------------------------------------------------- inventory
    await page.goto("/repositories");
    await expect(page.getByRole("heading", { name: "Repositories" }).first()).toBeVisible();
    await page.waitForLoadState("networkidle");
    await shot.page("repositories-inventory");
    await shot.el("repositories-kpis", page.getByLabel("Repository indicators"));
    await page.getByRole("button", { name: /More filters/ }).click();
    await page.waitForTimeout(300);
    await shot.el("repositories-filters", main.locator("div.space-y-2").first());
    await page.goto("/repositories?view=insights");
    const insightsTab = page.getByRole("tab", { name: "Insights" });
    if (await insightsTab.count()) await insightsTab.click();
    await page.waitForLoadState("networkidle");
    await shot.page("repositories-insights", { height: 1400 });

    // ----------------------------------------------------- drawer
    await page.goto(`/repositories?repo=${repo.id}`);
    const drawer = page.getByRole("dialog");
    await expect(drawer.getByRole("group", { name: "Repository ID" })).toBeVisible();
    await page.waitForLoadState("networkidle");
    await shot.page("repository-drawer");
    await shot.el("repository-drawer-full", drawer, { height: 1880 });
    await shot.el("repository-record", drawer.getByRole("region", { name: "Record" }).or(drawer.locator("section[aria-label=Record]")));
    await drawer.getByRole("tab", { name: "Source" }).click();
    await expect(drawer.getByText("Source snapshots")).toBeVisible();
    await shot.page("repository-source");
    await drawer.getByRole("tab", { name: "Security" }).click();
    await page.waitForTimeout(800);
    await shot.page("repository-security");
    await drawer.getByRole("tab", { name: "Details" }).click();
    await drawer.getByRole("button", { name: "Edit metadata" }).click();
    await page.waitForTimeout(500);
    await shot.page("repository-edit");
    await page.keyboard.press("Escape");

    // Scan the example repository so the scans page shows a real job.
    const scan = await api(page, "POST", `/api/v1/repositories/${repo.id}/scan`, {});
    expect([200, 201, 202]).toContain(scan.status);

    // -------------------------------------------------- SCM connections
    await page.goto("/admin/scm");
    await expect(page.getByRole("heading", { name: "SCM connections" })).toBeVisible();
    await page.waitForLoadState("networkidle");
    await shot.page("scm-connections");
    await page.getByRole("button", { name: "Connect provider" }).first().click();
    const cdlg = page.getByRole("dialog");
    await expect(cdlg.getByText("Choose where your repositories live.")).toBeVisible();
    await shot.el("connect-provider", cdlg);
    for (const [label, file] of [
      ["GitHub", "connect-github-methods"],
      ["GitLab", "connect-gitlab-methods"],
      ["Bitbucket Cloud", "connect-bitbucket-methods"],
      ["Azure DevOps Services", "connect-azure-devops-methods"],
    ] as const) {
      await cdlg.getByRole("button", { name: new RegExp(`^${label}\\b`) }).first().click();
      await expect(cdlg.getByText(/How PATHOS authenticates to/)).toBeVisible();
      await shot.el(file, cdlg, { height: 1100 });
      if (label === "GitHub") {
        await cdlg.getByRole("radio").first().check();
        await cdlg.getByRole("button", { name: "Continue" }).click();
        await shot.el("connect-github-app-fields", cdlg, { height: 1200 });
        await cdlg.getByRole("button", { name: "Back" }).click();
      }
      if (label === "Azure DevOps Services") {
        await cdlg.getByRole("radio").first().check();
        await cdlg.getByRole("button", { name: "Continue" }).click();
        await shot.el("connect-azure-sp-fields", cdlg, { height: 1400 });
        await cdlg.getByRole("button", { name: "Back" }).click();
      }
      await cdlg.getByRole("button", { name: "Back" }).click();
    }
    await cdlg.getByRole("button", { name: "Cancel" }).click();

    await page.goto("/admin/scm?tab=oauth");
    await expect(page.getByRole("button", { name: "Register application" })).toBeVisible();
    await shot.page("oauth-applications");
    await page.getByRole("button", { name: "Register application" }).click();
    const odlg = page.getByRole("dialog");
    await odlg.getByLabel("Provider").selectOption("azure_devops");
    await shot.el("oauth-register", odlg, { height: 1200 });
    await odlg.getByRole("button", { name: "Cancel" }).click();

    // ------------------------------------------------- admin pages
    await page.goto("/admin/assets");
    await expect(page.getByRole("heading", { name: /Asset settings/ }).first()).toBeVisible();
    await page.waitForLoadState("networkidle");
    await shot.page("asset-settings", { height: 1500 });

    await page.goto("/admin/tags");
    await expect(page.getByRole("heading", { name: "Tags" }).first()).toBeVisible();
    await page.waitForLoadState("networkidle");
    await shot.page("tags");

    await page.goto("/applications");
    await expect(page.getByText("Payments Platform")).toBeVisible();
    await shot.page("applications");

    // ------------------------------------------------- scanning
    await page.goto("/scans");
    await expect(page.getByRole("heading", { name: "Scans" }).first()).toBeVisible();
    // Give the worker a moment; capture whatever state the job is in.
    for (let i = 0; i < 40; i++) {
      const s = await api(page, "GET", `/api/v1/repositories/${repo.id}/security`);
      const st = s.json?.latest_scan?.status;
      if (st && !["queued", "running", "leased"].includes(st)) break;
      await page.waitForTimeout(5000);
    }
    await page.reload();
    await page.waitForLoadState("networkidle");
    await shot.page("scans");

    await page.goto(`/repositories?repo=${repo.id}`);
    await page.getByRole("dialog").getByRole("tab", { name: "Security" }).click();
    await page.waitForTimeout(1000);
    await shot.page("repository-security");

    await page.goto("/findings");
    await expect(page.getByRole("heading", { name: "Findings" }).first()).toBeVisible();
    await page.waitForLoadState("networkidle");
    await shot.page("findings");

  } finally {
    // ------------------------------------------------- clean up
    for (const id of created.repos) {
      await api(page, "POST", `/api/v1/repositories/${id}/archive`);
      const d = await api(page, "DELETE", `/api/v1/repositories/${id}`);
      console.log("repository deleted", d.status);
    }
    if (created.category) {
      const c = (await api(page, "GET", "/api/v1/tag-categories")).json;
      const catRow = (c.items ?? c).find((x: { id: string }) => x.id === created.category);
      for (const t of catRow?.tags ?? []) await api(page, "DELETE", `/api/v1/tags/${t.id}`);
      console.log("tag category deleted", (await api(page, "DELETE", `/api/v1/tag-categories/${created.category}`)).status);
    }
    if (created.app) console.log("application archived", (await api(page, "POST", `/api/v1/applications/${created.app}/archive`)).status);
    console.log("business unit kept (no delete endpoint)", created.buCreated ? "created" : "pre-existing");
  }
});
