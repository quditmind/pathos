import { test, expect } from "./fixtures";
import type { APIRequestContext, Page } from "@playwright/test";
import { createHash } from "node:crypto";
import { existsSync, readdirSync, readFileSync, statSync } from "node:fs";
import { join, relative, resolve } from "node:path";
import { zipSync } from "./zip";

// PATHOS 3.0 M10 reverse engineering, static tier (flag
// `reverse_engineering`). Our own build: the test-data service
// tests/fixtures-data/rea-svc is uploaded as a repository (the real
// worker-graph builds its CodeGraph); scripts/e2e-rea-build.sh compiled it
// with the pinned Go image and attested its SLSA provenance with cosign (the
// core image's binary) and a throw-away key; the binary is uploaded as a build artifact with the provenance bundle
// and verified by the existing cosign check of a target scan. The real
// worker-rea analyses it in its sandbox runner. An unsigned artifact is
// refused by default. Light and dark screenshots go to
// screenshots/out/rea (copied to ~/.cache/pathos-m10-screens).

const FIXTURE = "tests/fixtures-data/rea-svc";
const BUILD = resolve(".rea-build");
const APP = "E2E reverse engineering service (test data)";

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
    else out[`rea-svc/${relative(root, p)}`] = new Uint8Array(readFileSync(p));
  }
  return out;
}

/** Our own build: scripts/e2e-rea-build.sh compiled the fixture and attested its provenance. */
function ownBuild(): { binary: Buffer; sha256: string; provenance: string; publicKey: string } {
  const need = ["server", "provenance.sigstore.json", "cosign.pub"].map((f) => join(BUILD, f));
  for (const f of need) expect(existsSync(f), `${f} (run scripts/e2e-rea-build.sh; scripts/e2e.sh does)`).toBe(true);
  const binary = readFileSync(need[0]);
  return { binary, sha256: createHash("sha256").update(binary).digest("hex"), provenance: readFileSync(need[1], "utf8"),
    publicKey: readFileSync(need[2], "utf8") };
}

/** The application holding the uploaded fixture repository (created once). */
async function fixtureApp(request: APIRequestContext): Promise<{ appId: string; repoId: string }> {
  const apps = ((await (await request.get("/api/v1/applications")).json()).items ?? []) as { id: string; name: string }[];
  let app = apps.find((a) => a.name === APP);
  if (!app) {
    const archive = Buffer.from(zipSync(files(FIXTURE)));
    const sha256 = createHash("sha256").update(archive).digest("hex");
    const up = await call(request, "POST", "/api/v1/source-uploads", { filename: "rea-svc.zip", size: archive.length, sha256 });
    expect(up.status, JSON.stringify(up.json)).toBe(201);
    const part = await request.put(`/api/v1/source-uploads/${up.json.id}/parts/0`, {
      data: archive, headers: { "X-CSRF-Token": await csrf(request), "Content-Type": "application/octet-stream", "X-Content-SHA256": sha256 },
    });
    expect(part.ok(), await part.text()).toBe(true);
    expect((await call(request, "POST", `/api/v1/source-uploads/${up.json.id}/complete`)).status).toBe(200);
    const me = (await (await request.get("/api/v1/me")).json()).user as { id: string };
    const bu = await call(request, "POST", "/api/v1/business-units", { name: `E2E REA unit ${Date.now().toString(36)}` });
    const regions = ((await (await request.get("/api/v1/regions")).json()).items ?? []) as { id: string }[];
    const job = await call(request, "POST", "/api/v1/repository-imports", {
      source: "upload", idempotency_key: `rea-e2e-${Date.now().toString(36)}`, start_scan: false,
      metadata: { business_owner_id: me.id, technical_owner_id: me.id, business_unit_id: bu.json.id, business_region_id: regions[0]?.id,
        hosting_region: "europe", criticality: "high", environment: "production", data_classification: "confidential",
        public_exposure: "yes", production_url: "https://payments.example.test", public_urls: ["https://payments.example.test"], new_application: { name: APP } },
      items: [{ upload_id: up.json.id, display_name: "rea-svc" }],
    });
    expect([200, 202], JSON.stringify(job.json)).toContain(job.status);
    await expect.poll(async () => (await call(request, "GET", `/api/v1/repository-imports/${job.json.id}`)).json.status, { timeout: 120_000 }).toBe("completed");
    const again = ((await (await request.get("/api/v1/applications")).json()).items ?? []) as { id: string; name: string }[];
    app = again.find((a) => a.name === APP);
  }
  expect(app, "fixture application").toBeTruthy();
  const repos = ((await (await request.get(`/api/v1/repositories?application_id=${app!.id}`)).json()).items ?? []) as { id: string }[];
  expect(repos.length).toBeGreaterThan(0);
  return { appId: app!.id, repoId: repos[0].id };
}

/** A ready CodeGraph snapshot of the application (built by the real graph worker). */
async function readySnapshot(request: APIRequestContext, appId: string): Promise<string> {
  const base = `/api/v1/codegraph/applications/${appId}`;
  const list = async () => ((await call(request, "GET", `${base}/snapshots`)).json.snapshots ?? []) as { id: string; status: string }[];
  if (!(await list()).some((s) => s.status === "ready" || s.status === "partial")) {
    const r = await call(request, "POST", `${base}/build`, {});
    expect([202, 409], JSON.stringify(r.json)).toContain(r.status);
  }
  let id = "";
  await expect.poll(async () => {
    const s = (await list()).find((x) => x.status === "ready" || x.status === "partial");
    id = s?.id ?? "";
    return !!s;
  }, { timeout: 300_000, intervals: [3000] }).toBe(true);
  return id;
}

async function uploadArtifact(request: APIRequestContext, repoId: string, name: string, data: Buffer, provenance?: string) {
  const multipart: Record<string, any> = { repository_id: repoId, name, file: { name, mimeType: "application/octet-stream", buffer: data } };
  if (provenance) multipart.provenance = provenance;
  const r = await request.post("/api/v1/scan-targets/artifact", { multipart, headers: { "X-CSRF-Token": await csrf(request) } });
  const body = await r.json().catch(() => ({}));
  if (r.status() === 409) {
    const targets = ((await (await request.get(`/api/v1/scan-targets?repository_id=${repoId}`)).json()).items ?? []) as any[];
    const t = targets.find((x) => x.kind === "artifact" && x.name === name);
    expect(t, "existing artifact target").toBeTruthy();
    return t;
  }
  expect(r.status(), JSON.stringify(body)).toBe(201);
  return body;
}

async function trustOf(request: APIRequestContext, repoId: string, targetId: string) {
  const l = (await call(request, "GET", `/api/v1/rea/artifacts?repository_id=${repoId}`)).json.artifacts as any[];
  return l.find((a) => a.target_id === targetId)?.trust;
}

async function shot(page: Page, name: string) {
  const dismiss = page.getByRole("button", { name: "Dismiss version notice" });
  if (await dismiss.isVisible().catch(() => false)) await dismiss.click();
  for (const scheme of ["light", "dark"] as const) {
    await page.evaluate((dark) => document.documentElement.classList.toggle("dark", dark), scheme === "dark");
    await page.waitForTimeout(200);
    await page.screenshot({ path: `screenshots/out/rea/${name}-${scheme}.png`, fullPage: false });
  }
  await page.evaluate(() => document.documentElement.classList.remove("dark"));
}

test.describe.configure({ mode: "serial" });

test("Binary analysis stays a roadmap item while the flag is off", async ({ page, request }) => {
  await setFlags(request, { reverse_engineering: false });
  await page.goto("/");
  const nav = page.getByRole("navigation", { name: "Main" });
  await expect(nav.getByText("Binary analysis", { exact: true })).toBeVisible();
  await expect(nav.getByRole("link", { name: "Binary analysis", exact: true })).toHaveCount(0);
  expect((await request.get("/api/v1/rea/artifacts")).status()).toBe(404);
  await page.goto("/reverse-engineering");
  await expect(page.getByText(/not enabled/).first()).toBeVisible();
  await shot(page, "00-feature-disabled");
});

test("own build analysed in the sandbox; unsigned artifact refused; source ↔ binary diff", async ({ page, request }) => {
  test.setTimeout(1_200_000);
  await setFlags(request, { codegraph: true, reverse_engineering: true });
  const { appId, repoId } = await fixtureApp(request);
  const snapshotId = await readySnapshot(request, appId);

  // The worker-rea worker is online and its tools are installed.
  await expect.poll(async () => (await call(request, "GET", "/api/v1/rea/tools")).json.worker_online, { timeout: 120_000 }).toBe(true);
  const tools = (await call(request, "GET", "/api/v1/rea/tools")).json.tools as any[];
  expect(tools.find((t) => t.key === "radare2")?.installed, "radare2 installed").toBe(true);
  expect(tools.find((t) => t.key === "binwalk")?.installed, "binwalk installed").toBe(true);

  // An unknown, unsigned artifact is refused by default.
  const vendor = await uploadArtifact(request, repoId, "vendor-agent.bin", Buffer.from(`\x7fELF third-party (test data) ${Date.now()}`));
  expect((await trustOf(request, repoId, vendor.id)).status).toBe("untrusted");
  const refused = await call(request, "POST", "/api/v1/rea/analyses", { target_id: vendor.id });
  expect(refused.status).toBe(403);
  expect(refused.json.error.error_code).toBe("PTH-REA-1001");

  // Our own build with verified provenance.
  const build = ownBuild();
  const own = await uploadArtifact(request, repoId, `payments-server-${build.sha256.slice(0, 8)}`, build.binary, build.provenance);
  const put = await call(request, "PUT", `/api/v1/scan-targets/${own.id}`, { config: { signature: { mode: "key", public_key: build.publicKey,
    attestation: "slsaprovenance1", ignore_tlog: true } } });
  expect(put.status, JSON.stringify(put.json)).toBe(200);
  if ((await trustOf(request, repoId, own.id)).status !== "trusted") {
    const scan = await call(request, "POST", `/api/v1/scan-targets/${own.id}/scan`);
    expect(scan.status, JSON.stringify(scan.json)).toBe(202);
    await expect.poll(async () => (await trustOf(request, repoId, own.id))?.status, { timeout: 300_000, intervals: [3000] }).toBe("trusted");
  }
  const trust = await trustOf(request, repoId, own.id);
  expect(trust.basis).toBe("provenance");
  expect(trust.provenance.commit).toBe("0".repeat(40));

  // The workspace.
  await page.goto("/");
  await page.getByRole("navigation", { name: "Main" }).getByRole("link", { name: "Binary analysis", exact: true }).click();
  await expect(page.getByRole("heading", { level: 1, name: "Binary analysis" })).toBeVisible();
  const vendorRow = page.getByRole("row").filter({ hasText: "vendor-agent.bin" }).first();
  await expect(vendorRow.getByText(/Untrusted/).first()).toBeVisible();
  await expect(vendorRow.getByRole("button", { name: /Analyse/ })).toBeDisabled();
  const ownRow = page.getByRole("row").filter({ hasText: own.name }).first();
  await expect(ownRow.getByText(/Trusted/).first()).toBeVisible();
  await shot(page, "01-artifacts");
  await vendorRow.getByRole("button", { name: /Authorise untrusted artifact/ }).click();
  const dlg = page.getByRole("dialog", { name: "Authorise untrusted artifact" });
  await expect(dlg).toBeVisible();
  await shot(page, "02-authorise-dialog");
  await page.keyboard.press("Escape");

  await ownRow.getByRole("button", { name: /Analyse/ }).click();
  await expect(page).toHaveURL(/\/reverse-engineering\/analyses\/[0-9a-f-]{36}/, { timeout: 30_000 });
  const analysisId = page.url().match(/analyses\/([0-9a-f-]{36})/)![1];
  await expect.poll(async () => (await call(request, "GET", `/api/v1/rea/analyses/${analysisId}`)).json.analysis.status,
    { timeout: 900_000, intervals: [5000] }).toMatch(/ready|partial/);
  const a = (await call(request, "GET", `/api/v1/rea/analyses/${analysisId}`)).json;
  expect(a.analysis.trust_basis).toBe("provenance");
  expect(a.analysis.language).toBe("go");
  expect(a.counts.functions).toBeGreaterThan(100);
  expect(a.analysis.tools.radare2.status).toBe("succeeded");

  // Every binary edge carries verified binary evidence (offset and tool).
  const g = (await call(request, "GET", `/api/v1/rea/analyses/${analysisId}/graph?view=binary_call_graph&limit=500`)).json;
  expect(g.edges.length).toBeGreaterThan(0);
  for (const e of g.edges) {
    expect(e.evidence).toBe("verified");
    for (const r of e.evidence_refs) {
      expect(r.kind).toBe("binary");
      expect(r.ref).toMatch(/^0x[0-9a-f]+$/);
    }
  }

  // Functions: the pprof handlers are in the binary.
  await page.reload();
  await expect(page.getByRole("tab", { name: "Functions" })).toHaveAttribute("aria-selected", "true");
  await page.getByLabel("Search functions").fill("pprof.Index");
  await expect(page.getByRole("list", { name: "Functions" }).getByText("net/http/pprof.Index").first()).toBeVisible({ timeout: 30_000 });
  await page.getByRole("list", { name: "Functions" }).getByText("net/http/pprof.Index").first().click();
  await expect(page.getByRole("list", { name: "Evidence" }).first()).toBeVisible();
  await shot(page, "03-functions");

  await page.getByRole("tab", { name: "Call graph" }).click();
  await expect(page.getByTestId("graph-canvas").locator(".react-flow__node").first()).toBeVisible({ timeout: 60_000 });
  await shot(page, "04-call-graph");

  await page.getByRole("tab", { name: "Strings & imports" }).click();
  await expect(page.getByRole("heading", { name: "Imports" })).toBeVisible();
  await shot(page, "05-strings-imports");

  await page.getByRole("tab", { name: "Runtime behaviour" }).click();
  await expect(page.getByText("Sandbox tier arrives after 3.0")).toBeVisible();
  await shot(page, "06-runtime");

  // Source ↔ binary: the uploaded source has no commit, so a person picks
  // the CodeGraph snapshot (labelled as chosen).
  await page.getByRole("tab", { name: "Source ↔ binary" }).click();
  const diffNow = (await call(request, "GET", `/api/v1/rea/analyses/${analysisId}/diff`)).json;
  if (diffNow.status !== "ready") {
    await page.getByLabel("CodeGraph snapshot").selectOption(snapshotId);
    await page.getByRole("button", { name: "Compare", exact: true }).click();
  }
  await expect.poll(async () => (await call(request, "GET", `/api/v1/rea/analyses/${analysisId}/diff`)).json.status, { timeout: 60_000 }).toBe("ready");
  const diff = (await call(request, "GET", `/api/v1/rea/analyses/${analysisId}/diff?side=binary_only&limit=500`)).json;
  const pprof = diff.items.find((i: any) => i.kind === "route" && i.name === "/debug/pprof/");
  expect(pprof, JSON.stringify(diff.items.slice(0, 20))).toBeTruthy();
  expect(pprof.sensitive).toBe(true);
  expect(pprof.evidence.some((e: any) => e.kind === "binary" && /^0x/.test(e.ref))).toBe(true);
  expect(pprof.evidence.some((e: any) => e.kind === "file_line" && e.ref === "cmd/server/main.go:9")).toBe(true);
  const matched = (await call(request, "GET", `/api/v1/rea/analyses/${analysisId}/diff?side=matched&kind=function&limit=500`)).json;
  expect(matched.items.some((i: any) => i.name === "main.main")).toBe(true);
  expect(matched.items.some((i: any) => i.name === "example.com/payments/internal/orders.Create")).toBe(true);
  const drafts = (await call(request, "GET", `/api/v1/rea/analyses/${analysisId}/drafts`)).json.drafts as any[];
  const draft = drafts.find((d) => d.rule_id === "rea/go-pprof");
  expect(draft?.status).toBe("proposed");
  await page.reload();
  await expect(page.getByText("Proposal · needs human review").first()).toBeVisible({ timeout: 30_000 });
  await expect(page.getByText(draft.title).first()).toBeVisible();
  await shot(page, "07-source-binary");
  // Nothing became a finding by itself.
  expect(draft.finding_id).toBeNull();

  await page.getByRole("tab", { name: "History" }).click();
  await shot(page, "08-history");

  // Configuration (tool names are shown on this configuration page only).
  await page.goto("/configurations/reverse-engineering");
  await expect(page.getByRole("heading", { level: 1, name: "Reverse engineering tools" })).toBeVisible();
  await expect(page.getByText("Input policy")).toBeVisible();
  await shot(page, "09-configuration");
});
