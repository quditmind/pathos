import { test, expect } from "./fixtures";
import type { APIRequestContext, Page } from "@playwright/test";

// PATHOS 3.0 M4 CodeGraph (flag `codegraph`): sidebar items behind the flag,
// the CodeGraph of an application built by the real graph worker, every edge
// with evidence, the 15 views, inspector, list view, and light and dark
// screenshots (screenshots/out/codegraph, copied to ~/.cache/pathos-m4-screens).
//
// The application: E2E_CODEGRAPH_APP (id or name), else the first one with
// a repository. A build is requested when no snapshot is ready yet and the
// test waits for it (E2E_CODEGRAPH_WAIT_S, default 900 s).

const views = [
  "architecture", "call_graph", "data_flow", "api", "dependencies", "deployment", "ownership", "trust_boundaries",
  "internet_exposure", "findings_overlay", "sbom", "datastores", "external_services", "secrets_and_config", "change_impact",
] as const;

type Snapshot = { id: string; status: string; commit_sha: string; repository_name?: string; created_at: string };
type Edge = { id: string; evidence: string; evidence_refs: { kind: string; ref: string }[] };

async function csrf(request: APIRequestContext) {
  const me = await (await request.get("/api/v1/me")).json();
  return me.csrf_token as string;
}

async function setFlag(request: APIRequestContext, on: boolean) {
  const r = await request.put("/api/v1/admin/feature-flags", { data: { flags: { codegraph: on } }, headers: { "X-CSRF-Token": await csrf(request) } });
  expect(r.ok(), await r.text()).toBe(true);
}

async function pickApp(request: APIRequestContext): Promise<{ id: string; name: string }> {
  const apps = ((await (await request.get("/api/v1/applications")).json()).items ?? []) as { id: string; name: string; repository_count?: number }[];
  const want = process.env.E2E_CODEGRAPH_APP;
  const app = want ? apps.find((a) => a.id === want || a.name === want) : apps.find((a) => (a.repository_count ?? 0) > 0);
  // A named application must exist. CI seeds one (scripts/seed-e2e-app.py
  // --github-env sets E2E_CODEGRAPH_APP) and starts the graph worker, so the
  // real build runs there; on a stack without a seeded application the test
  // is skipped with the reason.
  if (!want) test.skip(!app, "no application with a repository: set E2E_CODEGRAPH_APP to run the real CodeGraph build");
  expect(app, `application ${want ?? "(any with a repository)"}`).toBeTruthy();
  return app!;
}

async function readySnapshot(request: APIRequestContext, appId: string): Promise<Snapshot> {
  const base = `/api/v1/codegraph/applications/${appId}`;
  const list = async () => ((await (await request.get(`${base}/snapshots`)).json()).snapshots ?? []) as Snapshot[];
  let snaps = await list();
  if (!snaps.some((s) => s.status === "ready" || s.status === "partial")) {
    if (!snaps.some((s) => s.status === "queued" || s.status === "building")) {
      const r = await request.post(`${base}/build`, { data: {}, headers: { "X-CSRF-Token": await csrf(request) } });
      expect(r.status(), await r.text()).toBe(202);
    }
    const deadline = Date.now() + Number(process.env.E2E_CODEGRAPH_WAIT_S || 900) * 1000;
    while (Date.now() < deadline) {
      snaps = await list();
      if (snaps.some((s) => s.status === "ready" || s.status === "partial")) break;
      const failed = snaps.find((s) => s.status === "failed");
      if (failed && !snaps.some((s) => s.status === "queued" || s.status === "building")) throw new Error(`CodeGraph build failed: ${JSON.stringify(failed)}`);
      await new Promise((r) => setTimeout(r, 5000));
    }
  }
  const ready = snaps.filter((s) => s.status === "ready" || s.status === "partial").sort((a, b) => b.created_at.localeCompare(a.created_at));
  expect(ready.length, "a ready CodeGraph snapshot").toBeGreaterThan(0);
  return ready[0]!;
}

async function shot(page: Page, name: string) {
  for (const scheme of ["light", "dark"] as const) {
    await page.evaluate((dark) => document.documentElement.classList.toggle("dark", dark), scheme === "dark");
    await page.waitForTimeout(150);
    await page.screenshot({ path: `screenshots/out/codegraph/${name}-${scheme}.png`, fullPage: false });
  }
  await page.evaluate(() => document.documentElement.classList.remove("dark"));
}

test.describe.configure({ mode: "serial" });

test("CodeGraph sidebar items stay roadmap items while the flag is off", async ({ page, request }) => {
  await setFlag(request, false);
  await page.goto("/");
  const nav = page.getByRole("navigation", { name: "Main" });
  await expect(nav.getByText("CodeGraph", { exact: true })).toBeVisible();
  await expect(nav.getByRole("link", { name: "CodeGraph", exact: true })).toHaveCount(0);
  await page.goto("/codegraph");
  await expect(page.getByText("CodeGraph is not enabled")).toBeVisible();
  await shot(page, "00-feature-disabled");
});

test("the CodeGraph of an application renders with evidence on every edge, in all 15 views", async ({ page, request }) => {
  test.setTimeout(Number(process.env.E2E_CODEGRAPH_WAIT_S || 900) * 1000 + 300_000);
  await setFlag(request, true);
  const app = await pickApp(request);
  const snap = await readySnapshot(request, app.id);
  const base = `/api/v1/codegraph/applications/${app.id}/snapshots/${snap.id}`;

  // Rule 5 through the API: every edge of every view carries evidence.
  for (const v of views) {
    const r = await request.get(`${base}/graph?view=${v}`);
    expect(r.ok(), `${v}: ${r.status()}`).toBe(true);
    const g = (await r.json()) as { nodes: unknown[]; edges: Edge[] };
    for (const e of g.edges) {
      expect(["verified", "observed", "ai_inferred"], `${v} edge ${e.id}`).toContain(e.evidence);
      expect(e.evidence_refs.length, `${v} edge ${e.id} has evidence references`).toBeGreaterThan(0);
    }
  }
  const arch = (await (await request.get(`${base}/graph?view=architecture`)).json()) as { nodes: unknown[]; edges: Edge[] };
  expect(arch.nodes.length, "architecture view nodes").toBeGreaterThan(0);

  // The sidebar link and the chooser.
  await page.goto("/");
  await page.getByRole("navigation", { name: "Main" }).getByRole("link", { name: "CodeGraph", exact: true }).click();
  await expect(page.getByRole("heading", { level: 1, name: "CodeGraph" })).toBeVisible();
  await page.getByRole("combobox", { name: "Application" }).selectOption(app.id);
  await expect(page).toHaveURL(new RegExp(`/codegraph/${app.id}`));
  await expect(page.getByRole("navigation", { name: "Breadcrumb" })).toContainText("CodeGraph");
  await expect(page.getByTestId("codegraph-commit")).toContainText(snap.commit_sha ? snap.commit_sha.slice(0, 12) : "no commit");
  await expect(page.getByRole("button", { name: "Rebuild" })).toBeVisible();
  const canvas = page.getByTestId("graph-canvas");
  await expect(canvas.locator(".react-flow__node").first()).toBeVisible({ timeout: 30_000 });
  await expect(page.getByRole("group", { name: "Legend" })).toContainText("Static: verified from code");
  // Every drawn edge is evidence-styled and named.
  const drawn = canvas.locator(".pathos-evidence-edge");
  if (arch.edges.length) {
    await expect(drawn.first()).toBeAttached();
    const evidence = await drawn.evaluateAll((els) => els.map((e) => e.getAttribute("data-evidence")));
    expect(evidence.every((e) => e === "verified" || e === "observed" || e === "ai_inferred")).toBe(true);
  }
  await shot(page, "01-architecture");

  // Inspector on the first node.
  await canvas.locator(".react-flow__node[aria-roledescription], .react-flow__node").filter({ hasNot: page.locator("[data-trust-boundary]") }).first().click();
  const insp = page.getByLabel("Node inspector");
  await expect(insp.getByRole("button", { name: "Trace out" })).toBeVisible();
  await shot(page, "02-inspector");
  await insp.getByRole("button", { name: "Trace out" }).click();
  await expect(page.getByText(/Tracing out of/)).toBeVisible();
  await shot(page, "03-trace-out");
  await page.keyboard.press("Escape");

  // List view (accessible alternative).
  await page.getByRole("button", { name: "List view" }).click();
  await expect(page.getByTestId("graph-list-view")).toBeVisible();
  await shot(page, "04-list-view");
  await page.getByRole("button", { name: "Graph view" }).click();

  // All 15 views render (graph, or the explained empty state).
  const switcher = page.getByRole("group", { name: "CodeGraph views" });
  const labels = await switcher.getByRole("button").allTextContents();
  expect(labels).toHaveLength(15);
  for (const [i, label] of labels.entries()) {
    await switcher.getByRole("button", { name: label, exact: true }).click();
    await expect(switcher.getByRole("button", { name: label, exact: true })).toHaveAttribute("aria-pressed", "true");
    await expect(
      canvas.locator(".react-flow__node").first().or(page.getByText(/^Nothing in the .* view$/)).or(page.getByText("Nothing to compare yet")),
    ).toBeVisible({ timeout: 30_000 });
    await expect(page.getByText("Something went wrong")).toHaveCount(0);
    await shot(page, `${String(10 + i)}-view-${views[i]}`);
  }
});

test("API & endpoints opens the api view; the context graph still works", async ({ page, request }) => {
  await setFlag(request, true);
  const app = await pickApp(request);
  await page.goto("/api-endpoints");
  await expect(page.getByRole("heading", { level: 1, name: "API & endpoints" })).toBeVisible();
  await page.getByRole("combobox", { name: "Application" }).selectOption(app.id);
  await expect(page).toHaveURL(/view=api/);
  await expect(page.getByRole("group", { name: "CodeGraph views" }).getByRole("button", { name: "API & endpoints" })).toHaveAttribute("aria-pressed", "true");
  await page.goto(`/posture/graph?node=application:${app.id}`);
  await expect(page.getByRole("heading", { level: 1, name: "Context graph" })).toBeVisible();
  await expect(page.getByRole("img", { name: /Context graph with \d+ nodes/ })).toBeVisible();
});
