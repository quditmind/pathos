import type { Page } from "@playwright/test";
import { test, expect } from "../tests/fixtures";

async function api(page: Page, method: string, path: string, body?: unknown) {
  const me = await (await page.request.get("/api/v1/me")).json();
  const res = await page.request.fetch(path, { method, headers: { "X-CSRF-Token": me.csrf_token, "Content-Type": "application/json" },
    data: body === undefined ? undefined : JSON.stringify(body) });
  return { status: res.status(), json: res.status() === 204 ? null : await res.json() };
}
const shot = (page: Page, name: string) => page.screenshot({ path: `screenshots/out/${name}.png`, mask: [page.getByText(/@/).filter({ hasText: /@[a-z0-9.-]+\.[a-z]{2,}/i })] });

test("real scan end to end, Scanning module screenshots", async ({ page }) => {
  test.setTimeout(20 * 60_000);
  await page.setViewportSize({ width: 1440, height: 900 });
  await page.goto("/");
  const repos = (await api(page, "GET", "/api/v1/repositories?limit=5")).json.items;
  expect(repos.length).toBeGreaterThan(0);
  const repo = repos.find((r: any) => r.source_type === "scm") ?? repos[0];
  const profiles = (await api(page, "GET", "/api/v1/scan-profiles")).json.items;
  const prof = profiles.find((p: any) => p.is_default) ?? profiles[0];
  const start = await api(page, "POST", "/api/v1/scans", { repository_ids: [repo.id], profile_id: prof.id, name: "Help Center example scan" });
  expect(start.status).toBe(202);
  const id = start.json.items[0].job_id;
  expect(id).toBeTruthy();
  // Watch it run in the Scans page, then wait for a real result.
  await page.goto("/scans");
  await page.waitForTimeout(4000);
  await shot(page, "scans-list-running");
  let job: any;
  for (let i = 0; i < 180; i++) {
    job = (await api(page, "GET", `/api/v1/scans/${id}`)).json;
    if (!["queued", "running"].includes(job.status)) break;
    await page.waitForTimeout(5000);
  }
  console.log("RESULT", job.scan_key, job.status, job.progress, job.stage, job.findings_total, JSON.stringify(job.severity));
  expect(["succeeded", "partial"]).toContain(job.status);
  expect(job.progress).toBe(100);
  for (const tab of ["overview", "findings", "logs", "stages", "configuration", "history"]) {
    await page.goto(`/scans/${id}?tab=${tab}`);
    await page.waitForLoadState("networkidle");
    await page.waitForTimeout(800);
    await shot(page, `scan-details-${tab}`);
  }
  const logs = (await api(page, "GET", `/api/v1/scans/${id}/logs`)).json;
  console.log("LOG LINES", logs.items.length, "SOURCES", logs.sources.join(","));
  const stages = (await api(page, "GET", `/api/v1/scans/${id}/stages`)).json.stages;
  console.log("STAGES", stages.map((s: any) => `${s.key}:${s.status}`).join(" "));
  await page.goto("/scans/overview"); await page.waitForLoadState("networkidle"); await page.waitForTimeout(1000);
  await shot(page, "scan-overview");
  await page.goto("/scans"); await page.waitForLoadState("networkidle");
  await shot(page, "scans-list");
  // Comparison with the previous execution of the same repository, if any.
  const hist = (await api(page, "GET", `/api/v1/scans/${id}/history`)).json.items;
  if (hist.length > 1) {
    await page.goto(`/scans/compare?ids=${hist[1].id},${id}`); await page.waitForLoadState("networkidle"); await page.waitForTimeout(1500);
    await shot(page, "scan-comparison");
  }
  await page.goto("/scans/schedules"); await page.waitForLoadState("networkidle");
  await shot(page, "scan-schedules");
  await page.getByRole("button", { name: /New schedule/ }).click();
  await page.waitForTimeout(800);
  await shot(page, "scan-schedule-dialog");
  await page.keyboard.press("Escape");
  await page.goto("/configurations/scan-profiles"); await page.waitForLoadState("networkidle");
  await shot(page, "configurations-profiles");
});
