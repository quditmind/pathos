import type { Page } from "@playwright/test";
import { test, expect } from "./fixtures";

// PATHOS 3.0 M8: remediation workspace, security gates and exceptions.
//   1. With the `remediation_workspace` flag OFF the pages say so and the
//      sidebar item is disabled.
//   2. With the flag ON the three pages render; evaluating a gate with no
//      gate configured passes and is recorded as "no policy" (rule 7).
//   3. Pull request settings require choosing Block or Warn.
// The flag is restored to its previous value afterwards.

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

async function setFlag(page: Page, on: boolean) {
  const r = await api(page, "PUT", "/api/v1/admin/feature-flags", { flags: { remediation_workspace: on } });
  expect(r.status, JSON.stringify(r.json)).toBeLessThan(300);
}

let initial = false;
test.beforeAll(async ({ browser }) => {
  const page = await browser.newPage();
  const r = await api(page, "GET", "/api/v1/admin/feature-flags");
  initial = !!(r.json?.items as { name: string; enabled: boolean }[] | undefined)?.find((f) => f.name === "remediation_workspace")?.enabled;
  await page.close();
});
test.afterAll(async ({ browser }) => {
  const page = await browser.newPage();
  await setFlag(page, initial);
  await page.close();
});

test("flag off: the module looks absent and says how to enable it", async ({ page }) => {
  await setFlag(page, false);
  await page.goto("/remediation");
  await expect(page.getByText(/is not enabled/)).toBeVisible();
  await expect(page.getByText("remediation_workspace", { exact: true })).toBeVisible();
  const nav = page.getByRole("navigation", { name: "Main" });
  await expect(nav.getByText("Remediation workspace").locator("xpath=ancestor-or-self::*[@aria-disabled='true'][1]")).toHaveAttribute("aria-disabled", "true");
  expect((await api(page, "GET", "/api/v1/remediation/items")).status).toBe(404);
});

test("flag on: workspace, gates and exceptions render", async ({ page }) => {
  await setFlag(page, true);
  await page.goto("/remediation");
  await expect(page.getByRole("heading", { level: 1, name: "Remediation workspace" })).toBeVisible();
  await expect(page.getByRole("tab", { name: "Workspace" })).toHaveAttribute("aria-selected", "true");
  await expect(page.getByLabel("Status")).toBeVisible();

  await page.getByRole("tab", { name: "Gates & decisions" }).click();
  await expect(page.getByRole("heading", { level: 1, name: "Security gates" })).toBeVisible();
  await expect(page.getByRole("heading", { name: "Gate decisions" })).toBeVisible();

  await page.getByRole("tab", { name: "Exceptions & approvals" }).click();
  await expect(page.getByRole("heading", { level: 1, name: "Gate exceptions and approvals" })).toBeVisible();
});

test("no gate configured: evaluation passes and is logged as no policy", async ({ page }) => {
  await setFlag(page, true);
  const repos = await api(page, "GET", "/api/v1/repositories?limit=1");
  const repo = (repos.json?.items as { id: string }[] | undefined)?.[0];
  test.skip(!repo, "needs one repository");
  const gates = await api(page, "GET", "/api/v1/gates?stage=deploy");
  test.skip(((gates.json?.items as unknown[]) ?? []).length > 0, "a deploy gate exists on this stack");
  const d = await api(page, "POST", "/api/v1/gates/evaluate", { stage: "deploy", repository_id: repo!.id, commit_sha: "0123456789abcdef0123456789abcdef01234567" });
  expect(d.status).toBe(200);
  expect(d.json.outcome).toBe("pass");
  expect(d.json.policy_ids).toEqual([]);
  await page.goto("/remediation/gates?stage=deploy&decision=" + d.json.id);
  await expect(page.getByTestId("decision-detail")).toContainText("Pass");
  await expect(page.getByTestId("decision-detail").getByText("no policy")).toBeVisible();
});

test("pull request checks need an explicit block or warn choice", async ({ page }) => {
  await page.goto("/pull-requests");
  await expect(page.getByRole("heading", { level: 1, name: "Pull request checks" })).toBeVisible();
  const repos = await api(page, "GET", "/api/v1/repositories?limit=20");
  const repo = (repos.json?.items as { id: string; full_name: string; source_type?: string }[] | undefined)?.find((r) => r.source_type !== "upload");
  test.skip(!repo, "needs a repository with an SCM connection");
  const before = await api(page, "GET", `/api/v1/repositories/${repo!.id}/pr-settings`);
  test.skip(before.json?.gate_mode, "the repository already has a choice");
  const r = await api(page, "PUT", `/api/v1/repositories/${repo!.id}/pr-settings`, { enabled: true, gate_severity: "high" });
  expect(r.status).toBe(422);
  expect(JSON.stringify(r.json)).toContain("PTH-GATE-1106");
});
