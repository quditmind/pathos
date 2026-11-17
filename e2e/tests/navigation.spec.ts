import { test, expect } from "./fixtures";

const pages: [string, string | RegExp][] = [
  ["/", "Security posture"],
  ["/repositories", "Repositories"],
  ["/applications", "Applications"],
  ["/posture", "Application posture"],
  ["/posture/coverage", "Scan coverage"],
  ["/posture/unmanaged", "Unmanaged assets"],
  ["/posture/benchmark", "Benchmarking"],
  ["/posture/blast-radius", "Blast radius"],
  ["/posture/graph", "Context graph"],
  ["/posture/attack-paths", "Attack paths"],
  ["/suppression-rules", "Suppression rules"],
  ["/vulnerabilities/CVE-2021-44906", "CVE-2021-44906"],
  ["/scans/overview", "Scan overview"],
  ["/scans", "Scans"],
  ["/scans/schedules", "Scan schedules"],
  ["/scans/compare", "Scan comparison"],
  ["/configurations/scan-profiles", "Scan profiles"],
  ["/configurations/scanners", /Scanners/],
  ["/findings", "Findings"],
  ["/risk", "Risk acceptances"],
  ["/sbom", "SBOM inventory"],
  ["/ai", "AI reviews"],
  ["/admin/ai", "AI settings"],
  ["/admin/mcp", "MCP registry"],
  ["/settings/tokens", /API tokens/],
  ["/admin/users", "Users"],
  ["/admin/organization", "Organization"],
  ["/admin/scm", "SCM connections"],
  ["/admin/tags", "Tags"],
  ["/admin/policies", "Policies"],
  ["/admin/notifications", "Notifications"],
  ["/admin/audit", "Audit log"],
];

for (const [path, heading] of pages) {
  test(`page ${path} renders`, async ({ page }) => {
    await page.goto(path);
    await expect(page.getByRole("heading", { level: 1, name: heading }).first()).toBeVisible();
    await expect(page.getByText("Something went wrong")).toHaveCount(0);
  });
}

test("command palette navigates", async ({ page }) => {
  await page.goto("/");
  await expect(page.getByRole("heading", { level: 1, name: "Security posture" })).toBeVisible();
  await page.keyboard.press("Control+k");
  await expect(page.getByRole("dialog")).toBeVisible();
  await page.keyboard.type("Scan schedules");
  await page.keyboard.press("Enter");
  await expect(page).toHaveURL(/\/scans\/schedules/);
});

test("security headers on the app shell", async ({ request }) => {
  const r = await request.get("/");
  const h = r.headers();
  expect(h["content-security-policy"]).toContain("script-src 'self'");
  expect(h["strict-transport-security"]).toContain("max-age=");
  expect(h["x-frame-options"]).toBe("DENY");
  expect(h["cross-origin-opener-policy"]).toBe("same-origin");
});

test("context graph of a repository renders its nodes", async ({ page, request }) => {
  const r = await request.get("/api/v1/repositories?limit=1");
  const items = r.ok() ? ((await r.json()) as { items: { id: string }[] }).items : [];
  test.skip(!items.length, "no repositories in this environment");
  await page.goto(`/posture/graph?node=repository:${items[0]!.id}`);
  const graph = page.getByRole("img", { name: /Context graph with \d+ nodes/ });
  await expect(graph).toBeVisible();
  await expect(graph.getByRole("link").first()).toBeVisible();
  await page.screenshot({ path: "test-results/context-graph.png", fullPage: true });
});
