import { test, expect } from "./fixtures";

const pages: [string, string | RegExp][] = [
  ["/", "Security posture"],
  ["/repositories", "Repositories"],
  ["/applications", "Applications"],
  ["/scans", "Scans"],
  ["/scans/profiles", "Scan profiles"],
  ["/scans/schedules", "Scan schedules"],
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
  ["/admin/scanners", /Scanners/],
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
