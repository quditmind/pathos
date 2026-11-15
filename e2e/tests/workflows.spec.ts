import { test, expect } from "./fixtures";

test("schedule lifecycle: create with preview, pause, delete", async ({ page }) => {
  const name = `E2E nightly ${Date.now()}`;
  await page.goto("/scans/schedules");
  await expect(page.getByText("Workers online")).toBeVisible();
  await page.getByRole("button", { name: "New schedule" }).click();
  await page.fill("#s-name", name);
  await expect(page.getByText(/^Next:/)).toBeVisible();
  // A too-frequent cadence is rejected in the preview.
  await page.fill("#s-cron", "*/5 * * * *");
  await expect(page.getByText(/at most once per hour/)).toBeVisible();
  await page.fill("#s-cron", "0 3 * * *");
  await expect(page.getByText(/Daily at 03:00/)).toBeVisible();
  await page.getByRole("button", { name: "Create schedule" }).click();
  const row = page.locator("tr", { hasText: name });
  await expect(row).toBeVisible();
  await row.getByRole("button", { name: "Pause" }).click();
  await expect(row.getByText("paused")).toBeVisible();
  page.once("dialog", (d) => d.accept());
  await row.getByRole("button", { name: "Delete" }).click();
  await expect(row).toHaveCount(0);
});

test("notification admin: rules, email, templates with live preview, history", async ({ page }) => {
  await page.goto("/admin/notifications");
  await expect(page.getByText("New critical findings")).toBeVisible();
  await page.getByText("Risk acceptance approvals").click();
  await expect(page.getByText("Dynamic recipients")).toBeVisible();
  await page.keyboard.press("Escape");
  await page.getByRole("tab", { name: "Email (SMTP)" }).click();
  await expect(page.getByLabel("SMTP host")).toBeVisible();
  await page.getByRole("tab", { name: "Templates" }).click();
  await expect(page.getByText("acme/payments-api").first()).toBeVisible();
  await page.getByRole("tab", { name: "Delivery history" }).click();
  await expect(page.getByText(/Sent · 7 days/i)).toBeVisible();
});

test("policies show seeded SLA and license rules", async ({ page }) => {
  await page.goto("/admin/policies");
  await expect(page.getByLabel("critical SLA days")).toHaveValue("7");
  await expect(page.locator("#lic")).toContainText("AGPL-3.0-only deny");
});

test("finding drawer shows lifecycle and history", async ({ page }) => {
  await page.goto("/findings?status=all");
  const rows = page.locator("tbody tr");
  await page.waitForLoadState("networkidle");
  test.skip((await rows.count()) === 0 || (await page.getByText("No findings match").count()) > 0, "no findings yet (scan a repository first)");
  await rows.first().locator("td").nth(2).click();
  await expect(page.getByRole("heading", { name: "History" })).toBeVisible();
  await expect(page.getByRole("heading", { name: "Risk acceptance" })).toBeVisible();
});

test("notification centre opens", async ({ page }) => {
  await page.goto("/");
  await page.getByRole("button", { name: /^Notifications/ }).click();
  await expect(page.getByText(/Mark all read|all caught up/).first()).toBeVisible();
});

test("user drawer shows the two-factor status", async ({ page }) => {
  await page.goto("/admin/users");
  await page.locator("tbody tr").first().click();
  await expect(page.getByText("Two-factor (TOTP)")).toBeVisible();
  await expect(page.getByText(/enabled|enrolment at next sign-in|not set up/).first()).toBeVisible();
});
