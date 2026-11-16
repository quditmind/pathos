import { test, expect } from "./fixtures";

// Scanning module: the four Scanning pages, the Configurations section,
// execution details and the schedule lifecycle with an execution plan.

const scanningPages: [string, string][] = [
  ["/scans/overview", "Scan overview"],
  ["/scans", "Scans"],
  ["/scans/schedules", "Scan schedules"],
  ["/scans/compare", "Scan comparison"],
];

for (const [path, heading] of scanningPages) {
  test(`scanning page ${path} renders`, async ({ page }) => {
    await page.goto(path);
    await expect(page.getByRole("heading", { level: 1, name: heading })).toBeVisible();
    await expect(page.getByText("Something went wrong")).toHaveCount(0);
  });
}

test("Scanning and Configurations navigation sections", async ({ page }) => {
  await page.goto("/scans/overview");
  const nav = page.getByRole("navigation", { name: "Main" });
  for (const label of ["Scan Overview", "Scans", "Scan Schedules", "Scan Comparison"]) {
    await expect(nav.getByRole("link", { name: label, exact: true })).toBeVisible();
  }
  await expect(nav.getByText("Configurations", { exact: true })).toBeVisible();
  await nav.getByRole("link", { name: "Scan profiles" }).click();
  await expect(page).toHaveURL(/\/configurations\/scan-profiles/);
  await expect(page.getByRole("heading", { level: 1, name: "Scan profiles" })).toBeVisible();
  await nav.getByRole("link", { name: "Scanners & workers" }).click();
  await expect(page).toHaveURL(/\/configurations\/scanners/);
  // Old URLs redirect.
  await page.goto("/scans/profiles");
  await expect(page).toHaveURL(/\/configurations\/scan-profiles/);
  await page.goto("/admin/scanners");
  await expect(page).toHaveURL(/\/configurations\/scanners/);
});

test("scan details shows six tabs for an existing execution", async ({ page, request }) => {
  const r = await request.get("/api/v1/scans");
  const items = r.ok() ? ((await r.json()) as { items: { id: string }[] }).items : [];
  test.skip(!items.length, "no scan executions in this environment");
  await page.goto(`/scans/${items[0]!.id}`);
  const tabs = page.getByRole("tab");
  await expect(tabs).toHaveText(["Overview", "Findings", "Execution Logs", "Stages", "Configuration", "History"]);
  await page.getByRole("tab", { name: "Configuration" }).click();
  await expect(page).toHaveURL(/tab=configuration/);
  await expect(page.getByText(/Snapshot — read-only/)).toBeVisible();
  await page.getByRole("tab", { name: "Execution Logs" }).click();
  await expect(page.getByRole("combobox", { name: "Minimum level" })).toBeVisible();
});

test("a schedule with a two-row plan can be created, previewed, paused, resumed and deleted", async ({ page }) => {
  const name = `E2E plan ${Date.now()}`;
  await page.goto("/scans/schedules");
  await expect(page.getByText("Workers online")).toBeVisible();
  await page.getByRole("button", { name: "New schedule" }).click();
  const dialog = page.getByRole("dialog");
  await dialog.getByLabel("Name").fill(name);
  await dialog.getByLabel("Schedule type").selectOption("weekly");
  await dialog.getByRole("group", { name: "Weekdays" }).getByRole("button", { name: "Wed" }).click();
  await dialog.locator("#s-time").fill("03:30");
  // Approved scan window.
  await dialog.locator("#s-ws").fill("01:00");
  await dialog.locator("#s-we").fill("06:00");
  // Row 1: all repositories with their own profile; row 2: the first region with the first existing profile.
  await dialog.getByRole("button", { name: "Add plan row" }).click();
  await dialog.getByLabel("Plan row 2 asset scope").selectOption("region");
  const region = dialog.getByLabel("Plan row 2 region");
  await expect(region.locator("option")).not.toHaveCount(1);
  await region.selectOption({ index: 1 });
  const profile = dialog.getByLabel("Plan row 2 scan profile");
  if ((await profile.locator("option").count()) > 1) await profile.selectOption({ index: 1 });
  // Live preview.
  const preview = dialog.getByTestId("schedule-preview");
  await expect(preview).toContainText(/executions? per activation/);
  await expect(preview).toContainText("window 01:00–06:00");
  await expect(preview).toContainText(/^.*Next:/);
  await dialog.getByRole("button", { name: "Create schedule" }).click();
  await expect(dialog).toHaveCount(0);

  const row = page.locator("tr", { hasText: name });
  await expect(row).toBeVisible();
  await expect(row).toContainText("2 plan rows");
  await expect(row).toContainText("01:00–06:00");
  await row.getByRole("button", { name: "Pause" }).click();
  await expect(row.getByText("paused")).toBeVisible();
  await row.getByRole("button", { name: "Resume" }).click();
  await expect(row.getByText("paused")).toHaveCount(0);
  await row.getByRole("button", { name: "Run history" }).click();
  await expect(page.getByRole("dialog").getByRole("link", { name: /View all executions/ })).toBeVisible();
  await page.keyboard.press("Escape");
  await row.getByRole("button", { name: "Delete" }).click();
  await page.getByRole("dialog").getByRole("button", { name: "Delete schedule" }).click();
  await expect(row).toHaveCount(0);
});
