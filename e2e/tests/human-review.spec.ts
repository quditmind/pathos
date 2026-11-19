import { test, expect } from "./fixtures";

// Human Eye module: the six pages, navigation, and the assessment
// workspace for a real finding (added to the queue through the API).

const pages: [string, string][] = [
  ["/human-review", "Human Eye"],
  ["/human-review/queue", "Review queue"],
  ["/human-review/assessments", "Assessments"],
  ["/human-review/assignments", "Assignments"],
  ["/human-review/reports", "Review reports"],
  ["/human-review/configurations", "Review configurations"],
];

for (const [path, heading] of pages) {
  test(`human review page ${path} renders`, async ({ page }) => {
    await page.goto(path);
    await expect(page.getByRole("heading", { level: 1, name: heading })).toBeVisible();
    await expect(page.getByText("Something went wrong")).toHaveCount(0);
  });
}

test("Human Eye is a section of Validate & intelligence", async ({ page }) => {
  await page.goto("/human-review");
  const nav = page.getByRole("navigation", { name: "Main" });
  // 3.0 sidebar: "Human Eye" is a sub-heading of "7 · Validate & intelligence"; labels follow §5.
  await expect(nav.getByText("7 · Validate & intelligence", { exact: true })).toBeVisible();
  await expect(nav.getByText("Human Eye", { exact: true })).toBeVisible();
  for (const label of ["Review queue", "Assessments", "Assignments", "Review reports", "Review configurations"]) {
    await expect(nav.getByRole("link", { name: label, exact: true })).toBeVisible();
  }
  await nav.getByRole("link", { name: "Review queue" }).click();
  await expect(page).toHaveURL(/\/human-review\/queue/);
});

test("assessment workspace for a queued finding", async ({ page, request }) => {
  await page.goto("/human-review/queue");
  const me = await (await page.request.get("/api/v1/me")).json();
  const csrf = me.csrf_token as string;
  const findings = await (await page.request.get("/api/v1/findings?status=all")).json();
  test.skip(!findings.items?.length, "no findings in this stack");
  const finding = findings.items[0];
  const created = await page.request.post("/api/v1/human-reviews", {
    headers: { "X-CSRF-Token": csrf },
    data: { finding_ids: [finding.id], reason: "e2e: manual assessment" },
  });
  expect(created.status()).toBe(201);
  const body = await created.json();
  const reviewId = (body.created[0] ?? (await (await page.request.get(`/api/v1/human-reviews/${finding.id}`)).json()).id) as string;
  void request;

  await page.goto(`/human-review/reviews/${reviewId}`);
  await expect(page.getByRole("heading", { level: 1 })).toBeVisible();
  const tabs = page.getByRole("tablist", { name: "Assessment sections" });
  for (const t of ["Overview", "Source code", "Data flow", "Exploitability", "Evidence", "Risk assessment", "Remediation", "History"]) {
    await tabs.getByRole("tab", { name: t }).click();
    await expect(page.getByText("Something went wrong")).toHaveCount(0);
  }
  await tabs.getByRole("tab", { name: "Source code" }).click();
  // Either the scanned source with the vulnerable line, or a clear unavailable state.
  await expect(page.getByText(/vulnerable line|Source code unavailable|did not report a (file|line)/).first()).toBeAttached();
  await tabs.getByRole("tab", { name: "History" }).click();
  await expect(page.getByText("Review created").first()).toBeVisible();
});
