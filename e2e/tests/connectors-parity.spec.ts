import type { Page } from "@playwright/test";
import { test, expect } from "./fixtures";

// Prompt §1.1 / M2: SCM connections (/admin/scm) and Integrations
// (/admin/integrations) may redirect into Connectors only after the hub
// reaches full parity. This spec proves it, action by action:
//   1. With the `connectors` flag OFF the old pages are unchanged (no redirect)
//      and offer the actions listed below.
//   2. With the flag ON every one of those actions is available inside the
//      hub and the ones that do not need a real vendor are performed there.
//   3. With the flag ON the old URLs redirect into the hub, keeping their
//      parameters (deep links and the OAuth callback).
// The flag is restored to its previous value afterwards.
//
// Nothing here talks to a real vendor: connections point at *.invalid hosts
// and fail their tests, which is enough to exercise every button.

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
  const r = await api(page, "PUT", "/api/v1/admin/feature-flags", { flags: { connectors: on } });
  expect(r.status, JSON.stringify(r.json)).toBeLessThan(300);
}

async function flagState(page: Page): Promise<boolean> {
  const r = await api(page, "GET", "/api/v1/admin/feature-flags");
  return !!(r.json?.items as { name: string; enabled: boolean }[] | undefined)?.find((f) => f.name === "connectors")?.enabled;
}

const stamp = Date.now();
const scmName = `E2E parity GitLab ${stamp}`;
const appName = `E2E parity OAuth ${stamp}`;
const jiraName = `E2E parity Jira ${stamp}`;

/** Every action of the old SCM connections page (with one token connection and one OAuth application present). */
const scmActions = {
  page: ["Connect provider"],
  tabs: ["Connections", "OAuth applications"],
  card: ["Test", "Rotate credential", "Re-sync metadata", "New webhook secret", `Delete connection ${scmName}`],
  oauth: ["Register application", `Edit ${appName}`, `Delete ${appName}`],
};
/** Every action of the old Integrations page (with one Jira connection present). */
const integrationActions = ["New connection", "Test", `Edit ${jiraName}`, `Delete ${jiraName}`];

let initialFlag = false;

test.beforeAll(async ({ browser }) => {
  const page = await browser.newPage();
  initialFlag = await flagState(page);
  await setFlag(page, false);
  await page.close();
});

test.afterAll(async ({ browser }) => {
  const page = await browser.newPage();
  // Clean up whatever a failed test left behind, then restore the flag.
  const conns = await api(page, "GET", "/api/v1/scm-connections");
  for (const c of (conns.json?.items ?? []) as { id: string; name: string }[]) if (c.name.startsWith("E2E parity")) await api(page, "DELETE", `/api/v1/scm-connections/${c.id}`);
  const apps = await api(page, "GET", "/api/v1/scm-oauth-apps");
  for (const a of (apps.json?.items ?? []) as { id: string; name: string }[]) if (a.name.startsWith("E2E parity")) await api(page, "DELETE", `/api/v1/scm-oauth-apps/${a.id}`);
  const tickets = await api(page, "GET", "/api/v1/ticket-connections");
  for (const t of (tickets.json?.items ?? []) as { id: string; name: string }[]) if (t.name.startsWith("E2E parity")) await api(page, "DELETE", `/api/v1/ticket-connections/${t.id}`);
  await setFlag(page, initialFlag);
  await page.close();
});

async function seed(page: Page) {
  const conn = await api(page, "POST", "/api/v1/scm-connections", { name: scmName, provider: "gitlab", auth_type: "pat", base_url: "https://gitlab.invalid", token: "glpat-e2e-not-a-real-token" });
  expect(conn.status, JSON.stringify(conn.json)).toBe(201);
  const app = await api(page, "POST", "/api/v1/scm-oauth-apps", { provider: "gitlab", name: appName, base_url: "https://gitlab.invalid", client_id: "e2e-client", client_secret: "e2e-secret-not-real" });
  expect(app.status, JSON.stringify(app.json)).toBeLessThan(300);
  const jira = await api(page, "POST", "/api/v1/ticket-connections", {
    kind: "jira", name: jiraName, base_url: "https://jira.invalid", auth_type: "basic", username: "e2e@example.com", secret: "not-a-real-token", enabled: true,
    config: { project_key: "SEC", issue_type: "Bug", labels: [] },
  });
  expect(jira.status, JSON.stringify(jira.json)).toBeLessThan(300);
}

async function expectScmActions(page: Page) {
  for (const a of scmActions.page) await expect(page.getByRole("button", { name: a }).first()).toBeVisible();
  for (const t of scmActions.tabs) await expect(page.getByRole("tab", { name: t })).toBeVisible();
  const card = page.locator("div.rounded-lg", { hasText: scmName }).last();
  for (const a of scmActions.card) await expect(card.getByRole("button", { name: a, exact: true })).toBeVisible();
  await page.getByRole("tab", { name: "OAuth applications" }).click();
  for (const a of scmActions.oauth) await expect(page.getByRole("button", { name: a })).toBeVisible();
  await page.getByRole("tab", { name: "Connections" }).click();
}

async function expectIntegrationActions(page: Page) {
  await expect(page.getByRole("button", { name: "New connection" })).toBeVisible();
  const row = page.locator("tr", { hasText: jiraName });
  for (const a of integrationActions.slice(1)) await expect(row.getByRole("button", { name: a })).toBeVisible();
}

test("flag off: the old pages are unchanged and list every action", async ({ page }) => {
  await seed(page);
  await page.goto("/admin/scm");
  await expect(page.getByRole("heading", { level: 1, name: "SCM connections" })).toBeVisible();
  await expectScmActions(page);
  await expect(page).toHaveURL(/\/admin\/scm/);

  await page.goto("/admin/integrations");
  await expect(page.getByRole("heading", { level: 1, name: "Integrations" })).toBeVisible();
  await expectIntegrationActions(page);
  await expect(page).toHaveURL(/\/admin\/integrations$/);

  await page.goto("/connectors");
  await expect(page.getByText("Connectors is not enabled")).toBeVisible();
  // The menu item stays disabled.
  await expect(page.getByRole("navigation", { name: "Main" }).getByTitle("Connectors: arrives in roadmap phase 2")).toBeVisible();
});

test("flag on: every SCM connections action works inside the hub", async ({ page }) => {
  await setFlag(page, true);
  await page.goto("/connectors?category=scm_ide&manage=scm");
  await expect(page.getByRole("heading", { level: 1, name: "Connectors" })).toBeVisible();
  await expect(page.getByRole("heading", { level: 2, name: "SCM connections" })).toBeVisible();
  await expectScmActions(page);

  const card = page.locator("div.rounded-lg", { hasText: scmName }).last();
  // Test (fails against the .invalid host, but runs).
  await card.getByRole("button", { name: "Test", exact: true }).click();
  await expect(card.getByText(/Test (succeeded|finished)|scm:|PTH-CONN|no such host|lookup/i).first()).toBeVisible({ timeout: 30_000 });
  // New webhook secret: shown once.
  await card.getByRole("button", { name: "New webhook secret" }).click();
  const secretDialog = page.getByRole("dialog");
  await expect(secretDialog).toBeVisible();
  await secretDialog.getByRole("button", { name: "Done" }).click();
  // Rotate credential.
  await card.getByRole("button", { name: "Rotate credential" }).click();
  const rotate = page.getByRole("dialog", { name: /Rotate credential/ });
  await rotate.locator("input[type=password]").first().fill("glpat-e2e-rotated-not-real");
  await rotate.getByRole("button", { name: "Replace credential" }).click();
  await expect(page.getByText(`Credential of “${scmName}” rotated.`)).toBeVisible({ timeout: 30_000 });
  // Connect provider dialog opens with the provider list.
  await page.getByRole("button", { name: "Connect provider" }).first().click();
  await expect(page.getByRole("dialog").getByText("GitLab").first()).toBeVisible();
  await page.keyboard.press("Escape");
  // OAuth applications: edit and save.
  await page.getByRole("tab", { name: "OAuth applications" }).click();
  await expect(page).toHaveURL(/scm_tab=oauth/);
  await page.getByRole("button", { name: `Edit ${appName}` }).click();
  await page.getByRole("dialog").getByRole("button", { name: "Save" }).click();
  await expect(page.getByRole("dialog")).toHaveCount(0);
  await page.getByRole("button", { name: `Delete ${appName}` }).click();
  await page.getByRole("dialog").getByRole("button", { name: /Delete/ }).last().click();
  await expect(page.getByRole("button", { name: `Edit ${appName}` })).toHaveCount(0);
  await page.getByRole("tab", { name: "Connections" }).click();
  // Delete the connection.
  await card.getByRole("button", { name: `Delete connection ${scmName}` }).click();
  await page.getByRole("dialog").getByRole("button", { name: "Delete connection" }).click();
  await expect(page.getByText(`Connection “${scmName}” deleted.`)).toBeVisible({ timeout: 30_000 });
  // Back to the cards.
  await page.getByRole("button", { name: "All connectors" }).click();
  await expect(page).not.toHaveURL(/manage=scm/);
});

test("flag on: every Integrations action works inside the hub", async ({ page }) => {
  await page.goto("/connectors?category=monitoring&manage=integrations");
  await expect(page.getByRole("heading", { level: 2, name: "Integrations" })).toBeVisible();
  await expectIntegrationActions(page);
  const row = page.locator("tr", { hasText: jiraName });
  await row.getByRole("button", { name: "Test" }).click();
  await expect(row.getByText(/Failed:|Connected as/)).toBeVisible({ timeout: 30_000 });
  await row.getByRole("button", { name: `Edit ${jiraName}` }).click();
  const dlg = page.getByRole("dialog", { name: `Edit ${jiraName}` });
  await dlg.locator("#tc-type").fill("Task");
  await dlg.getByRole("button", { name: "Save" }).click();
  await expect(dlg).toHaveCount(0);
  await page.getByRole("button", { name: "New connection" }).click();
  await expect(page.getByRole("dialog", { name: "New ticketing connection" })).toBeVisible();
  await page.keyboard.press("Escape");
  page.once("dialog", (d) => void d.accept());
  await row.getByRole("button", { name: `Delete ${jiraName}` }).click();
  await expect(page.locator("tr", { hasText: jiraName })).toHaveCount(0);
});

test("flag on: the old URLs redirect into the hub and keep their parameters", async ({ page }) => {
  await page.goto("/admin/scm");
  await expect(page).toHaveURL(/\/connectors\?.*manage=scm/);
  await expect(page.getByRole("heading", { level: 2, name: "SCM connections" })).toBeVisible();

  // Deep link from the import wizard: the connect dialog opens in the hub.
  await page.goto("/admin/scm?connect=git");
  await expect(page).toHaveURL(/\/connectors\?.*connect=git/);
  await expect(page.getByRole("dialog")).toBeVisible();
  await page.keyboard.press("Escape");

  // OAuth callback result is shown in the hub.
  await page.goto("/admin/scm?oauth=error&message=access_denied");
  await expect(page).toHaveURL(/\/connectors/);
  await expect(page.getByText(/The provider sign-in did not complete: access_denied/)).toBeVisible();

  await page.goto("/admin/scm?tab=oauth");
  await expect(page).toHaveURL(/scm_tab=oauth/);
  await expect(page.getByRole("tab", { name: "OAuth applications" })).toHaveAttribute("aria-selected", "true");

  await page.goto("/admin/integrations");
  await expect(page).toHaveURL(/\/connectors\?.*manage=integrations/);
  await expect(page.getByRole("heading", { level: 2, name: "Integrations" })).toBeVisible();

  // The sidebar item is a link now.
  await expect(page.getByRole("navigation", { name: "Main" }).getByRole("link", { name: "Connectors" })).toHaveAttribute("href", "/connectors");
});

test("flag on: hub tabs show real status only", async ({ page }) => {
  await page.goto("/connectors");
  const rail = page.getByRole("navigation", { name: "Connector categories" });
  for (const c of ["SCM & IDE", "CI/CD", "Cloud", "Containers", "Security", "IAM & Secrets", "APIs", "Databases", "Monitoring"]) await expect(rail.getByRole("button", { name: new RegExp(`^${c.replace(/[&/]/g, (m) => `\\${m}`)}`) })).toBeVisible();
  // No card claims a status without a check.
  await page.getByRole("tab", { name: /Health/ }).click();
  await expect(page.getByRole("heading", { level: 1, name: "Connectors" })).toBeVisible();
  const rows = page.locator("tbody tr");
  const n = await rows.count();
  for (let i = 0; i < n; i++) {
    const text = await rows.nth(i).innerText();
    if (/Healthy|Degraded|Failing/.test(text)) expect(text).not.toMatch(/Never checked/);
  }
  for (const t of ["Authentication", "Configuration"]) {
    await page.getByRole("tab", { name: t }).click();
    await expect(page.getByRole("tab", { name: t })).toHaveAttribute("aria-selected", "true");
  }
});
