import { mkdirSync } from "node:fs";
import type { Page } from "@playwright/test";
import { test, expect } from "@playwright/test";

// Light and dark screenshots of the remediation workspace and security gates
// (PATHOS 3.0 M8): the feature-disabled state, the workspace, the gates and
// decisions log (with one "no policy" decision created for the shot), the
// Add gate dialog (nothing submitted) and the exceptions page. The
// `remediation_workspace` flag is switched on for the run and restored
// afterwards. The signed-in e-mail is masked.
//
//   scripts/e2e.sh --reporter=line --config=screenshots.config.ts screenshots/remediation.spec.ts
//   (PNG files: e2e/screenshots/out/remediation/<name>-<theme>.png)

const OUT = "screenshots/out/remediation";
mkdirSync(OUT, { recursive: true });
const themes = ["light", "dark"] as const;

test.describe.configure({ mode: "serial" });

async function api(page: Page, method: string, path: string, body?: unknown) {
  const me = await (await page.request.get("/api/v1/me")).json();
  const res = await page.request.fetch(path, { method, headers: { "X-CSRF-Token": me.csrf_token, "Content-Type": "application/json" }, data: body === undefined ? undefined : JSON.stringify(body) });
  return res.status() === 204 ? null : await res.json().catch(() => null);
}

let initial = false;
test.beforeAll(async ({ browser }) => {
  const page = await browser.newPage();
  const flags = await api(page, "GET", "/api/v1/admin/feature-flags");
  initial = !!(flags?.items as { name: string; enabled: boolean }[] | undefined)?.find((f) => f.name === "remediation_workspace")?.enabled;
  await api(page, "PUT", "/api/v1/admin/feature-flags", { flags: { remediation_workspace: true } });
  // One real decision for the log (no gate configured → pass, "no policy").
  const repos = await api(page, "GET", "/api/v1/repositories?limit=1");
  const repo = (repos?.items as { id: string }[] | undefined)?.[0];
  if (repo) await api(page, "POST", "/api/v1/gates/evaluate", { stage: "release", repository_id: repo.id });
  await page.close();
});
test.afterAll(async ({ browser }) => {
  const page = await browser.newPage();
  await api(page, "PUT", "/api/v1/admin/feature-flags", { flags: { remediation_workspace: initial } });
  await page.close();
});

async function setTheme(page: Page, theme: (typeof themes)[number]) {
  await page.emulateMedia({ colorScheme: theme, reducedMotion: "reduce" });
  await page.addInitScript((t) => {
    try {
      localStorage.setItem("pathos-theme", t);
    } catch {
      /* ignore */
    }
  }, theme);
}

async function shot(page: Page, name: string, theme: string) {
  const email = page.locator("header [aria-label='User menu']");
  await page.waitForTimeout(300);
  await page.screenshot({ path: `${OUT}/${name}-${theme}.png`, mask: (await email.count()) ? [email] : [] });
}

for (const theme of themes) {
  test(`remediation ${theme}`, async ({ page }) => {
    await setTheme(page, theme);
    await api(page, "PUT", "/api/v1/admin/feature-flags", { flags: { remediation_workspace: false } });
    await page.goto("/remediation");
    await expect(page.getByText(/is not enabled/)).toBeVisible();
    await shot(page, "00-feature-disabled", theme);

    await api(page, "PUT", "/api/v1/admin/feature-flags", { flags: { remediation_workspace: true } });
    await page.goto("/remediation");
    await expect(page.getByRole("heading", { level: 1, name: "Remediation workspace" })).toBeVisible();
    await page.waitForLoadState("networkidle");
    await shot(page, "01-workspace", theme);

    await page.goto("/remediation/gates");
    await expect(page.getByRole("heading", { name: "Gate decisions" })).toBeVisible();
    await page.waitForLoadState("networkidle");
    const first = page.getByRole("table").last().getByRole("button").first();
    if (await first.count()) await first.click();
    await shot(page, "02-gates-and-decisions", theme);

    const add = page.getByRole("button", { name: "Add gate" });
    if (await add.count()) {
      await add.click();
      const dlg = page.getByRole("dialog", { name: "Add gate" });
      await dlg.getByLabel("Name").fill("Example deploy gate (screenshot)");
      await dlg.getByLabel("Stage").selectOption("deploy");
      await dlg.getByLabel("When the policy matches").selectOption("require_approval");
      await shot(page, "03-add-gate", theme);
      await page.keyboard.press("Escape");
    }

    await page.goto("/remediation/exceptions?status=all");
    await expect(page.getByRole("heading", { level: 1, name: "Gate exceptions and approvals" })).toBeVisible();
    await page.waitForLoadState("networkidle");
    await shot(page, "04-exceptions", theme);

    await page.goto("/pull-requests");
    await expect(page.getByRole("heading", { level: 1, name: "Pull request checks" })).toBeVisible();
    await shot(page, "05-pr-settings", theme);
  });
}
