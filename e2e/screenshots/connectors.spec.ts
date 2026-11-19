import { mkdirSync } from "node:fs";
import type { Page } from "@playwright/test";
import { test, expect } from "@playwright/test";

// Light and dark screenshots of the Connectors hub (PATHOS 3.0 M2): the four
// tabs, a selected connector with its health history, the embedded SCM
// connections and Integrations pages, the Add connector dialog (Generic Git
// with a Vault reference, and Vault/OpenBao) and the
// feature-disabled state. The `connectors` flag is switched on for the run
// and restored afterwards. The signed-in e-mail is masked.
//
//   scripts/e2e.sh --reporter=line --config=screenshots.config.ts screenshots/connectors.spec.ts
//   (PNG files: e2e/screenshots/out/connectors/<name>-<theme>.png)

const OUT = "screenshots/out/connectors";
mkdirSync(OUT, { recursive: true });
const themes = ["light", "dark"] as const;

test.describe.configure({ mode: "serial" });

async function api(page: Page, method: string, path: string, body?: unknown) {
  const me = await (await page.request.get("/api/v1/me")).json();
  const res = await page.request.fetch(path, { method, headers: { "X-CSRF-Token": me.csrf_token, "Content-Type": "application/json" }, data: body === undefined ? undefined : JSON.stringify(body) });
  return res.status() === 204 ? null : await res.json().catch(() => null);
}

let initial = false;
// Labelled example data: one SCM connection to an unresolvable host, so the
// details panel shows a real failed check. Deleted afterwards.
const EXAMPLE = "Example GitLab (screenshot)";
test.beforeAll(async ({ browser }) => {
  const page = await browser.newPage();
  const flags = await api(page, "GET", "/api/v1/admin/feature-flags");
  initial = !!(flags?.items as { name: string; enabled: boolean }[] | undefined)?.find((f) => f.name === "connectors")?.enabled;
  await api(page, "PUT", "/api/v1/admin/feature-flags", { flags: { connectors: true } });
  await api(page, "POST", "/api/v1/scm-connections", { name: EXAMPLE, provider: "gitlab", auth_type: "pat", base_url: "https://gitlab.invalid", token: "example-not-a-token" });
  const list = await api(page, "GET", "/api/v1/connectors");
  const row = (list?.items as { id: string; name: string }[] | undefined)?.find((c) => c.name === EXAMPLE);
  if (row) await api(page, "POST", `/api/v1/connectors/${row.id}/check`);
  await page.close();
});
test.afterAll(async ({ browser }) => {
  const page = await browser.newPage();
  const conns = await api(page, "GET", "/api/v1/scm-connections");
  for (const c of (conns?.items ?? []) as { id: string; name: string }[]) if (c.name === EXAMPLE) await api(page, "DELETE", `/api/v1/scm-connections/${c.id}`);
  await api(page, "PUT", "/api/v1/admin/feature-flags", { flags: { connectors: initial } });
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
  test(`connectors ${theme}`, async ({ page }) => {
    await setTheme(page, theme);
    await api(page, "PUT", "/api/v1/admin/feature-flags", { flags: { connectors: false } });
    await page.goto("/connectors");
    await expect(page.getByText("Connectors is not enabled")).toBeVisible();
    await shot(page, "00-feature-disabled", theme);

    await api(page, "PUT", "/api/v1/admin/feature-flags", { flags: { connectors: true } });
    await page.goto("/connectors");
    await expect(page.getByRole("navigation", { name: "Connector categories" })).toBeVisible();
    await expect(page.getByRole("region", { name: "Not connected" }).or(page.getByRole("region", { name: "Connected" })).first()).toBeVisible();
    await shot(page, "01-connectors-all", theme);

    await page.getByRole("navigation", { name: "Connector categories" }).getByRole("button", { name: /^SCM & IDE/ }).click();
    await shot(page, "02-connectors-scm", theme);

    const first = page.getByRole("region", { name: "Connected" }).getByRole("button", { name: new RegExp(EXAMPLE.replace(/[()]/g, "\\$&")) });
    if (await first.count()) {
      await first.click();
      await expect(page.getByRole("heading", { name: "Health history" })).toBeVisible();
      await shot(page, "03-connector-details", theme);
    }

    for (const [tab, file] of [
      ["Authentication", "04-authentication"],
      ["Configuration", "05-configuration"],
      [/Health/, "06-health"],
    ] as const) {
      await page.getByRole("tab", { name: tab }).click();
      await page.waitForLoadState("networkidle");
      await shot(page, file, theme);
    }

    await page.goto("/connectors?category=scm_ide&manage=scm");
    await expect(page.getByRole("heading", { level: 2, name: "SCM connections" })).toBeVisible();
    await shot(page, "07-embedded-scm", theme);

    await page.goto("/connectors?category=monitoring&manage=integrations");
    await expect(page.getByRole("heading", { level: 2, name: "Integrations" })).toBeVisible();
    await shot(page, "08-embedded-integrations", theme);

    // Add connector with the creatable kinds (nothing is submitted): Generic
    // Git with a Vault/OpenBao reference, then Vault itself.
    await page.goto("/connectors");
    const add = page.getByRole("button", { name: "Add connector" });
    await expect(add).toBeVisible();
    await add.click();
    const dlg = page.getByRole("dialog", { name: "Add connector" });
    await expect(dlg).toBeVisible();
    await dlg.getByLabel("Kind").selectOption("generic_git");
    await dlg.getByLabel("Name", { exact: true }).fill("Example Git server (screenshot)");
    await dlg.getByLabel(/Repository URL/).fill("https://git.example.com/team/app.git");
    await dlg.getByLabel(/Reference a secret in Vault or OpenBao/).check();
    await dlg.getByLabel(/Secret reference/).fill("vault:secret/pathos/git#token");
    await shot(page, "09-add-connector", theme);
    await dlg.getByLabel("Kind").selectOption("vault");
    await dlg.getByLabel("Name", { exact: true }).fill("Example Vault (screenshot)");
    await dlg.getByLabel(/Vault address/).fill("https://vault.example.com:8200");
    await shot(page, "10-add-connector-vault", theme);
    await page.keyboard.press("Escape");
  });
}
