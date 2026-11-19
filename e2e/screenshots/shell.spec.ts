import { mkdirSync } from "node:fs";
import type { Page } from "@playwright/test";
import { test, expect } from "@playwright/test";

// Light and dark screenshots of the PATHOS 3.0 enterprise shell (M1):
// brand header, Help menu, help drawer, About, keyboard shortcuts, what's new,
// system status, Troubleshooting centre, error panel, regrouped sidebar,
// collapsed sidebar and the sign-in page. The signed-in e-mail is masked.
//
//   scripts/e2e.sh --reporter=line --config=screenshots.config.ts screenshots/shell.spec.ts
//   (PNG files: e2e/screenshots/out/shell/<name>-<theme>.png)

const OUT = "screenshots/out/shell";
mkdirSync(OUT, { recursive: true });

const themes = ["light", "dark"] as const;

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
  await page.screenshot({ path: `${OUT}/${name}-${theme}.png`, mask: (await email.count()) ? [email] : [] });
}

async function openHelpMenu(page: Page) {
  await page.getByRole("button", { name: "Help", exact: true }).click();
  await expect(page.getByRole("menu")).toBeVisible();
}

for (const theme of themes) {
  test.describe(`${theme} theme`, () => {
    test.beforeEach(async ({ page }) => setTheme(page, theme));

    test(`shell ${theme}`, async ({ page }) => {
      await page.goto("/");
      await expect(page.getByTestId("version-chip")).not.toHaveText("…");
      await expect(page.getByRole("heading", { level: 1 }).first()).toBeVisible();
      await shot(page, "01-shell-dashboard", theme);

      await openHelpMenu(page);
      await shot(page, "02-help-menu", theme);
      await page.keyboard.press("Escape");

      await page.goto("/scans");
      await expect(page.getByRole("heading", { level: 1, name: "Scans" })).toBeVisible();
      await page.keyboard.press("F1");
      await expect(page.getByRole("dialog")).toBeVisible();
      await shot(page, "03-help-drawer", theme);
      await page.keyboard.press("Escape");

      await page.getByTestId("version-chip").click();
      await expect(page.getByRole("dialog", { name: "About PATHOS" })).toBeVisible();
      await shot(page, "04-about", theme);
      await page.keyboard.press("Escape");

      for (const [item, name, file] of [
        ["Keyboard shortcuts", "Keyboard shortcuts", "05-shortcuts"],
        [/What's new/, /What's new/, "06-whats-new"],
        ["System status", "System status", "07-system-status"],
      ] as const) {
        await openHelpMenu(page);
        await page.getByRole("menuitem", { name: item }).click();
        await expect(page.getByRole("dialog", { name })).toBeVisible();
        await page.waitForTimeout(300);
        await shot(page, file, theme);
        await page.keyboard.press("Escape");
      }

      await page.goto("/help/troubleshooting");
      await expect(page.getByRole("heading", { level: 1, name: "Troubleshooting centre" })).toBeVisible();
      await page.locator("details summary").first().click().catch(() => undefined);
      await shot(page, "08-troubleshooting-centre", theme);

      await page.goto("/help");
      await expect(page.getByRole("heading", { level: 1, name: "Help Center" })).toBeVisible();
      await shot(page, "09-help-centre", theme);

      // An error panel: a scan execution that does not exist.
      await page.goto("/scans/00000000-0000-7000-8000-000000000000");
      await page.waitForTimeout(1500);
      await shot(page, "10-error-panel", theme);

      await page.goto("/");
      await page.getByRole("button", { name: "Collapse navigation" }).click();
      await shot(page, "11-sidebar-collapsed", theme);
      await page.getByRole("button", { name: "Expand navigation" }).click();
    });

    test(`sign-in ${theme}`, async ({ browser }) => {
      const ctx = await browser.newContext({ storageState: { cookies: [], origins: [] }, ignoreHTTPSErrors: true, colorScheme: theme, viewport: { width: 1440, height: 900 } });
      const page = await ctx.newPage();
      await setTheme(page, theme);
      await page.goto("/login");
      await expect(page.getByRole("link", { name: "Sign in" })).toBeVisible();
      await page.waitForTimeout(500);
      await page.screenshot({ path: `${OUT}/12-sign-in-${theme}.png` });
      await ctx.close();
    });
  });
}
