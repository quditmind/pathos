import { mkdirSync } from "node:fs";
import type { Page } from "@playwright/test";
import { test, expect } from "@playwright/test";

// Light and dark screenshots of the M6 screens: Scan profiles with the tier
// profiles and the kinds-of-check panel, Scan coverage with the kinds of
// check, Findings and Scans. The signed-in e-mail is masked.
//
//   scripts/e2e.sh --reporter=line --config=screenshots.config.ts screenshots/scan-profiles-m6.spec.ts
//   (PNG files: e2e/screenshots/out/m6/<name>-<theme>.png)

const OUT = "screenshots/out/m6";
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

async function setTiers(page: Page, on: boolean) {
  const me = await (await page.request.get("/api/v1/me")).json();
  await page.request.fetch("/api/v1/admin/feature-flags", {
    method: "PUT",
    headers: { "X-CSRF-Token": me.csrf_token, "Content-Type": "application/json" },
    data: JSON.stringify({ flags: { scan_profile_tiers: on } }),
  });
}

for (const theme of themes) {
  test(`M6 screens (${theme})`, async ({ page }) => {
    await setTheme(page, theme);
    await page.goto("/");
    await setTiers(page, true);
    try {
      await page.goto("/configurations/scan-profiles");
      await expect(page.getByText("Comprehensive", { exact: true }).first()).toBeVisible();
      await page.waitForLoadState("networkidle");
      await shot(page, "scan-profiles", theme);
      await page.getByText("Standard", { exact: true }).first().click();
      await expect(page.getByTestId("profile-kinds")).toBeVisible();
      await shot(page, "scan-profile-kinds", theme);
      await page.keyboard.press("Escape");
    } finally {
      await setTiers(page, false);
    }
    await page.goto("/configurations/scan-coverage");
    await expect(page.getByRole("heading", { name: "Kinds of check" })).toBeVisible();
    await page.getByRole("button", { name: "Infrastructure as code tools" }).click();
    await shot(page, "scan-coverage-kinds", theme);
    for (const [path, name] of [["/findings", "findings"], ["/scans", "scans"]] as const) {
      await page.goto(path);
      await page.waitForLoadState("networkidle");
      await shot(page, name, theme);
    }
  });
}
