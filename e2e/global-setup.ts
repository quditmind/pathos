import { chromium, type FullConfig } from "@playwright/test";
import { mkdirSync } from "node:fs";

// Signs in once as the bootstrap administrator and stores the session.
// Handles the forced password change of a fresh install (same rule as
// scripts/smoke-test.py: E2E_NEW_PASSWORD).
export default async function globalSetup(config: FullConfig) {
  const { baseURL } = config.projects[0]!.use;
  const email = process.env.E2E_EMAIL;
  const passwords = [process.env.E2E_PASSWORD, process.env.E2E_NEW_PASSWORD].filter(Boolean) as string[];
  if (!email || !passwords.length) throw new Error("E2E_EMAIL and E2E_PASSWORD are required (scripts/e2e.sh sets them)");
  const browser = await chromium.launch();
  const page = await browser.newPage({ ignoreHTTPSErrors: true, baseURL });
  await page.goto("/");
  await page.getByRole("link", { name: "Sign in" }).click();
  for (const pw of passwords) {
    await page.fill("#username", email);
    await page.fill("#password", pw);
    await page.click("#kc-login");
    if (await page.locator("#password-new").isVisible({ timeout: 3000 }).catch(() => false)) {
      const next = process.env.E2E_NEW_PASSWORD ?? pw;
      await page.fill("#password-new", next);
      await page.fill("#password-confirm", next);
      await page.click("input[type=submit], button[type=submit]");
    }
    if (await page.getByText("Security posture").isVisible({ timeout: 10_000 }).catch(() => false)) break;
  }
  await page.getByText("Security posture").waitFor();
  mkdirSync(".auth", { recursive: true });
  await page.context().storageState({ path: ".auth/admin.json" });
  await browser.close();
}
