import { defineConfig } from "@playwright/test";

// Runs against a live stack (default https://localhost with Caddy's local CA).
export default defineConfig({
  testDir: "./tests",
  timeout: 45_000,
  expect: { timeout: 10_000 },
  fullyParallel: false,
  workers: 1,
  retries: process.env.CI ? 1 : 0,
  reporter: [["list"], ["html", { open: "never", outputFolder: "playwright-report" }]],
  globalSetup: "./global-setup.ts",
  use: {
    baseURL: process.env.PATHOS_URL ?? "https://localhost",
    ignoreHTTPSErrors: true,
    viewport: { width: 1440, height: 900 },
    storageState: ".auth/admin.json",
    trace: "retain-on-failure",
    screenshot: "only-on-failure",
  },
});
