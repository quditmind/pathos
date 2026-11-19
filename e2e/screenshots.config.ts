import { defineConfig } from "@playwright/test";
import base from "./playwright.config";

// shell.spec.ts captures the 3.0 shell in light and dark (it sets the colour
// scheme itself); run it alone by passing its path.
//
// Captures the Help Center screenshots (docs/user-guide/images) from the
// running stack with the same sign-in and session as the end-to-end tests:
// light theme, 1440×900. PNGs are written to screenshots/out/ (only e2e/ is
// mounted in the Playwright container); copy them into
// docs/user-guide/images afterwards.
//
//   scripts/e2e.sh --reporter=line --config=screenshots.config.ts
export default defineConfig({
  ...base,
  testDir: "./screenshots",
  timeout: 600_000,
  retries: 0,
  reporter: [["line"]],
  use: {
    ...base.use,
    viewport: { width: 1440, height: 900 },
    colorScheme: "light",
    trace: "off",
    screenshot: "off",
  },
});
