import { test as base, expect } from "@playwright/test";

// Every test fails on uncaught page errors or Content-Security-Policy
// violations, so a broken page or a too-strict header cannot slip through.
export const test = base.extend<{ problems: string[] }>({
  problems: [
    async ({ page }, use) => {
      const problems: string[] = [];
      page.on("pageerror", (e) => problems.push(`pageerror: ${e.message}`));
      page.on("console", (m) => {
        if (m.type() === "error" && /Content Security Policy|Refused to/i.test(m.text())) problems.push(m.text());
      });
      await use(problems);
      expect(problems, "page errors / CSP violations").toEqual([]);
    },
    { auto: true },
  ],
});
export { expect };
