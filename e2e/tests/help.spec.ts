import { test, expect } from "./fixtures";

test("Help (?) menu beside Notifications opens the Help Center", async ({ page }) => {
  await page.goto("/");
  // 3.0: Help is the (?) menu (a button), no longer a link.
  const help = page.getByRole("button", { name: "Help", exact: true });
  await expect(help).toBeVisible();
  // Directly after the notifications control in the top bar.
  const order = await page.locator("header a, header button").evaluateAll((els) => els.map((e) => e.getAttribute("aria-label") ?? e.textContent ?? ""));
  const i = order.findIndex((l) => /^Notifications/.test(l));
  expect(order[i + 1]).toBe("Help");
  await help.click();
  await page.getByRole("menuitem", { name: "Help centre" }).click();
  await expect(page.getByRole("heading", { name: "Help Center" })).toBeVisible();
  await expect(page.getByText(/Documentation version 1\.0/)).toBeVisible();
});

test("Help Center search, navigation, images and API reference", async ({ page }) => {
  await page.goto("/help?q=repository%20id");
  await expect(page.getByText(/results? for/)).toBeVisible();
  await page.getByRole("link", { name: "Repository management" }).first().click();
  await expect(page).toHaveURL(/\/help\/user-guide\/repository-management/);
  await expect(page.locator("article.help-prose h1")).toContainText(/Repository/);
  await expect(page.getByRole("navigation", { name: "On this page" })).toBeVisible();
  // Screenshots and diagrams load (no broken or missing images).
  await page.goto("/help/user-guide/repository-import");
  await expect(page.locator(".help-missing-image")).toHaveCount(0);
  const imgs = page.locator("article.help-prose img");
  expect(await imgs.count()).toBeGreaterThan(2);
  for (const img of await imgs.all()) {
    await img.scrollIntoViewIfNeeded();
    await expect.poll(() => img.evaluate((e: HTMLImageElement) => e.complete && e.naturalWidth > 0)).toBe(true);
  }
  // API reference renders tables and code.
  await page.getByRole("link", { name: "Imports" }).first().click().catch(() => page.goto("/help/api-reference/imports"));
  await page.goto("/help/api-reference/imports");
  await expect(page.locator("article.help-prose table").first()).toBeVisible();
  await expect(page.locator("article.help-prose pre").first()).toBeVisible();
});

test("every Help Center page renders without missing images or broken internal links", async ({ page }) => {
  await page.goto("/help");
  const links = await page.locator('nav[aria-label="Help topics"] a').evaluateAll((as) => as.map((a) => a.getAttribute("href")!));
  expect(links.length).toBeGreaterThanOrEqual(17);
  for (const href of links) {
    await page.goto(href);
    await expect(page.locator("article.help-prose h1"), href).toBeVisible();
    await expect(page.locator(".help-missing-image"), href).toHaveCount(0);
    const internal = await page.locator("article.help-prose a[data-help-link]").evaluateAll((as) => as.map((a) => a.getAttribute("href")!));
    for (const l of internal) {
      const [path] = l.split("#");
      expect(links.includes(path!), `${href} links to unknown page ${l}`).toBe(true);
    }
  }
});
