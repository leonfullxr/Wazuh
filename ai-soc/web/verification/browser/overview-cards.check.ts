import { expect, test } from "@playwright/test";

test("ranked tables keep a panel surface at every width", async ({ page }) => {
    await page.goto("/#overview");
    const table = page.locator(".overview-top").first();
    await expect(table).toBeVisible();
    for (const width of [768, 1440]) {
        await page.setViewportSize({ width, height: 900 });
        await expect
            .poll(() => table.evaluate((element) => getComputedStyle(element).backgroundColor))
            .not.toBe("rgba(0, 0, 0, 0)");
    }
});
