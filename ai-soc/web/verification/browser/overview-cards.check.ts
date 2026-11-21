import { expect, test } from "@playwright/test";

test("ranked lists keep a card surface when the overview stacks", async ({ page }) => {
    await page.setViewportSize({ width: 768, height: 900 });
    await page.goto("/#overview");
    const list = page.locator(".overview-v2-context .overview-v2-list").first();
    await expect(list).toBeVisible();
    await expect
        .poll(() => list.evaluate((element) => getComputedStyle(element).backgroundColor))
        .not.toBe("rgba(0, 0, 0, 0)");
    await page.setViewportSize({ width: 1440, height: 900 });
    await expect
        .poll(() => list.evaluate((element) => getComputedStyle(element).backgroundColor))
        .toBe("rgba(0, 0, 0, 0)");
});
