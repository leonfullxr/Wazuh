import { expect, test } from "@playwright/test";

test("a narrow heatmap marks the hours that continue off-screen", async ({ page }) => {
    await page.addInitScript(() => localStorage.setItem("ai-soc-language", "en"));
    await page.setViewportSize({ width: 390, height: 844 });
    await page.goto("/#overview");
    const scroll = page.locator(".overview-v2-heatmap-scroll");
    await expect(scroll).toBeVisible();
    await expect(scroll).toHaveAttribute("data-overflow", "more");
    await scroll.evaluate((element) => {
        element.scrollLeft = element.scrollWidth;
    });
    await expect(scroll).not.toHaveAttribute("data-overflow", "more");
    await page.setViewportSize({ width: 1600, height: 900 });
    await expect
        .poll(() => scroll.evaluate((element) => element.scrollWidth <= element.clientWidth + 1))
        .toBe(true);
    await expect(scroll).not.toHaveAttribute("data-overflow", "more");
});
