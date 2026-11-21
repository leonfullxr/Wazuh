import { expect, test } from "@playwright/test";

test("an unreported dashboard is one index, not a wall of empty cards", async ({ page }) => {
    await page.addInitScript(() => localStorage.setItem("ai-soc-language", "en"));
    await page.setViewportSize({ width: 1440, height: 900 });
    await page.goto("/#ai_quality");
    await expect(page.getByRole("heading", { name: "No data yet" })).toBeVisible();
    await expect(page.getByRole("heading", { name: "Quality summary" })).toBeVisible();
    await expect(page.getByRole("heading", { name: "Answer outcomes per day" })).toBeVisible();
    await expect(page.locator(".dashboard-v2-widget")).toHaveCount(0);
    await page.setViewportSize({ width: 390, height: 844 });
    await expect(page.getByRole("heading", { name: "No data yet" })).toBeVisible();
    expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBe(
        true,
    );
});
