import { expect, test } from "@playwright/test";

test("the page title stays a console label, not display type", async ({ page }) => {
    await page.setViewportSize({ width: 1440, height: 900 });
    await page.goto("/#overview");
    const size = await page
        .getByRole("heading", { level: 1 })
        .evaluate((element) => Number.parseFloat(getComputedStyle(element).fontSize));
    expect(size).toBeGreaterThanOrEqual(24);
    expect(size).toBeLessThanOrEqual(28);
    await expect(page.getByRole("heading", { level: 1 })).toHaveText("Overview");
});
