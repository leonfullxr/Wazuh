import { expect, test } from "@playwright/test";

const neutral = "rgb(244, 244, 242)";

async function background(page: import("@playwright/test").Page, text: string) {
    return page
        .locator(".alerts-v2 .tag", { hasText: text })
        .first()
        .evaluate((element) => getComputedStyle(element).backgroundColor);
}

test("alert levels use the severity fill instead of a gray pill", async ({ page }) => {
    await page.addInitScript(() => localStorage.setItem("ai-soc-language", "en"));
    await page.goto("/#alerts");
    expect(await background(page, "12")).not.toBe(neutral);
    expect(await background(page, "10")).not.toBe(neutral);
    await page.evaluate(() => document.documentElement.classList.add("dark"));
    const darkCritical = await background(page, "12");
    expect(darkCritical).not.toBe(neutral);
    expect(darkCritical).not.toBe("rgba(0, 0, 0, 0)");
});
