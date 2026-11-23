import { expect, test } from "@playwright/test";

test("an unreported dashboard is one index, not a wall of empty cards", async ({ page }) => {
    await page.addInitScript(() => localStorage.setItem("ai-soc-language", "en"));
    await page.setViewportSize({ width: 1440, height: 900 });
    await page.goto("/?samples=off#ai_quality");
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

test("the verification build fills the quality dashboard with labelled sample values", async ({ page }) => {
    await page.addInitScript(() => localStorage.setItem("ai-soc-language", "en"));
    await page.goto("/#ai_quality");
    await expect(page.getByText(/^Sample values for layout review/)).toBeVisible();
    await expect(page.getByRole("heading", { name: "AI verdict vs analyst" })).toBeVisible();
    await page.setViewportSize({ width: 390, height: 844 });
    expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBe(true);
});

const dashboards = [
    {
        route: "ai_quality",
        description: "Answer quality and validation reporting. Panels remain empty until these measurements are reported.",
        count: 7,
    },
    {
        route: "soc_operations",
        description: "Triage flow and analyst workload reporting. Panels remain empty until these measurements are reported.",
        count: 6,
    },
];

for (const dashboard of dashboards) {
    for (const viewport of [
        { name: "desktop", width: 1440, height: 900 },
        { name: "mobile", width: 390, height: 844 },
    ]) {
        test(`${dashboard.route} empty index and Metrics link at ${viewport.name}`, async ({ page }) => {
            await page.addInitScript(() => localStorage.setItem("ai-soc-language", "en"));
            await page.setViewportSize(viewport);
            await page.goto(`/?samples=off#${dashboard.route}`);
            const index = page.locator(".dashboard-v2-index");
            await expect(index).toBeVisible();
            await expect(page.locator(".dashboard-v2 > .page-description")).toHaveText(dashboard.description);
            await expect(page.getByRole("heading", { name: "No data yet" })).toHaveCount(1);
            await expect(page.locator(".dashboard-v2-widget")).toHaveCount(0);
            const items = index.locator("li");
            await expect(items).toHaveCount(dashboard.count);
            if (dashboard.route === "ai_quality") {
                await expect(index.getByRole("heading", { name: "Quality summary" })).toBeVisible();
                await expect(index.getByRole("heading", { name: "Answer outcomes per day" })).toBeVisible();
            }
            for (const item of await items.all()) {
                const title = item.locator("h3");
                const explanation = item.locator("p");
                await expect(title).toBeVisible();
                await expect(title).not.toHaveText(/^\s*$/);
                await expect(explanation).toBeVisible();
                await expect(explanation).not.toHaveText(/^\s*$/);
            }
            const link = page.getByRole("link", { name: "Open Metrics" });
            await expect(link).toBeVisible();
            await expect(link).toHaveAttribute("href", "#metrics");
            if (viewport.name === "mobile") {
                expect(await page.evaluate(() => document.documentElement.scrollWidth <= document.documentElement.clientWidth)).toBe(true);
            }
            await link.click();
            await expect(page.getByRole("heading", { name: "Metrics", level: 1 })).toBeVisible();
        });
    }
}
