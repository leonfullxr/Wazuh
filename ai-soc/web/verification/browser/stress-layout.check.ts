import { expect, test } from "@playwright/test";

const host = "web-01.edge.authentication.cluster.prod.soc.example.invalid";

test("long names and huge counts stay inside the viewport", async ({ page }) => {
    await page.addInitScript(() => localStorage.setItem("ai-soc-language", "en"));
    for (const width of [390, 1280]) {
        await page.setViewportSize({ width, height: 900 });
        for (const route of ["overview", "alerts", "queue", "metrics"]) {
            await page.goto(`/?scenario=workspace_stress#${route}`);
            await expect(page.getByRole("heading", { level: 1 })).toBeVisible();
            await expect(page.locator("body")).toContainText(host);
            const fits = await page.evaluate(
                () => document.documentElement.scrollWidth <= window.innerWidth,
            );
            expect(fits, `${width}px ${route}`).toBe(true);
        }
    }
    await expect(page.getByText(/12.345.678|12,345,678/).first()).toBeVisible();
});
