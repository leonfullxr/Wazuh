import { expect, test } from "@playwright/test";

test("a quiet site does not call an empty hour the peak", async ({ page }) => {
    await page.addInitScript(() => localStorage.setItem("ai-soc-language", "en"));
    await page.goto("/?scenario=workspace_quiet#overview");
    const heatmap = page.locator(".overview-v2-heatmap-panel");
    await expect(heatmap).toBeVisible();
    await expect(heatmap).toContainText("No alerts in the confirmed hours");
    await expect(heatmap).not.toContainText(/Peak total:.*0 alerts/);
    await expect(page.locator(".overview-v2-metric").first()).toContainText("0");
});
