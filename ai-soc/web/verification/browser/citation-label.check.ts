import { expect, test } from "@playwright/test";

test("an assessment citation names the rule instead of the raw evidence id", async ({ page }) => {
    await page.addInitScript(() => localStorage.setItem("ai-soc-language", "en"));
    await page.goto("/#queue");
    await page.getByRole("button", { name: "Repeated SSH authentication failures" }).click();
    const drawer = page.locator(".queue-pp-detail");
    const citation = drawer.getByText("Rule 5712 · web-01 · 203.0.113.8").first();
    await expect(citation).toBeVisible();
    await citation.click();
    await expect(drawer.getByText("203.0.113.8").first()).toBeVisible();
    const shownId = await drawer.locator(".assessment-evidence-id").first().innerText();
    expect(shownId.startsWith("ev1_")).toBe(true);
    expect(shownId.length).toBeLessThan(20);
    expect(await drawer.locator(".assessment-evidence-id").first().getAttribute("title")).toMatch(
        /^ev1_[0-9a-f]{64}$/,
    );
});
