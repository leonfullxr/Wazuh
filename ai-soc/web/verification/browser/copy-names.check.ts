import { expect, test } from "@playwright/test";

test("copy buttons name the value they copy", async ({ page }) => {
    await page.addInitScript(() => localStorage.setItem("ai-soc-language", "en"));
    await page.goto("/#status");
    const copies = page.getByRole("button", { name: /^Copy value,/ });
    await expect(copies.first()).toBeVisible();
    const count = await copies.count();
    expect(count).toBeGreaterThan(1);
    const names = await copies.evaluateAll((elements) =>
        elements.map((element) => element.getAttribute("aria-label")),
    );
    expect(names.every((name) => name && name !== "Copy value")).toBe(true);
    await page.context().grantPermissions(["clipboard-read", "clipboard-write"]);
    const first = page.locator("button.copy-value").first();
    await first.click();
    await expect(first).toHaveAccessibleName("Copied");
});
