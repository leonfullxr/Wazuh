import { expect, test } from "@playwright/test";

test("a false-positive note is not a second Reason field", async ({ page }) => {
    await page.addInitScript(() => localStorage.setItem("ai-soc-language", "en"));
    await page.goto("/#queue");
    await page.getByRole("button", { name: "Repeated SSH authentication failures" }).click();
    const drawer = page.getByRole("dialog");
    await drawer.getByRole("combobox", { name: "Label" }).selectOption("false_positive");
    await expect(drawer.getByRole("combobox", { name: "Reason" })).toHaveCount(1);
    await expect(drawer.getByRole("textbox", { name: "Analyst note" })).toBeVisible();
});
