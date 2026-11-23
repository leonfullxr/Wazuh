import { expect, test } from "@playwright/test";

test("saving a disposition paints the tag on the queue row", async ({ page }) => {
    await page.addInitScript(() => localStorage.setItem("ai-soc-language", "en"));
    await page.goto("/#queue");
    const row = page.getByRole("row", { name: /Repeated SSH authentication failures/ });
    await expect(row.getByText("False positive")).toHaveCount(0);
    await row.getByRole("button", { name: "Repeated SSH authentication failures" }).click();
    const drawer = page.locator(".queue-pp-detail");
    await drawer.getByRole("button", { name: "False positive", exact: true }).click();
    await drawer.getByRole("combobox", { name: "Reason" }).selectOption("test_activity");
    const saved = page.waitForResponse(
        (response) => response.request().method() === "POST" && response.url().includes("/disposition"),
    );
    await drawer.getByRole("button", { name: "Record disposition" }).click();
    await saved;
    await expect
        .poll(() =>
            page.evaluate(() => {
                const match = [...document.querySelectorAll("tr")].find((candidate) =>
                    /Repeated SSH authentication failures/.test(candidate.textContent ?? ""),
                );
                return match?.textContent?.includes("False positive") ?? false;
            }),
        )
        .toBe(true);
    await page.keyboard.press("Escape");
    await expect(row.getByText("False positive")).toBeVisible();
});
