import { expect, test } from "@playwright/test";

test.beforeEach(async ({ page }) => {
    await page.addInitScript(() => localStorage.setItem("ai-soc-language", "en"));
});

test("queue false-positive reasons and the duplicate tag use analyst labels", async ({ page }) => {
    await page.goto("/#queue");
    await page.getByRole("button", { name: "Repeated SSH authentication failures" }).click();
    const drawer = page.locator(".queue-pp-detail");
    await drawer.getByRole("button", { name: "False positive", exact: true }).click();
    const reason = drawer.getByRole("combobox", { name: "Reason" });
    await expect(reason.locator("option")).toHaveText([
        "Choose a reason",
        "Expected administrator activity",
        "Known scanner",
        "Misconfigured rule",
        "Test activity",
        "Other",
    ]);
    await reason.selectOption("test_activity");
    const saved = page.waitForResponse(
        (response) => response.url().includes("/v1/workspace/queue") && response.ok(),
    );
    await drawer.getByRole("button", { name: "Record disposition" }).click();
    const payload: { items: { group: { disposition: { label: string } | null } }[] } = await (
        await saved
    ).json();
    expect(payload.items[0]?.group.disposition?.label).toBe("false_positive");
    const savedTag = drawer.locator(".queue-pp-panel-ids");
    await expect(savedTag).toContainText("False positive");

    await drawer.getByRole("button", { name: "Duplicate", exact: true }).click();
    const savedDuplicate = page.waitForResponse(
        (response) => response.url().includes("/v1/workspace/queue") && response.ok(),
    );
    await drawer.getByRole("button", { name: "Record disposition" }).click();
    const duplicatePayload: { items: { group: { disposition: { label: string } | null } }[] } =
        await (await savedDuplicate).json();
    expect(duplicatePayload.items[0]?.group.disposition?.label).toBe("duplicate");
    await expect(savedTag).toContainText("Duplicate");
    await expect(savedTag).not.toContainText("Disposition");
});
