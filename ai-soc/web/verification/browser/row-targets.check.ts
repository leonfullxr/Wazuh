import { expect, test } from "@playwright/test";

test.beforeEach(async ({ page }) => {
    await page.addInitScript(() => localStorage.setItem("ai-soc-language", "en"));
});

test("the queue row identity opens the group", async ({ page }) => {
    await page.goto("/#queue");
    const openGroup = page.getByRole("button", { name: /Repeated SSH authentication failures/ });
    const box = await openGroup.boundingBox();
    expect(box?.height ?? 0).toBeGreaterThanOrEqual(44);
    await openGroup.getByText("web-01").click();
    await expect(page.getByRole("dialog").getByText("group-auth-001").first()).toBeVisible();
});

test("queue row identity stays a 44px target on a phone", async ({ page }) => {
    await page.setViewportSize({ width: 390, height: 844 });
    await page.goto("/#queue");
    const openGroup = page.getByRole("button", { name: /Repeated SSH authentication failures/ });
    const box = await openGroup.boundingBox();
    expect(box?.height ?? 0).toBeGreaterThanOrEqual(44);
    expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBe(
        true,
    );
});

test("alert evidence and asset edit controls meet the 24px target", async ({ page }) => {
    await page.goto("/#alerts");
    const evidence = page.getByRole("button", { name: "Evidence details" }).first();
    const evidenceBox = await evidence.boundingBox();
    expect(evidenceBox?.height ?? 0).toBeGreaterThanOrEqual(24);
    await page.goto("/#metrics");
    const edit = page.getByRole("button", { name: "Edit tags" }).first();
    await edit.scrollIntoViewIfNeeded();
    const editBox = await edit.boundingBox();
    expect(editBox?.height ?? 0).toBeGreaterThanOrEqual(24);
    await edit.click();
    await expect(page.getByRole("heading", { name: "web-01" })).toBeVisible();
});
