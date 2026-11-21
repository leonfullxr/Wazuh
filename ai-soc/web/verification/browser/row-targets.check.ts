import { expect, test } from "@playwright/test";

test.beforeEach(async ({ page }) => {
    await page.addInitScript(() => localStorage.setItem("ai-soc-language", "en"));
});

test("the queue row identity opens the group", async ({ page }) => {
    await page.goto("/#queue");
    const openGroup = page.getByRole("button", { name: /Repeated SSH authentication failures/ });
    await expect(openGroup).toBeVisible();
    await expect
        .poll(async () => (await openGroup.boundingBox())?.height ?? 0)
        .toBeGreaterThanOrEqual(44);
    await openGroup.getByText("web-01").click();
    await expect(page.getByRole("dialog").getByText("group-auth-001").first()).toBeVisible();
});

test("queue row identity stays a 44px target on a phone", async ({ page }) => {
    await page.setViewportSize({ width: 390, height: 844 });
    await page.goto("/#queue");
    const openGroup = page.getByRole("button", { name: /Repeated SSH authentication failures/ });
    await expect(openGroup).toBeVisible();
    await openGroup.scrollIntoViewIfNeeded();
    await expect
        .poll(async () => (await openGroup.boundingBox())?.height ?? 0)
        .toBeGreaterThanOrEqual(44);
    await openGroup.getByText("web-01").click();
    await expect(page.getByRole("dialog").getByText("group-auth-001").first()).toBeVisible();
    expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBe(
        true,
    );
});

test("alert evidence and asset edit controls meet the 24px target", async ({ page }) => {
    await page.goto("/#alerts");
    const evidence = page.getByRole("button", { name: "Evidence details" }).first();
    await expect(evidence).toBeVisible();
    await expect
        .poll(async () => (await evidence.boundingBox())?.height ?? 0)
        .toBeGreaterThanOrEqual(24);
    await page.goto("/#metrics");
    const edit = page.getByRole("button", { name: "Edit tags" }).first();
    await expect(edit).toBeVisible();
    await expect
        .poll(async () => {
            try {
                await edit.scrollIntoViewIfNeeded();
                return (await edit.boundingBox())?.height ?? 0;
            } catch {
                return 0;
            }
        })
        .toBeGreaterThanOrEqual(24);
    await edit.click();
    await expect(page.getByRole("heading", { name: "web-01" })).toBeVisible();
});
