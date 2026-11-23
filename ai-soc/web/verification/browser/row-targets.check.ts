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
    await expect(page.locator(".queue-pp-detail").getByRole("heading", { name: "Repeated SSH authentication failures" })).toBeVisible();
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
    await expect(page.locator(".queue-pp-detail").getByRole("heading", { name: "Repeated SSH authentication failures" })).toBeVisible();
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
    const edit = () => page.getByRole("button", { name: "Edit tags" }).first();
    await expect(edit()).toBeVisible();
    await expect
        .poll(async () => {
            const control = edit();
            try {
                await control.scrollIntoViewIfNeeded();
                return (await control.boundingBox())?.height ?? 0;
            } catch {
                return 0;
            }
        })
        .toBeGreaterThanOrEqual(24);
    await edit().click();
    await expect(page.getByRole("heading", { name: "web-01" })).toBeVisible();
});

test("site-scoped rows wait for the initial site selection", async ({ page }) => {
    const unscoped: string[] = [];
    page.on("request", (request) => {
        const url = new URL(request.url());
        if (
            ["/v1/workspace/queue", "/v1/workspace/assets"].includes(url.pathname) &&
            !url.searchParams.get("site_id")
        ) {
            unscoped.push(url.pathname);
        }
    });
    await page.goto("/?delay_bootstrap=1#queue");
    const row = page.getByRole("button", { name: /Repeated SSH authentication failures/ });
    await expect(row).toBeVisible();
    await expect(page).toHaveURL(/site_id=/);
    await page.goto("/?delay_bootstrap=1#metrics");
    await expect(page.getByRole("button", { name: "Edit tags" }).first()).toBeVisible();
    await expect(page).toHaveURL(/site_id=/);
    expect(unscoped).toEqual([]);
});
