import { expect, test, type Locator } from "@playwright/test";

const host = "web-01.edge.authentication.cluster.prod.soc.example.invalid";
const rule = "Repeated SSH authentication failures from one external source continued past the host lockout threshold and were correlated with a privileged session on the same agent.";
const tags = "internet-facing, production, pci, crown-jewel, linux, ssh, dmz, monitored, tier-0, patch-lag, customer-facing, soar-owned";
const count = "12,345,678";

test.use({ locale: "en-US" });

async function textFits(locator: Locator, container: Locator, text: string, singleLine = false) {
    await expect(locator).toBeVisible();
    const result = await locator.evaluate((element, value) => {
        const walker = document.createTreeWalker(element, NodeFilter.SHOW_TEXT);
        let node: Node | null;
        while ((node = walker.nextNode())) {
            const offset = node.textContent?.indexOf(value) ?? -1;
            if (offset < 0) continue;
            const range = document.createRange();
            range.setStart(node, offset);
            range.setEnd(node, offset + value.length);
            return Array.from(range.getClientRects(), ({ left, right, top, bottom }) => ({ left, right, top, bottom }));
        }
        return [];
    }, text);
    const box = await container.boundingBox();
    expect(box).not.toBeNull();
    expect(result.length, `text rectangles for ${text}`).toBeGreaterThan(0);
    if (singleLine) expect(result.length, `${text} must occupy one line`).toBe(1);
    for (const rect of result) {
        expect(rect.left, `${text} left edge`).toBeGreaterThanOrEqual(box!.x - 1);
        expect(rect.right, `${text} right edge`).toBeLessThanOrEqual(box!.x + box!.width + 1);
        expect(rect.top, `${text} top edge`).toBeGreaterThanOrEqual(box!.y - 1);
        expect(rect.bottom, `${text} bottom edge`).toBeLessThanOrEqual(box!.y + box!.height + 1);
    }
}

for (const viewport of [{ width: 390, height: 844 }, { width: 1280, height: 900 }]) {
    for (const route of ["overview", "alerts", "queue", "metrics"] as const) {
        test(`${route} stressed layout at ${viewport.width}x${viewport.height}`, async ({ page }) => {
            await page.setViewportSize(viewport);
            await page.addInitScript(() => localStorage.setItem("ai-soc-language", "en"));
            await page.goto(`/?scenario=workspace_stress#${route}`);
            await expect(page.getByRole("heading", { level: 1 })).toBeVisible();
            await page.evaluate(() => document.fonts.ready);
            if (route === "overview") {
                for (const value of [host, rule]) {
                    const label = page.getByText(value, { exact: true });
                    const button = label.locator("xpath=ancestor::button");
                    const row = label.locator("xpath=ancestor::li");
                    await textFits(label, button, value);
                    const countBox = await row.locator("strong").boundingBox();
                    const buttonBox = await button.boundingBox();
                    expect(buttonBox!.x + buttonBox!.width).toBeLessThanOrEqual(countBox!.x + 1);
                    await textFits(row.locator("strong"), row, count, true);
                }
                const summary = page.getByText(count, { exact: true }).first();
                await textFits(summary, summary.locator("xpath=.."), count, true);
            } else if (route === "alerts") {
                const row = page.locator(".alerts-v2 tbody tr").first();
                for (const value of [rule, host]) {
                    const cell = row.locator("td").filter({ hasText: value });
                    await textFits(cell, cell, value);
                }
            } else if (route === "queue") {
                const rows = page.locator(".queue-v2 tbody tr");
                const row = rows.first();
                const button = row.locator(".group-link");
                for (const value of [rule, host]) {
                    await textFits(button, button, value);
                    await textFits(button, button.locator("xpath=ancestor::td"), value);
                }
                for (const item of await rows.all()) {
                    const cell = item.locator("td").filter({ hasText: count });
                    await textFits(cell, cell, count, true);
                }
            } else {
                const row = page.locator(".metrics-v2-assets tbody tr").filter({ hasText: host });
                for (const value of [host, tags]) {
                    const cell = row.locator("td").filter({ hasText: value });
                    await textFits(cell, cell, value);
                }
                const backlog = page.locator(".metrics-v2-summary strong").filter({ hasText: count });
                await textFits(backlog, backlog.locator("xpath=.."), count, true);
                const volume = page.locator(".metrics-v2-volume tbody td.numeric");
                await expect(volume).toHaveCount(2);
                for (const cell of await volume.all()) await textFits(cell, cell, count, true);
                const total = page.locator(".metrics-v2-volume .metrics-v2-section-head span");
                await textFits(total, total, "24,691,356", true);
            }
            const dimensions = await page.evaluate(() => ({ scroll: document.documentElement.scrollWidth, client: document.documentElement.clientWidth }));
            expect(dimensions.scroll, "document scroll width").toBeLessThanOrEqual(dimensions.client);
        });
    }
}
