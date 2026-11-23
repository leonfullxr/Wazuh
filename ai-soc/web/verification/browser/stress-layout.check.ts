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
            const summary = page.locator(".summary-strip-value strong").filter({ hasText: count }).first();
            if (route === "overview") {
                const attention = page.locator(".overview-attention-row").first();
                await textFits(attention.locator(".overview-attention-title"), attention, rule);
                await textFits(attention.locator(".ent"), attention, host);
                for (const value of [rule, host]) {
                    const cell = page.locator(".pp-table td").filter({ hasText: value });
                    await textFits(cell, cell, value);
                    const row = cell.locator("xpath=..");
                    await textFits(row.locator("td.is-num, td:last-child").last(), row, count, true);
                }
                await textFits(summary, summary.locator("xpath=.."), count, true);
            } else if (route === "alerts") {
                const row = page.locator(".alerts-v2 tbody tr").first();
                for (const value of [rule, host]) {
                    const cell = row.locator("td").filter({ hasText: value });
                    await textFits(cell, cell, value);
                }
            } else if (route === "queue") {
                const rows = page.locator(".queue-pp-table tbody tr");
                await expect(rows.first()).toBeVisible();
                for (const row of await rows.all()) {
                    const cell = row.locator("td").filter({ has: page.locator(".queue-pp-group") });
                    for (const value of [rule, host]) await textFits(cell, cell, value);
                    const number = row.locator("td.is-num").filter({ hasText: count });
                    await textFits(number, number, count, true);
                }
            } else {
                const row = page.locator(".metrics-pp-assets tbody tr").filter({ hasText: host });
                const hostCell = row.locator("td").filter({ hasText: host });
                await textFits(hostCell, hostCell, host);
                expect((await hostCell.boundingBox())!.width, "host column keeps a readable width").toBeGreaterThan(120);
                const tagCell = row.locator("td").filter({ has: page.locator(".metrics-pp-tags") });
                for (const tag of tags.split(", ")) await textFits(tagCell, tagCell, tag, true);
                await textFits(summary, summary.locator("xpath=.."), count, true);
            }
            const dimensions = await page.evaluate(() => ({ scroll: document.documentElement.scrollWidth, client: document.documentElement.clientWidth }));
            expect(dimensions.scroll, "document scroll width").toBeLessThanOrEqual(dimensions.client);
        });
    }
}
