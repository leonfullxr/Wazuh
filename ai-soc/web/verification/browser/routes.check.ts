import { expect, test } from "@playwright/test";
import AxeBuilder from "@axe-core/playwright";

for (const route of [
    "overview",
    "alerts",
    "queue",
    "chains",
    "incidents",
    "metrics",
    "investigate",
    "history",
    "topics",
    "status",
    "ai_quality",
    "soc_operations",
]) {
    for (const mode of ["light", "dark"]) {
        test(`${route} ${mode} accessibility`, async ({ page }) => {
            await page.emulateMedia({ reducedMotion: "reduce" });
            await page.addInitScript((value) => localStorage.setItem("ai-soc-theme", value), mode);
            await page.goto(`/#${route}`);
            await expect(page.locator("main")).toBeVisible();
            const result = await new AxeBuilder({ page }).analyze();
            expect(
                result.violations.map((v) => ({
                    id: v.id,
                    targets: v.nodes.flatMap((n) => n.target),
                })),
            ).toEqual([]);
        });
    }
}

test("command palette searches within the selected site", async ({ page }) => {
    await page.goto("/");
    await expect(page.getByRole("button", { name: "Open search and navigation" })).toBeVisible();
    await page.keyboard.press("Control+k");
    const dialog = page.getByRole("dialog");
    await expect(dialog).toBeVisible();
    await dialog.getByLabel("Search", { exact: true }).fill("1234");
    await dialog.getByRole("option", { name: "Search Rule: 1234" }).click();
    await expect(page).toHaveURL(/rule_id=1234/);
    await expect(page).toHaveURL(/#alerts$/);
});

test("command keyboard controls restore focus and navigate", async ({ page }) => {
    await page.goto("/#overview");
    const trigger = page.getByRole("button", { name: "Open search and navigation" });
    await expect(trigger).toBeVisible();
    await trigger.focus();
    await page.keyboard.press("Control+k");
    const dialog = page.getByRole("dialog");
    await expect(dialog).toBeVisible();
    await page.keyboard.press("Escape");
    await expect(trigger).toBeFocused();
    await page.keyboard.press("Control+k");
    await dialog.getByRole("combobox").fill("Queue");
    await page.keyboard.press("Enter");
    await expect(page.getByRole("heading", { name: "Queue", level: 1 })).toBeVisible();
});

for (const route of [
    "overview",
    "alerts",
    "queue",
    "chains",
    "incidents",
    "metrics",
    "investigate",
    "history",
    "topics",
    "status",
    "ai_quality",
    "soc_operations",
]) {
    test(`${route} fits mobile viewport`, async ({ page }) => {
        await page.setViewportSize({ width: 375, height: 812 });
        await page.goto(`/#${route}`);
        await expect(page.locator("main")).toBeVisible();
        expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBe(
            true,
        );
    });
}

async function openWithKeyboard(
    page: import("@playwright/test").Page,
    opener: import("@playwright/test").Locator,
) {
    await expect(opener).toBeVisible();
    await opener.focus();
    await page.keyboard.press("Enter");
    const dialog = page.getByRole("dialog");
    await expect(dialog).toBeVisible();
    return dialog;
}

async function exerciseFocus(
    page: import("@playwright/test").Page,
    dialog: import("@playwright/test").Locator,
    names: [string, string],
) {
    await expect
        .poll(() => dialog.evaluate((el) => el.contains(document.activeElement)))
        .toBe(true);
    for (const key of ["Tab", "Shift+Tab"]) {
        const seen = new Set<string>();
        let start: import("@playwright/test").JSHandle | undefined;
        let moved = false;
        let wrapped = false;
        for (let i = 0; i < 120; i++) {
            await page.keyboard.press(key);
            expect(
                await dialog.evaluate((el) => el.contains(document.activeElement)),
                `${key} must stay in dialog`,
            ).toBe(true);
            const current = await page.evaluate(() => {
                const el = document.activeElement;
                if (!(el instanceof HTMLElement)) return "";
                return (
                    el.getAttribute("aria-label") ||
                    el.getAttribute("name") ||
                    el.textContent?.trim() ||
                    (el instanceof HTMLInputElement
                        ? el.closest("label")?.textContent?.trim()
                        : "") ||
                    el.tagName
                );
            });
            seen.add(current);
            if (!start) start = await page.evaluateHandle(() => document.activeElement);
            else if (await start.evaluate((el) => el === document.activeElement)) {
                if (moved) {
                    wrapped = true;
                    break;
                }
            } else moved = true;
        }
        await start?.dispose();
        for (const name of names)
            expect(
                [...seen].some((value) => value.includes(name)),
                `${key} visits ${name}`,
            ).toBe(true);
        expect(wrapped, `${key} completes a focus cycle`).toBe(true);
    }
}

async function dismissToOpener(
    page: import("@playwright/test").Page,
    dialog: import("@playwright/test").Locator,
    opener: import("@playwright/test").Locator,
) {
    await page.keyboard.press("Escape");
    await expect(dialog).toBeHidden();
    await expect(opener).toBeFocused();
}

test("Alerts evidence dialog contains keyboard focus and restores its opener", async ({ page }) => {
    await page.goto("/#alerts");
    const opener = page.getByRole("button", { name: "Evidence details" }).first();
    const dialog = await openWithKeyboard(page, opener);
    await exerciseFocus(page, dialog, ["Close", "Investigate"]);
    await dismissToOpener(page, dialog, opener);
});

test("Mobile navigation dialog contains keyboard focus and restores its opener", async ({
    page,
}) => {
    await page.setViewportSize({ width: 390, height: 844 });
    await page.goto("/#overview");
    const opener = page.getByRole("button", { name: "Open navigation" });
    const dialog = await openWithKeyboard(page, opener);
    await exerciseFocus(page, dialog, ["Close", "Queue"]);
    await dismissToOpener(page, dialog, opener);
});

test("Command palette contains keyboard focus and restores shortcut invoker", async ({ page }) => {
    await page.goto("/#overview");
    const opener = page.getByRole("button", { name: "Custom", exact: true });
    await opener.focus();
    await page.keyboard.press("Control+k");
    const dialog = page.getByRole("dialog");
    await expect(dialog).toBeVisible();
    await exerciseFocus(page, dialog, ["Search", "Close"]);
    await dismissToOpener(page, dialog, opener);
});

test("Custom range dialog contains keyboard focus and restores its opener", async ({ page }) => {
    await page.goto("/#overview");
    const opener = page.getByRole("button", { name: "Custom", exact: true });
    const dialog = await openWithKeyboard(page, opener);
    await exerciseFocus(page, dialog, ["From", "To"]);
    await dismissToOpener(page, dialog, opener);
});

async function openInvestigateEvidence(page: import("@playwright/test").Page) {
    await page.goto("/?scenario=answered#investigate");
    await page
        .getByRole("textbox", { name: "Question" })
        .fill("LDAP is not working. Recommend what to check next.");
    await page.getByRole("button", { name: "Ask" }).click();
    const opener = page.getByRole("button", { name: /Open evidence/ }).first();
    const dialog = await openWithKeyboard(page, opener);
    return { opener, dialog };
}

test("Investigate evidence dialog contains keyboard focus and restores its opener", async ({
    page,
}) => {
    const { opener, dialog } = await openInvestigateEvidence(page);
    await exerciseFocus(page, dialog, ["Close", "Copy"]);
    await dismissToOpener(page, dialog, opener);
});

test("Investigate evidence suppresses both command shortcuts", async ({ page }) => {
    const { opener, dialog } = await openInvestigateEvidence(page);
    for (const key of ["Control+k", "Meta+k"]) {
        await page.keyboard.press(key);
        await expect(page.getByRole("dialog")).toHaveCount(1);
        await expect(dialog).toBeVisible();
        await expect
            .poll(() => dialog.evaluate((el) => el.contains(document.activeElement)))
            .toBe(true);
    }
    await dismissToOpener(page, dialog, opener);
});
