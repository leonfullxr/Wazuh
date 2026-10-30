import { expect, test, type Page } from "@playwright/test";

const csp =
    "default-src 'self'; script-src 'self'; style-src 'self'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'";

const consoleErrors = new WeakMap<Page, string[]>();

test.beforeEach(async ({ page }) => {
    const violations: string[] = [];
    consoleErrors.set(page, violations);
    page.on("console", (message) => {
        if (
            message.type() === "error" &&
            /content security policy|violat(e|ion)/i.test(message.text())
        ) {
            violations.push(message.text());
        }
    });
    page.on("pageerror", (error) => {
        if (/content security policy|violat(e|ion)/i.test(error.message))
            violations.push(error.message);
    });
    await page.addInitScript(() => {
        const storageKey = "csp-violations";
        window.addEventListener("securitypolicyviolation", (event) => {
            const existing = JSON.parse(sessionStorage.getItem(storageKey) ?? "[]") as string[];
            existing.push(`${event.violatedDirective}: ${event.blockedURI}`);
            sessionStorage.setItem(storageKey, JSON.stringify(existing));
        });
        sessionStorage.removeItem(storageKey);
    });
    const response = await page.goto("/?scenario=answered#investigate");
    expect(response?.headers()["content-security-policy"]).toBe(csp);
    await expect(page.getByRole("textbox", { name: "Question" })).toBeVisible();
});

test.afterEach(async ({ page }) => {
    expect(
        await page.evaluate(
            () => JSON.parse(sessionStorage.getItem("csp-violations") ?? "[]") as string[],
        ),
    ).toEqual([]);
    expect(consoleErrors.get(page)).toEqual([]);
});

async function ask(page: Page, question: string) {
    await page.getByRole("textbox", { name: "Question" }).fill(question);
    await page.getByRole("button", { name: "Ask" }).click();
}

test("CSP permits answered, drawer, feedback, and all four screens in both locales", async ({
    page,
}) => {
    await ask(page, "LDAP review");
    await expect(page.locator(".answer-summary")).toBeVisible();
    await page
        .getByRole("button", { name: /Open evidence/ })
        .first()
        .click();
    await expect(page.locator(".evidence-drawer")).toBeVisible();
    await page.keyboard.press("Escape");
    await page.getByRole("button", { name: "Report this answer as wrong" }).click();
    await expect(page.getByText(/queued/)).toBeVisible();
    for (const name of ["Question history", "Question topics", "Service status", "Investigate"]) {
        await page.getByRole("link", { name, exact: true }).click();
        await expect(page.getByRole("heading", { level: 1 })).toBeVisible();
    }
    await page.getByLabel("Language").selectOption("es");
    for (const name of ["Historial de preguntas", "Temas de preguntas", "Estado del servicio", "Investigar"]) {
        await page.getByRole("link", { name, exact: true }).click();
        await expect(page.getByRole("heading", { level: 1 })).toBeVisible();
    }
});

test("CSP permits partial continuation and paging flows", async ({ page }) => {
    await page.goto("/?scenario=partial#investigate");
    await ask(page, "Investigate LDAP, authentication review and vulnerability review.");
    await expect(page.locator(".leftout")).toBeVisible();
    await page.locator(".leftout input[type=checkbox]").first().check();
    await page.getByRole("button", { name: "Continue selected" }).click();
    await expect(page.locator(".answer-summary")).toBeVisible();
    await page.goto("/?scenario=paged#investigate");
    await ask(page, "LDAP review");
    await page.getByRole("button", { name: "Load more" }).first().click();
    await page.getByRole("button", { name: "Load more" }).first().click();
    await page.getByRole("button", { name: "Load more" }).first().click();
    await expect(page.getByText(/results expired|Page 2|CURSOR_EXPIRED/i)).toBeVisible();
});
