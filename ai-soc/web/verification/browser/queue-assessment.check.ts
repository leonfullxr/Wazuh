import { expect, test } from "@playwright/test";
import AxeBuilder from "@axe-core/playwright";

test.beforeEach(async ({ page }) => {
    await page.addInitScript(() => localStorage.setItem("ai-soc-language", "en"));
});

test("a queue group shows its synthetic AI assessment", async ({ page }) => {
    await page.goto("/#queue");
    // The assessment verdict lives in the detail panel; the row shows score, SLA and status.
    const row = page.getByRole("row", { name: /Repeated SSH authentication failures/ });
    await row.getByRole("button", { name: "Repeated SSH authentication failures" }).click();
    const drawer = page.locator(".queue-pp-detail");
    await expect(drawer.getByRole("heading", { name: "AI assessment" })).toBeVisible();
    await expect(drawer.getByText("Workspace data is unavailable")).toHaveCount(0);
    await expect(drawer.getByText("Likely malicious")).toBeVisible();
    await expect(drawer.getByRole("link", { name: "Development scorecard" })).toHaveAttribute(
        "href",
        "#ai_quality",
    );
    await expect(
        drawer.getByText(
            "Repeated authentication failures from one source reached the failure threshold on web-01.",
        ),
    ).toBeVisible();
    await drawer.getByText("Rule 5712 · web-01 · 203.0.113.8").first().click();
    await expect(drawer.getByText("203.0.113.8").first()).toBeVisible();
    await expect(drawer.getByText(/^ev1_ab/).first()).toBeVisible();
    await drawer.getByRole("button", { name: "Save review" }).click();
    await expect(drawer.getByText("Review saved")).toBeVisible();
    const violations = await new AxeBuilder({ page }).analyze();
    expect(
        violations.violations.map((item) => ({
            id: item.id,
            targets: item.nodes.flatMap((node) => node.target),
        })),
    ).toEqual([]);
});

test("a failed assessment stays in the assessment section", async ({ page }) => {
    await page.goto("/?scenario=workspace_assessment_error#queue");
    await page.getByRole("button", { name: "Repeated SSH authentication failures" }).click();
    const drawer = page.locator(".queue-pp-detail");
    await expect(
        drawer.getByRole("heading", { name: "AI assessment is unavailable" }),
    ).toBeVisible();
    await expect(drawer.getByText("Assessment is unavailable.")).toBeVisible();
    await expect(drawer.getByText("Workspace data is unavailable")).toHaveCount(0);
    await expect(drawer.getByRole("heading", { name: "Triage" })).toBeVisible();
    await expect(drawer.getByRole("button", { name: "Retry" })).toBeVisible();
});
