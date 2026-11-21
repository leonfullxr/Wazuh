import { expect, test } from "@playwright/test";
import AxeBuilder from "@axe-core/playwright";

test.beforeEach(async ({ page }) => {
    await page.addInitScript(() => localStorage.setItem("ai-soc-language", "en"));
});

test("a queue group shows its synthetic AI assessment", async ({ page }) => {
    await page.goto("/#queue");
    const row = page.getByRole("row", { name: /Repeated SSH authentication failures/ });
    await expect(row).toContainText("Likely malicious");
    await row.getByRole("button", { name: "Repeated SSH authentication failures" }).click();
    const drawer = page.getByRole("dialog");
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
    await drawer.getByText("Evidence", { exact: true }).first().click();
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
    const drawer = page.getByRole("dialog");
    await expect(
        drawer.getByRole("heading", { name: "AI assessment is unavailable" }),
    ).toBeVisible();
    await expect(drawer.getByText("Assessment is unavailable.")).toBeVisible();
    await expect(drawer.getByText("Workspace data is unavailable")).toHaveCount(0);
    await expect(drawer.getByText("Alerts in group")).toBeVisible();
    await expect(drawer.getByRole("button", { name: "Retry" })).toBeVisible();
});
