import { expect, test } from "@playwright/test";
import AxeBuilder from "@axe-core/playwright";
import { partial } from "../mocks/fixtures";

async function ask(
    page: import("@playwright/test").Page,
    question: string,
    language: "en" | "es" = "en",
) {
    await page
        .getByRole("textbox", { name: language === "en" ? "Question" : "Pregunta" })
        .fill(question);
    await page.getByRole("button", { name: language === "en" ? "Ask" : "Preguntar" }).click();
    await expect(page.locator(".answer-summary")).toBeVisible();
}

async function assertAccessible(page: import("@playwright/test").Page) {
    expect((await new AxeBuilder({ page }).analyze()).violations).toEqual([]);
}

test("natural questions select captured single-topic and combined answer shapes", async ({
    page,
}) => {
    await page.goto("/?scenario=auto#investigate");
    await ask(page, "LDAP is not working. Recommend what to check next.");
    await expect(page.locator(".topic-section")).toHaveCount(1);
    await expect(page.locator(".topic-section").first()).toHaveAttribute("id", "topic-ldap");

    await ask(page, "Investigate authentication review.");
    await expect(page.locator(".topic-section")).toHaveCount(1);
    await expect(page.locator(".topic-section").first()).toHaveAttribute("id", "topic-auth_review");

    await ask(page, "Investigate vulnerability review.");
    await expect(page.locator(".topic-section")).toHaveCount(1);
    await expect(page.locator(".topic-section").first()).toHaveAttribute("id", "topic-vuln_review");

    await ask(page, "Investigate authentication review and vulnerability review.");
    await expect(page.locator(".topic-section")).toHaveCount(2);
    await expect(page.locator(".topic-section").nth(0)).toHaveAttribute("id", "topic-auth_review");
    await expect(page.locator(".topic-section").nth(1)).toHaveAttribute("id", "topic-vuln_review");

    await page.getByLabel("Language").selectOption("es");
    await ask(page, "Investiga revision de vulnerabilidades.", "es");
    await expect(page.locator(".topic-section")).toHaveCount(1);
    await expect(page.locator(".topic-section").first()).toHaveAttribute("id", "topic-vuln_review");

    await page.goto("/?scenario=partial#investigate");
    await ask(page, "LDAP is not working. Recommend what to check next.");
    await expect(page.locator(".topic-section")).toHaveCount(3);
    await expect(page.locator(".leftout")).toBeVisible();
});

test.beforeEach(async ({ page }) => {
    await page.addInitScript(() => localStorage.setItem("ai-soc-language", "en"));
});

test("Investigate answered, citation drawer, keyboard focus, and locale screenshots", async ({
    page,
}) => {
    await page.goto("/?scenario=answered#investigate");
    await ask(page, "LDAP is not working. Recommend what to check next.");
    await expect(
        page.getByRole("heading", { name: "Synthetic review guidance" }).first(),
    ).toBeVisible();
    await expect(page.locator(".answer-summary")).toContainText("Answer environment: synthetic");
    await expect(page.locator("#topic-auth_review .fetch-message")).toContainText(
        "Paging stopped:",
    );
    await expect(page.locator("#topic-auth_review .fetch-message")).toContainText(
        "Paging is unavailable because a stable three-part cursor boundary was not available.",
    );
    await expect(page.locator("#topic-ldap .eyebrow")).toHaveText("Topic 1");
    await expect(page.locator("#topic-ldap .topic-header code")).toHaveText("ldap");
    await expect(page.locator("#topic-ldap .judgment-meta")).toHaveText(
        "Model: synthetic-model / low",
    );
    await expect(page.locator("#topic-ldap .finding-kind")).toContainText("Observation");
    await expect(page.locator("#topic-ldap .finding-kind")).not.toContainText("[O]");
    await expect(page.locator("#topic-ldap .removed summary")).toHaveText(
        "1 finding removed by validation",
    );
    await expect(page.locator("#topic-auth_review .bucket-list caption")).toContainText(
        "Buckets, Completeness: Complete",
    );
    await expect(page.locator("#topic-auth_review .bucket-list th")).toHaveText(["Key", "Count"]);
    await expect(page.locator("#topic-auth_review .judgment-meta")).toHaveCount(0);
    await expect(page.locator("#topic-auth_review .topic-header code")).toHaveCount(1);
    const checkChip = page.locator("#topic-auth_review .checks .check-reference").first();
    await expect(checkChip).toContainText("check record (not included in the answer)");
    await expect(page.locator("#topic-auth_review .checks button.citation")).toHaveCount(0);
    const sortable = page.locator("#topic-auth_review th[aria-sort]").first();
    await expect(sortable).toHaveAttribute("aria-sort", /ascending|descending|none/);
    await expect(sortable.getByRole("button")).toBeVisible();
    await page.screenshot({
        path: "e2e/screenshots/mock/investigate-answered-en.png",
        fullPage: true,
    });
    await assertAccessible(page);
    const citation = page.getByRole("button", { name: /Open evidence/ }).first();
    await citation.focus();
    await page.keyboard.press("Enter");
    await expect(page.locator(".evidence-drawer")).toBeVisible();
    await page.screenshot({ path: "e2e/screenshots/mock/drawer-en.png" });
    await assertAccessible(page);
    await page.keyboard.press("Escape");
    await expect(page.locator(".evidence-drawer")).toHaveCount(0);
    await expect(citation).toBeFocused();
    await page.getByLabel("Language").selectOption("es");
    await expect(page.locator("#topic-ldap .eyebrow")).toHaveText("Tema 1");
    await page.screenshot({
        path: "e2e/screenshots/mock/investigate-answered-es.png",
        fullPage: true,
    });
    await page
        .getByRole("button", { name: /Abrir evidencia/ })
        .first()
        .click();
    await page.screenshot({ path: "e2e/screenshots/mock/drawer-es.png" });
    await assertAccessible(page);
});

test("single-topic natural routes keep captured ordinal, document, and table shape", async ({
    page,
}) => {
    const cases = [
        {
            question: "LDAP is not working",
            topic: "ldap",
            heading: "Synthetic LDAP setup example",
            ordinal: "Topic 1",
            fetch: "ldap_recent_alert_count",
            checks: 0,
        },
        {
            question: "Review authentication failures",
            topic: "auth_review",
            heading: "Authentication failure review",
            ordinal: "Topic 1",
            fetch: "auth_rows",
            checks: 5,
        },
        {
            question: "Review vulnerabilities",
            topic: "vuln_review",
            heading: "Vulnerability record review",
            ordinal: "Topic 1",
            fetch: "vuln_rows",
            checks: 3,
        },
    ];
    for (const scenario of cases) {
        await page.goto("/?scenario=auto#investigate");
        await ask(page, scenario.question);
        const block = page.locator(`#topic-${scenario.topic}`);
        await expect(block.locator(".eyebrow")).toHaveText(scenario.ordinal);
        await expect(block.locator(".topic-header h2")).toHaveText(scenario.heading);
        await expect(block.locator(".topic-header a")).toBeVisible();
        await expect(block.locator(".fetch-table")).toHaveCount(1);
        await expect(block.locator(".fetch-table summary")).toContainText(scenario.fetch);
        await expect(block.locator(".checks tbody tr")).toHaveCount(scenario.checks);
    }
});

test("reopening two answers from the same scenario restores each fresh identity", async ({
    page,
}) => {
    await page.goto("/?scenario=answered#investigate");
    await ask(page, "First LDAP review.");
    const firstId = await page.locator(".ids-row span:nth-child(2) code").textContent();
    await page.getByRole("textbox", { name: "Question" }).fill("Second LDAP review.");
    await page.getByRole("button", { name: "Ask" }).click();
    await expect(page.locator(".original-question")).toContainText("Second LDAP review.");
    const secondId = await page.locator(".ids-row span:nth-child(2) code").textContent();
    expect(firstId).not.toBe(secondId);
    await page.getByRole("link", { name: "Question history" }).click();
    await page.locator(".history-open").filter({ hasText: "First LDAP review." }).click();
    await expect(page.locator(".ids-row span:nth-child(2) code")).toHaveText(firstId!);
    await page.getByRole("link", { name: "Question history" }).click();
    await page.locator(".history-open").filter({ hasText: "Second LDAP review." }).click();
    await expect(page.locator(".ids-row span:nth-child(2) code")).toHaveText(secondId!);
});

test("composer edits and failed submissions never relabel the stored answer", async ({ page }) => {
    await page.goto("/?scenario=answered#investigate");
    await ask(page, "LDAP question A.");
    await page.getByRole("textbox", { name: "Question" }).fill("Unsubmitted question B.");
    await expect(page.locator(".original-question")).toContainText("LDAP question A.");
    await page.evaluate(() => {
        const url = new URL(location.href);
        url.searchParams.set("scenario", "audit_unavailable");
        history.replaceState(null, "", url);
    });
    await page.getByRole("button", { name: "Ask" }).click();
    await expect(page.getByRole("alert")).toContainText("AUDIT_UNAVAILABLE");
    await expect(page.locator(".original-question")).toContainText("LDAP question A.");
});

test("Investigate partial continues selected retryable topics", async ({ page }) => {
    await page.goto("/?scenario=partial#investigate");
    await ask(page, "Investigate LDAP, authentication review and vulnerability review.");
    await expect(page.getByText("Left out")).toBeVisible();
    await expect(
        page
            .locator(".leftout")
            .locator("xpath=preceding-sibling::section[contains(@class,'answer-summary')]"),
    ).toHaveCount(1);
    const checkReference = page.locator(".checks .check-reference").first();
    await expect(checkReference).toContainText("check record (not included in the answer)");
    await expect(page.locator(".checks button.citation")).toHaveCount(0);
    const deniedTable = page.locator("#topic-ldap .fetch-table").first();
    await expect(deniedTable.locator(".alert.warning")).toContainText("Synthetic read was denied.");
    await expect(deniedTable.locator(".fetch-message")).toContainText("Paging stopped:");
    const unavailableTable = page.locator("#topic-auth_review .fetch-table").first();
    await expect(unavailableTable.locator(".alert.warning")).toContainText(
        "Synthetic index service is unavailable.",
    );
    await expect(unavailableTable.locator(".fetch-message")).toContainText("Paging stopped:");
    const checkScroller = page.locator(".checks .table-scroll").first();
    expect(
        await checkScroller
            .locator("table")
            .evaluate(
                (table) =>
                    table.getBoundingClientRect().width <= table.parentElement!.clientWidth + 1,
            ),
    ).toBe(true);
    await page.setViewportSize({ width: 375, height: 900 });
    expect(
        await page.evaluate(
            () => document.documentElement.scrollWidth <= document.documentElement.clientWidth,
        ),
    ).toBe(true);
    expect(
        await checkScroller
            .locator("table")
            .evaluate(
                (table) =>
                    table.getBoundingClientRect().width <= table.parentElement!.clientWidth + 1,
            ),
    ).toBe(true);
    await page.setViewportSize({ width: 1280, height: 900 });
    await assertAccessible(page);
    await page.screenshot({
        path: "e2e/screenshots/mock/investigate-partial-en.png",
        fullPage: true,
    });
    await page.getByLabel("Language").selectOption("es");
    await page.screenshot({
        path: "e2e/screenshots/mock/investigate-partial-es.png",
        fullPage: true,
    });
    await page.getByLabel("Idioma").selectOption("en");
    await page.getByRole("checkbox").first().check();
    const firstContinuation = page.waitForRequest(
        (request) => request.url().endsWith("/v1/questions") && request.method() === "POST",
    );
    const firstChild = page.waitForResponse(
        (response) =>
            response.url().endsWith("/v1/questions") && response.request().method() === "POST",
    );
    await page.getByRole("button", { name: "Continue selected" }).click();
    const requestOne = await firstContinuation;
    expect(requestOne.postDataJSON()).toMatchObject({
        question: "continue the left-out judgments",
        continue_topic_ids: ["auth_review"],
        environment_id: "synthetic",
    });
    const childOne = await (await firstChild).json();
    expect(childOne).toMatchObject({ followup_revision: 1, status: "answered", left_out: [] });
    expect(childOne.followup_id).not.toBe(partial.followup_id);
    expect(childOne.blocks.map((block: { topic_id: string }) => block.topic_id)).toEqual([
        "auth_review",
    ]);
    expect(childOne.blocks[0].judgment.state).toMatch(/validated|no_findings/);
    await expect(page.locator(".leftout input[type=checkbox]")).toHaveCount(0);
    await expect(page.locator("#topic-auth_review")).toBeVisible();
    await expect(page.locator("#topic-vuln_review")).toHaveCount(0);
    await page.screenshot({
        path: "e2e/screenshots/mock/continuation-child-en.png",
        fullPage: true,
    });
    await expect(page.locator(".original-question button")).toContainText("Investigate LDAP");
    await page.locator(".original-question button").click();
    await expect(page.locator(".original-question")).toContainText("Investigate LDAP");
    await page.getByRole("link", { name: "Question history" }).click();
    await expect(page.locator(".history-child")).toHaveCount(1);
    await page.locator(".history-child .history-open").click();
    await expect(page.locator(".original-question button")).toBeVisible();
    await page.goto("/?scenario=partial#investigate");
    await page.getByLabel("Language").selectOption("es");
    await ask(page, "Investigar LDAP, revisión de autenticación y vulnerabilidades.", "es");
    await page.getByRole("checkbox").nth(1).check();
    await page.getByRole("button", { name: "Continuar selección" }).click();
    await expect(page.locator("#topic-vuln_review")).toBeVisible();
    await page.screenshot({
        path: "e2e/screenshots/mock/continuation-child-es.png",
        fullPage: true,
    });
    await assertAccessible(page);
});

test("history replays the exact continuation request and offers an explicit fallback on expiry", async ({
    page,
}) => {
    await page.goto("/?scenario=partial#investigate");
    await ask(page, "Investigate authentication review and vulnerability review.");
    await page.getByRole("checkbox").first().check();
    const continuationRequest = page.waitForRequest(
        (request) => request.url().endsWith("/v1/questions") && request.method() === "POST",
    );
    await page.getByRole("button", { name: "Continue selected" }).click();
    const originalContinuation = (await continuationRequest).postDataJSON();
    await expect(page.locator("#topic-auth_review")).toBeVisible();

    await page.getByRole("link", { name: "Question history" }).click();
    const childRow = page.locator(".history-child");
    const replayRequestPromise = page.waitForRequest(
        (request) => request.url().endsWith("/v1/questions") && request.method() === "POST",
    );
    await childRow.getByRole("button", { name: "Retry" }).click();
    const replayRequest = await replayRequestPromise;
    expect(replayRequest.postDataJSON()).toEqual(originalContinuation);
    await expect(page.locator("#topic-auth_review")).toBeVisible();
    await expect(page.getByText("Continued from:")).toBeVisible();
    await expect(page.getByTestId("continuation-topics")).toContainText("auth_review");

    await page.getByRole("link", { name: "Question history" }).click();
    await expect(page.locator(".history-child")).toHaveCount(2);
    await page.evaluate(() => {
        const url = new URL(location.href);
        url.searchParams.set("expire_followup", "1");
        history.replaceState(null, "", url);
    });
    const expiredReplayRequest = page.waitForRequest(
        (request) => request.url().endsWith("/v1/questions") && request.method() === "POST",
    );
    await page.locator(".history-child").first().getByRole("button", { name: "Retry" }).click();
    await expiredReplayRequest;
    await expect(page.getByRole("alert")).toContainText("continuation has expired");
    const separateRequest = page.waitForRequest(
        (request) => request.url().endsWith("/v1/questions") && request.method() === "POST",
    );
    const separateResponse = page.waitForResponse(
        (response) =>
            response.url().endsWith("/v1/questions") && response.request().method() === "POST",
    );
    await page.getByRole("button", { name: "Ask original question separately" }).click();
    expect((await separateRequest).postDataJSON()).not.toHaveProperty("continue_topic_ids");
    const separateAnswer = (await (await separateResponse).json()) as { question_id: string };
    await expect(page.locator(".answer-summary")).toContainText(separateAnswer.question_id);
    // A separate question is a new top-level investigation, not a child of the expired anchor.
    await expect(page.getByText("Continued from:")).toHaveCount(0);
    await page.getByRole("link", { name: "Question history" }).click();
    await expect(page.locator(".history-child")).toHaveCount(2);
});

test("topic fragment history navigation restores Investigate on browser Back", async ({ page }) => {
    await page.goto("/?scenario=answered#investigate");
    await ask(page, "LDAP is not working. Recommend what to check next.");
    await page.locator(".topic-jump a").first().click();
    await expect(page).toHaveURL(/#topic-/);
    await page.getByRole("link", { name: "Question history" }).click();
    await expect(page.locator(".history-panel")).toBeVisible();
    await page.goBack();
    await expect(page).toHaveURL(/#topic-/);
    await expect(page.locator(".answer-summary")).toBeVisible();
    await expect(page.getByRole("link", { name: "Investigate" })).toHaveAttribute(
        "aria-current",
        "page",
    );
});

test("browser Back from History restores Investigate at the hashless root", async ({ page }) => {
    await page.goto("/");
    await page.getByRole("link", { name: "Question history" }).click();
    await expect(page.locator(".history-panel")).toBeVisible();
    await page.goBack();
    await expect(page).toHaveURL(/\?scenario=auto&range=24h&site_id=synthetic$/);
    expect(new URL(page.url()).hash).toBe("");
    await expect(page.getByRole("heading", { name: "Overview", level: 1 })).toBeVisible();
    await expect(page.getByRole("link", { name: "Overview" })).toHaveAttribute(
        "aria-current",
        "page",
    );
});

test("cancel aborts a CSRF retry while its shared bootstrap refresh remains unresolved", async ({
    page,
}) => {
    await page.goto("/?scenario=cancel_refresh#investigate");
    await page.getByRole("textbox", { name: "Question" }).fill("Try a cancelled refresh.");
    const refreshPromise = page.waitForRequest((request) =>
        request.url().endsWith("/v1/bootstrap"),
    );
    await page.getByRole("button", { name: "Ask" }).click();
    await refreshPromise;
    await page.getByRole("button", { name: "Cancel" }).click();
    await expect(page.getByRole("alert")).toContainText("Request cancelled");
    await expect(page.getByRole("button", { name: "Ask" })).toBeEnabled();
    await expect(page.getByRole("button", { name: "Cancel" })).toHaveCount(0);
});

test("bootstrap refresh reconciles removed site, model, and effort capabilities", async ({
    page,
}) => {
    await page.goto("/?scenario=capability_refresh#investigate");
    await page.getByLabel("Model").selectOption("synthetic-model");
    await page.getByLabel("Effort").selectOption("medium");
    await page.getByLabel("Site").selectOption("synthetic");
    await page.getByRole("textbox", { name: "Question" }).fill("Refresh capabilities.");
    await page.getByRole("button", { name: "Ask" }).click();
    await expect(page.locator(".answer-summary")).toBeVisible();
    await expect(page.getByLabel("Site")).toHaveValue("synthetic");
    await expect(page.getByLabel("Model")).toHaveValue("synthetic-basic-model");
    await expect(page.getByLabel("Effort")).toHaveCount(0);

    await page.getByRole("textbox", { name: "Question" }).fill("Use refreshed capabilities.");
    const requestPromise = page.waitForRequest(
        (request) => request.url().endsWith("/v1/questions") && request.method() === "POST",
    );
    await page.getByRole("button", { name: "Ask" }).click();
    expect((await requestPromise).postDataJSON()).toMatchObject({
        environment_id: "refreshed-site",
        model_id: "synthetic-basic-model",
    });
});

test("no available sites disables question submission", async ({ page }) => {
    await page.goto("/?scenario=no_sites#investigate");
    await page.getByRole("textbox", { name: "Question" }).fill("There is no selectable site.");
    await expect(page.getByText("No sites are available. Ask cannot be submitted.")).toBeVisible();
    await expect(page.getByRole("button", { name: "Ask" })).toBeDisabled();
    await expect(page.getByLabel("Site").locator("option")).toHaveCount(1);
});

test("Clarify and refused keep the composer available", async ({ page }) => {
    await page.goto("/?scenario=clarify#investigate");
    await ask(page, "How many LDAP alerts were there?");
    await expect(page.getByText("Which time window should be reviewed?")).toBeVisible();
    await assertAccessible(page);
    await page.screenshot({ path: "e2e/screenshots/mock/clarify-en.png", fullPage: true });
    await page.getByLabel("Language").selectOption("es");
    await assertAccessible(page);
    await page.goto("/?scenario=refused#investigate");
    await ask(page, "What is the weather?");
    await expect(page.getByText(/could not map this question/i)).toBeVisible();
    await expect(page.getByRole("textbox", { name: "Question" })).toHaveValue(
        "What is the weather?",
    );
    await assertAccessible(page);
    await page.getByLabel("Language").selectOption("es");
    await assertAccessible(page);
});

test("bootstrap failures are actionable and model changes clear incompatible effort", async ({
    page,
}) => {
    await page.goto("/?scenario=answered&delay_bootstrap=1#investigate");
    await expect(page.getByText("Loading data mode...", { exact: true })).toBeVisible();
    await expect(page.getByText("Synthetic fixture", { exact: true })).toHaveCount(0);
    await page.waitForResponse((response) => response.url().endsWith("/v1/bootstrap"));
    await expect(page.getByText("Synthetic fixture", { exact: true })).toBeVisible();

    await page.goto("/?scenario=bootstrap_unavailable#investigate");
    await expect(page.getByText("Data mode unavailable", { exact: true })).toBeVisible();
    await expect(page.getByText("Synthetic fixture", { exact: true })).toHaveCount(0);
    await page.getByLabel("Language").selectOption("es");
    await expect(page.getByText("Modo de datos no disponible", { exact: true })).toBeVisible();
    await expect(page.getByText("Synthetic fixture", { exact: true })).toHaveCount(0);
    await page.getByLabel("Idioma").selectOption("en");
    await expect(page.locator(".alert.error").first()).toContainText(
        "Could not load service settings",
    );
    await expect(page.getByRole("button", { name: "Ask", exact: true })).toBeDisabled();
    await assertAccessible(page);

    await page.goto("/?scenario=answered#investigate");
    const effort = page.getByLabel("Effort");
    await effort.selectOption("low");
    await page.getByLabel("Model").selectOption("synthetic-basic-model");
    await expect(page.getByLabel("Effort")).toHaveCount(0);
    await page.getByLabel("Model").selectOption("synthetic-model");
    await expect(page.getByLabel("Effort")).toHaveValue("");
});

test("Paged rows load more and expired cursor is explained", async ({ page }) => {
    await page.goto("/?scenario=paged#investigate");
    await ask(page, "Review vulnerabilities.");
    await page.getByRole("button", { name: "Load more" }).click();
    await expect(page.locator(".fetch-table tbody tr")).toHaveCount(12);
    await page.getByRole("button", { name: "Load more" }).click();
    await expect(page.locator(".fetch-table tbody tr")).toHaveCount(18);
    const expired = page.waitForResponse(
        (response) => response.url().endsWith("/v1/fetches/page") && response.status() === 410,
    );
    await page.getByRole("button", { name: "Load more" }).click();
    const expiredResponse = await expired;
    expect(await expiredResponse.json()).toMatchObject({ code: "CURSOR_EXPIRED" });
    const table = page.locator(".fetch-table");
    await expect(table.getByRole("alert")).toContainText(
        "CURSOR_EXPIRED: Results expired, ask again.",
    );
    await expect(table.locator("tbody tr")).toHaveCount(18);
    // Expiry is terminal for that cursor, and collapsing the table keeps the disclosure.
    await expect(page.getByRole("button", { name: "Load more" })).toHaveCount(0);
    await table.locator("summary").click();
    await expect(table.locator("summary")).toContainText("Paging stopped");
    await table.locator("summary").click();
    await assertAccessible(page);
    await page.getByLabel("Language").selectOption("es");
    await expect(table.getByRole("alert")).toContainText(
        "CURSOR_EXPIRED: Los resultados caducaron. Vuelve a preguntar.",
    );
    await expect(table.locator("tbody tr")).toHaveCount(18);
    await assertAccessible(page);
});

test("overlapping pages across answers both settle after switching context", async ({ page }) => {
    await page.goto("/?scenario=paged&delay_page=1#investigate");
    await ask(page, "Review vulnerabilities A.");
    const pageA = page.waitForResponse((response) => response.url().endsWith("/v1/fetches/page"));
    await page.getByRole("button", { name: "Load more" }).click();

    await page.evaluate(() => {
        const url = new URL(location.href);
        url.searchParams.set("scenario", "paged");
        history.replaceState(null, "", url);
    });
    await page.getByRole("textbox", { name: "Question" }).fill("Review vulnerabilities B.");
    await page.getByRole("button", { name: "Ask" }).click();
    await expect(page.locator(".original-question")).toContainText("Review vulnerabilities B.");
    const pageB = page.waitForResponse((response) => response.url().endsWith("/v1/fetches/page"));
    await page.getByRole("button", { name: "Load more" }).click();
    await Promise.all([pageA, pageB]);

    await page.getByRole("link", { name: "Question history" }).click();
    await page.locator(".history-open").filter({ hasText: "Review vulnerabilities A." }).click();
    await expect(page.locator(".fetch-table tbody tr")).toHaveCount(12);
    await page.getByRole("link", { name: "Question history" }).click();
    await page.locator(".history-open").filter({ hasText: "Review vulnerabilities B." }).click();
    await expect(page.locator(".fetch-table tbody tr")).toHaveCount(12);
});

test("an unavailable page keeps prior evidence visible and explains the page limit", async ({
    page,
}) => {
    await page.goto("/?scenario=paged&page_unavailable=1#investigate");
    await ask(page, "Review vulnerabilities.");
    await page.getByRole("button", { name: "Load more" }).click();
    await expect(page.locator(".topic-section [role=alert]")).toContainText("EVIDENCE_LIMIT");
    await expect(page.locator(".topic-section [role=alert]")).toContainText(
        "page exceeded the available evidence limit",
    );
    await expect(page.locator(".fetch-table tbody tr")).toHaveCount(6);
    await expect(page.getByRole("button", { name: "Load more" })).toHaveCount(0);
});

test("empty results keep index, ingestion, and visibility uncertainty explicit", async ({
    page,
}) => {
    await page.goto("/?scenario=filtered#investigate");
    await ask(page, "Review LDAP and authentication evidence.");
    await expect(page.locator(".empty-proof").first()).toContainText(
        "No rows are visible, but the service could not confirm an empty result.",
    );
    await expect(page.locator(".empty-proof").first()).not.toContainText(
        "No matching records confirmed within this scope and window.",
    );
    await expect(page.locator("#topic-ldap .fetch-table summary")).toContainText(
        "Visibility: Filtered",
    );
    await expect(page.locator("#topic-auth_review .fetch-table summary")).toContainText(
        "Visibility: Unknown",
    );
    await expect(page.locator("#topic-auth_review .fetch-table summary svg")).toHaveCount(1);
    // Collapsing an unconfirmed empty table must keep the uncertainty in its summary.
    const emptySummary = page.locator("#topic-vuln_review .fetch-table summary");
    await emptySummary.click();
    await expect(page.locator("#topic-vuln_review .fetch-table .empty-proof")).toBeHidden();
    await expect(emptySummary).toContainText("Empty result not confirmed");
    await expect(page.locator("#topic-vuln_review .fetch-table tbody tr")).toHaveCount(0);
    await emptySummary.click();
    await assertAccessible(page);
    await page.getByLabel("Language").selectOption("es");
    await expect(page.locator(".empty-proof").first()).toContainText(
        "No hay filas visibles, pero el servicio no pudo confirmar que el resultado esté vacío.",
    );
    await assertAccessible(page);
});

test("Feedback queues and displays an unavailable response; audit failure publishes no answer", async ({
    page,
}) => {
    await page.goto("/?scenario=answered#investigate");
    await ask(page, "LDAP is not working. Recommend what to check next.");
    await page.getByRole("button", { name: /Report this answer as wrong/ }).click();
    await expect(page.getByRole("status")).toContainText("Feedback queued");
    await assertAccessible(page);
    await page.getByLabel("Language").selectOption("es");
    await assertAccessible(page);
    await page.goto("/?scenario=feedback_unavailable#investigate");
    await ask(page, "LDAP is not working. Recommend what to check next.");
    await page.getByRole("button", { name: /Report this answer as wrong/ }).click();
    await expect(page.getByRole("alert")).toContainText("FEEDBACK_UNAVAILABLE");
    await expect(page.getByRole("alert")).toContainText("30 minutes");
    await assertAccessible(page);
    await page.getByLabel("Language").selectOption("es");
    await assertAccessible(page);
    await page.goto("/?scenario=busy#investigate");
    await page.getByRole("textbox", { name: "Question" }).fill("LDAP is not working");
    await page.getByRole("button", { name: "Ask" }).click();
    await expect(page.getByRole("alert")).toContainText("60 s");
    await assertAccessible(page);
    await page.getByLabel("Language").selectOption("es");
    await assertAccessible(page);
    await page.goto("/?scenario=audit_unavailable#investigate");
    await page.getByRole("textbox", { name: "Question" }).fill("LDAP is not working");
    await page.getByRole("button", { name: "Ask" }).click();
    await expect(page.getByRole("alert")).toContainText("AUDIT_UNAVAILABLE");
    await expect(page.locator(".answer-summary")).toHaveCount(0);
    await assertAccessible(page);
    await page.getByLabel("Language").selectOption("es");
    await assertAccessible(page);
});

test("model selection clarification focuses its control and KEV context stays bounded", async ({
    page,
}) => {
    await page.goto("/?scenario=clarify_model#investigate");
    await ask(page, "Review the available security topics.");
    await expect(page.locator(".clarify")).toContainText(/model selection/i);
    await expect(page.locator("#model-select")).toBeFocused();
    await assertAccessible(page);
    await page.getByLabel("Language").selectOption("es");
    await assertAccessible(page);

    await page.goto("/?scenario=answered&kev=1#investigate");
    await ask(page, "Review vulnerability findings.");
    await expect(page.getByText("CISA KEV context", { exact: true }).first()).toBeVisible();
    await expect(page.locator(".kev-row li")).toHaveCount(4);
    await expect(page.locator(".kev-row").nth(0)).toContainText("CVE-2024-3094");
    await expect(page.locator(".kev-row").nth(1)).toContainText("CVE-2024-9999");
    await expect(page.locator(".kev-row").nth(2)).toContainText("CVE-2021-44228");
    await expect(page.getByText(/does not show exploitation|no indica explotación/i)).toBeVisible();
    await assertAccessible(page);
    await page.getByRole("link", { name: "Service status" }).click();
    await expect(page.locator(".kev-freshness")).toBeVisible();
    await assertAccessible(page);
    await page.getByLabel("Language").selectOption("es");
    await assertAccessible(page);
});

test("continuation double click submits exactly one question", async ({ page }) => {
    await page.goto("/?scenario=partial&delay_ask=1#investigate");
    let questionRequests = 0;
    page.on("request", (request) => {
        if (request.url().endsWith("/v1/questions") && request.method() === "POST")
            questionRequests += 1;
    });
    await ask(page, "Investigate LDAP, authentication review and vulnerability review.");
    await page.getByRole("checkbox").first().check();
    const continueButton = page.getByRole("button", { name: "Continue selected" });
    // Two clicks in one task reach the handler before React re-renders the disabled button,
    // so this exercises the submission lock itself rather than the disabled state.
    await continueButton.evaluate((button: HTMLButtonElement) => {
        button.click();
        button.click();
    });
    await expect(page.getByRole("button", { name: "Continue selected" })).toHaveCount(0);
    await expect(page.locator("#topic-auth_review")).toBeVisible();
    expect(questionRequests).toBe(2);
});
