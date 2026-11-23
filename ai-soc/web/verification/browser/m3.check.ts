import { expect, test, type Page } from "@playwright/test";
import AxeBuilder from "@axe-core/playwright";
import {
    validateIncidentActionResponse,
    validateIncidentContextResponse,
    validateNarrativeReadResponse,
} from "../../src/api/generated/workspace-validators.js";
import { demoChain, demoIds, demoGroupId } from "../mocks/workspace-incident-fixtures";

const title = "SSH access followed by privilege change";
async function selectIncident(page: Page, scenario = "") {
    await page.goto(`/${scenario ? `?scenario=${scenario}` : ""}#incidents`);
    await page.locator(".m3-list-item").filter({ hasText: title }).click();
    await expect(page.locator("#incident-detail-heading")).toHaveText(title);
}
async function selectChain(page: Page, scenario = "") {
    await page.goto(`/${scenario ? `?scenario=${scenario}` : ""}#chains`);
    await page.locator(".m3-list-item").filter({ hasText: "SSH brute force to persistence" }).click();
    await expect(page.getByRole("heading", { name: "SSH brute force to persistence" })).toBeVisible();
}
async function assertAccessible(page: Page) {
    const results = await new AxeBuilder({ page }).analyze();
    expect(
        results.violations.map((v) => ({ id: v.id, targets: v.nodes.flatMap((n) => n.target) })),
    ).toEqual([]);
}
test.beforeEach(async ({ page }) => {
    await page.addInitScript(() => localStorage.setItem("ai-soc-language", "en"));
});

test("review chain evidence, promote the pinned version once, and find its incident", async ({
    page,
}) => {
    let promotions = 0;
    page.on("request", (r) => {
        if (r.method() === "POST" && r.url().endsWith("/promote")) promotions++;
    });
    await selectChain(page);
    const stages = page.locator('[aria-labelledby="chain-stages-heading"]');
    for (const text of ["SSH failure", "SSH success", "Sudo", "Matched", "Missing"])
        await expect(stages).toContainText(text);
    await expect(page.getByText(/order tolerance applied/)).toBeVisible();
    await page.getByLabel("Incident title override").fill("Synthetic promoted incident");
    const request = page.waitForRequest(
        (r) => r.method() === "POST" && r.url().endsWith("/promote"),
    );
    await page.getByRole("button", { name: "Promote to incident" }).click();
    expect((await request).postDataJSON()).toMatchObject({
        site_id: "synthetic",
        expected_revision: demoChain.revision_digest,
        expected_manifest_id: demoChain.manifest_id,
        expected_decision_version: demoChain.decision_version,
        title_override: "Synthetic promoted incident",
    });
    await expect(page.getByRole("button", { name: "Promote to incident" })).toHaveCount(0);
    await page.getByRole("link", { name: "Incidents", exact: true }).click();
    await page.locator(".m3-list-item").filter({ hasText: "Synthetic promoted incident" }).click();
    await expect(page.locator("#incident-detail-heading")).toHaveText(
        "Synthetic promoted incident",
    );
    expect(promotions).toBe(1);
});

test("incident filters narrow the list and mobile evidence can be opened and closed", async ({
    page,
}) => {
    await page.setViewportSize({ width: 390, height: 844 });
    await page.goto("/#incidents");
    const status = page.getByLabel("Filter by status");
    await status.selectOption("closed");
    await expect(page.getByText("No incidents match these filters.")).toBeVisible();
    await status.selectOption("in_progress");
    const incident = page.getByRole("button", { name: /SSH access followed by privilege change/ });
    await expect(incident).toBeVisible();
    await page.getByLabel("Unassigned only").check();
    await expect(page.getByText("No incidents match these filters.")).toBeVisible();
    await page.getByLabel("Unassigned only").uncheck();
    await incident.click();

    await expect(incident).not.toBeVisible();
    await expect(page.locator(".m3-incident-detail")).toBeFocused();
    const timeline = page.getByRole("region", { name: "Evidence timeline" });
    await expect(timeline.getByText("Rule 5763", { exact: true }).first()).toBeVisible();
    await expect(timeline.getByText("Source", { exact: false }).first()).toBeVisible();
    const event = timeline.locator("details").first();
    await event.locator("summary").press("Enter");
    await expect(event.getByText("Frozen group revision")).toBeVisible();
    await page.getByRole("button", { name: "Back to incidents" }).click();
    await expect(status).toHaveValue("in_progress");
    await expect(incident).toBeVisible();
    await expect(page.locator(".m3-incident-list")).toBeFocused();
});

test("incident writes use current revisions and survive reload in the synthetic API", async ({
    page,
}) => {
    await selectIncident(page);
    let evidenceRevision = demoIds.evidenceRevision;
    async function action(name: string, click: () => Promise<void>, version: number) {
        const request = page.waitForRequest(
            (r) => r.method() === "POST" && r.url().endsWith(`/${name}`),
        );
        await click();
        const sent = await request;
        const body: unknown = sent.postDataJSON();
        const response = await sent.response();
        expect(response?.ok()).toBe(true);
        const result: unknown = await response?.json();
        if (!validateIncidentActionResponse(result))
            throw new Error("Invalid synthetic action response");
        evidenceRevision = result.evidence_revision;
        expect(body).toMatchObject({ site_id: "synthetic", expected_work_version: version });
        const record = page.locator(".m3-incident-record");
        await expect(record).toBeVisible();
        await record.locator("summary").click();
        await expect(record.getByText(String(version + 1), { exact: true })).toBeVisible();
        await record.locator("summary").click();
        return body;
    }
    await page
        .getByRole("region", { name: "Analyst work" })
        .getByLabel("Owner", { exact: true })
        .fill("analyst:synthetic");
    expect(
        await action("assign", () => page.getByRole("button", { name: "Save owner" }).click(), 3),
    ).toMatchObject({ owner_key: "analyst:synthetic" });
    await page.getByRole("combobox", { name: "Status", exact: true }).selectOption("resolved");
    expect(
        await action("status", () => page.getByRole("button", { name: "Save status" }).click(), 4),
    ).toMatchObject({ status: "resolved" });
    await page.getByLabel("Comment", { exact: true }).fill("Synthetic analyst comment");
    expect(
        await action("comment", () => page.getByRole("button", { name: "Add comment" }).click(), 5),
    ).toMatchObject({ body: "Synthetic analyst comment" });
    await page.getByRole("combobox", { name: "Label", exact: true }).selectOption("false_positive");
    await page
        .getByRole("combobox", { name: "Reason for false positive" })
        .selectOption("test_activity");
    await page.getByLabel("Analyst note").fill("Synthetic disposition note");
    expect(
        await action(
            "disposition",
            () => page.getByRole("button", { name: "Record disposition" }).click(),
            6,
        ),
    ).toMatchObject({
        expected_evidence_revision: demoIds.evidenceRevision,
        label: "false_positive",
        reason_code: "test_activity",
        propagate_to_members: false,
    });
    await page.getByText("Edit membership", { exact: true }).click();
    await page.getByLabel("Add group IDs").fill(demoIds.secondGroupId);
    await page.getByLabel("Remove group IDs").fill(demoGroupId);
    expect(
        await action(
            "members",
            () => page.getByRole("button", { name: "Update membership" }).click(),
            7,
        ),
    ).toMatchObject({ add_group_ids: [demoIds.secondGroupId], remove_group_ids: [demoGroupId] });
    await expect(page.locator('[aria-labelledby="incident-members-heading"]')).toContainText(
        "Manually added group",
    );
    expect(evidenceRevision).not.toBe(demoIds.evidenceRevision);
    await page.getByRole("combobox", { name: "Label", exact: true }).selectOption("undetermined");
    expect(
        await action(
            "disposition",
            () => page.getByRole("button", { name: "Record disposition" }).click(),
            8,
        ),
    ).toMatchObject({ expected_evidence_revision: evidenceRevision });
    await page.reload();
    await page.locator(".m3-list-item").filter({ hasText: title }).click();
    await expect(
        page.getByRole("region", { name: "Analyst work" }).getByLabel("Owner", { exact: true }),
    ).toHaveValue("analyst:synthetic");
    await expect(page.getByRole("combobox", { name: "Status", exact: true })).toHaveValue(
        "resolved",
    );
    await expect(page.getByText("Synthetic analyst comment")).toBeVisible();
    await expect(page.getByText("Synthetic disposition note")).toBeVisible();
    await expect(page.getByText("Test activity")).toBeVisible();
    await expect(page.getByText("test_activity")).toHaveCount(0);
    await expect(page.locator('[aria-labelledby="incident-members-heading"]')).toContainText(
        "Manually added group",
    );
    await expect(page.locator('[aria-labelledby="incident-members-heading"]')).not.toContainText(
        "Repeated SSH authentication failures",
    );
});

test("current and historical narrative disclose trust and cited same-site facts", async ({
    page,
}) => {
    const narrativeRequest = page.waitForRequest((r) =>
        r.url().includes(`/incidents/${demoIds.incidentId}/narrative`),
    );
    await selectIncident(page);
    const sent = await narrativeRequest;
    const response = await sent.response();
    const result: unknown = await response?.json();
    if (!validateNarrativeReadResponse(result) || !result.evidence)
        throw new Error("Invalid synthetic narrative evidence");
    expect(new URL(sent.url()).searchParams.get("site_id")).toBe("synthetic");
    expect(result.evidence.site_id).toBe("synthetic");
    const narrative = page.locator('[aria-labelledby="incident-narrative-heading"]');
    await expect(narrative).toContainText("Unvalidated AI summary");
    await expect(narrative).toContainText("Rule 5763");
    await narrative.getByRole("button", { name: /Group fact/ }).click();
    await expect(narrative.getByText("Matching frozen fact")).toBeVisible();
    await expect(narrative.locator(".m3-citation-detail")).toContainText("0.71");
    await narrative.getByRole("button", { name: /Alert fact/ }).click();
    await expect(narrative.locator(".m3-citation-detail")).toContainText("5763");
    await selectIncident(page, "workspace_narrative_historical");
    await expect(narrative).toContainText("historical evidence revision");
    await expect(narrative).toContainText("Unvalidated AI summary");
});
for (const [scenario, message] of [
    ["workspace_narrative_unavailable", "No narrative is available for this revision yet."],
    [
        "workspace_narrative_all_removed",
        "No generated selections passed validation. No narrative text is shown.",
    ],
]) {
    test(`${scenario} shows no generated narrative`, async ({ page }) => {
        await selectIncident(page, scenario);
        const narrative = page.locator('[aria-labelledby="incident-narrative-heading"]');
        await expect(narrative).toContainText(message);
        await expect(narrative.locator(".m3-narrative-text")).toHaveCount(0);
    });
}
test("Investigate receives an editable bounded draft without submitting it", async ({ page }) => {
    let submitted = 0;
    page.on("request", (request) => {
        if (request.method() === "POST" && new URL(request.url()).pathname === "/v1/questions")
            submitted++;
    });
    await selectIncident(page);
    const request = page.waitForRequest((r) =>
        r.url().includes(`/incidents/${demoIds.incidentId}/context`),
    );
    await page.getByRole("button", { name: "Investigate this incident" }).click();
    const sent = await request;
    const url = new URL(sent.url());
    const response = await sent.response();
    const context: unknown = await response?.json();
    if (!validateIncidentContextResponse(context))
        throw new Error("Invalid synthetic context response");
    expect(context.sampled_alerts.length).toBeLessThanOrEqual(context.sample_limit);
    expect(context.sample_limit).toBe(100);
    expect(context.question_draft.editable).toBe(true);
    expect(url.searchParams.get("site_id")).toBe("synthetic");
    expect(url.searchParams.get("evidence_revision")).toBe(demoIds.evidenceRevision);
    const question = page.getByRole("textbox", { name: "Question" });
    await expect(question).toHaveValue(
        `Investigate incident ${demoIds.incidentId} and its frozen evidence.`,
    );
    await question.fill("Synthetic edited question");
    await expect(question).toHaveValue("Synthetic edited question");
    expect(submitted).toBe(0);
});
test("stale promotion is refused and refreshes the review", async ({ page }) => {
    await selectChain(page, "workspace_conflict");
    await page.getByRole("button", { name: "Promote to incident" }).click();
    await expect(page.getByRole("alert")).toContainText("version changed");
    await expect(page.getByRole("button", { name: "Promote to incident" })).toBeVisible();
});
for (const [scenario, message] of [
    ["workspace_denied", /do not have access/i],
    ["workspace_error", /unavailable/i],
] as const) {
    test(`${scenario} does not present sample data as a successful result`, async ({ page }) => {
        await page.goto(`/?scenario=${scenario}#incidents`);
        await expect(page.getByRole("alert").first()).toContainText(message);
        await expect(page.locator(".m3-list-item")).toHaveCount(0);
    });
}
test("EN and ES keyboard interaction keeps focus and passes axe on loaded incident", async ({
    page,
}) => {
    await selectIncident(page);
    const citation = page.getByRole("button", { name: /Group fact/ });
    await citation.focus();
    await page.keyboard.press("Enter");
    await expect(citation).toBeFocused();
    await expect(citation).toHaveAttribute("aria-pressed", "true");
    await assertAccessible(page);
    await page.getByLabel("Language").selectOption("es");
    await expect(page.locator('[aria-labelledby="incident-narrative-heading"]')).toContainText(
        "Resumen de IA no validado",
    );
    const spanishCitation = page.locator(".m3-citations .narrative-source").last();
    await spanishCitation.focus();
    await page.keyboard.press("Enter");
    await expect(spanishCitation).toBeFocused();
    await expect(spanishCitation).toHaveAttribute("aria-pressed", "true");
    await assertAccessible(page);
});
