import AxeBuilder from "@axe-core/playwright";
import { expect, test, type Page } from "@playwright/test";
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import type {
  Answer,
  BootstrapResponse,
  FetchState,
  LeftOut,
} from "../../contracts/v1/generated/types.js";

const csrfEnvelope = "bm9uY2U.1791036000.1791036600.signature";
const g006FixtureBytes = readFileSync(
  new URL("../../tests/fixtures/v1/g006_table_before_judgment.json", import.meta.url),
);
const g006FixtureSha256 = "2b0c300b7bc5ebbcbaaea4c7305f353ff3b4d2f5bd6476d1ff914c6f6f79447a";
const g006Fixture = JSON.parse(g006FixtureBytes.toString("utf8")) as {
  cases: Record<"positive" | "negative" | "boundary" | "failure", {
    input: {
      status?: "partial" | "answered";
      topics?: Array<{
        topic_id: string;
        ordinal: number;
        table: { state: string; label: string; count_label: string };
        judgment: { state: string; sentences: string[] };
      }>;
      left_out?: LeftOut[];
      fetch_state?: string;
      fetch_count?: number;
      judgment_provider_outcome?: string;
      topic_id?: string;
    };
    expected: {
      render_order?: string[];
      topic_order?: string[];
      table_visible?: boolean;
      finding_visible?: boolean;
      fabricated_finding_visible?: boolean;
      retryable_judgment_left_out?: boolean;
      table_retained?: boolean;
      answer_status?: string;
      left_out?: LeftOut;
    };
  }>;
};
const g035FixtureBytes = readFileSync(
  new URL("./data/g035_mixed_access_cases.json", import.meta.url),
);
const g035Fixture = JSON.parse(g035FixtureBytes.toString("utf8")) as {
  cases: Record<"positive" | "negative" | "boundary" | "failure", {
    status: "partial" | "answered";
    topics: Array<{ topic_id: string; ordinal: number; outcome: "allowed" | "denied" | "unavailable" }>;
    expected_allowed: string[];
    expected_denied: string[];
    expected_failed?: string[];
  }>;
};
const g035FixtureSha256 = "5d7e1f50f984270ee5a107414b40aafdf8f738019cfd72db7d974e3abd797471";
const guiFixtureBytes = readFileSync(new URL("./data/gui_surface_cases.json", import.meta.url));
const guiFixtureSha256 = "1e0966568fafe977ed4928fffb562653e268999875edee4b9e408850879c9bca";
const g053FixtureBytes = readFileSync(new URL("./data/g053_provider_token_cases.json", import.meta.url));
const g053FixtureSha256 = "143330300aa660cee4062e07d18226eecc1790f0896bf710a2ee40919afbd30c";
const g053Fixture = JSON.parse(g053FixtureBytes.toString("utf8")) as {
  hostile_first_token: string;
  cases: Record<"positive" | "negative" | "boundary" | "failure", {
    judgment_state: "validated" | "invalid_output" | "model_unavailable";
    safe_answer_message: string;
    render_safe_finding: boolean;
  }>;
};
function annotateGuiSurface(variant: "positive" | "negative" | "boundary" | "failure") {
  test.info().annotations.push(
    { type: "acceptance_ids", description: "GUI" },
    { type: "case_id", description: "B5-GUI.browser-surface" },
    { type: "variant", description: variant },
    { type: "fixture_sha256", description: guiFixtureSha256 },
  );
}
function annotateG053Envelope(variant: "positive" | "negative" | "boundary" | "failure") {
  test.info().annotations.push(
    { type: "acceptance_ids", description: "G053" },
    { type: "case_id", description: "B5-G053.ui-sanitized-envelope" },
    { type: "variant", description: variant },
    { type: "fixture_sha256", description: g053FixtureSha256 },
  );
}
const guiFixture = JSON.parse(guiFixtureBytes.toString("utf8")) as {
  cases: {
    positive: {
      language: "en";
      site_id: string;
      model_id: string;
      effort: string;
      question: string;
      submission: "keyboard";
      site_change_clears_continuation: true;
      expected_status: string;
    };
    negative: {
      language: "es";
      site_id: string;
      model_id: string;
      question: string;
      expected_denied_topic: string;
      expected_status: string;
    };
    boundary: {
      exact_utf8_bytes: number;
      over_utf8_bytes: number;
      multibyte_character: string;
      expected_status: string;
    };
    failure: {
      status_code: number;
      error_code: string;
      safe_message: string;
      hostile_provider_sentinel: string;
    };
  };
};

const bootstrap: BootstrapResponse = {
  schema_version: "1",
  sites: [{ id: "alpha", label: "Alpha SOC" }],
  models: [{ id: "fixture-claude-small", label: "Fixture Claude", efforts: [], context_tokens: 4096, max_output_tokens: 512 }],
  provenance: {
    service_sha: "a".repeat(40),
    content_repository: "https://example.test/content",
    content_sha: "b".repeat(40),
    pack_sha256: "c".repeat(64),
    image_digest: `sha256:${"d".repeat(64)}`,
    docs_origin: "https://docs.example.test",
    docs_manifest_sha256: "e".repeat(64),
    contract_version: "1" as const,
  },
  mode: "fixture",
  limits: { question_bytes: 16384, page_size: 50, window_days: 90, request_bytes: 65536, plan_bytes: 131072 },
  csrf_token: csrfEnvelope,
};

function answer(status: "partial" | "answered" = "partial"): Answer {
  return {
    schema_version: "1",
    question_id: "11111111-1111-4111-8111-111111111111",
    environment_id: "alpha",
    language: "en",
    status,
    blocks: [
      {
        topic_id: "authentication",
        ordinal: 0,
        document: null,
        missing: [],
        tables: [
          {
            fetch_id: "alerts",
            topic_id: "authentication",
            state: "rows",
            scope: { environment_id: "alpha", template_id: "alerts_rows_v1", index_family: "alerts", filters: [], visibility: "full", policy_hash: "f".repeat(64), snapshot: "first_page_only", displayed_rows: 1 },
            window: { start: "2026-09-29T12:00:00Z", end: "2026-09-30T12:00:00Z", semantics: "rolling", source_text: "past day", timezone: "UTC", anchor_at: "2026-09-30T12:00:00Z" },
            columns: [],
            rows: [{ evidence_id: `ev1_${"1".repeat(64)}`, topic_id: "authentication", fetch_id: "alerts", record_ref: null, values: { rule: "Synthetic alert" } }],
            count: { value: 1, relation: "eq", scope: "matching_visible_records", computed_by: "indexer", approximate: false },
            checks: [],
            empty_proof: null,
            next_cursor: "cursor-1",
            snapshot_at: "2026-09-30T12:00:00Z",
            snapshot: { kind: "first_page_only", key: "2".repeat(64), at: "2026-09-30T12:00:00Z", expires_at: null },
            items: [],
            buckets: [],
            bucket_completeness: "complete",
            message: null,
            error: null,
          },
        ],
        checks: [],
        judgment: {
          state: "validated",
          model_id: "fixture-claude-small",
          effort: null,
          sentences: [{ finding_id: "synthetic-finding", kind: "observation", text: "Synthetic finding is linked to the visible alert.", evidence_ids: [`ev1_${"1".repeat(64)}`] }],
          removed: [],
          usage: null,
          message: null,
        },
      },
    ],
    message: null,
    clarify: null,
    followup_id: "22222222-2222-4222-8222-222222222222",
    followup_revision: 1,
    left_out: [
      { topic_id: "ldap", stage: "judgment", reason: "capacity_limited", retryable: true },
      { topic_id: "tls", stage: "judgment", reason: "capacity_limited", retryable: true },
    ],
    provenance: bootstrap.provenance,
    trace_id: "3".repeat(32),
    feedback_receipt: "opaque-fixture-receipt",
  };
}

function frozenG006Answer(variant: "positive" | "negative" | "boundary" | "failure") {
  const scenario = g006Fixture.cases[variant];
  const fixtureCase = scenario.input;
  const result = answer(fixtureCase.status ?? "partial");
  const sourceTopics = fixtureCase.topics ?? [{
    topic_id: fixtureCase.topic_id ?? "authentication",
    ordinal: 0,
    table: {
      state: fixtureCase.fetch_state ?? "rows",
      label: "Authentication alerts",
      count_label: `rows · =${fixtureCase.fetch_count ?? 0}`,
    },
    judgment: { state: "unavailable", sentences: [] },
  }];
  const template = result.blocks[0]!;
  result.blocks = sourceTopics.map((topic) => {
    const count = Number(topic.table.count_label.match(/=(\d+)/)?.[1] ?? 0);
    const judgmentState = topic.judgment.state === "unavailable" ? "model_unavailable" : "validated";
    const sentences = topic.judgment.sentences.map((text) => ({
      finding_id: `synthetic-${topic.topic_id}`,
      kind: "observation" as const,
      text,
      evidence_ids: [`ev1_${"1".repeat(64)}`],
    }));
    return {
      ...template,
      topic_id: topic.topic_id,
      ordinal: topic.ordinal,
      tables: [{
        ...template.tables[0]!,
        state: topic.table.state as typeof template.tables[number]["state"],
        count: { ...template.tables[0]!.count!, value: count },
      }],
      judgment: { ...template.judgment, state: judgmentState, sentences },
    };
  });
  result.status = fixtureCase.status ?? (variant === "failure" ? "partial" : "answered");
  result.left_out = fixtureCase.left_out ?? (variant === "failure" ? [scenario.expected.left_out!] : []);
  return result;
}

function mixedAccessAnswer(variant: "positive" | "negative" | "boundary" | "failure") {
  const scenario = g035Fixture.cases[variant];
  const result = answer(scenario.status);
  const template = result.blocks[0]!;
  result.blocks = scenario.topics.map((topic) => {
    if (topic.outcome !== "allowed") {
      const fetchState: FetchState = topic.outcome === "denied" ? "denied" : "unavailable";
      return {
        ...template,
        topic_id: topic.topic_id,
        ordinal: topic.ordinal,
        tables: template.tables.map((table) => ({
          ...table,
          topic_id: topic.topic_id,
          state: fetchState,
          rows: [],
          count: null,
          next_cursor: null,
        })),
        judgment: {
          ...template.judgment,
          state: topic.outcome === "denied" ? "denial" : "evidence_unavailable",
          sentences: [],
        },
      };
    }
    const rows = template.tables[0]!.rows.map((row) => ({
      ...row,
      topic_id: topic.topic_id,
      values: { rule: `Synthetic ${topic.topic_id} alert` },
    }));
    const evidenceIds = rows.map((row) => row.evidence_id);
    return {
      ...template,
      topic_id: topic.topic_id,
      ordinal: topic.ordinal,
      tables: template.tables.map((table) => ({ ...table, topic_id: topic.topic_id, rows })),
      judgment: {
        ...template.judgment,
        sentences: [{
          ...template.judgment.sentences[0]!,
          finding_id: `synthetic-${topic.topic_id}`,
          text: `Synthetic ${topic.topic_id} finding is linked to the visible alert.`,
          evidence_ids: evidenceIds,
        }],
      },
    };
  });
  result.left_out = (scenario.expected_failed ?? []).map((topic_id) => ({
    topic_id,
    stage: "fetch",
    reason: "evidence_unavailable",
    retryable: true,
  }));
  return result;
}

async function stubBootstrap(page: Page, payload = bootstrap) {
  await page.route("**/v1/bootstrap", async (route) => {
    await route.fulfill({
      status: 200,
      json: payload,
      headers: { "Set-Cookie": `__Host-soc-csrf=${csrfEnvelope}; Path=/; HttpOnly; Secure; SameSite=Strict` },
    });
  });
}

test("GUI positive selects an allowed site and capable effort by keyboard", async ({ page }) => {
  annotateGuiSurface("positive");
  expect(createHash("sha256").update(guiFixtureBytes).digest("hex")).toBe(guiFixtureSha256);
  const scenario = guiFixture.cases.positive;
  const capableBootstrap: BootstrapResponse = {
    ...bootstrap,
    sites: [
      { id: "alpha", label: "Alpha SOC" },
      { id: "beta", label: "Beta SOC" },
    ],
    models: [
      ...bootstrap.models,
      {
        id: "fixture-claude-large",
        label: "Fixture Claude Large",
        efforts: ["low", "medium", "high"],
        context_tokens: 32768,
        max_output_tokens: 4096,
      },
    ],
  };
  await stubBootstrap(page, capableBootstrap);
  const sentBodies: unknown[] = [];
  await page.route("**/v1/questions", async (route) => {
    const body = route.request().postDataJSON() as { environment_id: string };
    sentBodies.push(body);
    const result = answer("answered");
    result.environment_id = body.environment_id;
    await route.fulfill({ status: 200, json: result });
  });
  await page.setViewportSize({ width: 1280, height: 800 });
  await page.goto("/");
  await page.getByLabel("Site").selectOption(scenario.site_id);
  await page.getByLabel("Model").selectOption(scenario.model_id);
  await expect(page.getByLabel("Effort")).toBeVisible();
  await page.getByLabel("Effort").selectOption(scenario.effort);
  await page.getByRole("textbox", { name: "Question" }).fill(scenario.question);
  await page.getByRole("button", { name: "Ask SOC" }).focus();
  await page.keyboard.press("Enter");
  await expect(page.locator("#answer-status")).toContainText(scenario.expected_status);
  expect(sentBodies[0]).toMatchObject({
    question: scenario.question,
    environment_id: scenario.site_id,
    model_id: scenario.model_id,
    effort: scenario.effort,
    language_hint: scenario.language,
  });
  await expect(page.getByRole("group", { name: "Select unfinished topics" })).toBeVisible();
  await page.getByLabel("Site").selectOption("alpha");
  if (scenario.site_change_clears_continuation) {
    await expect(page.locator("#answer-panel")).toBeHidden();
  }
  await page.getByRole("textbox", { name: "Question" }).fill("show authentication alerts");
  await page.getByRole("button", { name: "Ask SOC" }).click();
  await expect(page.locator("#answer-status")).toContainText(scenario.expected_status);
  expect(sentBodies).toHaveLength(2);
  expect(sentBodies[1]).toMatchObject({ environment_id: "alpha" });
  expect(sentBodies[1]).not.toHaveProperty("followup_id");
  expect((await new AxeBuilder({ page }).analyze()).violations).toEqual([]);
});

test("GUI negative renders denied topics without evidence in Spanish mobile layout", async ({ page }) => {
  annotateGuiSurface("negative");
  expect(createHash("sha256").update(guiFixtureBytes).digest("hex")).toBe(guiFixtureSha256);
  const scenario = guiFixture.cases.negative;
  await stubBootstrap(page);
  await page.route("**/v1/questions", async (route) => {
    await route.fulfill({ status: 200, json: mixedAccessAnswer("negative") });
  });
  await page.setViewportSize({ width: 320, height: 740 });
  await page.goto("/");
  await page.getByLabel("Language").selectOption(scenario.language);
  await expect(page.getByRole("heading", { name: "Investigación de seguridad" })).toBeVisible();
  await page.getByLabel("Sitio").selectOption(scenario.site_id);
  await page.getByLabel("Modelo").selectOption(scenario.model_id);
  await expect(page.getByLabel("Esfuerzo")).toBeHidden();
  await page.getByRole("textbox", { name: "Pregunta" }).fill(scenario.question);
  await page.getByRole("button", { name: "Preguntar a SOC" }).click();
  const denied = page.locator(".topic").filter({
    has: page.getByRole("heading", { name: scenario.expected_denied_topic, exact: true }),
  });
  await expect(denied.getByText("denied", { exact: true })).toBeVisible();
  await expect(denied.getByText(/Synthetic .* (alert|finding)/)).toHaveCount(0);
  await expect(page.locator("body")).toHaveJSProperty("scrollWidth", 320);
  expect((await new AxeBuilder({ page }).analyze()).violations).toEqual([]);
});

test("GUI boundary admits exactly 16384 UTF-8 bytes and rejects the next multibyte character", async ({ page }) => {
  annotateGuiSurface("boundary");
  expect(createHash("sha256").update(guiFixtureBytes).digest("hex")).toBe(guiFixtureSha256);
  const scenario = guiFixture.cases.boundary;
  await stubBootstrap(page);
  let calls = 0;
  let acceptedQuestion = "";
  await page.route("**/v1/questions", async (route) => {
    calls += 1;
    acceptedQuestion = (route.request().postDataJSON() as { question: string }).question;
    await route.fulfill({ status: 200, json: answer("answered") });
  });
  await page.goto("/");
  const input = page.getByRole("textbox", { name: "Question" });
  const exact = scenario.multibyte_character.repeat(scenario.exact_utf8_bytes / 2);
  expect(new TextEncoder().encode(exact).byteLength).toBe(scenario.exact_utf8_bytes);
  await input.fill(exact);
  await page.getByRole("button", { name: "Ask SOC" }).click();
  await expect(page.locator("#answer-status")).toContainText(scenario.expected_status);
  expect(acceptedQuestion).toBe(exact);

  const over = scenario.multibyte_character.repeat(scenario.over_utf8_bytes / 2);
  expect(new TextEncoder().encode(over).byteLength).toBe(scenario.over_utf8_bytes);
  await input.fill(over);
  await page.getByRole("button", { name: "Ask SOC" }).click();
  await expect(page.locator("#status")).toContainText("The request could not be completed.");
  expect(calls).toBe(1);
});

test("GUI failure shows only the typed safe error message", async ({ page }) => {
  annotateGuiSurface("failure");
  expect(createHash("sha256").update(guiFixtureBytes).digest("hex")).toBe(guiFixtureSha256);
  const scenario = guiFixture.cases.failure;
  await stubBootstrap(page);
  await page.route("**/v1/questions", async (route) => {
    await route.fulfill({
      status: scenario.status_code,
      json: {
        code: scenario.error_code,
        message: scenario.safe_message,
        trace_id: "f".repeat(32),
        retryable: true,
        details: { provider_text: scenario.hostile_provider_sentinel },
      },
    });
  });
  await page.goto("/");
  await page.getByRole("textbox", { name: "Question" }).fill("show alerts");
  await page.getByRole("button", { name: "Ask SOC" }).click();
  await expect(page.locator("#status")).toHaveText(scenario.safe_message);
  await expect(page.getByText(scenario.hostile_provider_sentinel)).toHaveCount(0);
  await expect(page.locator("#answer-panel")).toBeHidden();
});

for (const variant of ["positive", "negative", "boundary", "failure"] as const) {
  test(`UI renders only sanitized provider outcome: ${variant}`, async ({ page }) => {
    annotateG053Envelope(variant);
    expect(createHash("sha256").update(g053FixtureBytes).digest("hex")).toBe(g053FixtureSha256);
    const scenario = g053Fixture.cases[variant];
    await stubBootstrap(page);
    let serializedResponse = "";
    await page.route("**/v1/questions", async (route) => {
      const safeAnswer = answer();
      safeAnswer.message = scenario.safe_answer_message;
      safeAnswer.blocks = safeAnswer.blocks.map((block) => ({
        ...block,
        judgment: {
          ...block.judgment,
          state: scenario.judgment_state,
          sentences: scenario.render_safe_finding ? block.judgment.sentences : [],
          removed: [],
          usage: null,
          message: scenario.safe_answer_message,
        },
      }));
      serializedResponse = JSON.stringify(safeAnswer);
      await route.fulfill({ status: 200, json: safeAnswer });
    });
    await page.goto("/");
    await page.getByRole("textbox", { name: "Question" }).fill("show alerts");
    await page.getByRole("button", { name: "Ask SOC" }).click();

    await expect(page.locator("#answer-panel")).toBeVisible();
    await expect(page.locator("#answer-message")).toHaveText(scenario.safe_answer_message);
    await expect(page.getByText(g053Fixture.hostile_first_token)).toHaveCount(0);
    if (scenario.render_safe_finding) {
      await expect(page.getByText("Synthetic finding is linked to the visible alert.")).toBeVisible();
    } else {
      await expect(page.getByText("Synthetic finding is linked to the visible alert.")).toHaveCount(0);
    }
    expect(serializedResponse).not.toContain(g053Fixture.hostile_first_token);
  });
}

test("English question supports keyboard submission and accessible answer announcement", async ({ page }) => {
  await stubBootstrap(page);
  let sentBody: unknown;
  const checkMessage = "<img src=check onerror=alert(1)>";
  const tableMessage = "<img src=table onerror=alert(1)>";
  await page.route("**/v1/questions", async (route) => {
    sentBody = route.request().postDataJSON();
    const result = answer();
    result.blocks[0]!.tables[0]!.message = tableMessage;
    result.blocks[0]!.checks = [{
      check_id: "auth_recency",
      topic_id: "authentication",
      label: "Newest returned record within synthetic limit",
      outcome: "failed",
      evidence_ids: [`ev1_${"1".repeat(64)}`],
      message: checkMessage,
      expectation_id: null,
    }];
    await route.fulfill({ status: 200, json: result });
  });
  await page.goto("/");
  await page.getByRole("textbox", { name: "Question" }).fill("show authentication alerts");
  await page.getByRole("button", { name: "Ask SOC" }).focus();
  await page.keyboard.press("Enter");

  await expect(page.locator("#answer-status")).toContainText("Status: partial");
  await expect(page.getByText("Synthetic finding is linked to the visible alert.")).toBeVisible();
  await expect(page.getByText("Newest returned record within synthetic limit: failed")).toBeVisible();
  await expect(page.getByText(checkMessage, { exact: true })).toBeVisible();
  await expect(page.getByText(tableMessage, { exact: true })).toBeVisible();
  await expect(page.locator("img")).toHaveCount(0);
  const accessibility = await new AxeBuilder({ page }).analyze();
  expect(accessibility.violations).toEqual([]);
  expect(sentBody).toMatchObject({ question: "show authentication alerts", environment_id: "alpha", language_hint: "en" });
  await expect(page.getByLabel("Language")).toHaveValue("en");
});

test("topic table precedes judgment and remains visible when judgment fails", async ({ page }) => {
  await stubBootstrap(page);
  let questions = 0;
  await page.route("**/v1/questions", async (route) => {
    questions += 1;
    if (questions === 1) {
      await route.fulfill({ status: 200, json: answer("answered") });
      return;
    }
    const failed = answer();
    failed.blocks[0]!.judgment.state = "model_unavailable";
    failed.blocks[0]!.judgment.sentences = [];
    failed.left_out = [
      { topic_id: "authentication", stage: "judgment", reason: "model_unavailable", retryable: true },
    ];
    await route.fulfill({ status: 200, json: failed });
  });
  await page.goto("/");
  const question = page.getByRole("textbox", { name: "Question" });
  await question.fill("show authentication alerts");
  await page.getByRole("button", { name: "Ask SOC" }).click();

  const topic = page.locator(".topic");
  await expect(topic.getByText("rows · =1")).toBeVisible();
  await expect(topic.getByText("Synthetic finding is linked to the visible alert.")).toBeVisible();
  const paragraphs = topic.locator("p");
  expect(await paragraphs.nth(0).textContent()).toContain("rows · =1");
  expect(await paragraphs.nth(1).textContent()).toContain("Synthetic finding");

  await question.fill("show authentication alerts again");
  await page.getByRole("button", { name: "Ask SOC" }).click();
  await expect(topic.getByText("rows · =1")).toBeVisible();
  await expect(topic.getByText("Synthetic finding is linked to the visible alert.")).toHaveCount(0);
  await expect(
    page.getByRole("group", { name: "Select unfinished topics" }).getByText("authentication"),
  ).toBeVisible();
});

for (const variant of ["positive", "negative", "boundary", "failure"] as const) {
  test(`QA-015.resolution ${variant} renders the frozen G006 oracle`, async ({ page }) => {
    test.info().annotations.push(
      { type: "acceptance_ids", description: "G006" },
      { type: "case_id", description: "QA-015.resolution" },
      { type: "variant", description: variant },
      { type: "fixture_sha256", description: g006FixtureSha256 },
    );
    expect(createHash("sha256").update(g006FixtureBytes).digest("hex")).toBe(g006FixtureSha256);
    await stubBootstrap(page);
    await page.route("**/v1/questions", async (route) => {
      await route.fulfill({ status: 200, json: frozenG006Answer(variant) });
    });
    await page.goto("/");
    await page.getByRole("textbox", { name: "Question" }).fill("show authentication alerts");
    await page.getByRole("button", { name: "Ask SOC" }).click();

    const expected = g006Fixture.cases[variant].expected;
    const topics = page.locator(".topic");
    await expect(topics).toHaveCount(expected.topic_order?.length ?? 1);
    if (expected.topic_order) {
      await expect(topics.locator("h3")).toHaveText(expected.topic_order);
    }
    for (const topic of await topics.all()) {
      const paragraphs = await topic.locator("p").allTextContents();
      expect(paragraphs[0]).toContain("rows · =");
      if (expected.finding_visible) {
        const findingIndex = paragraphs.findIndex((text) => text.includes("Synthetic finding"));
        expect(findingIndex).toBeGreaterThan(0);
        expect(findingIndex).toBeGreaterThan(paragraphs.findIndex((text) => text.includes("rows · =")));
      }
      if (expected.fabricated_finding_visible === false) {
        expect(paragraphs.some((text) => text.includes("Synthetic finding"))).toBe(false);
      }
    }
    if (expected.answer_status) {
      await expect(page.locator("#answer-status")).toContainText(expected.answer_status);
    }
    if (expected.left_out) {
      await expect(page.getByRole("group", { name: "Select unfinished topics" })
        .getByText(expected.left_out.topic_id)).toBeVisible();
    }
  });
}

for (const variant of ["positive", "negative", "boundary", "failure"] as const) {
  test(`B5-G035 ${variant} keeps allowed topic evidence beside denial`, async ({ page }) => {
    expect(createHash("sha256").update(g035FixtureBytes).digest("hex")).toBe(g035FixtureSha256);
    await stubBootstrap(page);
    await page.route("**/v1/questions", async (route) => {
      await route.fulfill({ status: 200, json: mixedAccessAnswer(variant) });
    });
    await page.goto("/");
    await page.getByRole("textbox", { name: "Question" }).fill("compare authentication and VPN alerts");
    await page.getByRole("button", { name: "Ask SOC" }).click();

    const topics = page.locator(".topic");
    const scenario = g035Fixture.cases[variant];
    await expect(topics.locator("h3")).toHaveText(scenario.topics.map((topic) => topic.topic_id));
    for (const topicId of scenario.expected_allowed) {
      const section = topics.filter({ has: page.getByRole("heading", { name: topicId, exact: true }) });
      await expect(section.getByText(`Synthetic ${topicId} alert`)).toBeVisible();
      await expect(section.getByText(`Synthetic ${topicId} finding is linked to the visible alert.`)).toBeVisible();
    }
    for (const topicId of scenario.expected_denied) {
      const section = topics.filter({ has: page.getByRole("heading", { name: topicId, exact: true }) });
      await expect(section.getByText("denied", { exact: true })).toBeVisible();
      await expect(section.getByText(/Synthetic .* (alert|finding)/)).toHaveCount(0);
    }
    for (const topicId of scenario.expected_failed ?? []) {
      const section = topics.filter({ has: page.getByRole("heading", { name: topicId, exact: true }) });
      await expect(section.getByText("unavailable", { exact: true })).toBeVisible();
      await expect(page.getByRole("group", { name: "Select unfinished topics" }).getByText(topicId)).toBeVisible();
      await expect(section.getByText(/Synthetic .* (alert|finding)/)).toHaveCount(0);
    }
    await expect(page.locator("#answer-status")).toContainText(scenario.status);
  });
}

test("Spanish mobile layout can cancel an in-flight question", async ({ page }) => {
  await page.setViewportSize({ width: 390, height: 844 });
  await stubBootstrap(page);
  await page.route("**/v1/questions", async (route) => {
    await new Promise((resolve) => setTimeout(resolve, 300));
    await route.fulfill({ status: 200, json: answer() });
  });
  await page.goto("/");
  await page.getByLabel("Language").selectOption("es");
  await expect(page.getByRole("heading", { name: "Investigación de seguridad" })).toBeVisible();
  await page.getByRole("textbox", { name: "Pregunta" }).fill("muestra alertas de autenticación");
  await page.getByRole("button", { name: "Preguntar a SOC" }).click();
  await page.getByRole("button", { name: "Cancelar" }).click();

  await expect(page.getByRole("status").first()).toHaveText("Solicitud cancelada.");
  await expect(page.getByRole("button", { name: "Preguntar a SOC" })).toBeEnabled();
  await expect(page.locator("body")).toHaveJSProperty("scrollWidth", 390);
});

test("selected continuation, paging and feedback use their real REST paths", async ({ page }) => {
  await stubBootstrap(page);
  const requests: Array<{ path: string; body: unknown }> = [];
  await page.route("**/v1/questions", async (route) => {
    const body = route.request().postDataJSON() as { question: string; continue_topic_ids?: string[] };
    requests.push({ path: "/v1/questions", body });
    const result = body.continue_topic_ids ? answer("answered") : answer();
    await route.fulfill({ status: 200, json: result });
  });
  await page.route("**/v1/fetches/page", async (route) => {
    const body = route.request().postDataJSON() as { environment_id: string; cursor: string };
    requests.push({ path: "/v1/fetches/page", body });
    await route.fulfill({
      status: 200,
      json: {
        rows: [{ values: { rule: "Second synthetic row" } }],
        next_cursor: null,
        message: "<img src=paging onerror=alert(2)>",
      },
    });
  });
  await page.route("**/v1/feedback", async (route) => {
    const body = route.request().postDataJSON() as { question_id: string; feedback_receipt: string; kind: string };
    requests.push({ path: "/v1/feedback", body });
    await route.fulfill({ status: 202, json: { feedback_id: "33333333-3333-4333-8333-333333333333", status: "queued" } });
  });
  await page.goto("/");
  await page.getByRole("textbox", { name: "Question" }).fill("show authentication alerts");
  await page.getByRole("button", { name: "Ask SOC" }).click();
  await page.getByLabel("tls").uncheck();
  await page.getByRole("button", { name: "Continue selected topics" }).click();
  await page.getByRole("button", { name: "Load more rows" }).click();
  await page.getByLabel("Optional note").fill("Check the synthetic finding");
  await page.getByRole("button", { name: "This answer is wrong" }).click();

  await expect(page.getByText("Second synthetic row")).toBeVisible();
  await expect(page.getByText("<img src=paging onerror=alert(2)>", { exact: true })).toBeVisible();
  await expect(page.locator("img")).toHaveCount(0);
  await expect(page.getByText("Feedback sent for human review.")).toBeVisible();
  expect(requests[1]?.body).toMatchObject({
    followup_id: "22222222-2222-4222-8222-222222222222",
    followup_revision: 1,
    continue_topic_ids: ["ldap"],
  });
  expect(requests[2]?.body).toEqual({ environment_id: "alpha", cursor: "cursor-1" });
  expect(requests[3]?.body).toMatchObject({
    question_id: "11111111-1111-4111-8111-111111111111",
    environment_id: "alpha",
    feedback_receipt: "opaque-fixture-receipt",
    kind: "wrong",
  });
});

test("empty paging response still shows its message and closes pagination", async ({ page }) => {
  await stubBootstrap(page);
  await page.route("**/v1/questions", async (route) => {
    await route.fulfill({ status: 200, json: answer() });
  });
  await page.route("**/v1/fetches/page", async (route) => {
    await route.fulfill({
      status: 200,
      json: {
        rows: [],
        next_cursor: null,
        message: "<img src=empty-page onerror=alert(3)>",
      },
    });
  });
  await page.goto("/");
  await page.getByRole("textbox", { name: "Question" }).fill("show authentication alerts");
  await page.getByRole("button", { name: "Ask SOC" }).click();
  await page.getByRole("button", { name: "Load more rows" }).click();

  await expect(page.getByText("<img src=empty-page onerror=alert(3)>", { exact: true })).toBeVisible();
  await expect(page.getByRole("button", { name: "Load more rows" })).toHaveCount(0);
  await expect(page.locator("img")).toHaveCount(0);
});
