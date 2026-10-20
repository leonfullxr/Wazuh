import AxeBuilder from "../../ui/node_modules/@axe-core/playwright/dist/index.mjs";
import { expect, test } from "../../ui/node_modules/@playwright/test/index.mjs";
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";

const g053FixtureBytes = readFileSync(
  resolve(process.cwd(), "../tests/unit/application/data/g053_provider_token_cases.json"),
);
const g053Fixture = JSON.parse(g053FixtureBytes.toString("utf8")) as {
  hostile_first_token: string;
  cases: Record<string, { expected_judgment_state: string }>;
};
const g053FixtureSha256 = "21598a271610d1986d7a575aad0ebf96289e19c9bbb57dc5b7a46c518a386e19";

for (const variant of ["positive", "negative", "boundary", "failure"] as const) {
  test(`actual application G053 answer stays sanitized in browser routes: ${variant}`, async ({ page }) => {
    expect(createHash("sha256").update(g053FixtureBytes).digest("hex")).toBe(g053FixtureSha256);
    test.info().annotations.push(
      { type: "acceptance_ids", description: "G053" },
      { type: "case_id", description: "B5-G053.provider-token-application" },
      { type: "variant", description: variant },
      { type: "fixture_sha256", description: g053FixtureSha256 },
    );
    const requests: string[] = [];
    page.on("request", (request) => requests.push(new URL(request.url()).pathname));
    await page.goto("/");

    await expect(page.getByLabel("Site")).toHaveValue("alpha");
    await page.getByRole("textbox", { name: "Question" }).fill(`g053:${variant}`);
    const answerResponsePromise = page.waitForResponse(
      (response) => new URL(response.url()).pathname === "/v1/questions",
    );
    await page.getByRole("button", { name: "Ask SOC" }).click();
    const answerResponse = await answerResponsePromise;
    expect(answerResponse.status()).toBe(200);
    const serializedAnswer = await answerResponse.text();
    expect(serializedAnswer).not.toContain(g053Fixture.hostile_first_token);
    expect(serializedAnswer).not.toContain("PRIVATE-CONVERSE-TIMEOUT:");
    const answer: { blocks: Array<{ topic_id: string; judgment: { state: string } }> } =
      JSON.parse(serializedAnswer);
    const vpn = answer.blocks.find((block) => block.topic_id === "vpn");
    expect(vpn?.judgment.state).toBe(g053Fixture.cases[variant].expected_judgment_state);
    await expect(page.getByText(g053Fixture.hostile_first_token)).toHaveCount(0);
    expect(requests).toContain("/v1/bootstrap");
    expect(requests).toContain("/v1/questions");
    const accessibility = await new AxeBuilder({ page }).analyze();
    expect(accessibility.violations).toEqual([]);
  });
}

test("wrong Origin is rejected by the real route before application work", async ({ page }) => {
  await page.goto("/");
  const before = await page.request.get("/__fixture/counters");
  const baseline = await before.json();
  const denied = await page.request.post("/v1/questions", {
    data: { question: "show alerts", environment_id: "alpha" },
    headers: { Origin: "http://attacker.example.test" },
  });
  expect(denied.status()).toBe(403);
  expect((await denied.json()).code).toBe("CSRF_DENIED");
  const counters = await page.request.get("/__fixture/counters");
  expect(await counters.json()).toEqual(baseline);
});
