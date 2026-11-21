import { describe, expect, it } from "vitest";
import { citationSummary, shortEvidenceId } from "../../src/features/queue/citation-summary";

const evidenceId = `ev1_${"ab".repeat(32)}`;

describe("assessment citation labels", () => {
    it("names the rule, agent, and source instead of the evidence id", () => {
        expect(
            citationSummary({
                rule_id: "5712",
                agent: "web-01",
                source: "203.0.113.8",
            }),
        ).toBe("Rule 5712 · web-01 · 203.0.113.8");
        expect(citationSummary({})).toBe("");
    });

    it("keeps a short evidence id readable", () => {
        expect(shortEvidenceId(evidenceId)).toBe("ev1_ababab…abab");
        expect(shortEvidenceId(evidenceId)).not.toBe(evidenceId);
        expect(shortEvidenceId("short-id")).toBe("short-id");
    });
});
