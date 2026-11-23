import { describe, expect, it } from "vitest";
import { answerStatusTags, healthTags, judgmentStateTags, severityTag, statusTags } from "../../src/lib/semantic";

describe("semantic tags", () => {
    it("keeps severity boundaries and dots consistent", () => {
        expect([0, 6, 7, 9, 10, 11, 12, 15].map(severityTag)).toEqual(
            ["green", "green", "amber", "amber", "orange", "orange", "red", "red"].map(
                (tone) => ({ tone, dot: true, variant: "severity" }),
            ),
        );
        expect(severityTag("info")).toEqual({ tone: "neutral", dot: false, variant: "severity" });
    });

    it("distinguishes outcomes, status, and health", () => {
        expect(answerStatusTags.refused.tone).toBe("neutral");
        expect(judgmentStateTags.invalid_output.tone).toBe("red");
        expect(statusTags.resolved.tone).toBe("green");
        expect(healthTags.unknown).toEqual({ tone: "neutral", dot: true });
    });
});
