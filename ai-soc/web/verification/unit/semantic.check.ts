import { describe, expect, it } from "vitest";
import { answerStatusTags, healthTags, judgmentStateTags, severityTag, statusTags } from "../../src/lib/semantic";

describe("semantic tags", () => {
    it("keeps severity boundaries and dots consistent", () => {
        expect([0, 6, 7, 11, 12, 14, 15].map(severityTag)).toEqual([
            { tone: "neutral", dot: true }, { tone: "neutral", dot: true },
            { tone: "amber", dot: true }, { tone: "amber", dot: true },
            { tone: "orange", dot: true }, { tone: "orange", dot: true },
            { tone: "red", dot: true },
        ]);
        expect(severityTag("info")).toEqual({ tone: "neutral", dot: false });
    });

    it("distinguishes outcomes, status, and health", () => {
        expect(answerStatusTags.refused.tone).toBe("neutral");
        expect(judgmentStateTags.invalid_output.tone).toBe("red");
        expect(statusTags.resolved.tone).toBe("green");
        expect(healthTags.unknown).toEqual({ tone: "neutral", dot: true });
    });
});
