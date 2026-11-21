import { describe, expect, it } from "vitest";
import { falsePositiveReasonText } from "../../src/i18n/workspace-copy";

const labels: Record<string, string> = {
    m3Reason_test_activity: "Test activity",
    m3Reason_other: "Other",
};

describe("false-positive reason text", () => {
    const t = (key: string) => labels[key] ?? key;

    it("uses the translated label and keeps an unknown code", () => {
        expect(falsePositiveReasonText(t, "test_activity")).toBe("Test activity");
        expect(falsePositiveReasonText(t, "not_a_reason")).toBe("not_a_reason");
    });
});
