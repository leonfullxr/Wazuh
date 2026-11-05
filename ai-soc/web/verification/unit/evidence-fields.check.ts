import { describe, expect, it } from "vitest";
import { isFlatRecord } from "../../src/lib/utils";

describe("isFlatRecord", () => {
    it("accepts objects of primitive fields and rejects everything else", () => {
        expect(isFlatRecord({ ordinal: 1, stage_id: "ssh_failure", ok: true, note: null })).toBe(
            true,
        );
        expect(isFlatRecord({ nested: { a: 1 } })).toBe(false);
        expect(isFlatRecord({ ids: ["a", "b"], confidence: 0.9 })).toBe(true);
        expect(isFlatRecord({ list: [{ a: 1 }] })).toBe(false);
        expect(isFlatRecord([1, 2])).toBe(false);
        expect(isFlatRecord("text")).toBe(false);
        expect(isFlatRecord(null)).toBe(false);
    });
});

import { fmtRange } from "../../src/features/incidents/M3WorkspacePage";

describe("fmtRange", () => {
    it("shows the date once for a same-day range and both dates otherwise", () => {
        const sameDay = fmtRange("2026-10-23T09:12:00Z", "2026-10-23T09:14:00Z");
        const twoDays = fmtRange("2026-10-23T23:50:00Z", "2026-10-24T00:10:00Z");
        expect(sameDay.split(" – ")).toHaveLength(2);
        expect(sameDay.split(" – ")[1]).not.toMatch(/2026/);
        expect(twoDays.split(" – ")[1]).toMatch(/2026/);
    });
});
