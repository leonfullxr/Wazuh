import { describe, expect, it } from "vitest";
import { isFlatRecord } from "../../src/lib/utils";

describe("isFlatRecord", () => {
    it("accepts objects of primitive fields and rejects everything else", () => {
        expect(isFlatRecord({ ordinal: 1, stage_id: "ssh_failure", ok: true, note: null })).toBe(true);
        expect(isFlatRecord({ nested: { a: 1 } })).toBe(false);
        expect(isFlatRecord({ ids: ["a", "b"], confidence: 0.9 })).toBe(true);
        expect(isFlatRecord({ list: [{ a: 1 }] })).toBe(false);
        expect(isFlatRecord([1, 2])).toBe(false);
        expect(isFlatRecord("text")).toBe(false);
        expect(isFlatRecord(null)).toBe(false);
    });
});
