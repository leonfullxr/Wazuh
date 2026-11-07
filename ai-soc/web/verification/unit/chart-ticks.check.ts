import { describe, expect, it } from "vitest";
import { niceTicks } from "../../src/features/overview/OverviewPage";

describe("niceTicks", () => {
    it("starts at zero, steps by 1/2/5 x 10^n and covers the maximum", () => {
        expect(niceTicks(0)).toEqual([0, 1]);
        expect(niceTicks(5)).toEqual([0, 2, 4, 6]);
        expect(niceTicks(12)).toEqual([0, 5, 10, 15]);
        expect(niceTicks(31)).toEqual([0, 20, 40]);
        expect(niceTicks(100)).toEqual([0, 50, 100]);
    });
});
