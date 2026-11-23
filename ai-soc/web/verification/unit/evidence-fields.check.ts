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

import { compactId } from "../../src/features/incidents/NarrativePanel";

describe("compactId", () => {
    it("keeps short ids and shortens long ones to head and tail", () => {
        expect(compactId("chain-demo-001")).toBe("chain-demo-001");
        const long = "a".repeat(12) + "b".repeat(40) + "c".repeat(8);
        expect(compactId(long)).toBe(`${"a".repeat(12)}…${"c".repeat(8)}`);
    });
});

import { humanizeKey } from "../../src/lib/utils";

describe("humanizeKey", () => {
    it("turns API keys into sentence-case labels with acronyms", () => {
        expect(humanizeKey("evidence_ids")).toBe("Evidence IDs");
        expect(humanizeKey("group_id")).toBe("Group ID");
        expect(humanizeKey("added_at")).toBe("Added at");
        expect(humanizeKey("host")).toBe("Host");
        expect(humanizeKey("count_30d")).toBe("Count 30d");
        expect(humanizeKey("docs_manifest_sha256")).toBe("Docs manifest SHA-256");
    });
});
import { createElement } from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { HashText } from "../../src/features/incidents/NarrativePanel";

describe("HashText", () => {
    it("names a known group instead of its hash", () => {
        const hash = "a".repeat(64);
        const html = renderToStaticMarkup(
            createElement(HashText, {
                text: `Group ${hash} has a score.`,
                locale: "en",
                groupTitles: new Map([[hash, "Repeated SSH failures"]]),
            }),
        );
        expect(html).toBe('Group <span class="ent">Repeated SSH failures</span> has a score.');
    });
    it("shows an unknown hash as a prefixed ID chip with the full value in the title", () => {
        const hash = "a".repeat(64);
        const html = renderToStaticMarkup(
            createElement(HashText, { text: `Group ${hash} has a score.`, locale: "en" }),
        );
        expect(html.startsWith("Group ")).toBe(true);
        expect(html).toContain(`title="Full group ID: ${hash}"`);
        expect(html).toContain("grp_</span>aaaaaa");
        expect(html).not.toContain(`>${hash}<`);
        expect(html.endsWith(" has a score.")).toBe(true);
    });
    it("sets host ids as entities and rule numbers as plain text", () => {
        const html = renderToStaticMarkup(
            createElement(HashText, {
                text: "Rule 5763 was observed on agent agent-042 for a first-page read.",
                locale: "en",
            }),
        );
        expect(html).toContain('agent <span class="ent">agent-042</span>');
        expect(html).toContain("Rule 5763 was");
        expect(html).toContain("first-page read.");
    });
    it("renders ISO timestamps in prose as dates", () => {
        const html = renderToStaticMarkup(
            createElement(HashText, { text: "seen at 2026-10-23T09:12:00+00:00.", locale: "en" }),
        );
        expect(html).toContain('<time dateTime="2026-10-23T09:12:00+00:00">');
        expect(html).not.toContain(">2026-10-23T09:12");
        expect(html.endsWith("</time>.")).toBe(true);
    });
});
