/* Local mirror of SOC-009a wire shapes; replace with generated types when that contract lands. */
import type {
    Answer,
    EvidenceItem,
    FetchResult,
    TopicAnswer,
} from "../../../contracts/v1/generated/types.ts";
export type KevOutcome = "hit" | "not_listed" | "unavailable";
export type KevFreshness = "fresh" | "stale" | "not_yet_valid" | "unknown";
export type KevCoverage = "complete" | "incomplete" | "unavailable";
export interface KevPreviewUse {
    outcome: KevOutcome;
    freshness: KevFreshness;
    coverage: KevCoverage;
    cve: string | null;
    added_on: string | null;
    valid_from: string | null;
    expires_at: string | null;
    reason: "not_configured" | "limit" | "lookup_error" | "not_yet_available" | null;
}
export interface KevUseRefPreview {
    approval_key_id: string | null;
    approved_at: string | null;
    content_sha: string;
    evaluation_at: string;
    expires_at: string | null;
    metadata: null;
    pack_sha256: string;
    policy_sha256: string;
    valid_from: string | null;
}
export interface KevContextEvidenceItem {
    evidence_id: string;
    topic_id: "vuln_review";
    fetch_id?: "vuln_rows" | null;
    kind: "context";
    source: {
        role: "page" | "subject";
        kev_use?: KevUseRefPreview | null;
        member_index?: number | null;
        page_evidence_id?: string | null;
        parent_evidence_id?: string | null;
    };
    snapshot: EvidenceItem["snapshot"];
    values: Record<string, string | number | boolean | null | string[]>;
    visibility: EvidenceItem["visibility"];
    scope_hash: string;
}
export type KevPreviewFetch = Omit<FetchResult, "items"> & {
    items: Array<EvidenceItem | KevContextEvidenceItem>;
};
export type KevPreviewTopic = Omit<TopicAnswer, "tables"> & { tables: KevPreviewFetch[] };
export type KevPreviewAnswer = Omit<Answer, "blocks"> & { blocks: KevPreviewTopic[] };
const hash = (seed: number, size = 64) => {
    let state = seed >>> 0;
    let result = "";
    for (let index = 0; index < size; index++) {
        state = (Math.imul(state, 1664525) + 1013904223) >>> 0;
        result += ((state >>> 28) & 15).toString(16);
    }
    return result;
};
const sha = hash(11);
const gitSha = hash(12, 40);
const kevUse = (validFrom: string | null, expiresAt: string | null): KevUseRefPreview => ({
    approval_key_id: null,
    approved_at: null,
    content_sha: gitSha,
    evaluation_at: "2026-10-20T10:00:00Z",
    expires_at: expiresAt,
    metadata: null,
    pack_sha256: hash(12),
    policy_sha256: hash(13),
    valid_from: validFrom,
});
export const kevPreview = [
    {
        outcome: "hit",
        freshness: "fresh",
        coverage: "complete",
        cve: "CVE-2024-3094",
        added_on: "2024-03-29",
        valid_from: "2026-10-19T00:00:00Z",
        expires_at: "2026-10-26T00:00:00Z",
        reason: null,
    },
    {
        outcome: "not_listed",
        freshness: "fresh",
        coverage: "complete",
        cve: "CVE-2024-9999",
        added_on: null,
        valid_from: "2026-10-19T00:00:00Z",
        expires_at: "2026-10-26T00:00:00Z",
        reason: null,
    },
    {
        outcome: "hit",
        freshness: "stale",
        coverage: "incomplete",
        cve: "CVE-2021-44228",
        added_on: "2021-12-10",
        valid_from: "2025-10-01T00:00:00Z",
        expires_at: "2025-10-08T00:00:00Z",
        reason: null,
    },
    {
        outcome: "unavailable",
        freshness: "unknown",
        coverage: "unavailable",
        cve: null,
        added_on: null,
        valid_from: null,
        expires_at: null,
        reason: "lookup_error",
    },
] satisfies KevPreviewUse[];
const contextSnapshot = { kind: "first_page_only" as const, key: sha, at: "2026-10-20T10:00:00Z" };
const pageId = `ev1_${"6".repeat(64)}`;
export const kevContextItems: KevContextEvidenceItem[] = [
    {
        evidence_id: pageId,
        topic_id: "vuln_review",
        fetch_id: "vuln_rows",
        kind: "context",
        source: { role: "page", kev_use: kevUse("2026-10-19T00:00:00Z", "2026-10-26T00:00:00Z") },
        snapshot: contextSnapshot,
        values: {
            kev_lookup: "unavailable",
            kev_freshness: "unknown",
            kev_coverage: "incomplete",
            kev_reason: "limit",
            kev_row_n: 3,
            kev_subject_n: 4,
            kev_annotated_n: 4,
            kev_omitted_n: 0,
            kev_hit_n: 2,
            kev_not_listed_n: 1,
            kev_unavailable_n: 1,
        },
        visibility: "full",
        scope_hash: pageId.slice(4),
    },
    {
        evidence_id: `ev1_${"7".repeat(64)}`,
        topic_id: "vuln_review",
        fetch_id: "vuln_rows",
        kind: "context",
        source: {
            role: "subject",
            kev_use: kevUse("2026-10-19T00:00:00Z", "2026-10-26T00:00:00Z"),
            member_index: 0,
            page_evidence_id: pageId,
            parent_evidence_id: `ev1_${"3".repeat(64)}`,
        },
        snapshot: contextSnapshot,
        values: {
            kev_cve: "CVE-2024-3094",
            kev_lookup: "hit",
            kev_freshness: "fresh",
            kev_added_on: "2024-03-29",
            kev_coverage: "complete",
        },
        visibility: "full",
        scope_hash: `7${"0".repeat(63)}`,
    },
    {
        evidence_id: `ev1_${"8".repeat(64)}`,
        topic_id: "vuln_review",
        fetch_id: "vuln_rows",
        kind: "context",
        source: {
            role: "subject",
            kev_use: kevUse("2026-10-19T00:00:00Z", "2026-10-26T00:00:00Z"),
            member_index: 1,
            page_evidence_id: pageId,
            parent_evidence_id: `ev1_${"3".repeat(64)}`,
        },
        snapshot: contextSnapshot,
        values: {
            kev_cve: "CVE-2024-9999",
            kev_lookup: "not_listed",
            kev_freshness: "fresh",
            kev_added_on: null,
            kev_coverage: "complete",
        },
        visibility: "full",
        scope_hash: `8${"0".repeat(63)}`,
    },
    {
        evidence_id: `ev1_${"9".repeat(64)}`,
        topic_id: "vuln_review",
        fetch_id: "vuln_rows",
        kind: "context",
        source: {
            role: "subject",
            kev_use: kevUse("2025-10-01T00:00:00Z", "2025-10-08T00:00:00Z"),
            member_index: 2,
            page_evidence_id: pageId,
            parent_evidence_id: `ev1_${"3".repeat(64)}`,
        },
        snapshot: contextSnapshot,
        values: {
            kev_cve: "CVE-2021-44228",
            kev_lookup: "hit",
            kev_freshness: "stale",
            kev_added_on: "2021-12-10",
            kev_coverage: "incomplete",
        },
        visibility: "full",
        scope_hash: `9${"0".repeat(63)}`,
    },
    {
        evidence_id: `ev1_${"a".repeat(64)}`,
        topic_id: "vuln_review",
        fetch_id: "vuln_rows",
        kind: "context",
        source: {
            role: "subject",
            kev_use: kevUse(null, null),
            member_index: 3,
            page_evidence_id: pageId,
            parent_evidence_id: `ev1_${"3".repeat(64)}`,
        },
        snapshot: contextSnapshot,
        values: {
            kev_cve: "CVE-2099-0004",
            kev_lookup: "unavailable",
            kev_freshness: "unknown",
            kev_added_on: null,
            kev_coverage: "unavailable",
            kev_reason: "lookup_error",
        },
        visibility: "full",
        scope_hash: `a${"0".repeat(63)}`,
    },
];
export function makeKevAnswer(base: Answer): KevPreviewAnswer {
    return {
        ...base,
        blocks: base.blocks.map((block) =>
            block.topic_id === "vuln_review"
                ? {
                      ...block,
                      tables: block.tables.map((table) => {
                          const subjects = kevContextItems.filter(
                              (item) => item.source.role === "subject",
                          );
                          const boundSubjects = subjects.flatMap((item) => {
                              const row = table.rows.find(
                                  (candidate) =>
                                      candidate.values["vulnerability.id"] === item.values.kev_cve,
                              );
                              return row
                                  ? [
                                        {
                                            ...item,
                                            source: {
                                                ...item.source,
                                                parent_evidence_id: row.evidence_id,
                                            },
                                        },
                                    ]
                                  : [];
                          });
                          return {
                              ...table,
                              items: [...table.items, kevContextItems[0]!, ...boundSubjects],
                          };
                      }),
                  }
                : block,
        ),
    };
}
