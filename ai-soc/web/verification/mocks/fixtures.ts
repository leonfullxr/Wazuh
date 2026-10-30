import type {
    Answer,
    DomainError,
    FetchResult,
    EvidenceItem,
} from "../../../contracts/v1/generated/types.ts";
import { bootstrapFixture, errorResponse, feedbackQueued } from "./fixture-metadata";

export { bootstrapFixture, errorResponse, feedbackQueued };

import {
    authCols,
    cols,
    count,
    distinctEvidenceId,
    fetch,
    judgment,
    gitSha,
    one,
    provenance,
    qid,
    snapshot,
    topic,
    trace,
    hash,
    vulnCols,
    window,
    withBucket,
} from "./fixture-builders";

const ldapItem = one("ldap", "ldap_rows", "ev1_" + "1".repeat(64), "rule.id", "5710");
const authItem = one("auth_review", "auth_rows", "ev1_" + "2".repeat(64), "rule.id", "5501");
const vulnItem = one(
    "vuln_review",
    "vuln_rows",
    "ev1_" + "3".repeat(64),
    "vulnerability.id",
    "CVE-2024-3094",
);
const ldapAggregate: EvidenceItem = {
    ...ldapItem,
    evidence_id: distinctEvidenceId(),
    fetch_id: "ldap_recent_alert_count",
    kind: "aggregate",
    source: {
        template_id: "alerts_count_v1",
        window,
        filters: [],
        scope: "matching_visible_records",
    },
    values: { count: 2, relation: "eq", approximate: false },
};
const ldapAggregateFetch: FetchResult = {
    ...fetch("ldap", "ldap_recent_alert_count", ldapAggregate, []),
    rows: [],
    columns: [],
    count: count(2),
    items: [ldapAggregate],
    scope: {
        ...fetch("ldap", "ldap_recent_alert_count", ldapAggregate, []).scope,
        displayed_rows: 0,
        template_id: "alerts_count_v1",
    },
};
const answeredBlocks = [
    topic("ldap", 0, ldapAggregateFetch, ldapAggregate, true),
    {
        ...topic(
            "auth_review",
            1,
            withBucket(
                fetch("auth_review", "auth_rows", authItem, authCols, {
                    message:
                        "Paging is unavailable because a stable three-part cursor boundary was not available.",
                }),
                "5501",
                "rule.id",
            ),
            authItem,
        ),
        judgment: {
            ...judgment("auth_review", authItem.evidence_id),
            state: "not_requested" as const,
            sentences: [],
            removed: [],
            message: null,
            model_id: "synthetic-model",
            effort: null,
            usage: null,
        },
    },
    {
        ...topic(
            "vuln_review",
            2,
            withBucket(
                fetch("vuln_review", "vuln_rows", vulnItem, vulnCols, {
                    message:
                        "Paging is unavailable because a stable three-part cursor boundary was not available.",
                }),
                "High",
                "vulnerability.severity",
            ),
            vulnItem,
            true,
        ),
        judgment: {
            ...judgment("vuln_review", vulnItem.evidence_id),
            state: "not_requested" as const,
            sentences: [],
            removed: [],
            message: null,
            model_id: "synthetic-model",
            effort: null,
            usage: null,
        },
    },
];

export const answered = {
    schema_version: "1",
    question_id: qid,
    environment_id: "synthetic",
    language: "en",
    status: "answered",
    blocks: answeredBlocks,
    followup_id: "12345678-1234-4234-8234-123456789abc",
    followup_revision: 1,
    left_out: [],
    feedback_receipt: "synthetic-feedback-receipt",
    trace_id: trace,
    provenance,
} satisfies Answer;
const capturedDocuments: Record<string, string> = {
    ldap: "Synthetic LDAP setup example",
    auth_review: "Authentication failure review",
    vuln_review: "Vulnerability record review",
};
export const singleTopicAnswers: Record<string, Answer> = Object.fromEntries(
    answeredBlocks.map((block) => {
        const tables = block.tables.map((table) => {
            const filters: FetchResult["scope"]["filters"] =
                block.topic_id === "auth_review"
                    ? [{ field: "rule.groups", op: "eq", value: "authentication_failed" }]
                    : block.topic_id === "vuln_review"
                      ? [
                            {
                                field: "vulnerability.severity",
                                op: "in",
                                value: ["High", "Critical"],
                            },
                        ]
                      : [{ field: "rule.groups", op: "eq", value: "ldap" }];
            const rows = table.rows.slice(0, 2);
            const countItem: EvidenceItem = {
                ...(table.items.find((item) => item.kind === "aggregate") ?? table.items[0]!),
                evidence_id: distinctEvidenceId(),
                topic_id: block.topic_id,
                fetch_id: table.fetch_id,
                kind: "aggregate",
                source: {
                    template_id: table.scope.template_id,
                    window: table.window,
                    filters,
                    scope: "matching_visible_records",
                },
                values: { count: 2, relation: "eq", approximate: false },
            };
            const rowItems = table.items.filter((item) => item.kind === "row").slice(0, 2);
            return {
                ...table,
                scope: { ...table.scope, filters, displayed_rows: rows.length },
                rows,
                count: count(2),
                items: [...rowItems, countItem],
                buckets: [],
                bucket_completeness: "complete" as const,
            } satisfies FetchResult;
        });
        const capturedJudgment =
            block.topic_id === "ldap"
                ? {
                      state: "validated" as const,
                      model_id: "synthetic-model",
                      effort: null,
                      sentences: [
                          {
                              finding_id: "synthetic-grounded-finding",
                              kind: "observation" as const,
                              text: "The synthetic LDAP example reports only 2 as its configured visible count.",
                              evidence_ids: [
                                  tables.flatMap((table) => table.items)[0]!.evidence_id,
                              ],
                          },
                      ],
                      removed: [],
                      usage: {
                          topic_id: "ldap",
                          input_tokens: 128,
                          output_tokens: 16,
                          cache_read_input_tokens: 0,
                          cache_write_input_tokens: 0,
                          total_input_tokens: 128,
                          reserved_tokens: 1408,
                          reservation_id: "fcbb28ef-8cd4-4999-99b8-62d7311403c6",
                      },
                      message: null,
                  }
                : block.judgment;
        const capturedBlock = {
            ...block,
            tables,
            ordinal: 0,
            judgment: capturedJudgment,
            document: {
                ...(block.document ?? {
                    anchor: "review",
                    content_sha: gitSha,
                    document_id: `${block.topic_id}-guide`,
                    document_sha256: hash(8),
                    source_path: `docs/${block.topic_id}.md`,
                    url: `https://example.invalid/docs/${block.topic_id}`,
                }),
                heading: capturedDocuments[block.topic_id]!,
            },
        };
        return [block.topic_id, { ...answered, blocks: [capturedBlock] }];
    }),
);

const deniedError: DomainError = {
    code: "INDEXER_DENIED",
    message: "Synthetic read was denied.",
    retryable: false,
    trace_id: trace,
};
const unavailableError: DomainError = {
    code: "INDEXER_UNAVAILABLE",
    message: "Synthetic index service is unavailable.",
    retryable: true,
    trace_id: trace,
};
const partialItem = one("ldap", "ldap_rows", "ev1_" + "4".repeat(64), "rule.id", "5710");
const partialBlocks = [
    {
        ...topic(
            "ldap",
            0,
            fetch("ldap", "ldap_rows", partialItem, cols, { state: "denied", error: deniedError }),
            partialItem,
        ),
        judgment: judgment("ldap", partialItem.evidence_id, "denial"),
    },
    {
        ...topic(
            "auth_review",
            1,
            fetch("auth_review", "auth_rows", authItem, authCols, {
                state: "unavailable",
                error: unavailableError,
            }),
            authItem,
        ),
        judgment: judgment("auth_review", authItem.evidence_id, "evidence_unavailable"),
    },
    {
        ...topic(
            "vuln_review",
            2,
            fetch("vuln_review", "vuln_rows", vulnItem, vulnCols, { count: count(5, true) }),
            vulnItem,
        ),
        judgment: judgment("vuln_review", vulnItem.evidence_id, "model_unavailable"),
    },
];
export const partial = {
    ...answered,
    question_id: "11111111-1111-4111-8111-111111111111",
    trace_id: "11111111111111111111111111111111",
    feedback_receipt: "synthetic-feedback-partial",
    status: "partial",
    blocks: partialBlocks,
    left_out: [
        {
            topic_id: "auth_review",
            stage: "fetch",
            reason: "evidence_unavailable",
            retryable: true,
        },
        {
            topic_id: "vuln_review",
            stage: "judgment",
            reason: "model_unavailable",
            retryable: true,
        },
    ],
} satisfies Answer;
export const clarify = {
    ...answered,
    question_id: "22222222-2222-4222-8222-222222222222",
    trace_id: "22222222222222222222222222222222",
    feedback_receipt: "synthetic-feedback-clarify",
    status: "clarify",
    blocks: [],
    clarify: {
        kind: "missing_slots",
        question: "Which time window should be reviewed?",
        slots: ["time_window"],
    },
    followup_id: null,
    followup_revision: null,
} satisfies Answer;
export const modelSelection = {
    ...clarify,
    question_id: "33333333-3333-4333-8333-333333333333",
    trace_id: "33333333333333333333333333333333",
    feedback_receipt: "synthetic-feedback-model-selection",
    clarify: {
        kind: "model_selection",
        question: "Choose a model before judgment.",
        slots: ["model_id"],
    },
} satisfies Answer;
export const refused = {
    ...answered,
    question_id: "44444444-4444-4444-8444-444444444444",
    trace_id: "44444444444444444444444444444444",
    feedback_receipt: "synthetic-feedback-refused",
    status: "refused",
    blocks: [],
    message: "The request could not be mapped to an approved security topic.",
    followup_id: null,
    followup_revision: null,
} satisfies Answer;
const emptyUnknownItem = one(
    "auth_review",
    "auth_rows",
    "ev1_" + "5".repeat(64),
    "rule.id",
    "5501",
    "unknown",
);
const emptyFilteredItem = one(
    "ldap",
    "ldap_rows",
    distinctEvidenceId(),
    "rule.id",
    "5710",
    "filtered",
);
// A genuine empty read: full visibility, but window ingestion is not confirmed.
const emptyFullItem = one(
    "vuln_review",
    "vuln_rows",
    distinctEvidenceId(),
    "vulnerability.id",
    "CVE-2024-3094",
);
const emptyProof = (visibility: "full" | "filtered" | "unknown") => ({
    consistency: "unconfirmed" as const,
    filter_probes: [],
    index_exists: "unknown" as const,
    items: [],
    matched_nothing: [],
    snapshot,
    visibility,
    window_has_data: "unknown" as const,
    window_count: count(0),
});
export const filtered = {
    ...answered,
    question_id: "55555555-5555-4555-8555-555555555555",
    trace_id: "55555555555555555555555555555555",
    feedback_receipt: "synthetic-feedback-filtered",
    status: "partial",
    blocks: [
        {
            ...topic(
                "ldap",
                0,
                fetch("ldap", "ldap_rows", emptyFilteredItem, cols, {
                    state: "filtered",
                    visibility: "filtered",
                    count: count(0),
                    proof: emptyProof("filtered"),
                }),
                emptyFilteredItem,
            ),
            judgment: judgment("ldap", emptyFilteredItem.evidence_id, "ingestion_unconfirmed"),
        },
        {
            ...topic(
                "auth_review",
                1,
                fetch("auth_review", "auth_rows", emptyUnknownItem, cols, {
                    state: "rows",
                    visibility: "unknown",
                }),
                emptyUnknownItem,
            ),
            judgment: judgment(
                "auth_review",
                emptyUnknownItem.evidence_id,
                "ingestion_unconfirmed",
            ),
        },
        {
            ...topic(
                "vuln_review",
                2,
                fetch("vuln_review", "vuln_rows", emptyFullItem, vulnCols, {
                    state: "empty",
                    visibility: "full",
                    count: count(0),
                    proof: emptyProof("full"),
                }),
                emptyFullItem,
            ),
            judgment: judgment("vuln_review", emptyFullItem.evidence_id, "ingestion_unconfirmed"),
        },
    ],
} satisfies Answer;
export const paged = {
    ...answered,
    question_id: "66666666-6666-4666-8666-666666666666",
    trace_id: "66666666666666666666666666666666",
    feedback_receipt: "synthetic-feedback-paged",
    blocks: [
        {
            ...answeredBlocks[2]!,
            tables: [
                fetch("vuln_review", "vuln_rows", vulnItem, vulnCols, {
                    cursor: "synthetic-next-cursor",
                    count: count(18),
                }),
            ],
        },
    ],
} satisfies Answer;
const pagedBase = paged.blocks[0]!.tables[0]!;
export const pageResponses: FetchResult[] = [1, 2].map((pageNumber) => {
    const rows = pagedBase.rows.map((row, index) => {
        const evidence_id = `ev1_${(3000 + pageNumber * 20 + index).toString(16).padStart(64, "0")}`;
        return {
            ...row,
            evidence_id,
            record_ref: {
                index_alias: "synthetic-vulnerabilities",
                record_id: `vuln-page-${pageNumber}-record-${index + 1}`,
            },
            values: {
                ...row.values,
                "agent.name": `synthetic-vulnerability-page-${pageNumber}-${index + 1}`,
            },
        };
    });
    const items = rows.map((row) => ({
        ...pagedBase.items[0]!,
        evidence_id: row.evidence_id,
        scope_hash: hash(Number.parseInt(row.evidence_id.slice(-2), 16) || 1),
        source: { index_alias: "synthetic-vulnerabilities", record_id: row.record_ref!.record_id },
        values: row.values,
    }));
    return {
        ...pagedBase,
        scope: { ...pagedBase.scope, snapshot: "pit" },
        snapshot: { ...pagedBase.snapshot, kind: "pit", expires_at: "2026-10-20T10:05:00Z" },
        rows,
        items: items.map((item) => ({
            ...item,
            snapshot: { ...pagedBase.snapshot, kind: "pit", expires_at: "2026-10-20T10:05:00Z" },
        })),
        next_cursor: pageNumber === 1 ? "synthetic-page-2" : "expired",
    };
});

export const answeredEs = {
    ...answered,
    question_id: "77777777-7777-4777-8777-777777777777",
    trace_id: "77777777777777777777777777777777",
    feedback_receipt: "synthetic-feedback-spanish",
    language: "es" as const,
} satisfies Answer;
export const fetchFixtures = [ldapItem, authItem, vulnItem];
export const allAnswers: Record<string, Answer> = {
    answered,
    partial,
    clarify,
    modelSelection,
    clarify_model: modelSelection,
    refused,
    filtered,
    paged,
};
export { deniedError, unavailableError };
