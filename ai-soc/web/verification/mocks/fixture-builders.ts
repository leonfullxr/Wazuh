import { authCols, cols, vulnCols } from "./fixture-columns";

export { authCols, cols, vulnCols };

import type {
    CheckOutcome,
    Count,
    DomainError,
    EvidenceItem,
    FetchResult,
    SnapshotRef,
} from "../../../contracts/v1/generated/types.ts";

const hex = (seed: number, size: number) => {
    let state = seed >>> 0;
    let result = "";
    for (let index = 0; index < size; index++) {
        state = (Math.imul(state, 1664525) + 1013904223) >>> 0;
        result += ((state >>> 28) & 15).toString(16);
    }
    return result;
};
export const hash = (value: number) => hex(value, 64);
export const commit = (value: number) => hex(value, 40);
export const sha = hash(1);
export const gitSha = commit(2);
export const at = "2026-10-20T10:00:00Z";
export const qid = "0f1e2d3c-4b5a-6978-9012-3456789abcde";
export const trace = "1234567890abcdef1234567890abcdef";
export const snapshot: SnapshotRef = { kind: "first_page_only", key: sha, at };
export const policy = hash(3);
export const window = {
    start: "2026-10-19T10:00:00Z",
    end: at,
    semantics: "rolling" as const,
    source_text: "last 24 hours",
    timezone: "UTC",
    anchor_at: at,
};
export const provenance = {
    content_repository: "https://example.invalid/synthetic-content",
    content_sha: gitSha,
    contract_version: "1" as const,
    docs_manifest_sha256: hash(4),
    docs_origin: "https://example.invalid",
    image_digest: `sha256:${hash(5)}`,
    pack_sha256: hash(6),
    service_sha: gitSha,
};
let evidenceSequence = 100;
export const distinctEvidenceId = () =>
    `ev1_${(evidenceSequence++).toString(16).padStart(64, "0")}`;
export const one = (
    topic: string,
    fetchId: string,
    evidenceId: string,
    key: string,
    value: string,
    visibility: "full" | "filtered" | "unknown" = "full",
): EvidenceItem => ({
    evidence_id: evidenceId,
    topic_id: topic,
    fetch_id: fetchId,
    kind: "row",
    scope_hash: hash(Number.parseInt(evidenceId.slice(-2), 16) || 1),
    snapshot,
    source: {
        index_alias: topic === "vuln_review" ? "synthetic-vulnerabilities" : "synthetic-alerts",
        record_id: `${topic}-record-01`,
    },
    values: { [key]: value, timestamp: at, "agent.name": "synthetic-web-01" },
    visibility,
});
export const count = (value: number, approximate = false): Count => ({
    value,
    relation: approximate ? "gte" : "eq",
    approximate,
    computed_by: "indexer",
    scope: "matching_visible_records",
});
export const fetch = (
    topic: string,
    id: string,
    evidence: EvidenceItem,
    fields: Array<{
        field:
            | "timestamp"
            | "agent.name"
            | "rule.id"
            | "data.srcip"
            | "data.dstip"
            | "agent.id"
            | "rule.level"
            | "rule.groups"
            | "vulnerability.id"
            | "vulnerability.severity"
            | "vulnerability.detected_at"
            | "package.name"
            | "package.version";
        kind: "text" | "integer" | "date" | "ip";
        label: { en: string; es: string };
    }>,
    opts: {
        state?: FetchResult["state"];
        visibility?: "full" | "filtered" | "unknown";
        count?: Count;
        error?: DomainError;
        cursor?: string;
        proof?: FetchResult["empty_proof"];
        message?: string;
    } = {},
): FetchResult => {
    const hidden =
        opts.state === "denied" ||
        opts.state === "unavailable" ||
        opts.state === "empty" ||
        (opts.state === "filtered" && opts.count?.value === 0);
    const visibleRows = hidden
        ? []
        : Array.from({ length: 6 }, (_, index) => {
              const evidenceId = index === 0 ? evidence.evidence_id : distinctEvidenceId();
              const timestamp = new Date(Date.parse(at) - index * 60 * 60 * 1000).toISOString();
              const values = {
                  ...evidence.values,
                  timestamp,
                  ...(topic === "auth_review"
                      ? {
                            "agent.id": String(201 + index),
                            "agent.name": `auth-${index + 1}.example.test`,
                            "rule.id": String(5710 + index),
                            "rule.level": 10,
                            "rule.groups": ["authentication_failed"],
                            "data.srcip": "192.0.2.41",
                            "data.dstip": null,
                        }
                      : topic === "vuln_review"
                        ? {
                              "agent.id": String(101 + index),
                              "agent.name": `host-${index + 1}.example.test`,
                              "vulnerability.detected_at": timestamp,
                              "vulnerability.id":
                                  index === 0
                                      ? (evidence.values["vulnerability.id"] ?? null)
                                      : ([
                                            "CVE-2024-9999",
                                            "CVE-2021-44228",
                                            `CVE-2099-${String(index + 1).padStart(4, "0")}`,
                                        ][(index - 1) % 3] ?? null),
                              "vulnerability.severity": "Critical",
                              "package.name": "synthetic-package",
                              "package.version": "1.0",
                          }
                        : {}),
              };
              return {
                  evidence_id: evidenceId,
                  fetch_id: id,
                  topic_id: topic,
                  record_ref: {
                      index_alias:
                          topic === "vuln_review"
                              ? "wazuh-vulnerabilities-synthetic-000001"
                              : topic === "auth_review"
                                ? "wazuh-alerts-synthetic-000001"
                                : "synthetic-alerts",
                      record_id:
                          topic === "auth_review"
                              ? `synthetic-auth-${index + 1}`
                              : topic === "vuln_review"
                                ? `synthetic-vuln-${index + 1}`
                                : `${topic}-record-${String(index + 1).padStart(2, "0")}`,
                  },
                  values,
              };
          });
    const resultSnapshot = opts.cursor
        ? { ...snapshot, kind: "pit" as const, expires_at: "2026-10-20T10:05:00Z" }
        : snapshot;
    const visibleItems = visibleRows.map((row) => ({
        ...evidence,
        snapshot: resultSnapshot,
        evidence_id: row.evidence_id,
        scope_hash: hash(Number.parseInt(row.evidence_id.slice(-2), 16) || 1),
        source: {
            ...evidence.source,
            index_alias:
                row.record_ref?.index_alias ??
                ("index_alias" in evidence.source ? evidence.source.index_alias : "synthetic"),
            record_id: row.record_ref?.record_id ?? "synthetic-record",
        },
        values: row.values,
    }));
    return {
        fetch_id: id,
        topic_id: topic,
        state: opts.state ?? "rows",
        scope: {
            displayed_rows: visibleRows.length,
            environment_id: "synthetic",
            filters: [],
            index_family: topic === "vuln_review" ? "vulnerabilities" : "alerts",
            policy_hash: policy,
            snapshot: resultSnapshot.kind,
            template_id: topic === "vuln_review" ? "vulnerabilities_rows_v1" : "alerts_rows_v1",
            visibility: opts.visibility ?? "full",
        },
        window,
        columns: fields,
        rows: visibleRows,
        count:
            opts.state === "denied" || opts.state === "unavailable"
                ? null
                : (opts.count ?? count(visibleRows.length)),
        checks: [
            { name: "execute_as_analyst", outcome: "passed", code: "synthetic_read_completed" },
        ],
        empty_proof: opts.proof ?? null,
        next_cursor: opts.cursor ?? null,
        snapshot: resultSnapshot,
        items: visibleItems,
        buckets: [],
        bucket_completeness: "complete",
        message: opts.message ?? opts.error?.message ?? null,
        error: opts.error ?? null,
    };
};
export const withBucket = (
    result: FetchResult,
    key: string,
    field: "rule.id" | "vulnerability.severity",
): FetchResult => {
    const totals = new Map<string, number>();
    for (const row of result.rows) {
        const value = row.values[field];
        if (value !== null && value !== undefined) {
            const bucket = String(value);
            totals.set(bucket, (totals.get(bucket) ?? 0) + 1);
        }
    }
    if (!totals.size && result.rows.length) totals.set(key, result.rows.length);
    const aggregates = [...totals.entries()].map(([bucket, total], index) => {
        const evidence_id = `ev1_${(1000 + index + (result.fetch_id === "auth_rows" ? 100 : 200)).toString(16).padStart(64, "0")}`;
        const item: EvidenceItem = {
            evidence_id,
            topic_id: result.topic_id,
            fetch_id: result.fetch_id,
            kind: "aggregate",
            scope_hash: hash(Number.parseInt(evidence_id.slice(-2), 16) || 1),
            snapshot,
            source: { group_field: field, key: bucket },
            values: { bucket_key: bucket, count: total },
            visibility: result.scope.visibility,
        };
        return {
            item,
            bucket: {
                key: bucket,
                count: { ...count(total), scope: "bucket_visible_records" as const },
                evidence_id,
            },
        };
    });
    return {
        ...result,
        items: [...result.items, ...aggregates.map(({ item }) => item)],
        buckets: aggregates.map(({ bucket }) => bucket),
        bucket_completeness: "complete",
    };
};
export const checkList = (topic: string, _evidenceId: string) => {
    const definitions: Array<[string, CheckOutcome, string]> =
        topic === "auth_review"
            ? [
                  ["At least one matching record", "passed", "Check passed."],
                  ["Review volume threshold", "failed", "Check failed."],
                  ["Source address field coverage", "passed", "Check passed."],
                  ["Higher severity rule observed", "passed", "Check passed."],
                  [
                      "Newest returned record within synthetic limit",
                      "passed",
                      "Newest valid returned timestamp 2026-10-20T19:19:35.914918+00:00 is 1799.999 s before the read time; limit 3600 s; 0 returned rows have no valid timestamp inside the read window. Based on returned rows only; this does not establish source health or completeness. The read was a first-page read.",
                  ],
              ]
            : topic === "vuln_review"
              ? [
                    ["At least one matching record", "passed", "Check passed."],
                    ["Package version field coverage", "passed", "Check passed."],
                    ["Critical severity observed", "passed", "Check passed."],
                ]
              : [];
    return definitions.map(([label, outcome, message], index) => ({
        check_id: `${topic}-check-${index}`,
        topic_id: topic,
        evidence_ids: [distinctEvidenceId()],
        label,
        message,
        outcome,
    }));
};
export const judgment = (
    topic: string,
    evidenceId: string,
    state:
        | "validated"
        | "denial"
        | "evidence_unavailable"
        | "model_unavailable"
        | "ingestion_unconfirmed" = "validated",
) => ({
    state,
    model_id: state === "validated" ? "synthetic-model" : null,
    effort: state === "validated" ? ("low" as const) : null,
    removed:
        state === "validated"
            ? [
                  {
                      candidate_sha256: hash(7),
                      finding_id: `${topic}-removed`,
                      reason: "unsupported_value" as const,
                  },
              ]
            : [],
    sentences:
        state === "validated"
            ? [
                  {
                      finding_id: `${topic}-observation`,
                      kind: "observation" as const,
                      evidence_ids: [evidenceId],
                      text:
                          topic === "ldap"
                              ? "The synthetic LDAP example reports only 2 as its configured visible count."
                              : "Synthetic evidence item is available for analyst review.",
                  },
              ]
            : [],
    message: state === "validated" ? null : `Synthetic ${state} result.`,
});
export const topic = (
    topicId: string,
    ordinal: number,
    result: FetchResult,
    item: EvidenceItem,
    doc = false,
) => ({
    topic_id: topicId,
    ordinal,
    document: doc
        ? {
              anchor: "review",
              content_sha: gitSha,
              document_id: `${topicId}-guide`,
              document_sha256: hash(8),
              heading: "Synthetic review guidance",
              source_path: `docs/${topicId}.md`,
              url: `https://example.invalid/docs/${topicId}`,
          }
        : null,
    missing: [],
    tables: [result],
    checks:
        result.state === "denied" || result.state === "unavailable"
            ? []
            : checkList(topicId, item.evidence_id),
    judgment: judgment(topicId, item.evidence_id),
});
