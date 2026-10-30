import type { components } from "../../../contracts/workspace/v1/types.ts";

type Chain = components["schemas"]["ChainCandidateDTO"];
type ChainDetail = components["schemas"]["ChainCandidateDetail"];
type Incident = components["schemas"]["IncidentSummaryDTO"];
type IncidentDetail = components["schemas"]["IncidentDetailResponse"];

export const demoGroupId = "a".repeat(64);
const secondGroupId = "b".repeat(64);
const chainId = "chain-demo-001";
const incidentId = "33333333-3333-4333-8333-333333333333";
const now = "2026-10-23T10:00:00.000Z";
const revision = "c".repeat(64);
const evidenceRevision = "11111111-1111-4111-8111-111111111111";

export const demoChain: Chain = {
    chain_id: chainId,
    revision_digest: revision,
    manifest_id: "22222222-2222-4222-8222-222222222222",
    rule_id: "linux.ssh_bruteforce_to_persistence",
    rule_version: "1.0.0",
    state: "open",
    decision_version: 1,
    created_at: now,
    updated_at: now,
    score: 0.83,
    score_available: true,
    result: { anchor_group_id: demoGroupId, missing_stages: ["persistence"], window_start: now },
    stages: [
        { ordinal: 1, stage_id: "ssh_failure", outcome: "matched", group_id: demoGroupId },
        { ordinal: 2, stage_id: "ssh_success", outcome: "matched", group_id: secondGroupId },
        { ordinal: 3, stage_id: "sudo", outcome: "missing", group_id: null },
    ],
    weak_heuristic: false,
};

export const demoChainDetail: ChainDetail = {
    ...demoChain,
    edges: [
        {
            type: "same_src_ip_user",
            confidence: 0.91,
            reason: "Shared source IP and destination user",
            evidence_ids: [demoGroupId, secondGroupId],
        },
    ],
    weak_edges: [
        {
            type: "same_host",
            confidence: 0.31,
            reason: "Shared host only; weak fallback",
            evidence_ids: [demoGroupId, secondGroupId],
        },
    ],
    score_pins: [
        { group_id: demoGroupId, revision: "d".repeat(64), score: 0.71, score_version: "m2.1" },
    ],
};

export const demoIncident: Incident = {
    incident_id: incidentId,
    title: "SSH access followed by privilege change",
    owner_key: "analyst:demo",
    status: "in_progress",
    work_version: 3,
    evidence_head: evidenceRevision,
    revision_seq: 1,
    priority: 0.83,
    created_at: now,
    created_by: "analyst:demo",
};

export const demoIncidentDetail: IncidentDetail = {
    incident: {
        incident_id: demoIncident.incident_id,
        title: demoIncident.title,
        owner_key: demoIncident.owner_key,
        status: demoIncident.status,
        work_version: demoIncident.work_version,
        evidence_head: demoIncident.evidence_head,
        revision_seq: demoIncident.revision_seq,
        priority: demoIncident.priority,
    },
    members: [
        {
            group_id: demoGroupId,
            group_revision: "d".repeat(64),
            title: "Repeated SSH authentication failures",
            first_ts: "2026-10-23T09:12:00.000Z",
            last_ts: "2026-10-23T09:14:00.000Z",
            alert_count: 18,
            score: 0.71,
            score_version: "m2.1",
            score_digest: "e".repeat(64),
        },
    ],
    membership_intervals: [
        {
            group_id: demoGroupId,
            membership_id: "55555555-5555-4555-8555-555555555555",
            added_at: "2026-10-23T09:20:00Z",
            added_by: "analyst:demo",
            removed_at: null,
            removed_by: null,
        },
    ],
    history: [
        {
            history_id: "33333333-3333-4333-8333-333333333333",
            work_version: 3,
            action: "status_changed",
            before: { status: "new" },
            after: { status: "in_progress" },
            actor_key: "analyst:demo",
            at: now,
        },
    ],
    comments: [],
    dispositions: [],
    next_cursors: { membership: null, history: null, comments: null, dispositions: null },
};

export const demoIncidentEvent: components["schemas"]["IncidentEventDTO"] = {
    kind: "alert",
    event_id: "44444444-4444-4444-8444-444444444444",
    event_ts: "2026-10-23T09:12:00.000Z",
    alert_key: "synthetic:alert:5763",
    group_id: demoGroupId,
    group_revision: "d".repeat(64),
    rule_id: "5763",
    fields: { src_ip: "198.51.100.24", dst_user: "ops" },
    stages: [{ stage_id: "ssh_failure", ordinal: 1 }],
};

const groupFactId = "1".repeat(64);
const alertFactId = "2".repeat(64);
const narrativePack: components["schemas"]["FrozenIncidentPack"] = {
    site_id: "synthetic",
    incident_id: incidentId,
    incident_revision_id: "66666666-6666-4666-8666-666666666666",
    revision_seq: 1,
    as_of: now,
    builder_version: "workspace.incident-narrative-pack.v1",
    incident_reference: {
        reference_id: "3".repeat(64),
        incident_id: incidentId,
        incident_revision_id: "66666666-6666-4666-8666-666666666666",
        site_id: "synthetic",
    },
    coverage: {
        membership_count: 1,
        alert_count: 18,
        score_unknown_count: 0,
        included_group_facts: 1,
        omitted_group_facts: 0,
        included_alert_facts: 1,
        omitted_alert_facts: 17,
    },
    group_facts: [
        {
            fact_id: groupFactId,
            membership_id: "77777777-7777-4777-8777-777777777777",
            group_id: demoGroupId,
            group_revision: "d".repeat(64),
            first_event_at: "2026-10-23T09:12:00.000Z",
            last_event_at: "2026-10-23T09:14:00.000Z",
            alert_count: 18,
            score: 0.71,
            score_version: "m2.1",
            score_digest: "e".repeat(64),
            rule_id: "5763",
            agent_id: "agent-042",
        },
    ],
    alert_facts: [
        {
            fact_id: alertFactId,
            group_fact_id: groupFactId,
            group_id: demoGroupId,
            group_revision: "d".repeat(64),
            alert_key: "8".repeat(64),
            event_at: "2026-10-23T09:12:00.000Z",
            rule_id: "5763",
            agent_id: "agent-042",
            source_hash: "9".repeat(64),
        },
    ],
    content_digest: "a".repeat(64),
};

export function makeNarrative(
    options: {
        status?: components["schemas"]["NarrativeReadResponse"]["status"];
        evidenceRevision?: string;
        allRemoved?: boolean;
    } = {},
): components["schemas"]["NarrativeReadResponse"] {
    const status = options.allRemoved ? "unavailable" : (options.status ?? "available");
    const responseRevision = options.evidenceRevision ?? evidenceRevision;
    const allRemoved = options.allRemoved ?? false;
    const summary: components["schemas"]["ValidatedNarrative"] | null =
        status === "available"
            ? {
                  label_en: "Unvalidated AI summary",
                  label_es: "Resumen de IA no validado",
                  status: allRemoved ? "all_removed" : "validated",
                  rendered_en: `Group ${demoGroupId} has a recorded score of 0.71. Rule 5763 was observed on agent agent-042 at 2026-10-23T09:12:00+00:00.`,
                  rendered_es: `El grupo ${demoGroupId} tiene una puntuación registrada de 0.71. La regla 5763 se observó en el agente agent-042 a las 2026-10-23T09:12:00+00:00.`,
                  pack_digest: narrativePack.content_digest,
                  citations: allRemoved
                      ? []
                      : [
                            { kind: "group", fact_id: groupFactId },
                            { kind: "alert", fact_id: alertFactId },
                        ],
                  removals: allRemoved
                      ? [{ reason: "unknown_citation", selection_digest: "c".repeat(64) }]
                      : [],
                  selections: [
                      {
                          template: "member_score",
                          group_fact_id: groupFactId,
                          group_id: demoGroupId,
                          score: 0.71,
                      },
                      {
                          template: "rule_observed",
                          alert_fact_id: alertFactId,
                          group_id: demoGroupId,
                          rule_id: "5763",
                          agent_id: "agent-042",
                          event_at: "2026-10-23T09:12:00+00:00",
                      },
                  ],
                  static_error: null,
              }
            : null;
    return {
        incident_id: incidentId,
        evidence_revision: responseRevision,
        is_current: responseRevision === evidenceRevision,
        status,
        reason_code: allRemoved ? "all_removed" : status === "unavailable" ? "account_limit" : null,
        removals: allRemoved
            ? [{ reason: "unknown_citation", selection_digest: "c".repeat(64) }]
            : [],
        generation_id: status === "available" ? "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa" : null,
        generation_digest: status === "available" ? "b".repeat(64) : null,
        pack_digest: status === "available" ? narrativePack.content_digest : null,
        call_id: status === "available" ? "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb" : null,
        completed_at: status === "available" ? now : null,
        usage:
            status === "available"
                ? { input_tokens: 240, cached_input_tokens: 0, output_tokens: 72 }
                : { input_tokens: null, cached_input_tokens: null, output_tokens: null },
        summary,
        evidence: status === "available" ? structuredClone(narrativePack) : null,
    };
}

export const narrativeFactIds = { groupFactId, alertFactId };

export const newDemoIncidentId = () => crypto.randomUUID();

export function makeIncident(
    incidentId: string,
    groupIds: string[],
    title: string | null,
    ownerKey: string | null,
): IncidentDetail {
    const incident: components["schemas"]["IncidentSnapshotDTO"] = {
        incident_id: incidentId,
        title: title ?? "Analyst-created incident",
        owner_key: ownerKey,
        status: "new",
        work_version: 1,
        evidence_head: crypto.randomUUID(),
        revision_seq: 1,
        priority: null,
    };
    return {
        incident,
        members: groupIds.map((groupId) => ({
            group_id: groupId,
            group_revision: "f".repeat(64),
            title: "Manually selected group",
            first_ts: now,
            last_ts: now,
            alert_count: 1,
            score: null,
            score_version: null,
            score_digest: null,
        })),
        membership_intervals: [],
        history: [],
        comments: [],
        dispositions: [],
        next_cursors: { membership: null, history: null, comments: null, dispositions: null },
    };
}

export const demoIds = { chainId, incidentId, evidenceRevision, now, secondGroupId };
