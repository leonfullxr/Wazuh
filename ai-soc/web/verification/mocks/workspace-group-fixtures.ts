import type { components } from "../../../contracts/workspace/v1/types.ts";
import { workspaceAlerts } from "./workspace-fixtures";

type Group = components["schemas"]["GroupSummary"];
type Detail = components["schemas"]["GroupDetail"];
type QueueRow = components["schemas"]["QueueSummary"];
type Asset = components["schemas"]["AssetTag"];
type WorkState = components["schemas"]["WorkState"];
const now = Date.now();
const timestamp = (offset: number) => new Date(now - offset).toISOString();
const alertOne = workspaceAlerts[0];
const alertTwo = workspaceAlerts[1];
const alertThree = workspaceAlerts[2];

function makeGroup(
    id: string,
    title: string,
    score: number | null,
    alert: NonNullable<typeof alertOne>,
    status: components["schemas"]["WorkState"]["status"],
    owner: string | null,
): Group {
    return {
        group_id: id,
        group_revision: `revision:${id}`,
        title,
        score,
        computation_version: score === null ? null : "score-v1.0.0",
        input_digest: score === null ? null : `digest:${id}`,
        components: [
            {
                name: "Wazuh level",
                value: 12,
                weight: 3.2,
                contribution: 38.4,
                evidence_ids: [alert.alert_key],
                explanation: "Highest member alert level multiplied by the score weight.",
                available: true,
            },
            {
                name: "Vulnerability context",
                value: null,
                weight: 1.1,
                contribution: 0,
                evidence_ids: [],
                explanation: "Vulnerability source is unavailable for this host.",
                available: false,
            },
        ],
        alert_count: 3,
        first_ts: timestamp(3_600_000),
        last_ts: alert.event_ts,
        rule_id: alert.rule_id,
        primary_entity: {
            kind: "host",
            value: alert.agent_name ?? "unknown",
            role: "primary",
            first_seen: timestamp(86_400_000),
            last_seen: alert.event_ts,
        },
        status,
        owner_key: owner,
        disposition: null,
        pipeline_version: "workspace-pipeline-m2.1",
    };
}
const baseGroups = [
    makeGroup(
        "group-auth-001",
        "Repeated SSH authentication failures",
        78.4,
        alertOne,
        "new",
        null,
    ),
    makeGroup(
        "group-sudo-002",
        "Privileged command on auth-02",
        62.1,
        alertTwo,
        "in_progress",
        "analyst:maria",
    ),
    makeGroup("group-score-pending", "New group awaiting score", null, alertThree, "new", null),
];
const initialStates = new Map<string, WorkState>(
    baseGroups.map((group) => [
        group.group_id,
        {
            status: parseWorkStatus(group.status),
            owner_key: group.owner_key,
            updated_at: timestamp(120_000),
        },
    ]),
);
export const queueRows: QueueRow[] = baseGroups.map((group, index) => ({
    group,
    queue_reasons:
        index === 2 ? ["Score calculation pending"] : ["Priority score", "Unassigned work"],
    work_state: stateFor(group.group_id),
}));
export const groupDetails = new Map<string, Detail>(
    baseGroups.map((group, index) => {
        const alerts = index === 0 ? [alertOne, alertThree] : [alertTwo];
        const detail: Detail = {
            ...group,
            site_id: "synthetic",
            members: {
                items: index === 0 ? [alertOne] : alerts,
                next_cursor: index === 0 ? "members-next" : null,
                limit: 50,
            },
            enrichments: [
                {
                    enrichment_id: `enrichment-${group.group_id}`,
                    source: "site_prevalence",
                    source_version: "prevalence-v1",
                    value: { count_30d: group.alert_count },
                    fetched_at: timestamp(60_000),
                    expires_at: timestamp(-3_600_000),
                },
            ],
            edges: [],
            chain_ids: [],
            history: [],
            work_state: stateFor(group.group_id),
        };
        return [group.group_id, detail];
    }),
);
export const assetTags: Asset[] = [
    {
        site_id: "synthetic",
        entity_id: 31,
        entity_kind: "host",
        entity_value: "web-01",
        criticality: 3,
        tags: ["internet-facing", "production"],
        set_by: "analyst:maria",
        set_at: timestamp(86_400_000),
    },
    {
        site_id: "synthetic",
        entity_id: 42,
        entity_kind: "host",
        entity_value: "auth-02",
        criticality: 2,
        tags: ["identity"],
        set_by: "analyst:leon",
        set_at: timestamp(86_400_000),
    },
];
export const opsMetrics: components["schemas"]["OpsMetricsResponse"] = {
    window: { from: timestamp(86_400_000), to: timestamp(0), preset: "24h" },
    volume: [
        { hour: timestamp(3_600_000), level_band: "high", count: 12 },
        { hour: timestamp(7_200_000), level_band: "medium", count: 31 },
    ],
    ingest_lag_seconds: { p50: 38, p90: 95, p95: 120, max: 240, sample_count: 144 },
    queue_age_seconds: { p50: 480, p90: 1800, p95: 3200, max: 5400, sample_count: 21 },
    backlog: { current: 12, previous: 15, delta: -3, unassigned: 4 },
    time_to_ack_seconds: { p50: 95, p90: 420, p95: 520, max: 1200, sample_count: 18 },
    time_to_triage_seconds: { p50: 620, p90: 2100, p95: 2800, max: 4900, sample_count: 11 },
    dead_jobs: 0,
};
export const qualityMetrics: components["schemas"]["QualityMetricsResponse"] = {
    window: { from: timestamp(30 * 86_400_000), to: timestamp(0), preset: "30d" },
    dispositions: [
        { label: "true_positive", count: 8 },
        { label: "benign_true_positive", count: 3 },
        { label: "false_positive", count: 4 },
        { label: "duplicate", count: 2 },
        { label: "undetermined", count: 6 },
    ],
    label_coverage: 0.38,
    labelled_group_count: 38,
    group_count: 100,
    rule_precision: [
        {
            rule_id: "5712",
            labelled_count: 8,
            true_positive_count: 6,
            false_positive_count: 2,
            benign_true_positive_count: 1,
            precision: 0.75,
        },
        {
            rule_id: "31151",
            labelled_count: 4,
            true_positive_count: 2,
            false_positive_count: 2,
            benign_true_positive_count: 2,
            precision: 0.5,
        },
        {
            rule_id: "5501",
            labelled_count: 0,
            true_positive_count: 0,
            false_positive_count: 0,
            benign_true_positive_count: 0,
            precision: null,
        },
    ],
    precision_at_k: [
        { k: 10, precision: 0.7, relevant_count: 7, labelled_count: 10 },
        { k: 25, precision: null, relevant_count: 0, labelled_count: 0 },
    ],
};
export function updateMockWorkState(
    groupId: string,
    state: components["schemas"]["WorkState"],
): void {
    const detail = groupDetails.get(groupId);
    if (!detail) return;
    const updated = {
        ...detail,
        status: state.status,
        owner_key: state.owner_key,
        work_state: state,
    };
    groupDetails.set(groupId, updated);
    const row = queueRows.find((item) => item.group.group_id === groupId);
    if (row) {
        row.work_state = state;
        row.group = { ...row.group, status: state.status, owner_key: state.owner_key };
    }
}
export function updateMockDisposition(
    groupId: string,
    disposition: components["schemas"]["Disposition"],
): void {
    const detail = groupDetails.get(groupId);
    if (detail) groupDetails.set(groupId, { ...detail, disposition });
    const row = queueRows.find((item) => item.group.group_id === groupId);
    if (row) row.group = { ...row.group, disposition };
}
function stateFor(groupId: string): WorkState {
    const state = initialStates.get(groupId);
    if (!state) throw new Error(`Missing fixture work state for ${groupId}`);
    return state;
}
function parseWorkStatus(value: string): WorkState["status"] {
    if (value === "new" || value === "in_progress" || value === "resolved" || value === "closed")
        return value;
    throw new Error(`Invalid fixture work status: ${value}`);
}
