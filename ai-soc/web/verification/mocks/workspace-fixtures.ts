import type { components } from "../../../contracts/workspace/v1/types.ts";

type Overview = components["schemas"]["OverviewResponse"];
type AlertDetail = components["schemas"]["AlertDetail"];
type SitePage = components["schemas"]["Page_SiteSummary_"];
type IngestionHealth = components["schemas"]["IngestionHealthResponse"];

const now = Date.now();
const hour = (offset: number) => new Date(now - offset * 3_600_000).toISOString();
const site = {
    site_id: "synthetic",
    label: "Synthetic site",
    wazuh_version: "4.9.2",
    health: "ok",
    health_detail: null,
    updated_at: new Date(now).toISOString(),
} satisfies components["schemas"]["SiteSummary"];

export const workspaceSites = {
    items: [site],
    next_cursor: null,
    limit: 200,
} satisfies SitePage;

export function workspaceIngestionHealth(stalled = false): IngestionHealth {
    const checkedAt = new Date(now - 60_000).toISOString();
    return {
        site: stalled ? { ...site, health: "unreachable", health_detail: "No recent successful poll" } : site,
        checkpoint_at: stalled ? null : checkedAt,
        last_success_at: stalled ? null : checkedAt,
        last_run: stalled ? null : {
            run_id: "6cf5f8bd-6556-4d51-a5f9-e55f49e2e34d",
            kind: "poll",
            started_at: checkedAt,
            finished_at: checkedAt,
            outcome: "success",
            error_code: null,
            pipeline_version: "workspace-pipeline-m1.1",
        },
        lag_seconds: stalled ? null : 50,
        counts: { read: 128, inserted: 32, duplicates: 96, normalized: 32, rejected: 0 },
        reconciliation: { checked_hours: 48, mismatched_hours: 0, last_checked_at: checkedAt },
    };
}

export const workspaceOverview = (from: string, to: string): Overview => ({
    site,
    window: { from, to, preset: "24h" },
    totals: { alerts: 32, groups: null, unassigned_actionable: null, open_incidents: null },
    hourly: Array.from({ length: 24 }, (_, index) => ({
        hour: hour(23 - index),
        level_band: "10-12",
        count: [0, 1, 2, 0, 4, 3, 1, 2, 0, 1, 5, 2, 1, 0, 2, 3, 1, 1, 0, 2, 0, 1, 0, 0][index] ?? 0,
    })),
    top_rules: [
        { key: "5712", label: "Multiple authentication failures", count: 11 },
        { key: "5501", label: "Login session opened", count: 7 },
        { key: "31151", label: "Sudo command executed", count: 4 },
    ],
    top_agents: [{ key: "003", label: "web-01", count: 14 }, { key: "007", label: "auth-02", count: 9 }],
    top_tactics: [{ key: "credential-access", label: "Credential Access", count: 12 }],
    top_src_ips: [{ key: "203.0.113.8", label: "203.0.113.8", count: 6 }],
    top_users: [{ key: "root", label: "root", count: 5 }, { key: "svc-deploy", label: "svc-deploy", count: 3 }],
    freshness: {
        last_success_at: new Date(now - 50_000).toISOString(),
        checkpoint_at: new Date(now - 45_000).toISOString(),
        lag_seconds: 50,
        reconcile_mismatches_48h: 0,
        state: "ok",
    },
});

export const workspaceAlerts = [
    {
        alert_key: "sha256:auth-5712-001",
        event_ts: new Date(now - 4 * 60_000).toISOString(),
        rule_id: "5712",
        rule_level: 12,
        rule_description: "Multiple authentication failures",
        rule_groups: ["authentication_failed", "authentication_failures"],
        mitre_tactics: ["credential-access"],
        mitre_techniques: ["T1110"],
        agent_id: "003",
        agent_name: "web-01",
        agent_ip: "10.0.1.12",
        src_ip: "203.0.113.8",
        dst_ip: "10.0.1.12",
        src_user: null,
        dst_user: "root",
        group_id: "sha256:auth-group-001",
    },
    {
        alert_key: "sha256:sudo-31151-004",
        event_ts: new Date(now - 22 * 60_000).toISOString(),
        rule_id: "31151",
        rule_level: 10,
        rule_description: "Sudo command executed",
        rule_groups: ["sudo", "privilege_escalation"],
        mitre_tactics: ["privilege-escalation"],
        mitre_techniques: ["T1548.003"],
        agent_id: "007",
        agent_name: "auth-02",
        agent_ip: "10.0.2.7",
        src_ip: null,
        dst_ip: null,
        src_user: "deploy",
        dst_user: "root",
        group_id: "sha256:sudo-group-002",
    },
    {
        alert_key: "sha256:auth-5712-002",
        event_ts: new Date(now - 58 * 60_000).toISOString(),
        rule_id: "5712",
        rule_level: 12,
        rule_description: "Multiple authentication failures",
        rule_groups: ["authentication_failed"],
        mitre_tactics: ["credential-access"],
        mitre_techniques: ["T1110"],
        agent_id: "003",
        agent_name: "web-01",
        agent_ip: "10.0.1.12",
        src_ip: "203.0.113.8",
        dst_ip: "10.0.1.12",
        src_user: null,
        dst_user: "root",
        group_id: "sha256:auth-group-001",
    },
] satisfies components["schemas"]["AlertSummary"][];

export const workspaceAlertDetails: AlertDetail[] = workspaceAlerts.map((alert, index) => ({
    ...alert,
    wazuh_id: `175000000${index + 1}.12345`,
    manager: "wazuh-manager-01",
    decoder: index === 0 ? "sshd" : "sudo",
    location: "/var/log/auth.log",
    entities: [
        {
            kind: "ip",
            value: alert.src_ip ?? "10.0.2.7",
            role: "source",
            first_seen: new Date(now - 86_400_000).toISOString(),
            last_seen: alert.event_ts,
        },
    ],
    raw: {},
    normalize_gaps: index === 0 ? ["data.srcuser", "data.dstport"] : ["data.srcip", "data.dstport"],
    mapping_profile: "wazuh-4.9.2-v1",
    ingested_at: new Date(now - 3 * 60_000).toISOString(),
    wazuh_url: "https://wazuh.example.invalid/app/discover#/doc/wazuh-alerts-4.x/1750000001.12345",
}));

export function workspaceAlertContext(alert: AlertDetail) {
    const summary = workspaceAlerts.find((candidate) => candidate.alert_key === alert.alert_key);
    return {
        site_id: site.site_id,
        group_id: alert.group_id ?? "sha256:context-unavailable",
        alerts: summary ? [summary] : [],
        entities: alert.entities,
        enrichments: [],
        related_groups: [],
        window: {
            from: new Date(new Date(alert.event_ts).getTime() - 3_600_000).toISOString(),
            to: new Date(new Date(alert.event_ts).getTime() + 3_600_000).toISOString(),
            preset: null,
        },
    } satisfies components["schemas"]["GroupContextResponse"];
}
