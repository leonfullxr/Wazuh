import { useQuery } from "@tanstack/react-query";
import type { OverviewResponse, SiteSummary } from "../../api/workspace";
import { getOverview } from "../../api/workspace";
import { Panel } from "../../components/ui/panel";
import { QuietSiteState, WorkspaceFailure, WorkspaceLoading } from "../workspace/WorkspaceStates";

export type AlertDrilldown = {
    rule_id?: string;
    agent_id?: string;
    tactic?: string;
    entity_kind?: string;
    entity?: string;
    from?: string;
    to?: string;
    min_level?: number;
    max_level?: number;
};

type Translate = (key: string) => string;

export function OverviewPage({
    site,
    from,
    to,
    timezone,
    t,
    onDrilldown,
}: {
    site: Pick<SiteSummary, "site_id" | "label"> | undefined;
    from: string;
    to: string;
    timezone: string;
    t: Translate;
    onDrilldown: (filters: AlertDrilldown) => void;
}) {
    const query = useQuery({
        queryKey: ["workspace", "overview", site?.site_id, from, to, timezone],
        queryFn: ({ signal }) =>
            site
                ? getOverview({ siteId: site.site_id, from, to, timezone }, signal)
                : Promise.reject(new Error("No workspace site selected.")),
        enabled: site !== undefined,
    });
    if (query.isLoading) return <WorkspaceLoading label={t("loading")} />;
    if (query.isError || !query.data)
        return <WorkspaceFailure error={query.error} t={t} onRetry={() => void query.refetch()} />;

    const data: OverviewResponse = query.data;
    const stale = data.freshness.state === "auth_failed" || data.freshness.state === "unreachable";
    const empty = data.totals.alerts === 0;
    return (
        <div className="workspace-page">
            <p className="page-description">{t("overviewDescription")}</p>
            {stale && (
                <section className="alert error ingestion-alert" role="alert">
                    <div>
                        <strong>{t("stalledTitle")}</strong>
                        <p>{t("stalledDescription")}</p>
                    </div>
                    <span className={`status-pill ${data.freshness.state === "auth_failed" ? "status-pill-warning" : "status-pill-neutral"}`}>
                        {t(`freshness${data.freshness.state === "auth_failed" ? "AuthFailed" : "Unreachable"}`)}
                    </span>
                </section>
            )}
            <section className="workspace-metric-grid" aria-label={t("overview")}>
                <Metric label={t("alertsTotal")} value={data.totals.alerts.toLocaleString()} />
                <Metric label={t("freshness")} value={t(`freshness${freshnessKey(data.freshness.state)}`)} />
                <Metric label={t("lastSuccess")} value={formatTime(data.freshness.last_success_at)} />
                <Metric label={t("lag")} value={formatDuration(data.freshness.lag_seconds)} />
            </section>
            {empty ? (
                <Panel className="workspace-panel">
                    <QuietSiteState t={t} />
                </Panel>
            ) : (
                <>
                    <Panel className="workspace-panel">
                        <SectionTitle title={t("hourlyVolume")} />
                        <div className="volume-chart" role="group" aria-label={t("hourlyVolume")}>
                            {data.hourly.map((bucket, index) => {
                                const maximum = Math.max(1, ...data.hourly.map((item) => item.count));
                                const fromHour = new Date(bucket.hour).toISOString();
                                const toHour = new Date(new Date(bucket.hour).getTime() + 3_600_000).toISOString();
                                const minLevel = Number(bucket.level_band.split("-")[0]);
                                return (
                                    <button
                                        className="volume-bar"
                                        type="button"
                                        key={`${bucket.hour}-${bucket.level_band}-${index}`}
                                        aria-label={`${formatTime(bucket.hour)} · ${bucket.count} · ${bucket.level_band}`}
                                        title={`${formatTime(bucket.hour)} · ${bucket.count}`}
                                        onClick={() => onDrilldown({ from: fromHour, to: toHour, min_level: minLevel, max_level: Number(bucket.level_band.split("-")[1]) })}
                                    >
                                        <span style={{ height: `${Math.max(bucket.count ? 8 : 2, (bucket.count / maximum) * 100)}%` }} />
                                    </button>
                                );
                            })}
                        </div>
                        <div className="volume-axis" aria-hidden="true">
                            <span>{formatTime(data.hourly[0]?.hour ?? from)}</span>
                            <span>{formatTime(data.hourly.at(-1)?.hour ?? to)}</span>
                        </div>
                    </Panel>
                    <div className="workspace-two-column">
                        <TopList title={t("topRules")} items={data.top_rules} t={t} onSelect={(item) => onDrilldown({ rule_id: item.key })} />
                        <TopList title={t("topAgents")} items={data.top_agents} t={t} onSelect={(item) => onDrilldown({ agent_id: item.key })} />
                        <TopList title={t("topTactics")} items={data.top_tactics} t={t} onSelect={(item) => onDrilldown({ tactic: item.key })} />
                        <TopList title={t("topIps")} items={data.top_src_ips} t={t} onSelect={(item) => onDrilldown({ entity_kind: "ip", entity: item.key })} />
                        <TopList title={t("topUsers")} items={data.top_users} t={t} onSelect={(item) => onDrilldown({ entity_kind: "user", entity: item.key })} />
                    </div>
                </>
            )}
            <div className="freshness-footnote">
                {t("checkpoint")}: {formatTime(data.freshness.checkpoint_at)}
                <span>·</span>
                {t("mismatch48h")}: {data.freshness.reconcile_mismatches_48h}
            </div>
        </div>
    );
}

function Metric({ label, value }: { label: string; value: string }) {
    return (
        <div className="workspace-metric panel">
            <span>{label}</span>
            <strong>{value}</strong>
        </div>
    );
}

function SectionTitle({ title }: { title: string }) {
    return <h2 className="section-title">{title}</h2>;
}

function TopList({
    title,
    items,
    t,
    onSelect,
}: {
    title: string;
    items: OverviewResponse["top_rules"];
    t: Translate;
    onSelect: (item: OverviewResponse["top_rules"][number]) => void;
}) {
    return (
        <Panel className="workspace-panel top-list">
            <SectionTitle title={title} />
            {items.length === 0 ? (
                <p className="muted">{t("noData")}</p>
            ) : (
                <ul>
                    {items.map((item) => (
                        <li key={`${item.key}-${item.label}`}>
                            <button className="text-link" type="button" onClick={() => onSelect(item)}>
                                <span>{item.label}</span>
                                <code>{item.key}</code>
                            </button>
                            <span className="top-count">{item.count.toLocaleString()}</span>
                        </li>
                    ))}
                </ul>
            )}
        </Panel>
    );
}

function freshnessKey(state: string): string {
    switch (state) {
        case "ok":
            return "Fresh";
        case "lagging":
            return "Lagging";
        case "auth_failed":
            return "AuthFailed";
        case "unreachable":
            return "Unreachable";
        case "unknown":
            return "Unknown";
        default:
            return "Unknown";
    }
}

function formatTime(value: string | null): string {
    return value ? new Intl.DateTimeFormat(undefined, { dateStyle: "medium", timeStyle: "short" }).format(new Date(value)) : "—";
}

function formatDuration(seconds: number | null): string {
    if (seconds === null) return "—";
    if (seconds < 60) return `${Math.max(0, Math.round(seconds))}s`;
    if (seconds < 3_600) return `${Math.round(seconds / 60)}m`;
    return `${(seconds / 3_600).toFixed(1)}h`;
}
