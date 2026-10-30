import { useMemo, useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { Bar, BarChart, Cell, ResponsiveContainer, XAxis, YAxis } from "recharts";
import type { OverviewResponse, SiteSummary } from "../../api/workspace";
import { getOverview } from "../../api/workspace";
import { Panel } from "../../components/ui/panel";
import { QuietSiteState, WorkspaceFailure, WorkspaceLoading } from "../workspace/WorkspaceStates";
import "./overview-v2.css";

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
type HourlyBucket = OverviewResponse["hourly"][number];
type HourGroup = { hour: string; buckets: HourlyBucket[]; total: number };
type HourChartDatum = { hour: string; total: number } & Record<string, string | number>;
type HourChartSeries = { band: string; dataKey: string };

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
    const [selectedHour, setSelectedHour] = useState("");
    const query = useQuery({
        queryKey: ["workspace", "overview", site?.site_id, from, to, timezone],
        queryFn: ({ signal }) =>
            site
                ? getOverview({ siteId: site.site_id, from, to, timezone }, signal)
                : Promise.reject(new Error("No workspace site selected.")),
        enabled: site !== undefined,
    });
    const hourly = query.data?.hourly;
    const chart = useMemo(() => buildChart(hourly ?? []), [hourly]);

    if (query.isLoading) return <WorkspaceLoading label={t("loading")} />;
    if (query.isError || !query.data)
        return <WorkspaceFailure error={query.error} t={t} onRetry={() => void query.refetch()} />;

    const data: OverviewResponse = query.data;
    const stale = data.freshness.state === "auth_failed" || data.freshness.state === "unreachable";
    const empty = data.totals.alerts === 0;
    const freshness = t(`freshness${freshnessKey(data.freshness.state)}`);
    const activeHour = chart.groups.some((group) => group.hour === selectedHour)
        ? selectedHour
        : (chart.groups.at(-1)?.hour ?? "");
    const activeGroup = chart.groups.find((group) => group.hour === activeHour);

    return (
        <div className="workspace-page overview-v2">
            <p className="page-description">{t("overviewDescription")}</p>
            {stale && (
                <section className="alert error ingestion-alert" role="alert">
                    <div>
                        <strong>{t("stalledTitle")}</strong>
                        <p>{t("stalledDescription")}</p>
                    </div>
                    <span
                        className={`status-pill ${data.freshness.state === "auth_failed" ? "status-pill-warning" : "status-pill-neutral"}`}
                    >
                        {freshness}
                    </span>
                </section>
            )}

            <section className="overview-v2-summary" aria-label={t("overview")}>
                <Metric label={t("alertsTotal")} value={data.totals.alerts} />
                <Metric label={t("groupsTotal")} value={data.totals.groups} />
                <Metric label={openIncidentsLabel(t)} value={data.totals.open_incidents} />
                <Metric label={t("unassigned")} value={data.totals.unassigned_actionable} />
                <Metric
                    label={t("lag")}
                    value={formatDuration(data.freshness.lag_seconds)}
                    state={freshness}
                    stateKind={freshnessStateKind(data.freshness.state)}
                />
            </section>

            {empty ? (
                <Panel className="workspace-panel overview-v2-quiet">
                    <QuietSiteState t={t} />
                </Panel>
            ) : (
                <>
                    <Panel className="workspace-panel overview-v2-volume">
                        <PanelHeading
                            title={t("hourlyVolume")}
                            description={`${data.totals.alerts.toLocaleString()} ${t("alerts").toLocaleLowerCase()} · ${formatWindow(from, to, timezone)}`}
                        />
                        {chart.groups.length === 0 ? (
                            <EmptyPanel text={t("noData")} />
                        ) : (
                            <>
                                <ChartLegend totals={chart.totals} t={t} />
                                <label className="overview-v2-hour-select">
                                    <span>{t("eventTime")}</span>
                                    <select
                                        value={activeHour}
                                        onChange={(event) => setSelectedHour(event.target.value)}
                                    >
                                        {chart.groups.map((group) => (
                                            <option key={group.hour} value={group.hour}>
                                                {formatTime(group.hour, timezone)} ·{" "}
                                                {group.total.toLocaleString()}
                                            </option>
                                        ))}
                                    </select>
                                </label>
                                <div
                                    className="overview-v2-chart"
                                    role="img"
                                    aria-label={`${t("hourlyVolume")}. ${data.totals.alerts.toLocaleString()} ${t("alerts").toLocaleLowerCase()}.`}
                                >
                                    <ResponsiveContainer width="100%" height="100%">
                                        <BarChart
                                            data={chart.data}
                                            margin={{ top: 4, right: 2, bottom: 0, left: 2 }}
                                            barCategoryGap="28%"
                                            accessibilityLayer={false}
                                        >
                                            <XAxis dataKey="hour" hide />
                                            <YAxis domain={[0, chart.maximum]} hide />
                                            {[...chart.series].reverse().map((series) => (
                                                <Bar
                                                    key={series.band}
                                                    dataKey={series.dataKey}
                                                    stackId="alerts"
                                                    fill={`var(--${bandVariable(series.band)})`}
                                                    isAnimationActive={false}
                                                    maxBarSize={28}
                                                    onClick={(_, index) => {
                                                        const datum = chart.data[index];
                                                        if (datum) setSelectedHour(datum.hour);
                                                    }}
                                                >
                                                    {chart.data.map((datum) => {
                                                        const selected = datum.hour === activeHour;
                                                        return (
                                                            <Cell
                                                                key={`${series.band}-${datum.hour}`}
                                                                fillOpacity={selected ? 1 : 0.58}
                                                                stroke={
                                                                    selected
                                                                        ? "var(--accent)"
                                                                        : "none"
                                                                }
                                                                strokeWidth={selected ? 1 : 0}
                                                            />
                                                        );
                                                    })}
                                                </Bar>
                                            ))}
                                        </BarChart>
                                    </ResponsiveContainer>
                                </div>
                                <div className="overview-v2-axis" aria-hidden="true">
                                    <span>
                                        {formatTime(chart.groups[0]?.hour ?? from, timezone)}
                                    </span>
                                    <span>
                                        {formatTime(chart.groups.at(-1)?.hour ?? to, timezone)}
                                    </span>
                                </div>
                                {activeGroup && (
                                    <HourBreakdown
                                        group={activeGroup}
                                        viewFrom={from}
                                        viewTo={to}
                                        timezone={timezone}
                                        t={t}
                                        onDrilldown={onDrilldown}
                                    />
                                )}
                            </>
                        )}
                    </Panel>

                    <div className="overview-v2-lists">
                        <TopList
                            title={t("topRules")}
                            items={data.top_rules}
                            t={t}
                            mono
                            onSelect={(item) => onDrilldown({ rule_id: item.key })}
                        />
                        <TopList
                            title={t("topAgents")}
                            items={data.top_agents}
                            t={t}
                            mono
                            onSelect={(item) => onDrilldown({ agent_id: item.key })}
                        />
                        <TopList
                            title={t("topTactics")}
                            items={data.top_tactics}
                            t={t}
                            onSelect={(item) => onDrilldown({ tactic: item.key })}
                        />
                        <TopList
                            title={t("topIps")}
                            items={data.top_src_ips}
                            t={t}
                            mono
                            onSelect={(item) =>
                                onDrilldown({ entity_kind: "ip", entity: item.key })
                            }
                        />
                        <TopList
                            title={t("topUsers")}
                            items={data.top_users}
                            t={t}
                            mono
                            onSelect={(item) =>
                                onDrilldown({ entity_kind: "user", entity: item.key })
                            }
                        />
                    </div>
                </>
            )}

            <div className="freshness-footnote">
                <span>
                    {t("lastSuccess")}: {formatTime(data.freshness.last_success_at, timezone)}
                </span>
                <span>·</span>
                <span>
                    {t("checkpoint")}: {formatTime(data.freshness.checkpoint_at, timezone)}
                </span>
                <span>·</span>
                <span>
                    {t("mismatch48h")}: {data.freshness.reconcile_mismatches_48h}
                </span>
            </div>
        </div>
    );
}

function Metric({
    label,
    value,
    state,
    stateKind = "neutral",
}: {
    label: string;
    value: number | string | null | undefined;
    state?: string;
    stateKind?: "good" | "warning" | "danger" | "neutral";
}) {
    const formatted = typeof value === "number" ? value.toLocaleString() : (value ?? "—");
    return (
        <div className="overview-v2-metric">
            <span>{label}</span>
            <strong>{formatted}</strong>
            {state && <small data-state={stateKind}>{state}</small>}
        </div>
    );
}

function PanelHeading({ title, description }: { title: string; description?: string }) {
    return (
        <header className="overview-v2-panel-head">
            <div>
                <h2>{title}</h2>
                {description && <p>{description}</p>}
            </div>
        </header>
    );
}

function HourBreakdown({
    group,
    viewFrom,
    viewTo,
    timezone,
    t,
    onDrilldown,
}: {
    group: HourGroup;
    viewFrom: string;
    viewTo: string;
    timezone: string;
    t: Translate;
    onDrilldown: (filters: AlertDrilldown) => void;
}) {
    const range = clippedHourRange(group.hour, viewFrom, viewTo);
    return (
        <div className="overview-v2-breakdown">
            <div>
                <strong>{formatTime(group.hour, timezone)}</strong>
                <span>
                    {group.total.toLocaleString()} {t("alerts").toLocaleLowerCase()}
                </span>
            </div>
            <div className="overview-v2-breakdown-actions">
                {orderedBuckets(group.buckets).map((bucket) => {
                    const level = levelRange(bucket.level_band);
                    const content = (
                        <>
                            <i
                                className={`overview-v2-band-${bandClass(bucket.level_band)}`}
                                aria-hidden="true"
                            />
                            <span>{levelLabel(bucket.level_band, t)}</span>
                            <strong>{bucket.count.toLocaleString()}</strong>
                        </>
                    );
                    if (!level) {
                        return (
                            <span
                                className="overview-v2-breakdown-disabled"
                                key={bucket.level_band}
                            >
                                {content}
                            </span>
                        );
                    }
                    return (
                        <button
                            type="button"
                            key={bucket.level_band}
                            onClick={() =>
                                onDrilldown({
                                    from: range.from,
                                    to: range.to,
                                    min_level: level.min,
                                    max_level: level.max,
                                })
                            }
                        >
                            {content}
                        </button>
                    );
                })}
            </div>
        </div>
    );
}

function ChartLegend({ totals, t }: { totals: Map<string, number>; t: Translate }) {
    return (
        <div className="overview-v2-legend" aria-label={t("filterLevel")}>
            {orderedBands([...totals.keys()]).map((band) => (
                <span key={band}>
                    <i className={`overview-v2-band-${bandClass(band)}`} aria-hidden="true" />
                    {levelLabel(band, t)}{" "}
                    <strong>{(totals.get(band) ?? 0).toLocaleString()}</strong>
                </span>
            ))}
        </div>
    );
}

function TopList({
    title,
    items,
    t,
    mono = false,
    onSelect,
}: {
    title: string;
    items: OverviewResponse["top_rules"];
    t: Translate;
    mono?: boolean;
    onSelect: (item: OverviewResponse["top_rules"][number]) => void;
}) {
    return (
        <Panel className="workspace-panel overview-v2-list">
            <PanelHeading title={title} />
            {items.length === 0 ? (
                <EmptyPanel text={t("noData")} />
            ) : (
                <ol>
                    {items.map((item, index) => (
                        <li key={`${item.key}-${item.label}`}>
                            <span className="overview-v2-rank" aria-hidden="true">
                                {index + 1}
                            </span>
                            <button type="button" onClick={() => onSelect(item)}>
                                <span>{item.label}</span>
                                {mono && <code>{item.key}</code>}
                            </button>
                            <strong>{item.count.toLocaleString()}</strong>
                        </li>
                    ))}
                </ol>
            )}
        </Panel>
    );
}

function EmptyPanel({ text }: { text: string }) {
    return <p className="overview-v2-empty">{text}</p>;
}

function buildChart(buckets: HourlyBucket[]): {
    groups: HourGroup[];
    maximum: number;
    totals: Map<string, number>;
    data: HourChartDatum[];
    series: HourChartSeries[];
} {
    const byHour = new Map<string, HourlyBucket[]>();
    const totals = new Map<string, number>();
    for (const bucket of buckets) {
        const hour = byHour.get(bucket.hour) ?? [];
        hour.push(bucket);
        byHour.set(bucket.hour, hour);
        totals.set(bucket.level_band, (totals.get(bucket.level_band) ?? 0) + bucket.count);
    }
    const groups = [...byHour.entries()]
        .sort(([left], [right]) => left.localeCompare(right))
        .map(([hour, hourBuckets]) => ({
            hour,
            buckets: hourBuckets,
            total: hourBuckets.reduce((sum, bucket) => sum + bucket.count, 0),
        }));
    const series = orderedBands([...totals.keys()]).map((band, index) => ({
        band,
        dataKey: `band_${index}`,
    }));
    const data = groups.map((group) => {
        const datum: HourChartDatum = { hour: group.hour, total: group.total };
        for (const item of series) {
            datum[item.dataKey] = group.buckets
                .filter((bucket) => bucket.level_band === item.band)
                .reduce((sum, bucket) => sum + bucket.count, 0);
        }
        return datum;
    });
    return {
        groups,
        maximum: Math.max(1, ...groups.map((group) => group.total)),
        totals,
        data,
        series,
    };
}

function orderedBuckets(buckets: HourlyBucket[]): HourlyBucket[] {
    return [...buckets].sort(
        (left, right) => bandOrder(left.level_band) - bandOrder(right.level_band),
    );
}
function orderedBands(bands: string[]): string[] {
    return [...bands].sort((left, right) => bandOrder(left) - bandOrder(right));
}
function bandOrder(band: string): number {
    if (band === "13-15") return 0;
    if (band === "10-12") return 1;
    if (band === "7-9") return 2;
    if (band === "0-6") return 3;
    return 4;
}
function bandClass(band: string): string {
    if (band === "13-15") return "series-one";
    if (band === "10-12") return "series-two";
    if (band === "7-9") return "series-three";
    if (band === "0-6") return "series-four";
    return "unknown";
}
function bandVariable(band: string): string {
    if (band === "13-15") return "series-blue";
    if (band === "10-12") return "series-orange";
    if (band === "7-9") return "series-teal";
    if (band === "0-6") return "series-purple";
    return "series-other";
}
function levelRange(band: string): { min: number; max: number } | null {
    const match = /^(\d+)-(\d+)$/.exec(band);
    if (!match) return null;
    const min = Number(match[1]);
    const max = Number(match[2]);
    return Number.isFinite(min) && Number.isFinite(max) ? { min, max } : null;
}
function levelLabel(band: string, t: Translate): string {
    return band === "unknown" ? t("nullUnknown") : `${t("level")} ${band}`;
}
function freshnessKey(state: string): string {
    if (state === "ok") return "Fresh";
    if (state === "lagging") return "Lagging";
    if (state === "auth_failed") return "AuthFailed";
    if (state === "unreachable") return "Unreachable";
    return "Unknown";
}
function freshnessStateKind(state: string): "good" | "warning" | "danger" | "neutral" {
    if (state === "ok") return "good";
    if (state === "lagging") return "warning";
    if (state === "auth_failed" || state === "unreachable") return "danger";
    return "neutral";
}
function openIncidentsLabel(t: Translate): string {
    return t("incidents") === "Incidentes" ? "Incidentes abiertos" : "Open incidents";
}
function clippedHourRange(
    hour: string,
    viewFrom: string,
    viewTo: string,
): { from: string; to: string } {
    const hourStart = new Date(hour).getTime();
    const hourEnd = hourStart + 3_600_000;
    const from = Math.max(hourStart, new Date(viewFrom).getTime());
    const to = Math.min(hourEnd, new Date(viewTo).getTime());
    return { from: new Date(from).toISOString(), to: new Date(to).toISOString() };
}
function formatTime(value: string | null, timezone: string): string {
    return value
        ? new Intl.DateTimeFormat(undefined, {
              dateStyle: "medium",
              timeStyle: "short",
              timeZone: timezone,
          }).format(new Date(value))
        : "—";
}
function formatWindow(from: string, to: string, timezone: string): string {
    const formatter = new Intl.DateTimeFormat(undefined, {
        month: "short",
        day: "numeric",
        timeZone: timezone,
    });
    return `${formatter.format(new Date(from))}–${formatter.format(new Date(to))}`;
}
function formatDuration(seconds: number | null): string {
    if (seconds === null) return "—";
    if (seconds < 60) return `${Math.max(0, Math.round(seconds))}s`;
    if (seconds < 3_600) return `${Math.round(seconds / 60)}m`;
    return `${(seconds / 3_600).toFixed(1)}h`;
}
