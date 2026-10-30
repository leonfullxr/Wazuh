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
type HeatmapCell =
    | {
          kind: "covered";
          day: number;
          hour: number;
          count: number;
          coverageMs: number;
          intensity: number;
      }
    | { kind: "uncovered"; day: number; hour: number };
type HeatmapState =
    | {
          kind: "available";
          cells: HeatmapCell[];
          peak: HeatmapCell & { kind: "covered" };
          confirmedThrough: number | null;
      }
    | { kind: "unavailable"; reason: "range" | "timezone" | "unconfirmed" };

const HOUR_MS = 3_600_000;
const HEATMAP_DAYS = [1, 2, 3, 4, 5, 6, 0];

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
    const checkpoint = query.data?.freshness.checkpoint_at ?? null;
    const chart = useMemo(() => buildChart(hourly ?? []), [hourly]);
    const heatmap = useMemo(
        () => buildHeatmap(hourly ?? [], from, to, timezone, checkpoint),
        [checkpoint, from, hourly, timezone, to],
    );

    if (query.isLoading) return <WorkspaceLoading label={t("loading")} />;
    if (query.isError || !query.data)
        return <WorkspaceFailure error={query.error} t={t} onRetry={() => void query.refetch()} />;

    const data: OverviewResponse = query.data;
    const stale = data.freshness.state === "auth_failed" || data.freshness.state === "unreachable";
    const empty = data.totals.alerts === 0;
    const freshness = t(`freshness${freshnessKey(data.freshness.state)}`);
    const activeHour = chart.groups.some((group) => group.hour === selectedHour)
        ? selectedHour
        : (chart.groups
              .slice()
              .reverse()
              .find((group) => group.total > 0)?.hour ??
          chart.groups.at(-1)?.hour ??
          "");
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
                <>
                    {heatmap.kind === "available" && heatmap.confirmedThrough === null && (
                        <Panel className="workspace-panel overview-v2-quiet">
                            <QuietSiteState t={t} />
                        </Panel>
                    )}
                    <AlertTimeHeatmap heatmap={heatmap} timezone={timezone} t={t} />
                </>
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

                    <AlertTimeHeatmap heatmap={heatmap} timezone={timezone} t={t} />

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

function AlertTimeHeatmap({
    heatmap,
    timezone,
    t,
}: {
    heatmap: HeatmapState;
    timezone: string;
    t: Translate;
}) {
    const copy = heatmapCopy(t);
    if (heatmap.kind === "unavailable") {
        const unavailable = unavailableHeatmapCopy(heatmap.reason, copy);
        return (
            <Panel className="workspace-panel overview-v2-heatmap-panel">
                <PanelHeading title={copy.title} description={unavailable.description} />
                <EmptyPanel text={unavailable.title} />
            </Panel>
        );
    }

    const days = dayLabels(t);
    const peak = `${copy.peakTotal}: ${days[heatmap.peak.day]} ${formatHeatmapHour(heatmap.peak.hour)} · ${heatmap.peak.count.toLocaleString()} ${copy.alerts} · ${copy.coverage} ${formatCoverageDuration(heatmap.peak.coverageMs, t)}`;
    const cutoff = heatmap.confirmedThrough
        ? `${copy.confirmedThrough} ${formatTime(new Date(heatmap.confirmedThrough).toISOString(), timezone)}`
        : null;
    const subtitle = cutoff ? `${peak} · ${cutoff}` : peak;
    const cells = new Map(heatmap.cells.map((cell) => [`${cell.day}-${cell.hour}`, cell]));

    return (
        <Panel className="workspace-panel overview-v2-heatmap-panel">
            <PanelHeading title={copy.title} description={subtitle} />
            <div
                className="overview-v2-heatmap-scroll"
                tabIndex={0}
                role="region"
                aria-label={copy.title}
            >
                <div className="overview-v2-heatmap" aria-hidden="true">
                    <span />
                    {Array.from({ length: 24 }, (_, hour) => (
                        <span className="overview-v2-heatmap-hour" key={hour}>
                            {hour % 3 === 0 ? String(hour).padStart(2, "0") : ""}
                        </span>
                    ))}
                    {HEATMAP_DAYS.map((day) => (
                        <HeatmapVisualRow
                            key={day}
                            day={day}
                            dayLabel={days[day]}
                            cells={cells}
                            noCoverage={copy.noCoverage}
                            alerts={copy.alerts}
                            coverage={copy.coverage}
                            t={t}
                        />
                    ))}
                </div>
            </div>
            <table className="sr-only">
                <caption>
                    {copy.title}. {subtitle}
                </caption>
                <thead>
                    <tr>
                        <th scope="col">{copy.day}</th>
                        {Array.from({ length: 24 }, (_, hour) => (
                            <th scope="col" key={hour}>
                                {formatHeatmapHour(hour)}
                            </th>
                        ))}
                    </tr>
                </thead>
                <tbody>
                    {HEATMAP_DAYS.map((day) => (
                        <tr key={day}>
                            <th scope="row">{days[day]}</th>
                            {Array.from({ length: 24 }, (_, hour) => {
                                const cell = cells.get(`${day}-${hour}`);
                                return (
                                    <td key={hour}>
                                        {cell?.kind === "covered"
                                            ? `${cell.count.toLocaleString()} ${copy.alerts}; ${copy.coverage} ${formatCoverageDuration(cell.coverageMs, t)}`
                                            : copy.noCoverage}
                                    </td>
                                );
                            })}
                        </tr>
                    ))}
                </tbody>
            </table>
        </Panel>
    );
}

function HeatmapVisualRow({
    day,
    dayLabel,
    cells,
    noCoverage,
    alerts,
    coverage,
    t,
}: {
    day: number;
    dayLabel: string;
    cells: Map<string, HeatmapCell>;
    noCoverage: string;
    alerts: string;
    coverage: string;
    t: Translate;
}) {
    return (
        <>
            <span className="overview-v2-heatmap-day">{dayLabel}</span>
            {Array.from({ length: 24 }, (_, hour) => {
                const cell = cells.get(`${day}-${hour}`);
                const title =
                    cell?.kind === "covered"
                        ? `${dayLabel} ${formatHeatmapHour(hour)} — ${cell.count.toLocaleString()} ${alerts}; ${coverage} ${formatCoverageDuration(cell.coverageMs, t)}`
                        : `${dayLabel} ${formatHeatmapHour(hour)} — ${noCoverage}`;
                return (
                    <span
                        className="overview-v2-heatmap-cell"
                        data-coverage={cell?.kind ?? "uncovered"}
                        data-intensity={cell?.kind === "covered" ? cell.intensity : undefined}
                        key={hour}
                        title={title}
                    >
                        <strong>
                            {cell?.kind === "covered" ? cell.count.toLocaleString() : "—"}
                        </strong>
                        <small>
                            {cell?.kind === "covered"
                                ? formatCoverageDuration(cell.coverageMs, t)
                                : formatCoverageDuration(0, t)}
                        </small>
                    </span>
                );
            })}
        </>
    );
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

export function buildHeatmap(
    buckets: HourlyBucket[],
    from: string,
    to: string,
    timezone: string,
    checkpoint: string | null,
): HeatmapState {
    const fromMs = new Date(from).getTime();
    const toMs = new Date(to).getTime();
    if (!Number.isFinite(fromMs) || !Number.isFinite(toMs) || toMs <= fromMs) {
        return { kind: "unavailable", reason: "range" };
    }
    if (checkpoint === null) return { kind: "unavailable", reason: "unconfirmed" };
    const checkpointMs = new Date(checkpoint).getTime();
    if (!Number.isFinite(checkpointMs)) {
        return { kind: "unavailable", reason: "unconfirmed" };
    }
    const checkpointInsideWindow = checkpointMs < toMs;
    const confirmedTo = checkpointInsideWindow
        ? Math.floor(checkpointMs / HOUR_MS) * HOUR_MS
        : toMs;
    if (confirmedTo <= fromMs) return { kind: "unavailable", reason: "unconfirmed" };

    let formatter: Intl.DateTimeFormat;
    try {
        formatter = new Intl.DateTimeFormat("en-US", {
            timeZone: timezone,
            weekday: "short",
            year: "numeric",
            month: "2-digit",
            day: "2-digit",
            hour: "2-digit",
            minute: "2-digit",
            second: "2-digit",
            hourCycle: "h23",
        });
    } catch {
        return { kind: "unavailable", reason: "timezone" };
    }

    const counts = new Map<number, number>();
    for (const bucket of buckets) {
        const timestamp = new Date(bucket.hour).getTime();
        if (!Number.isFinite(timestamp)) continue;
        const utcHour = Math.floor(timestamp / HOUR_MS) * HOUR_MS;
        counts.set(utcHour, (counts.get(utcHour) ?? 0) + bucket.count);
    }

    const aggregate = new Map<
        string,
        { day: number; hour: number; count: number; coverageMs: number }
    >();
    const firstUtcHour = Math.floor(fromMs / HOUR_MS) * HOUR_MS;
    for (let utcHour = firstUtcHour; utcHour < confirmedTo; utcHour += HOUR_MS) {
        const coordinate = localCoordinate(formatter, utcHour);
        const bucketOffset = localUtcOffsetMinutes(formatter, utcHour);
        const coveredFrom = Math.max(fromMs, utcHour);
        const coveredTo = Math.min(confirmedTo, utcHour + HOUR_MS);
        const lastCoveredSecond = Math.max(coveredFrom, coveredTo - 1_000);
        const coveredStartOffset = localUtcOffsetMinutes(formatter, coveredFrom);
        const coveredEndOffset = localUtcOffsetMinutes(formatter, lastCoveredSecond);
        if (
            coordinate === null ||
            bucketOffset === null ||
            coveredStartOffset === null ||
            coveredEndOffset === null ||
            coordinate.minute !== 0 ||
            coordinate.second !== 0 ||
            bucketOffset % 60 !== 0 ||
            coveredStartOffset !== bucketOffset ||
            coveredEndOffset !== bucketOffset
        ) {
            return { kind: "unavailable", reason: "timezone" };
        }
        const key = `${coordinate.day}-${coordinate.hour}`;
        const current = aggregate.get(key);
        aggregate.set(key, {
            day: coordinate.day,
            hour: coordinate.hour,
            count: (current?.count ?? 0) + (counts.get(utcHour) ?? 0),
            coverageMs: (current?.coverageMs ?? 0) + (coveredTo - coveredFrom),
        });
    }

    const maximum = Math.max(0, ...[...aggregate.values()].map((cell) => cell.count));
    const cells: HeatmapCell[] = [];
    for (const day of HEATMAP_DAYS) {
        for (let hour = 0; hour < 24; hour += 1) {
            const value = aggregate.get(`${day}-${hour}`);
            cells.push(
                value
                    ? {
                          kind: "covered",
                          ...value,
                          intensity:
                              value.count === 0 || maximum === 0
                                  ? 1
                                  : 1 + Math.ceil((value.count / maximum) * 5),
                      }
                    : { kind: "uncovered", day, hour },
            );
        }
    }
    let peak: (HeatmapCell & { kind: "covered" }) | null = null;
    for (const cell of cells) {
        if (cell.kind === "covered" && (peak === null || cell.count > peak.count)) peak = cell;
    }
    if (peak === null) return { kind: "unavailable", reason: "range" };
    return {
        kind: "available",
        cells,
        peak,
        confirmedThrough: checkpointInsideWindow ? confirmedTo : null,
    };
}

function localCoordinate(
    formatter: Intl.DateTimeFormat,
    timestamp: number,
): { day: number; hour: number; minute: number; second: number } | null {
    const parts = formatter.formatToParts(new Date(timestamp));
    const weekday = weekdayNumber(partValue(parts, "weekday"));
    const hour = Number(partValue(parts, "hour"));
    const minute = Number(partValue(parts, "minute"));
    const second = Number(partValue(parts, "second"));
    return weekday !== null && [hour, minute, second].every(Number.isInteger)
        ? { day: weekday, hour, minute, second }
        : null;
}

function localUtcOffsetMinutes(formatter: Intl.DateTimeFormat, timestamp: number): number | null {
    const secondTimestamp = Math.floor(timestamp / 1_000) * 1_000;
    const parts = formatter.formatToParts(new Date(secondTimestamp));
    const year = Number(partValue(parts, "year"));
    const month = Number(partValue(parts, "month"));
    const day = Number(partValue(parts, "day"));
    const hour = Number(partValue(parts, "hour"));
    const minute = Number(partValue(parts, "minute"));
    const second = Number(partValue(parts, "second"));
    if (![year, month, day, hour, minute, second].every(Number.isInteger)) return null;
    return (Date.UTC(year, month - 1, day, hour, minute, second) - secondTimestamp) / 60_000;
}

function partValue(parts: Intl.DateTimeFormatPart[], type: string): string {
    return parts.find((part) => part.type === type)?.value ?? "";
}

function weekdayNumber(weekday: string): number | null {
    if (weekday === "Sun") return 0;
    if (weekday === "Mon") return 1;
    if (weekday === "Tue") return 2;
    if (weekday === "Wed") return 3;
    if (weekday === "Thu") return 4;
    if (weekday === "Fri") return 5;
    if (weekday === "Sat") return 6;
    return null;
}

function dayLabels(t: Translate): string[] {
    return t("alerts") === "Alertas"
        ? ["Dom", "Lun", "Mar", "Mié", "Jue", "Vie", "Sáb"]
        : ["Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"];
}

function heatmapCopy(t: Translate): {
    title: string;
    peakTotal: string;
    timezoneUnavailable: string;
    timezoneUnavailableDescription: string;
    dataUnconfirmed: string;
    dataUnconfirmedDescription: string;
    invalidRange: string;
    coverage: string;
    confirmedThrough: string;
    noCoverage: string;
    day: string;
    alerts: string;
} {
    return t("alerts") === "Alertas"
        ? {
              title: "Cuándo ocurren las alertas",
              peakTotal: "Total máximo",
              timezoneUnavailable: "No disponible para esta zona horaria.",
              timezoneUnavailableDescription:
                  "Los intervalos UTC no coinciden con horas locales completas; no se muestran datos para evitar una agrupación incorrecta.",
              dataUnconfirmed: "Los datos de este periodo no están confirmados.",
              dataUnconfirmedDescription:
                  "No hay un punto de control que confirme ningún intervalo horario completo.",
              invalidRange: "El periodo seleccionado no es válido.",
              coverage: "cobertura",
              confirmedThrough: "Los datos confirmados terminan a las",
              noCoverage: "Sin cobertura temporal",
              day: "Día",
              alerts: "alertas",
          }
        : {
              title: "When alerts happen",
              peakTotal: "Peak total",
              timezoneUnavailable: "Unavailable for this timezone.",
              timezoneUnavailableDescription:
                  "UTC buckets do not align to whole local hours, so no potentially misbinned data is shown.",
              dataUnconfirmed: "Data for this period is not confirmed.",
              dataUnconfirmedDescription:
                  "No checkpoint confirms a complete hourly interval in this period.",
              invalidRange: "The selected time range is invalid.",
              coverage: "coverage",
              confirmedThrough: "Confirmed data ends at",
              noCoverage: "No temporal coverage",
              day: "Day",
              alerts: "alerts",
          };
}

function unavailableHeatmapCopy(
    reason: Extract<HeatmapState, { kind: "unavailable" }>["reason"],
    copy: ReturnType<typeof heatmapCopy>,
): { title: string; description: string } {
    if (reason === "timezone") {
        return {
            title: copy.timezoneUnavailable,
            description: copy.timezoneUnavailableDescription,
        };
    }
    if (reason === "unconfirmed") {
        return { title: copy.dataUnconfirmed, description: copy.dataUnconfirmedDescription };
    }
    return { title: copy.invalidRange, description: copy.invalidRange };
}

function formatCoverageDuration(milliseconds: number, t: Translate): string {
    const locale = t("alerts") === "Alertas" ? "es-ES" : "en-US";
    const hours = milliseconds / HOUR_MS;
    return `${new Intl.NumberFormat(locale, { maximumFractionDigits: 2 }).format(hours)} h`;
}

function formatHeatmapHour(hour: number): string {
    return `${String(hour).padStart(2, "0")}:00`;
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
