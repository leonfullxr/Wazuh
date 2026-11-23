import { useEffect, useMemo, useRef, useState, type ReactNode } from "react";
import { useQuery } from "@tanstack/react-query";
import {
    Bar,
    BarChart,
    CartesianGrid,
    Cell,
    LabelList,
    ReferenceDot,
    ResponsiveContainer,
    XAxis,
    YAxis,
} from "recharts";
import type { OverviewResponse, SiteSummary } from "../../api/workspace";
import { getOverview, listAssets, listQueue } from "../../api/workspace";
import { BriefcaseBusiness } from "lucide-react";
import { Tag } from "../../components/ui/tag";
import {
    ShareBar,
    SlaText,
    SummaryStrip,
    slaFrom,
    workStatusKeys,
    workStatusTones,
} from "../../components/ui/portfolio";
import { useSamples } from "../workspace/samples";
import { Panel } from "../../components/ui/panel";
import { QuietSiteState, WorkspaceFailure, WorkspaceLoading } from "../workspace/WorkspaceStates";
import "./overview-v2.css";
import "./overview-pp.css";

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
    const yTicks = niceTicks(chart.maximum);
    const heatmap = useMemo(
        () => buildHeatmap(hourly ?? [], from, to, timezone, checkpoint),
        [checkpoint, from, hourly, timezone, to],
    );

    const assets = useQuery({
        queryKey: ["workspace", "assets", site?.site_id, ""],
        queryFn: ({ signal }) => listAssets(site?.site_id ?? "", "", signal),
        enabled: site !== undefined,
    });
    const criticality = useMemo(
        () =>
            new Map(
                (assets.data?.items ?? [])
                    .filter((asset) => asset.entity_kind === "host")
                    .map((asset) => [asset.entity_value, asset.criticality]),
            ),
        [assets.data],
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
    const peakGroup = chart.groups.reduce<HourGroup | undefined>(
        (peak, group) => (!peak || group.total > peak.total ? group : peak),
        undefined,
    );
    const quietHours = chart.groups.filter((group) => group.total === 0).length;
    const unassigned = data.totals.unassigned_actionable;
    const strip = [
        {
            label: t("alertsTotal"),
            value: data.totals.alerts.toLocaleString(),
            note: [...chart.totals.keys()].length === 1
                ? levelLabel([...chart.totals.keys()][0] ?? "", t).toLocaleLowerCase()
                : undefined,
        },
        {
            label: t("busiestHour"),
            value: peakGroup ? peakGroup.total.toLocaleString() : "\u2014",
            note: peakGroup ? formatShortHour(peakGroup.hour, timezone) : undefined,
        },
        {
            label: t("groupsToTriage"),
            value: data.totals.groups == null ? "\u2014" : data.totals.groups.toLocaleString(),
            note:
                unassigned == null
                    ? undefined
                    : `${unassigned.toLocaleString()} ${t("unassignedShort")}`,
        },
        {
            label: t("lag"),
            value: formatDuration(data.freshness.lag_seconds),
            note: (
                <span className="overview-freshness" data-state={freshnessStateKind(data.freshness.state)}>
                    <span className="dot" data-tone={dotTone(freshnessStateKind(data.freshness.state))} />
                    {freshness}
                </span>
            ),
        },
    ];

    return (
        <div className="workspace-page overview-pp pp-stack">
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

            <SummaryStrip items={strip} label={t("overview")} className="overview-summary" />

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
                    <div className="pp-grid">
                        <section className="pp-panel pp-panel-pad pp-wide overview-volume" aria-labelledby="overview-volume-heading">
                            <div className="overview-volume-head">
                                <div>
                                    <h2 id="overview-volume-heading" className="t-section">
                                        {t("hourlyVolume")}
                                    </h2>
                                    <p className="t-secondary">
                                        {data.totals.alerts.toLocaleString()}{" "}
                                        {t("alerts").toLocaleLowerCase()} ·{" "}
                                        {formatWindow(from, to, timezone)}
                                    </p>
                                </div>
                                {chart.groups.length > 0 && (
                                    <label className="overview-hour-select">
                                        <span>{t("eventTime")}</span>
                                        <select
                                            value={activeHour}
                                            onChange={(event) => setSelectedHour(event.target.value)}
                                        >
                                            {chart.groups.map((group) => (
                                                <option key={group.hour} value={group.hour}>
                                                    {formatShortHour(group.hour, timezone)} ·{" "}
                                                    {group.total.toLocaleString()}{" "}
                                                    {t(
                                                        group.total === 1 ? "alertSingular" : "alerts",
                                                    ).toLocaleLowerCase()}
                                                </option>
                                            ))}
                                        </select>
                                    </label>
                                )}
                            </div>
                            {chart.groups.length === 0 ? (
                                <EmptyPanel text={t("noData")} />
                            ) : (
                                <>
                                    <div
                                        className="overview-chart"
                                        role="img"
                                        aria-label={`${t("hourlyVolume")}. ${data.totals.alerts.toLocaleString()} ${t("alerts").toLocaleLowerCase()}.${peakGroup ? ` ${t("peak")} ${peakGroup.total.toLocaleString()}, ${formatShortHour(peakGroup.hour, timezone)}.` : ""}`}
                                    >
                                        <ResponsiveContainer width="100%" height="100%">
                                            <BarChart
                                                data={chart.data}
                                                margin={{ top: 18, right: 4, bottom: 0, left: 0 }}
                                                barCategoryGap="22%"
                                                accessibilityLayer={false}
                                            >
                                                <XAxis
                                                    dataKey="hour"
                                                    tickFormatter={(hour: string) => formatTick(hour, timezone)}
                                                    interval="equidistantPreserveStart"
                                                    minTickGap={40}
                                                    axisLine={{ stroke: "var(--border-strong)" }}
                                                    tickLine={false}
                                                    height={22}
                                                    tick={{ fontSize: 11, fill: "var(--text-muted)" }}
                                                />
                                                <CartesianGrid vertical={false} stroke="var(--chart-grid)" />
                                                <YAxis
                                                    domain={[0, yTicks.at(-1) ?? 1]}
                                                    ticks={yTicks}
                                                    width={22}
                                                    axisLine={false}
                                                    tickLine={false}
                                                    tick={{ fontSize: 11, fill: "var(--text-muted)" }}
                                                />
                                                <Bar
                                                    dataKey="total"
                                                    isAnimationActive={false}
                                                    maxBarSize={18}
                                                    radius={[3, 3, 0, 0]}
                                                    onClick={(_, index) => {
                                                        const datum = chart.data[index];
                                                        if (datum) setSelectedHour(datum.hour);
                                                    }}
                                                >
                                                    {chart.data.map((datum) => (
                                                        <Cell
                                                            key={datum.hour}
                                                            fill={
                                                                datum.hour === peakGroup?.hour
                                                                    ? "var(--accent-hover)"
                                                                    : "var(--bar-fill)"
                                                            }
                                                            fillOpacity={
                                                                datum.hour === activeHour || datum.hour === peakGroup?.hour
                                                                    ? 1
                                                                    : 0.85
                                                            }
                                                            stroke="none"
                                                            cursor="pointer"
                                                        />
                                                    ))}
                                                    <LabelList
                                                        dataKey="total"
                                                        position="top"
                                                        content={(props) => {
                                                            const { x, y, width, index } = props as {
                                                                x?: number;
                                                                y?: number;
                                                                width?: number;
                                                                index?: number;
                                                            };
                                                            const datum = index === undefined ? undefined : chart.data[index];
                                                            if (!datum || datum.hour !== peakGroup?.hour) return null;
                                                            return (
                                                                <text
                                                                    x={(x ?? 0) + (width ?? 0) / 2}
                                                                    y={(y ?? 0) - 5}
                                                                    textAnchor="middle"
                                                                    fontSize={11}
                                                                    fontWeight={500}
                                                                    fill="var(--text)"
                                                                >
                                                                    {datum.total}
                                                                </text>
                                                            );
                                                        }}
                                                    />
                                                </Bar>
                                                <ReferenceDot
                                                    x={activeHour}
                                                    y={0}
                                                    r={3}
                                                    fill="var(--accent)"
                                                    stroke="var(--surface)"
                                                    strokeWidth={1}
                                                    ifOverflow="visible"
                                                    isFront
                                                />
                                            </BarChart>
                                        </ResponsiveContainer>
                                    </div>
                                    <div className="overview-volume-foot">
                                        {peakGroup && (
                                            <span>
                                                {t("peak")}{" "}
                                                <b>
                                                    {peakGroup.total.toLocaleString()}{" "}
                                                    {t(peakGroup.total === 1 ? "alertSingular" : "alerts").toLocaleLowerCase()}
                                                </b>{" "}
                                                {formatShortHour(peakGroup.hour, timezone)}
                                            </span>
                                        )}
                                        <span>
                                            {t("quietHours")}{" "}
                                            <b>
                                                {quietHours} / {chart.groups.length}
                                            </b>
                                        </span>
                                        <span>
                                            {t("checkpoint")}: {formatTime(data.freshness.checkpoint_at, timezone)}
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
                        </section>
                        <NeedsAttention
                            siteId={site?.site_id ?? ""}
                            from={from}
                            to={to}
                            openIncidents={data.totals.open_incidents}
                            t={t}
                        />
                    </div>

                    <div className="pp-grid">
                        <TopTable
                            id="overview-rules"
                            title={t("topRules")}
                            column={t("rule")}
                            items={data.top_rules}
                            total={data.totals.alerts}
                            t={t}
                            sub={(item) => `${t("rule")} ${item.key}`}
                            onSelect={(item) => onDrilldown({ rule_id: item.key })}
                        />
                        <TopTable
                            id="overview-agents"
                            title={t("topAgents")}
                            column={t("agent")}
                            items={data.top_agents}
                            total={data.totals.alerts}
                            t={t}
                            entity
                            sub={(item) => `${t("agent")} ${item.key}`}
                            criticality={(item) => criticality.get(item.label)}
                            onSelect={(item) => onDrilldown({ agent_id: item.key })}
                        />
                    </div>

                    <AlertTimeHeatmap heatmap={heatmap} timezone={timezone} t={t} />

                    <div className="pp-grid overview-lists">
                        <TopTable
                            id="overview-tactics"
                            title={t("topTactics")}
                            column={t("tactic")}
                            items={data.top_tactics}
                            total={data.totals.alerts}
                            t={t}
                            onSelect={(item) => onDrilldown({ tactic: item.key })}
                        />
                        <TopTable
                            id="overview-ips"
                            title={t("topIps")}
                            column={t("sourceIp")}
                            items={data.top_src_ips}
                            total={data.totals.alerts}
                            t={t}
                            entity
                            onSelect={(item) => onDrilldown({ entity_kind: "ip", entity: item.key })}
                        />
                        <TopTable
                            id="overview-users"
                            title={t("topUsers")}
                            column={t("user")}
                            items={data.top_users}
                            total={data.totals.alerts}
                            t={t}
                            entity
                            onSelect={(item) => onDrilldown({ entity_kind: "user", entity: item.key })}
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

function dotTone(kind: "good" | "warning" | "danger" | "neutral"): string {
    return kind === "good" ? "good" : kind === "warning" ? "warn" : kind === "danger" ? "bad" : "neutral";
}


function NeedsAttention({
    siteId,
    from,
    to,
    openIncidents,
    t,
}: {
    siteId: string;
    from: string;
    to: string;
    openIncidents: number | null | undefined;
    t: Translate;
}) {
    const samples = useSamples();
    const queue = useQuery({
        queryKey: ["workspace", "queue", siteId, { from, to }],
        queryFn: ({ signal }) => listQueue({ siteId, from, to }, signal),
        enabled: !!siteId,
    });
    const rows = (queue.data?.items ?? [])
        .filter((row) => row.work_state.status === "new" || row.work_state.status === "in_progress")
        .slice()
        .sort((left, right) => (right.group.score ?? -1) - (left.group.score ?? -1))
        .slice(0, 3);
    return (
        <section className="pp-panel pp-narrow overview-attention" aria-labelledby="overview-attention-heading">
            <div className="pp-panel-head">
                <div>
                    <h2 id="overview-attention-heading" className="t-section">
                        {t("needsAttention")}
                    </h2>
                </div>
                <a href="#queue">{t("openQueue")}</a>
            </div>
            {queue.isLoading ? (
                <p className="overview-attention-empty">{t("loading")}</p>
            ) : rows.length === 0 ? (
                <p className="overview-attention-empty">{t("nothingNeedsAttention")}</p>
            ) : (
                <ul className="overview-attention-list">
                    {rows.map((row) => {
                        const sla = samples?.groupSla[row.group.group_id];
                        const status = row.work_state.status;
                        return (
                            <li key={row.group.group_id}>
                                <a href={`#queue`} className="overview-attention-row">
                                    <span className="overview-attention-score num">
                                        {row.group.score === null ? "\u2014" : row.group.score.toFixed(1)}
                                    </span>
                                    <span className="overview-attention-main">
                                        <span className="overview-attention-title">{row.group.title}</span>
                                        <span className="overview-attention-meta">
                                            <Tag tone={workStatusTones[status]}>{t(workStatusKeys[status])}</Tag>
                                            {row.group.primary_entity && (
                                                <span>
                                                    {t("on")} <span className="ent">{row.group.primary_entity.value}</span>
                                                </span>
                                            )}
                                            <span>{row.work_state.owner_key ?? t("unassignedOwner")}</span>
                                            <SlaText
                                                sla={sla ? slaFrom(sla) : undefined}
                                                notReported={t("slaNotReported")}
                                            />
                                        </span>
                                    </span>
                                </a>
                            </li>
                        );
                    })}
                </ul>
            )}
            {typeof openIncidents === "number" && (
                <a className="overview-attention-foot" href="#incidents">
                    <BriefcaseBusiness size={16} aria-hidden="true" />
                    <span>
                        {openIncidents.toLocaleString()}{" "}
                        {t(openIncidents === 1 ? "openIncidentSingular" : "openIncidentPlural")}
                    </span>
                    <span className="pp-link">{t("view")}</span>
                </a>
            )}
        </section>
    );
}

type TopItem = OverviewResponse["top_rules"][number];

function TopTable({
    id,
    title,
    column,
    items,
    total,
    t,
    entity = false,
    sub,
    criticality,
    onSelect,
}: {
    id: string;
    title: string;
    column: string;
    items: TopItem[];
    total: number;
    t: Translate;
    entity?: boolean;
    sub?: (item: TopItem) => string;
    criticality?: (item: TopItem) => number | undefined;
    onSelect: (item: TopItem) => void;
}) {
    const listed = items.reduce((sum, item) => sum + item.count, 0);
    const other = Math.max(0, total - listed);
    return (
        <section className="pp-panel overview-top" aria-labelledby={`${id}-heading`}>
            <div className="pp-panel-head">
                <div>
                    <h2 id={`${id}-heading`} className="t-section">
                        {title}
                    </h2>
                </div>
            </div>
            {items.length === 0 ? (
                <EmptyPanel text={t("noData")} />
            ) : (
                <div className="pp-table-scroll">
                    <table className="pp-table">
                        <thead>
                            <tr>
                                <th scope="col">{column}</th>
                                <th scope="col" className="share-col">
                                    {t("shareOfAlerts")}
                                </th>
                                <th scope="col" className="is-num">
                                    {t("alerts")}
                                </th>
                            </tr>
                        </thead>
                        <tbody>
                            {items.map((item) => {
                                const level = criticality?.(item);
                                return (
                                    <tr key={`${item.key}-${item.label}`}>
                                        <td>
                                            <button
                                                type="button"
                                                className="overview-top-link"
                                                onClick={() => onSelect(item)}
                                            >
                                                <span className={entity ? "ent" : "cell-main"}>{item.label}</span>
                                                {level !== undefined && level > 0 && (
                                                    <Tag tone={level >= 3 ? "red" : level >= 2 ? "amber" : "neutral"}>
                                                        {criticalityLabel(level, t)}
                                                    </Tag>
                                                )}
                                            </button>
                                            {sub && item.key !== item.label && (
                                                <span className="cell-sub">{sub(item)}</span>
                                            )}
                                        </td>
                                        <td>
                                            <ShareBar share={total ? item.count / total : 0} />
                                        </td>
                                        <td className="is-num">{item.count.toLocaleString()}</td>
                                    </tr>
                                );
                            })}
                            {other > 0 && (
                                <tr className="overview-top-other">
                                    <td>
                                        <span className="cell-main">{t("otherRows")}</span>
                                        <span className="cell-sub">{t("allRemaining")}</span>
                                    </td>
                                    <td>
                                        <ShareBar share={total ? other / total : 0} muted />
                                    </td>
                                    <td className="is-num">{other.toLocaleString()}</td>
                                </tr>
                            )}
                        </tbody>
                    </table>
                </div>
            )}
        </section>
    );
}

function criticalityLabel(level: number, t: Translate): string {
    if (level >= 3) return t("criticalityHigh");
    if (level >= 2) return t("criticalityMedium");
    return t("criticalityLow");
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
                    {group.total.toLocaleString()}{" "}
                    {t(group.total === 1 ? "alertSingular" : "alerts").toLocaleLowerCase()}
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

function EmptyPanel({ text }: { text: string }) {
    return <p className="overview-v2-empty">{text}</p>;
}

function HeatmapScroller({ children, label }: { children: ReactNode; label: string }) {
    const ref = useRef<HTMLDivElement>(null);
    const [more, setMore] = useState(false);
    useEffect(() => {
        const element = ref.current;
        if (!element) return;
        const update = () => {
            setMore(element.scrollWidth - element.clientWidth - element.scrollLeft > 1);
        };
        update();
        const frame = requestAnimationFrame(update);
        element.addEventListener("scroll", update, { passive: true });
        const observer = new ResizeObserver(update);
        observer.observe(element);
        const grid = element.firstElementChild;
        if (grid) observer.observe(grid);
        return () => {
            cancelAnimationFrame(frame);
            element.removeEventListener("scroll", update);
            observer.disconnect();
        };
    }, []);
    return (
        <div
            ref={ref}
            className="overview-v2-heatmap-scroll"
            data-overflow={more ? "more" : undefined}
            tabIndex={0}
            role="region"
            aria-label={label}
        >
            {children}
        </div>
    );
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
    const peak =
        heatmap.peak.count === 0
            ? copy.noAlerts
            : `${copy.peakTotal}: ${days[heatmap.peak.day]} ${formatHeatmapHour(heatmap.peak.hour)} · ${heatmap.peak.count.toLocaleString()} ${copy.alerts} · ${copy.coverage} ${formatCoverageDuration(heatmap.peak.coverageMs, t)}`;
    const cutoff = heatmap.confirmedThrough
        ? `${copy.confirmedThrough} ${formatTime(new Date(heatmap.confirmedThrough).toISOString(), timezone)}`
        : null;
    const subtitle = cutoff ? `${peak} · ${cutoff}` : peak;
    const cells = new Map(heatmap.cells.map((cell) => [`${cell.day}-${cell.hour}`, cell]));

    return (
        <Panel className="workspace-panel overview-v2-heatmap-panel">
            <PanelHeading title={copy.title} description={subtitle} />
            <HeatmapScroller label={copy.title}>
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
            </HeatmapScroller>
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
                        data-empty={cell?.kind !== "covered" || cell.count === 0 || undefined}
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

/** Axis ticks from 0 at a 1/2/5 x 10^n step, about three steps tall. */
export function niceTicks(maximum: number): number[] {
    const raw = Math.max(maximum, 1) / 3;
    const power = 10 ** Math.floor(Math.log10(raw));
    const scaled = raw / power;
    const step = (scaled <= 1 ? 1 : scaled <= 2 ? 2 : scaled <= 5 ? 5 : 10) * power;
    const size = Math.max(1, Math.round(step));
    const count = Math.max(1, Math.ceil(maximum / size));
    return Array.from({ length: count + 1 }, (_, index) => index * size);
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
    noAlerts: string;
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
              noAlerts: "Ninguna alerta en las horas confirmadas",
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
              noAlerts: "No alerts in the confirmed hours",
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
/** Chart ticks: time of day only; the end labels below the chart carry the dates. */
function formatTick(value: string, timezone: string): string {
    return new Intl.DateTimeFormat(undefined, { timeStyle: "short", timeZone: timezone }).format(
        new Date(value),
    );
}

function formatShortHour(value: string, timezone: string): string {
    return new Intl.DateTimeFormat(undefined, {
        month: "short",
        day: "numeric",
        hour: "numeric",
        minute: "2-digit",
        timeZone: timezone,
    }).format(new Date(value));
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
