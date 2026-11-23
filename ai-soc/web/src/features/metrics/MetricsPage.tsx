import { useEffect, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Tag } from "../../components/ui/tag";
import { ShareBar, SummaryStrip } from "../../components/ui/portfolio";
import { useSamples } from "../workspace/samples";
import { WorkspaceFailure, WorkspaceLoading } from "../workspace/WorkspaceStates";
import * as api from "../../api/workspace";
import type { AssetTag, DispositionLabel, MetricStats } from "../../api/workspace";
import "./metrics-v2.css";
import "./metrics-pp.css";

type Translate = (key: string) => string;
const labels: DispositionLabel[] = [
    "true_positive",
    "benign_true_positive",
    "false_positive",
    "duplicate",
    "undetermined",
];

export function MetricsPage({
    siteId,
    from,
    to,
    t,
}: {
    siteId: string;
    from: string;
    to: string;
    t: Translate;
}) {
    const queryClient = useQueryClient();
    const samples = useSamples();
    const operations = useQuery({
        queryKey: ["workspace", "metrics", "ops", siteId, from, to],
        queryFn: ({ signal }) => api.getOpsMetrics(siteId, from, to, signal),
    });
    const quality = useQuery({
        queryKey: ["workspace", "metrics", "quality", siteId, from, to],
        queryFn: ({ signal }) => api.getQualityMetrics(siteId, from, to, signal),
    });
    const assetsQuery = useQuery({
        queryKey: ["workspace", "assets", siteId],
        queryFn: ({ signal }) => api.listAssets(siteId, "", signal),
    });
    const assets = assetsQuery.data?.items ?? [];
    const [selectedAsset, setSelectedAsset] = useState<number | null>(null);
    const [criticality, setCriticality] = useState(0);
    const [tagDraft, setTagDraft] = useState("");
    const [saved, setSaved] = useState(false);
    const [assetError, setAssetError] = useState("");
    useEffect(() => {
        setSelectedAsset(null);
        setSaved(false);
        setAssetError("");
    }, [siteId]);
    const saveAsset = useMutation({
        mutationFn: ({ asset, level, tags }: { asset: AssetTag; level: number; tags: string[] }) =>
            api.saveAsset(siteId, asset.entity_id, level, tags),
        onSuccess: (asset) => {
            queryClient.setQueryData<api.AssetPage>(["workspace", "assets", siteId], (page) =>
                page
                    ? {
                          ...page,
                          items: page.items.map((item) =>
                              item.entity_id === asset.entity_id ? asset : item,
                          ),
                      }
                    : page,
            );
            setSaved(true);
            setAssetError("");
        },
        onError: (error) =>
            setAssetError(error instanceof Error ? error.message : t("requestFailed")),
        onSettled: () =>
            queryClient.invalidateQueries({ queryKey: ["workspace", "assets", siteId] }),
    });
    const selected = assets.find((asset) => asset.entity_id === selectedAsset) ?? null;
    const save = () => {
        if (!selected || !Number.isInteger(criticality) || criticality < 0 || criticality > 3)
            return;
        saveAsset.mutate({ asset: selected, level: criticality, tags: uniqueTags(tagDraft) });
    };
    const busy = operations.isLoading || quality.isLoading || assetsQuery.isLoading;
    const failed = [operations, quality, assetsQuery].find((query) => query.isError);
    if (busy)
        return (
            <div className="workspace-page">
                <WorkspaceLoading label={t("metrics")} />
            </div>
        );
    if (failed)
        return (
            <div className="workspace-page">
                <WorkspaceFailure
                    error={failed.error}
                    t={t}
                    onRetry={() => {
                        void operations.refetch();
                        void quality.refetch();
                        void assetsQuery.refetch();
                    }}
                />
            </div>
        );
    const ops = operations.data;
    const qualityData = quality.data;
    if (!ops || !qualityData) return null;
    const labelled = qualityData.labelled_group_count;
    const assetScaleLabel =
        t("metrics") === "Métricas"
            ? "0 = predeterminado · 3 = máximo"
            : "0 = default · 3 = highest";
    const labelCounts = labels.map((label) => ({
        label,
        count: qualityData.dispositions.find((item) => item.label === label)?.count ?? 0,
    }));
    const labelTotal = labelCounts.reduce((sum, item) => sum + item.count, 0);
    const tp = qualityData.rule_precision.reduce((sum, item) => sum + item.true_positive_count, 0);
    const fp = qualityData.rule_precision.reduce((sum, item) => sum + item.false_positive_count, 0);
    const targets = samples?.slaTargetsSeconds;
    return (
        <div className="workspace-page metrics-pp pp-stack">
            <section className="metrics-pp-ops">
                <div className="metrics-pp-head">
                    <h2 id="metrics-ops-heading" className="t-section">
                        {t("operationalMetrics")}
                    </h2>
                    <span className="t-secondary">
                        {t("metricAsOf")}: {formatTime(ops.window.to)}
                    </span>
                </div>
                <SummaryStrip
                    label={t("operationalMetrics")}
                    items={[
                        { label: t("backlog"), value: ops.backlog.current.toLocaleString(), note: `${t("previousWord")} ${ops.backlog.previous.toLocaleString()}` },
                        {
                            label: t("unassigned"),
                            value: ops.backlog.unassigned.toLocaleString(),
                            note: t("ofOpen").replace("{count}", ops.backlog.current.toLocaleString()),
                        },
                        {
                            label: t("backlogDelta"),
                            value: formatSigned(ops.backlog.delta),
                            note: (
                                <span className="dash-delta" data-tone={ops.backlog.delta > 0 ? "warn" : ops.backlog.delta < 0 ? "good" : undefined}>
                                    {t("sincePrevious")}
                                </span>
                            ),
                        },
                        {
                            label: t("deadJobs"),
                            value: ops.dead_jobs.toLocaleString(),
                            note: (
                                <span className="dash-delta" data-tone={ops.dead_jobs ? "warn" : "good"}>
                                    {ops.dead_jobs ? t("deadJobsNeedLook") : t("workersHealthy")}
                                </span>
                            ),
                        },
                    ]}
                />
            </section>
            <div className="pp-grid">
                <Distribution title={t("timeToAck")} stats={ops.time_to_ack_seconds} target={targets?.acknowledge} t={t} />
                <Distribution title={t("timeToTriage")} stats={ops.time_to_triage_seconds} target={targets?.triage} t={t} />
            </div>
            <div className="pp-grid">
                <Distribution title={t("lag")} stats={ops.ingest_lag_seconds} t={t} />
                <Distribution title={t("queueAge")} stats={ops.queue_age_seconds} t={t} />
            </div>
            <section className="pp-panel pp-panel-pad metrics-pp-quality" aria-labelledby="metrics-quality-heading">
                <div className="metrics-pp-head">
                    <h2 id="metrics-quality-heading" className="t-section">
                        {t("labelQuality")}
                    </h2>
                    <span className="t-secondary">
                        {t("metricAsOf")}: {formatTime(qualityData.window.to)}
                    </span>
                </div>
                <div className="metrics-pp-quality-grid">
                    <div className="metrics-pp-quality-col">
                        <p className="dash-big">
                            <strong className="num">
                                {qualityData.label_coverage === null ? "\u2014" : `${(qualityData.label_coverage * 100).toFixed(1)}%`}
                            </strong>
                            <span>
                                {qualityData.label_coverage === null
                                    ? t("emptyDenominator")
                                    : t("coverageOf")
                                          .replace("{labelled}", labelled.toLocaleString())
                                          .replace("{total}", qualityData.group_count.toLocaleString())}
                            </span>
                        </p>
                        <div
                            className="dash-hundred"
                            role="img"
                            aria-label={labelCounts.map((item) => `${item.count} ${t(dispositionKey(item.label))}`).join(", ")}
                        >
                            {labelCounts.map((item, index) => (
                                <span key={item.label} data-disposition={index} style={{ flexGrow: item.count }} />
                            ))}
                        </div>
                        <ul className="dash-rows">
                            {labelCounts.map((item, index) => (
                                <li key={item.label}>
                                    <i data-disposition={index} aria-hidden="true" />
                                    <span className="dash-row-main">{t(dispositionKey(item.label))}</span>
                                    <span className="num dash-row-value">{item.count.toLocaleString()}</span>
                                </li>
                            ))}
                        </ul>
                        {labelTotal === 0 && <EmptyState text={t("noData")} />}
                    </div>
                    <div className="metrics-pp-quality-col">
                        <p className="dash-big">
                            <strong className="num">{tp + fp ? `${((tp / (tp + fp)) * 100).toFixed(1)}%` : "\u2014"}</strong>
                            <span>{t("scorePrecision")}</span>
                        </p>
                        <p className="t-secondary">
                            {t("precisionExplain").replace("{tp}", String(tp)).replace("{total}", String(tp + fp))}
                        </p>
                        <h3 className="t-sub">{t("precisionAtK")}</h3>
                        {qualityData.precision_at_k.length > 0 ? (
                            <ul className="dash-rows">
                                {qualityData.precision_at_k.map((item) => (
                                    <li key={item.k} className="metrics-pp-patk">
                                        <span className="dash-row-label">{t("topK").replace("{k}", String(item.k))}</span>
                                        <ShareBar share={item.precision ?? 0} className="metrics-pp-patk-bar" />
                                        <span className="num dash-row-value">
                                            {item.precision === null ? "\u2014" : `${(item.precision * 100).toFixed(0)}%`}
                                        </span>
                                        <span className="t-secondary metrics-pp-patk-n">
                                            {item.precision === null
                                                ? t("emptyDenominator")
                                                : `${item.relevant_count} / ${item.labelled_count}`}
                                        </span>
                                    </li>
                                ))}
                            </ul>
                        ) : (
                            <EmptyState text={t("noData")} />
                        )}
                        <p className="t-secondary">{t("uncalibratedNote")}</p>
                    </div>
                </div>
                <details className="metrics-pp-details">
                    <summary className="t-secondary">{t("rulePrecisionTable")}</summary>
                    <div className="pp-table-scroll">
                        <table className="pp-table">
                            <thead>
                                <tr>
                                    <th scope="col">{t("rule")}</th>
                                    <th scope="col" className="is-num">{t("precision")}</th>
                                    <th scope="col" className="is-num">{t("truePositive")}</th>
                                    <th scope="col" className="is-num">{t("falsePositive")}</th>
                                    <th scope="col" className="is-num">{t("benignTruePositive")}</th>
                                </tr>
                            </thead>
                            <tbody>
                                {qualityData.rule_precision.map((item) => (
                                    <tr key={item.rule_id}>
                                        <td>
                                            {t("rule")} {item.rule_id}
                                        </td>
                                        <td className="is-num">
                                            {item.precision === null ? "\u2014" : `${(item.precision * 100).toFixed(1)}%`}
                                        </td>
                                        <td className="is-num">{item.true_positive_count}</td>
                                        <td className="is-num">{item.false_positive_count}</td>
                                        <td className="is-num">{item.benign_true_positive_count}</td>
                                    </tr>
                                ))}
                                {qualityData.rule_precision.length === 0 && (
                                    <tr>
                                        <td colSpan={5} className="pp-table-empty">
                                            {t("noData")}
                                        </td>
                                    </tr>
                                )}
                            </tbody>
                        </table>
                    </div>
                </details>
            </section>
            <section className="pp-panel metrics-pp-assets" aria-labelledby="metrics-assets-heading">
                <div className="pp-panel-head">
                    <div>
                        <h2 id="metrics-assets-heading" className="t-section">
                            {t("assetTags")}
                        </h2>
                        <p>
                            {t("assetTagsNote")} {assetScaleLabel}
                        </p>
                    </div>
                </div>
                <div className="pp-table-scroll">
                    <table className="pp-table metrics-v2-assets">
                        <thead>
                            <tr>
                                <th scope="col">{t("host")}</th>
                                <th scope="col">{t("criticality")}</th>
                                <th scope="col">{t("tags")}</th>
                                <th scope="col">{t("setBy")}</th>
                                <th scope="col">
                                    <span className="sr-only">{t("actions")}</span>
                                </th>
                            </tr>
                        </thead>
                        <tbody>
                            {assets.map((asset) => (
                                <tr key={`${asset.entity_kind}-${asset.entity_id}`} data-selected={asset.entity_id === selectedAsset || undefined}>
                                    <td>
                                        <span className="ent">{asset.entity_value}</span>
                                        <span className="cell-sub">
                                            {humanizeKind(asset.entity_kind)} {asset.entity_id}
                                        </span>
                                    </td>
                                    <td className="num">{asset.criticality}</td>
                                    <td>
                                        <span className="metrics-pp-tags">
                                            {asset.tags.length ? asset.tags.map((tag) => <Tag key={tag}>{tag}</Tag>) : "\u2014"}
                                        </span>
                                    </td>
                                    <td className="t-secondary">
                                        {asset.set_by ?? t("unavailable")}
                                        {asset.set_at && <span className="cell-sub">{formatTime(asset.set_at)}</span>}
                                    </td>
                                    <td>
                                        <button
                                            className="btn compact"
                                            type="button"
                                            onClick={() => {
                                                setSelectedAsset(asset.entity_id);
                                                setCriticality(asset.criticality);
                                                setTagDraft(asset.tags.join(", "));
                                                setSaved(false);
                                                setAssetError("");
                                            }}
                                        >
                                            {t("editAssetTags")}
                                        </button>
                                    </td>
                                </tr>
                            ))}
                            {assets.length === 0 && (
                                <tr>
                                    <td colSpan={5} className="pp-table-empty">
                                        {t("noData")}
                                    </td>
                                </tr>
                            )}
                        </tbody>
                    </table>
                </div>
                {selected && (
                    <form
                        className="asset-edit metrics-pp-asset-edit"
                        onSubmit={(event) => {
                            event.preventDefault();
                            save();
                        }}
                    >
                        <h3 className="t-sub">{selected.entity_value}</h3>
                        <label className="pp-field">
                            {t("criticality")}
                            <input
                                aria-label={t("criticality")}
                                type="number"
                                min={0}
                                max={3}
                                step={1}
                                value={criticality}
                                onChange={(event) => setCriticality(Number(event.target.value))}
                            />
                        </label>
                        <label className="pp-field">
                            {t("tags")}
                            <input aria-label={t("tags")} value={tagDraft} onChange={(event) => setTagDraft(event.target.value)} />
                        </label>
                        <button
                            className="btn primary"
                            type="submit"
                            disabled={!Number.isInteger(criticality) || criticality < 0 || criticality > 3 || saveAsset.isPending}
                        >
                            {t("saveAsset")}
                        </button>
                        {saved && <span role="status">{t("assetSaved")}</span>}
                        {assetError && <p role="alert">{assetError}</p>}
                    </form>
                )}
            </section>
            <details className="pp-panel metrics-pp-details metrics-pp-volume">
                <summary>
                    <span className="t-sub">{t("hourlyVolume")}</span>{" "}
                    <span className="t-secondary">
                        {ops.volume.reduce((sum, bucket) => sum + bucket.count, 0).toLocaleString()} {t("alerts").toLocaleLowerCase()}
                    </span>
                </summary>
                {ops.volume.length > 0 ? (
                    <div className="pp-table-scroll">
                        <table className="pp-table">
                            <thead>
                                <tr>
                                    <th scope="col">{t("eventTime")}</th>
                                    <th scope="col">{t("alertLevel")}</th>
                                    <th scope="col" className="is-num">{t("alerts")}</th>
                                </tr>
                            </thead>
                            <tbody>
                                {ops.volume.map((bucket, index) => (
                                    <tr key={`${bucket.hour}-${bucket.level_band}-${index}`}>
                                        <td>{formatTime(bucket.hour)}</td>
                                        <td>{t("level")} {bucket.level_band}</td>
                                        <td className="is-num">{bucket.count.toLocaleString()}</td>
                                    </tr>
                                ))}
                            </tbody>
                        </table>
                    </div>
                ) : (
                    <EmptyState text={t("noData")} />
                )}
            </details>
        </div>
    );
}

/** p50 solid, p50 to p90 light, a red target tick, then the p50/p90/p95/max row. */
function Distribution({
    title,
    stats,
    target,
    t,
}: {
    title: string;
    stats: MetricStats;
    target?: number;
    t: Translate;
}) {
    const scale = Math.max(1, stats.max ?? 0, stats.p90 ?? 0, target ?? 0) * 1.05;
    const at = (value: number | null) => `${((value ?? 0) / scale) * 100}%`;
    const points = [
        { label: t("p50"), value: stats.p50 },
        { label: t("p90"), value: stats.p90 },
        { label: t("p95"), value: stats.p95 },
        { label: t("maximum"), value: stats.max },
    ];
    return (
        <section className="pp-panel pp-panel-pad metrics-pp-dist">
            <div className="metrics-pp-head">
                <h2 className="t-section">{title}</h2>
                <span className="t-secondary num">
                    {stats.sample_count.toLocaleString()} {t("samples").toLocaleLowerCase()}
                </span>
            </div>
            {stats.sample_count > 0 ? (
                <>
                    <div
                        className="metrics-pp-track"
                        role="img"
                        aria-label={`${title}: p50 ${duration(stats.p50)}, p90 ${duration(stats.p90)}${target ? `, ${t("targetWord").toLocaleLowerCase()} ${duration(target)}` : ""}`}
                    >
                        <span className="metrics-pp-p90" style={{ width: at(stats.p90) }} />
                        <span className="metrics-pp-p50" style={{ width: at(stats.p50) }} />
                        {target !== undefined && (
                            <>
                                <i className="metrics-pp-target" style={{ left: at(target) }} />
                                <span className="metrics-pp-target-label" style={{ left: at(target) }}>
                                    {t("targetWord").toLocaleLowerCase()} {duration(target)}
                                </span>
                            </>
                        )}
                    </div>
                    <dl className="metrics-pp-points">
                        {points.map((point) => (
                            <div key={point.label}>
                                <dt>{point.label}</dt>
                                <dd className="num">{duration(point.value)}</dd>
                            </div>
                        ))}
                    </dl>
                </>
            ) : (
                <EmptyState text={t("noData")} />
            )}
        </section>
    );
}
function humanizeKind(kind: string): string {
    return kind === "agent" ? "Agent" : kind.charAt(0).toUpperCase() + kind.slice(1);
}

function EmptyState({ text }: { text: string }) {
    return <p className="metrics-v2-empty">{text}</p>;
}
function uniqueTags(value: string): string[] {
    return [
        ...new Set(
            value
                .split(",")
                .map((item) => item.trim())
                .filter((item) => item.length > 0 && item.length <= 64),
        ),
    ].slice(0, 32);
}
function duration(value: number | null): string {
    if (value === null) return "—";
    if (value < 60) return `${Math.round(value)}s`;
    if (value < 3_600) return `${Math.round(value / 60)}m`;
    return `${(value / 3_600).toFixed(1)}h`;
}
function formatTime(value: string): string {
    return new Intl.DateTimeFormat(undefined, { dateStyle: "medium", timeStyle: "short" }).format(
        new Date(value),
    );
}
function formatSigned(value: number): string {
    return `${value > 0 ? "+" : ""}${value}`;
}
function dispositionKey(value: DispositionLabel): string {
    switch (value) {
        case "true_positive":
            return "truePositive";
        case "benign_true_positive":
            return "benignTruePositive";
        case "false_positive":
            return "falsePositiveDisposition";
        case "duplicate":
            return "duplicate";
        case "undetermined":
            return "undetermined";
    }
}
