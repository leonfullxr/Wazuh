import { useEffect, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Panel } from "../../components/ui/panel";
import { WorkspaceFailure, WorkspaceLoading } from "../workspace/WorkspaceStates";
import * as api from "../../api/workspace";
import type { AssetTag, DispositionLabel, MetricStats } from "../../api/workspace";

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
                <p className="page-description">{t("metricsDescription")}</p>
                <WorkspaceLoading label={t("metrics")} />
            </div>
        );
    if (failed)
        return (
            <div className="workspace-page">
                <p className="page-description">{t("metricsDescription")}</p>
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
    return (
        <div className="workspace-page">
            <p className="page-description">{t("metricsDescription")}</p>
            <Panel className="workspace-panel metrics-panel">
                <div className="section-heading-row">
                    <h2>{t("operationalMetrics")}</h2>
                    <span>
                        {t("metricAsOf")}: {formatTime(ops.window.to)}
                    </span>
                </div>
                <div className="workspace-two-column">
                    <StatsCard title={t("lag")} stats={ops.ingest_lag_seconds} t={t} />
                    <StatsCard title={t("queueAge")} stats={ops.queue_age_seconds} t={t} />
                    <StatsCard title={t("timeToAck")} stats={ops.time_to_ack_seconds} t={t} />
                    <StatsCard title={t("timeToTriage")} stats={ops.time_to_triage_seconds} t={t} />
                </div>
                <div className="backlog-strip">
                    <Metric label={t("backlog")} value={ops.backlog.current.toLocaleString()} />
                    <Metric
                        label={t("unassigned")}
                        value={ops.backlog.unassigned.toLocaleString()}
                    />
                    <Metric label={t("backlogDelta")} value={formatSigned(ops.backlog.delta)} />
                    <Metric label={t("deadJobs")} value={ops.dead_jobs.toLocaleString()} />
                </div>
                {ops.volume.length > 0 && (
                    <div className="table-scroll">
                        <table className="workspace-table">
                            <thead>
                                <tr>
                                    <th>{t("eventTime")}</th>
                                    <th>{t("alertLevel")}</th>
                                    <th>{t("alerts")}</th>
                                </tr>
                            </thead>
                            <tbody>
                                {ops.volume.map((bucket, index) => (
                                    <tr key={`${bucket.hour}-${bucket.level_band}-${index}`}>
                                        <td>{formatTime(bucket.hour)}</td>
                                        <td>{bucket.level_band}</td>
                                        <td>{bucket.count.toLocaleString()}</td>
                                    </tr>
                                ))}
                            </tbody>
                        </table>
                    </div>
                )}
            </Panel>
            <Panel className="workspace-panel metrics-panel">
                <div className="section-heading-row">
                    <h2>{t("qualityMetrics")}</h2>
                    <span>
                        {t("metricAsOf")}: {formatTime(qualityData.window.to)}
                    </span>
                </div>
                <div className="coverage-card">
                    <strong>{labelled.toLocaleString()}</strong>
                    <span>{t("labelledCount")}</span>
                    <small>
                        {t("labelCoverage")}:{" "}
                        {qualityData.label_coverage === null
                            ? t("emptyDenominator")
                            : `${(qualityData.label_coverage * 100).toFixed(1)}%`}
                    </small>
                    <small>
                        {t("coverageDenominator")}:{" "}
                        {qualityData.labelled_group_count.toLocaleString()} /{" "}
                        {qualityData.group_count.toLocaleString()}
                    </small>
                </div>
                <div className="workspace-two-column">
                    <section className="metric-subpanel">
                        <h3>{t("dispositions")}</h3>
                        <ul className="metric-count-list">
                            {labels.map((label) => {
                                const count =
                                    qualityData.dispositions.find((item) => item.label === label)
                                        ?.count ?? 0;
                                return (
                                    <li key={label}>
                                        <span>{t(dispositionKey(label))}</span>
                                        <strong>{count.toLocaleString()}</strong>
                                    </li>
                                );
                            })}
                        </ul>
                    </section>
                    <section className="metric-subpanel">
                        <h3>{t("precisionAtK")}</h3>
                        <ul className="metric-count-list">
                            {qualityData.precision_at_k.map((item) => (
                                <li key={item.k}>
                                    <span>Precision@{item.k}</span>
                                    <span>
                                        {item.precision === null
                                            ? t("emptyDenominator")
                                            : `${(item.precision * 100).toFixed(1)}%`}
                                    </span>
                                    <small>
                                        {item.relevant_count} / {item.labelled_count}{" "}
                                        {t("labelled")}
                                    </small>
                                </li>
                            ))}
                        </ul>
                    </section>
                </div>
                <div className="table-scroll">
                    <table className="workspace-table">
                        <thead>
                            <tr>
                                <th>{t("filterRule")}</th>
                                <th>{t("precision")}</th>
                                <th>{t("truePositive")}</th>
                                <th>{t("falsePositive")}</th>
                                <th>{t("benignTruePositive")}</th>
                                <th>{t("denominatorLabel")}</th>
                            </tr>
                        </thead>
                        <tbody>
                            {qualityData.rule_precision.map((item) => (
                                <tr key={item.rule_id}>
                                    <td>{item.rule_id}</td>
                                    <td>
                                        {item.precision === null
                                            ? t("emptyDenominator")
                                            : `${(item.precision * 100).toFixed(1)}%`}
                                    </td>
                                    <td>{item.true_positive_count.toLocaleString()}</td>
                                    <td>{item.false_positive_count.toLocaleString()}</td>
                                    <td>{item.benign_true_positive_count.toLocaleString()}</td>
                                    <td>
                                        {item.true_positive_count.toLocaleString()} +{" "}
                                        {item.false_positive_count.toLocaleString()} ={" "}
                                        {item.true_positive_count + item.false_positive_count}
                                    </td>
                                </tr>
                            ))}
                        </tbody>
                    </table>
                </div>
            </Panel>
            <Panel className="workspace-panel metrics-panel">
                <div className="section-heading-row">
                    <h2>{t("assetTags")}</h2>
                    <span>0 = default · 3 = highest</span>
                </div>
                <div className="table-scroll">
                    <table className="workspace-table">
                        <thead>
                            <tr>
                                <th>{t("agent")}</th>
                                <th>{t("criticality")}</th>
                                <th>{t("tags")}</th>
                                <th>{t("owner")}</th>
                                <th>{t("eventTime")}</th>
                                <th>{t("actions")}</th>
                            </tr>
                        </thead>
                        <tbody>
                            {assets.map((asset) => (
                                <tr key={`${asset.entity_kind}-${asset.entity_id}`}>
                                    <td>
                                        <span className="table-primary">{asset.entity_value}</span>
                                        <span className="table-secondary">
                                            #{asset.entity_id} · {asset.entity_kind}
                                        </span>
                                    </td>
                                    <td>{asset.criticality}</td>
                                    <td>{asset.tags.join(", ") || "—"}</td>
                                    <td>{asset.set_by ?? t("unavailable")}</td>
                                    <td>
                                        {asset.set_at ? formatTime(asset.set_at) : t("unavailable")}
                                    </td>
                                    <td>
                                        <button
                                            className="text-link"
                                            type="button"
                                            onClick={() => {
                                                setSelectedAsset(asset.entity_id);
                                                setCriticality(asset.criticality);
                                                setTagDraft(asset.tags.join(", "));
                                                setSaved(false);
                                                setAssetError("");
                                            }}
                                        >
                                            {t("actions")}
                                        </button>
                                    </td>
                                </tr>
                            ))}
                        </tbody>
                    </table>
                </div>
                {selected && (
                    <form
                        className="asset-edit"
                        onSubmit={(event) => {
                            event.preventDefault();
                            save();
                        }}
                    >
                        <h3>{selected.entity_value}</h3>
                        <label>
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
                        <label>
                            {t("tags")}
                            <input
                                aria-label={t("tags")}
                                value={tagDraft}
                                onChange={(event) => setTagDraft(event.target.value)}
                            />
                        </label>
                        <button
                            className="btn primary"
                            type="submit"
                            disabled={
                                !Number.isInteger(criticality) ||
                                criticality < 0 ||
                                criticality > 3 ||
                                saveAsset.isPending
                            }
                        >
                            {t("saveAsset")}
                        </button>
                        {saved && <span role="status">{t("assetSaved")}</span>}
                        {assetError && <p role="alert">{assetError}</p>}
                    </form>
                )}
            </Panel>
        </div>
    );
}
function StatsCard({ title, stats, t }: { title: string; stats: MetricStats; t: Translate }) {
    return (
        <section className="metric-subpanel">
            <h3>{title}</h3>
            <dl className="stats-list">
                <dt>{t("p50")}</dt>
                <dd>{duration(stats.p50)}</dd>
                <dt>{t("p90")}</dt>
                <dd>{duration(stats.p90)}</dd>
                <dt>{t("p95")}</dt>
                <dd>{duration(stats.p95)}</dd>
                <dt>{t("maximum")}</dt>
                <dd>{duration(stats.max)}</dd>
                <dt>{t("samples")}</dt>
                <dd>{stats.sample_count.toLocaleString()}</dd>
            </dl>
        </section>
    );
}
function Metric({ label, value }: { label: string; value: string }) {
    return (
        <div>
            <span>{label}</span>
            <strong>{value}</strong>
        </div>
    );
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
