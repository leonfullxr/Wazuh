import { useEffect, useRef, useState } from "react";
import { useQuery } from "@tanstack/react-query";
import type { AlertDetail, AlertFilters, AlertSummary, SiteSummary } from "../../api/workspace";
import { getAlert, getIngestionHealth, listAlerts } from "../../api/workspace";
import { Panel } from "../../components/ui/panel";
import { Sheet, SheetClose, SheetContent, SheetTrigger } from "../../components/ui/sheet";
import { QuietSiteState, WorkspaceFailure, WorkspaceLoading } from "../workspace/WorkspaceStates";

type Translate = (key: string) => string;
export type AlertFilterPatch = {
    rule_id?: string;
    agent_id?: string;
    min_level?: number | null;
    max_level?: number | null;
    tactic?: string;
    entity_kind?: string;
    entity?: string;
    cursor?: string;
};

export function AlertsPage({
    site,
    filters,
    linkedAlertKey,
    t,
    onFilters,
    onCloseDetails,
    onInvestigate,
}: {
    site: Pick<SiteSummary, "site_id" | "label"> | undefined;
    filters: AlertFilters;
    linkedAlertKey?: string | null;
    t: Translate;
    onFilters: (filters: AlertFilterPatch) => void;
    onCloseDetails: () => void;
    onInvestigate: (alert: AlertDetail) => void;
}) {
    const [ruleId, setRuleId] = useState(filters.ruleId ?? "");
    const [agentId, setAgentId] = useState(filters.agentId ?? "");
    const [minLevel, setMinLevel] = useState(filters.minLevel?.toString() ?? "");
    const [maxLevel, setMaxLevel] = useState(filters.maxLevel?.toString() ?? "");
    const [selectedAlert, setSelectedAlert] = useState<AlertSummary | null>(null);
    const detailTriggerKey = useRef<string | null>(null);
    const restoreFocusPending = useRef(false);
    const page = useQuery({
        queryKey: ["workspace", "alerts", site?.site_id, filters],
        queryFn: ({ signal }) =>
            site
                ? listAlerts({ ...filters, siteId: site.site_id }, signal)
                : Promise.reject(new Error("No workspace site selected.")),
        enabled: site !== undefined,
    });
    const alertKey = selectedAlert?.alert_key ?? linkedAlertKey ?? null;
    const health = useQuery({
        queryKey: ["workspace", "ingestion-health", site?.site_id],
        queryFn: ({ signal }) =>
            site
                ? getIngestionHealth(site.site_id, signal)
                : Promise.reject(new Error("No site selected.")),
        enabled: site !== undefined && page.data?.items.length === 0,
    });
    const detail = useQuery({
        queryKey: ["workspace", "alert", site?.site_id, alertKey],
        queryFn: ({ signal }) =>
            site && alertKey
                ? getAlert(site.site_id, alertKey, signal)
                : Promise.reject(new Error("No alert selected.")),
        enabled: site !== undefined && alertKey !== null,
    });
    const restoreTriggerFocus = () => {
        restoreFocusPending.current = true;
        requestAnimationFrame(() => {
            const key = detailTriggerKey.current;
            const trigger = key
                ? document.querySelector<HTMLButtonElement>(
                      `button[data-alert-key="${CSS.escape(key)}"]`,
                  )
                : null;
            const target =
                trigger ??
                document.querySelector<HTMLButtonElement>(".alert-filter-form button[type=submit]");
            if (target) {
                target.focus();
                restoreFocusPending.current = false;
            }
        });
    };
    useEffect(() => {
        if (alertKey === null && page.data && restoreFocusPending.current) restoreTriggerFocus();
    }, [alertKey, page.data]);
    if (page.isLoading) return <WorkspaceLoading label={t("loadingAlerts")} />;
    if (page.isError || !page.data)
        return <WorkspaceFailure error={page.error} t={t} onRetry={() => void page.refetch()} />;
    const healthState = health.data?.site.health;
    const stalled =
        healthState === "lagging" ||
        healthState === "auth_failed" ||
        healthState === "unreachable" ||
        (health.data !== undefined && health.data.last_success_at === null);

    const apply = () =>
        onFilters({
            rule_id: ruleId.trim() || undefined,
            agent_id: agentId.trim() || undefined,
            min_level: minLevel === "" ? null : Number(minLevel),
            max_level: maxLevel === "" ? null : Number(maxLevel),
        });
    const next = () =>
        onFilters({
            rule_id: filters.ruleId,
            agent_id: filters.agentId,
            min_level: filters.minLevel,
            max_level: filters.maxLevel,
            tactic: filters.tactic,
            entity_kind: filters.entityKind,
            entity: filters.entity,
            cursor: page.data.next_cursor ?? undefined,
        });

    return (
        <Sheet
            open={alertKey !== null}
            onOpenChange={(open) => {
                if (!open) {
                    setSelectedAlert(null);
                    onCloseDetails();
                }
            }}
        >
            <div className="workspace-page">
                <p className="page-description">{t("alertsDescription")}</p>
                <Panel className="workspace-panel">
                    <form
                        className="alert-filter-form"
                        onSubmit={(event) => {
                            event.preventDefault();
                            apply();
                        }}
                        aria-label={t("alerts")}
                    >
                        <label>
                            {t("filterRule")}
                            <input
                                value={ruleId}
                                onChange={(event) => setRuleId(event.target.value)}
                            />
                        </label>
                        <label>
                            {t("filterAgent")}
                            <input
                                value={agentId}
                                onChange={(event) => setAgentId(event.target.value)}
                            />
                        </label>
                        <label>
                            {t("filterLevel")}
                            <select
                                value={minLevel}
                                onChange={(event) => setMinLevel(event.target.value)}
                            >
                                <option value="">{t("allLevels")}</option>
                                {Array.from({ length: 16 }, (_, value) => (
                                    <option key={value} value={value}>
                                        {value}
                                    </option>
                                ))}
                            </select>
                        </label>
                        <label>
                            {t("maximumLevel")}
                            <select
                                value={maxLevel}
                                onChange={(event) => setMaxLevel(event.target.value)}
                            >
                                <option value="">{t("allLevels")}</option>
                                {Array.from({ length: 16 }, (_, value) => (
                                    <option key={value} value={value}>
                                        {value}
                                    </option>
                                ))}
                            </select>
                        </label>
                        <div className="filter-actions">
                            <button className="btn primary" type="submit">
                                {t("applyFilters")}
                            </button>
                            <button
                                className="btn outline"
                                type="button"
                                onClick={() => {
                                    setRuleId("");
                                    setAgentId("");
                                    setMinLevel("");
                                    setMaxLevel("");
                                    onFilters({});
                                }}
                            >
                                {t("clearFilters")}
                            </button>
                        </div>
                    </form>
                </Panel>
                <Panel className="workspace-panel table-panel">
                    {page.data.items.length === 0 ? (
                        health.isLoading ? (
                            <p className="muted" role="status">
                                {t("loading")}
                            </p>
                        ) : health.isError ? (
                            <WorkspaceFailure
                                error={health.error}
                                t={t}
                                onRetry={() => void health.refetch()}
                            />
                        ) : stalled ? (
                            <section className="alert error" role="alert">
                                <strong>{t("stalledTitle")}</strong>
                                <p>{t("stalledDescription")}</p>
                            </section>
                        ) : (
                            <QuietSiteState t={t} />
                        )
                    ) : (
                        <div className="table-scroll">
                            <table className="workspace-table">
                                <thead>
                                    <tr>
                                        <th>{t("eventTime")}</th>
                                        <th>{t("rule")}</th>
                                        <th>{t("level")}</th>
                                        <th>{t("agent")}</th>
                                        <th>{t("source")}</th>
                                        <th>{t("user")}</th>
                                        <th>{t("tactic")}</th>
                                        <th>{t("actions")}</th>
                                    </tr>
                                </thead>
                                <tbody>
                                    {page.data.items.map((alert) => (
                                        <tr key={alert.alert_key}>
                                            <td>{formatTime(alert.event_ts)}</td>
                                            <td>
                                                <strong>{alert.rule_id ?? "—"}</strong>
                                                <span className="table-secondary">
                                                    {alert.rule_description ?? t("nullUnknown")}
                                                </span>
                                            </td>
                                            <td>
                                                <span className="level-badge">
                                                    {alert.rule_level ?? "—"}
                                                </span>
                                            </td>
                                            <td>{alert.agent_name ?? alert.agent_id ?? "—"}</td>
                                            <td>
                                                <code>{alert.src_ip ?? "—"}</code>
                                            </td>
                                            <td>{alert.dst_user ?? alert.src_user ?? "—"}</td>
                                            <td>{alert.mitre_tactics[0] ?? "—"}</td>
                                            <td>
                                                <SheetTrigger asChild>
                                                    <button
                                                        className="text-link"
                                                        data-alert-key={alert.alert_key}
                                                        type="button"
                                                        onClick={() => {
                                                            detailTriggerKey.current =
                                                                alert.alert_key;
                                                            setSelectedAlert(alert);
                                                        }}
                                                    >
                                                        {t("details")}
                                                    </button>
                                                </SheetTrigger>
                                            </td>
                                        </tr>
                                    ))}
                                </tbody>
                            </table>
                        </div>
                    )}
                    <div className="page-controls">
                        <button
                            className="btn outline"
                            type="button"
                            disabled={!filters.cursor}
                            onClick={() =>
                                onFilters({
                                    rule_id: filters.ruleId,
                                    agent_id: filters.agentId,
                                    min_level: filters.minLevel,
                                    max_level: filters.maxLevel,
                                    tactic: filters.tactic,
                                    entity_kind: filters.entityKind,
                                    entity: filters.entity,
                                })
                            }
                        >
                            {t("previousPage")}
                        </button>
                        <button
                            className="btn outline"
                            type="button"
                            disabled={!page.data.next_cursor}
                            onClick={next}
                        >
                            {t("nextPage")}
                        </button>
                    </div>
                </Panel>
                <SheetContent title={t("alertDetails")} restoreFocus={restoreTriggerFocus}>
                    {alertKey && (
                        <>
                            {detail.isLoading && <p role="status">{t("loading")}</p>}
                            {detail.isError && (
                                <WorkspaceFailure
                                    error={detail.error}
                                    t={t}
                                    onRetry={() => void detail.refetch()}
                                />
                            )}
                            {detail.data && (
                                <AlertDrawer
                                    alert={detail.data}
                                    t={t}
                                    onInvestigate={() => onInvestigate(detail.data)}
                                />
                            )}
                        </>
                    )}
                </SheetContent>
            </div>
        </Sheet>
    );
}

function AlertDrawer({
    alert,
    t,
    onInvestigate,
}: {
    alert: AlertDetail;
    t: Translate;
    onInvestigate: () => void;
}) {
    const wazuhUrl = safeWazuhUrl(alert.wazuh_url);
    return (
        <div className="alert-drawer-body">
            <p className="drawer-alert-title">{alert.rule_description ?? t("nullUnknown")}</p>
            <dl className="alert-detail-list">
                <dt>{t("eventTime")}</dt>
                <dd>{formatTime(alert.event_ts)}</dd>
                <dt>{t("rule")}</dt>
                <dd>
                    {alert.rule_id ?? "—"} · {alert.rule_level ?? "—"}
                </dd>
                <dt>{t("agent")}</dt>
                <dd>
                    {alert.agent_name ?? alert.agent_id ?? "—"} · {alert.agent_ip ?? "—"}
                </dd>
                <dt>{t("source")}</dt>
                <dd>{alert.src_ip ?? "—"}</dd>
                <dt>{t("destination")}</dt>
                <dd>{alert.dst_ip ?? "—"}</dd>
                <dt>{t("user")}</dt>
                <dd>
                    {alert.src_user ?? "—"} → {alert.dst_user ?? "—"}
                </dd>
                <dt>{t("mappingProfile")}</dt>
                <dd>{alert.mapping_profile}</dd>
                <dt>{t("ingestedAt")}</dt>
                <dd>{formatTime(alert.ingested_at)}</dd>
            </dl>
            <section className="drawer-section">
                <h3>{t("normalizedFields")}</h3>
                <p>
                    {[...alert.rule_groups, ...alert.mitre_tactics, ...alert.mitre_techniques].join(
                        " · ",
                    ) || "—"}
                </p>
            </section>
            <section className="drawer-section">
                <h3>{t("normalizationGaps")}</h3>
                {alert.normalize_gaps.length === 0 ? (
                    <p>{t("noGaps")}</p>
                ) : (
                    <ul>
                        {alert.normalize_gaps.map((gap) => (
                            <li key={gap}>
                                <code>{gap}</code>
                            </li>
                        ))}
                    </ul>
                )}
            </section>
            <section className="drawer-section">
                <h3>{t("rawSource")}</h3>
                <pre className="raw-json" tabIndex={0}>
                    <code>{JSON.stringify(alert.raw, null, 2)}</code>
                </pre>
            </section>
            <div className="drawer-actions">
                {wazuhUrl && (
                    <a className="btn outline" href={wazuhUrl} target="_blank" rel="noreferrer">
                        {t("wazuhRecord")}
                    </a>
                )}
                <SheetClose asChild>
                    <button className="btn primary" type="button" onClick={onInvestigate}>
                        {t("investigateAction")}
                    </button>
                </SheetClose>
            </div>
        </div>
    );
}

function safeWazuhUrl(value: string | null | undefined): string | null {
    if (!value) return null;
    try {
        const parsed = new URL(value);
        return parsed.protocol === "https:" ? parsed.href : null;
    } catch {
        return null;
    }
}

function formatTime(value: string): string {
    return new Intl.DateTimeFormat(undefined, { dateStyle: "medium", timeStyle: "short" }).format(
        new Date(value),
    );
}
