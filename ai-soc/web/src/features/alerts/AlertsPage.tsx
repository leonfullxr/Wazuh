import { useEffect, useRef, useState } from "react";
import { useQuery } from "@tanstack/react-query";
import type { AlertDetail, AlertFilters, AlertSummary, SiteSummary } from "../../api/workspace";
import { getAlert, getIngestionHealth, listAlerts } from "../../api/workspace";
import { Panel } from "../../components/ui/panel";
import { Sheet, SheetClose, SheetContent, SheetTrigger } from "../../components/ui/sheet";
import { Tag } from "../../components/ui/tag";
import { severityTag } from "../../lib/semantic";
import { QuietSiteState, WorkspaceFailure, WorkspaceLoading } from "../workspace/WorkspaceStates";
import "./alerts-v2.css";

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
    const previousSiteId = useRef(site?.site_id);
    const previousFilterValues = useRef({
        ruleId: filters.ruleId,
        agentId: filters.agentId,
        minLevel: filters.minLevel,
        maxLevel: filters.maxLevel,
    });
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
    const siteChanged =
        previousSiteId.current !== undefined &&
        site?.site_id !== undefined &&
        previousSiteId.current !== site.site_id;
    const alertKey = siteChanged ? null : (selectedAlert?.alert_key ?? linkedAlertKey ?? null);
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
    useEffect(() => {
        const previous = previousFilterValues.current;
        if (previous.ruleId !== filters.ruleId) setRuleId(filters.ruleId ?? "");
        if (previous.agentId !== filters.agentId) setAgentId(filters.agentId ?? "");
        if (previous.minLevel !== filters.minLevel) setMinLevel(filters.minLevel?.toString() ?? "");
        if (previous.maxLevel !== filters.maxLevel) setMaxLevel(filters.maxLevel?.toString() ?? "");
        previousFilterValues.current = {
            ruleId: filters.ruleId,
            agentId: filters.agentId,
            minLevel: filters.minLevel,
            maxLevel: filters.maxLevel,
        };
    }, [filters.agentId, filters.maxLevel, filters.minLevel, filters.ruleId]);
    useEffect(() => {
        if (site?.site_id === undefined) return;
        if (previousSiteId.current === site?.site_id) return;
        const hadSelectedSite = previousSiteId.current !== undefined;
        previousSiteId.current = site?.site_id;
        if (!hadSelectedSite) return;
        setSelectedAlert(null);
        detailTriggerKey.current = null;
        onCloseDetails();
    }, [onCloseDetails, site?.site_id]);
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
            tactic: filters.tactic,
            entity_kind: filters.entityKind,
            entity: filters.entity,
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
    const isSpanish = t("alerts") === "Alertas";
    const copy = isSpanish
        ? {
              filters: "Filtros de alertas",
              filtersHelp: "Filtra las alertas por regla, agente o nivel.",
              limitedSearch: "Búsqueda avanzada no disponible",
              limitedSearchHelp:
                  "La búsqueda por consulta, los recuentos por campo y el histograma aún no están disponibles.",
              activeFilters: "Filtros activos",
              removeFilter: "Quitar filtro",
              results: "Resultados",
              loadedRows: "Filas cargadas en esta página",
              description: "Descripción",
              fields: "Campos",
              json: "JSON",
              documentView: "Vista del documento",
          }
        : {
              filters: "Alert filters",
              filtersHelp: "Filter alerts by rule, agent, or level.",
              limitedSearch: "Advanced search unavailable",
              limitedSearchHelp:
                  "Query search, field counts, and the histogram are not available yet.",
              activeFilters: "Active filters",
              removeFilter: "Remove filter",
              results: "Results",
              loadedRows: "Rows loaded on this page",
              description: "Description",
              fields: "Fields",
              json: "JSON",
              documentView: "Document view",
          };

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
            <div className="workspace-page alerts-v2">
                <p className="page-description">{t("alertsDescription")}</p>
                <Panel className="workspace-panel">
                    <div className="alerts-v2-panel-heading">
                        <div>
                            <h3>{copy.filters}</h3>
                            <p>{copy.filtersHelp}</p>
                        </div>
                        <div className="alerts-v2-capability" role="note">
                            <strong>{copy.limitedSearch}</strong>
                            <span>{copy.limitedSearchHelp}</span>
                        </div>
                    </div>
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
                    {(filters.ruleId ||
                        filters.agentId ||
                        filters.minLevel !== undefined ||
                        filters.maxLevel !== undefined ||
                        filters.tactic ||
                        filters.entity) && (
                        <div
                            className="alerts-v2-active-filters"
                            aria-label={copy.activeFilters}
                            role="group"
                        >
                            <span>{copy.activeFilters}</span>
                            {filters.ruleId && (
                                <ActiveFilter
                                    label={`${t("rule")} ${filters.ruleId}`}
                                    removeLabel={`${copy.removeFilter}: ${t("rule")}`}
                                    onRemove={() =>
                                        onFilters({
                                            agent_id: filters.agentId,
                                            min_level: filters.minLevel,
                                            max_level: filters.maxLevel,
                                            tactic: filters.tactic,
                                            entity_kind: filters.entityKind,
                                            entity: filters.entity,
                                        })
                                    }
                                />
                            )}
                            {filters.agentId && (
                                <ActiveFilter
                                    label={`${t("agent")} ${filters.agentId}`}
                                    removeLabel={`${copy.removeFilter}: ${t("agent")}`}
                                    onRemove={() =>
                                        onFilters({
                                            rule_id: filters.ruleId,
                                            min_level: filters.minLevel,
                                            max_level: filters.maxLevel,
                                            tactic: filters.tactic,
                                            entity_kind: filters.entityKind,
                                            entity: filters.entity,
                                        })
                                    }
                                />
                            )}
                            {filters.minLevel !== undefined && (
                                <ActiveFilter
                                    label={`${t("filterLevel")} ${filters.minLevel}`}
                                    removeLabel={`${copy.removeFilter}: ${t("filterLevel")}`}
                                    onRemove={() =>
                                        onFilters({
                                            rule_id: filters.ruleId,
                                            agent_id: filters.agentId,
                                            max_level: filters.maxLevel,
                                            tactic: filters.tactic,
                                            entity_kind: filters.entityKind,
                                            entity: filters.entity,
                                        })
                                    }
                                />
                            )}
                            {filters.maxLevel !== undefined && (
                                <ActiveFilter
                                    label={`${t("maximumLevel")} ${filters.maxLevel}`}
                                    removeLabel={`${copy.removeFilter}: ${t("maximumLevel")}`}
                                    onRemove={() =>
                                        onFilters({
                                            rule_id: filters.ruleId,
                                            agent_id: filters.agentId,
                                            min_level: filters.minLevel,
                                            tactic: filters.tactic,
                                            entity_kind: filters.entityKind,
                                            entity: filters.entity,
                                        })
                                    }
                                />
                            )}
                            {filters.tactic && (
                                <ActiveFilter
                                    label={`${t("tactic")} ${filters.tactic}`}
                                    removeLabel={`${copy.removeFilter}: ${t("tactic")}`}
                                    onRemove={() =>
                                        onFilters({
                                            rule_id: filters.ruleId,
                                            agent_id: filters.agentId,
                                            min_level: filters.minLevel,
                                            max_level: filters.maxLevel,
                                            entity_kind: filters.entityKind,
                                            entity: filters.entity,
                                        })
                                    }
                                />
                            )}
                            {filters.entity && (
                                <ActiveFilter
                                    label={`${filters.entityKind ?? "Entity"} ${filters.entity}`}
                                    removeLabel={`${copy.removeFilter}: ${filters.entity}`}
                                    onRemove={() =>
                                        onFilters({
                                            rule_id: filters.ruleId,
                                            agent_id: filters.agentId,
                                            min_level: filters.minLevel,
                                            max_level: filters.maxLevel,
                                            tactic: filters.tactic,
                                        })
                                    }
                                />
                            )}
                        </div>
                    )}
                </Panel>
                <Panel className="workspace-panel table-panel">
                    <div className="alerts-v2-results-heading">
                        <div>
                            <h3>{copy.results}</h3>
                            <p>{copy.loadedRows}</p>
                        </div>
                        <strong>{page.data.items.length.toLocaleString()}</strong>
                    </div>
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
                                        <th>{t("level")}</th>
                                        <th>{t("rule")}</th>
                                        <th>{copy.description}</th>
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
                                            <td className="alerts-v2-time">
                                                {formatTime(alert.event_ts)}
                                            </td>
                                            <td>
                                                {alert.rule_level === null ? (
                                                    <Tag>{t("nullUnknown")}</Tag>
                                                ) : (
                                                    <Tag {...severityTag(alert.rule_level)} mono>
                                                        {alert.rule_level}
                                                    </Tag>
                                                )}
                                            </td>
                                            <td>
                                                <code>{alert.rule_id ?? "—"}</code>
                                            </td>
                                            <td>{alert.rule_description ?? t("nullUnknown")}</td>
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
                <SheetContent
                    title={t("alertDetails")}
                    closeLabel={t("detailsClose")}
                    restoreFocus={restoreTriggerFocus}
                >
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
                                    copy={copy}
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

function ActiveFilter({
    label,
    removeLabel,
    onRemove,
}: {
    label: string;
    removeLabel: string;
    onRemove: () => void;
}) {
    const remove = (event: React.MouseEvent<HTMLButtonElement>) => {
        const button = event.currentTarget;
        const group = button.closest<HTMLElement>(".alerts-v2-active-filters");
        const buttons = group
            ? Array.from(group.querySelectorAll<HTMLButtonElement>("button"))
            : [];
        const index = buttons.indexOf(button);
        const nextButton = buttons[index + 1] ?? buttons[index - 1] ?? null;
        const fallback = document.querySelector<HTMLInputElement>(".alert-filter-form input");

        onRemove();
        requestAnimationFrame(() => {
            if (nextButton?.isConnected) nextButton.focus();
            else fallback?.focus();
        });
    };

    return (
        <Tag>
            {label}
            <button type="button" aria-label={removeLabel} onClick={remove}>
                ×
            </button>
        </Tag>
    );
}

function AlertDrawer({
    alert,
    t,
    copy,
    onInvestigate,
}: {
    alert: AlertDetail;
    t: Translate;
    copy: {
        fields: string;
        json: string;
        documentView: string;
    };
    onInvestigate: () => void;
}) {
    const wazuhUrl = safeWazuhUrl(alert.wazuh_url);
    const [view, setView] = useState<"fields" | "json">("fields");
    return (
        <div className="alert-drawer-body">
            <p className="drawer-alert-title">{alert.rule_description ?? t("nullUnknown")}</p>
            <div className="alerts-v2-view-toggle" aria-label={copy.documentView} role="group">
                <button
                    type="button"
                    aria-pressed={view === "fields"}
                    onClick={() => setView("fields")}
                >
                    {copy.fields}
                </button>
                <button
                    type="button"
                    aria-pressed={view === "json"}
                    onClick={() => setView("json")}
                >
                    {copy.json}
                </button>
            </div>
            {view === "fields" ? (
                <>
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
                            {[
                                ...alert.rule_groups,
                                ...alert.mitre_tactics,
                                ...alert.mitre_techniques,
                            ].join(" · ") || "—"}
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
                </>
            ) : (
                <section className="drawer-section">
                    <h3>{t("rawSource")}</h3>
                    <pre className="raw-json" tabIndex={0}>
                        <code>{JSON.stringify(alert.raw, null, 2)}</code>
                    </pre>
                </section>
            )}
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
