import { useEffect, useRef, useState } from "react";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { ChevronLeft, CircleDashed, Globe, Server, User } from "lucide-react";
import { IdChip, SlaText, ViewTabs, slaFrom } from "../../components/ui/portfolio";
import { useSamples } from "../workspace/samples";
import type { AlertDrilldown } from "../overview/OverviewPage";
import type { components } from "../../../../contracts/workspace/v1/types.ts";
import {
    createIncident,
    dismissChain,
    getChain,
    getIncident,
    getIncidentContext,
    getIncidentEvents,
    incidentAction,
    listChains,
    listIncidents,
    promoteChain,
    type IncidentActionCommand,
} from "../../api/workspace-m3";
import { WorkspaceRequestError } from "../../api/workspace";
import { Tag } from "../../components/ui/tag";
import { statusTags, type WorkStatus } from "../../lib/semantic";
import { falsePositiveReasonText } from "../../i18n/workspace-copy";
import { humanizeKey, isFlatRecord } from "../../lib/utils";
import { IdValue, NarrativePanel } from "./NarrativePanel";
import "./incident-v2.css";
import "./incident-pp.css";

type Locale = "en" | "es";
type Translate = (key: string) => string;
type PageKind = "chains" | "incidents";
type Selection = { kind: "chain"; id: string } | { kind: "incident"; id: string } | null;
type IncidentStatus = components["schemas"]["IncidentStatusRequest"]["status"];
type DispositionLabel = components["schemas"]["IncidentDispositionRequest"]["label"];

const incidentStatusLabels = {
    new: "newStatus",
    in_progress: "inProgress",
    resolved: "resolved",
    closed: "closed",
} satisfies Record<IncidentStatus, string>;


export function M3WorkspacePage({
    kind,
    siteId,
    locale,
    t,
    onInvestigate,
    onNavigate,
    onSearchAlerts,
}: {
    kind: PageKind;
    siteId: string;
    locale: Locale;
    t: Translate;
    onInvestigate?: (question: string, environmentId: string) => void;
    onNavigate?: (route: PageKind) => void;
    onSearchAlerts?: (filters: AlertDrilldown) => void;
}) {
    const [chainView, setChainView] = useState<"open" | "promoted" | "dismissed">("open");
    const onOpenChain = (chainId: string) => {
        setChainView("open");
        setSelection({ kind: "chain", id: chainId });
        onNavigate?.("chains");
    };
    const queryClient = useQueryClient();
    const [selection, setSelection] = useState<Selection>(null);
    const [error, setError] = useState("");
    const [chainCursor, setChainCursor] = useState("");
    const [incidentCursor, setIncidentCursor] = useState("");
    const [incidentStatus, setIncidentStatus] = useState<IncidentStatus>();
    const [unassignedOnly, setUnassignedOnly] = useState(false);
    const incidentList = useRef<HTMLElement>(null);
    const incidentPanel = useRef<HTMLElement>(null);
    const selectedIncidentId = selection?.kind === "incident" ? selection.id : undefined;
    const [eventCursor, setEventCursor] = useState("");
    const [detailCursors, setDetailCursors] = useState<
        Partial<Record<"history" | "comments" | "dispositions" | "membership", string>>
    >({});
    useEffect(() => {
        setChainCursor("");
        setIncidentCursor("");
        setEventCursor("");
        setDetailCursors({});
        setSelection(null);
    }, [siteId]);
    useEffect(() => {
        if (kind === "incidents" && selectedIncidentId && matchMedia("(max-width: 700px)").matches)
            incidentPanel.current?.focus();
    }, [kind, selectedIncidentId]);
    const chains = useQuery({
        queryKey: ["m3", "chains", siteId, chainCursor],
        queryFn: ({ signal }) => listChains({ siteId, cursor: chainCursor || undefined }, signal),
        enabled: !!siteId && kind === "chains",
    });
    const incidents = useQuery({
        queryKey: ["m3", "incidents", siteId, incidentStatus, unassignedOnly, incidentCursor],
        queryFn: ({ signal }) =>
            listIncidents(
                {
                    siteId,
                    status: incidentStatus,
                    unassigned: unassignedOnly || undefined,
                    cursor: incidentCursor || undefined,
                },
                signal,
            ),
        enabled: !!siteId && kind === "incidents",
    });
    const chainsForIncident = useQuery({
        queryKey: ["m3", "chains", siteId, ""],
        queryFn: ({ signal }) => listChains({ siteId }, signal),
        enabled: !!siteId && kind === "incidents",
    });
    const chain = useQuery({
        queryKey: ["m3", "chain", siteId, selection?.kind === "chain" ? selection.id : ""],
        queryFn: ({ signal }) =>
            selection?.kind === "chain"
                ? getChain(siteId, selection.id, signal)
                : Promise.reject(new Error("Chain selection is missing")),
        enabled: !!siteId && selection?.kind === "chain",
    });
    const incident = useQuery({
        queryKey: [
            "m3",
            "incident",
            siteId,
            selection?.kind === "incident" ? selection.id : "",
            detailCursors,
        ],
        queryFn: ({ signal }) =>
            selection?.kind === "incident"
                ? getIncident(siteId, selection.id, detailCursors, signal)
                : Promise.reject(new Error("Incident selection is missing")),
        enabled: !!siteId && selection?.kind === "incident",
    });
    const activeIncident =
        selection?.kind === "incident" && !incident.isError ? incident.data?.incident : undefined;
    const contextAbort = useRef<AbortController | null>(null);
    const activeScope = useRef("");
    activeScope.current = `${kind}:${siteId}:${selection?.kind}:${selection?.id}:${activeIncident?.evidence_head}`;
    useEffect(
        () => () => {
            contextAbort.current?.abort();
        },
        [kind, siteId, selection?.kind, selection?.id, activeIncident?.evidence_head],
    );
    const events = useQuery({
        queryKey: [
            "m3",
            "incident-events",
            siteId,
            activeIncident?.incident_id,
            activeIncident?.evidence_head,
            eventCursor,
        ],
        queryFn: ({ signal }) =>
            activeIncident
                ? getIncidentEvents(
                      {
                          siteId,
                          incidentId: activeIncident.incident_id,
                          evidenceRevision: activeIncident.evidence_head,
                          cursor: eventCursor || undefined,
                      },
                      signal,
                  )
                : Promise.reject(new Error("Incident selection is missing")),
        enabled: !!siteId && !!activeIncident,
    });

    const resetIncidentSelection = () => {
        setSelection(null);
        setEventCursor("");
        setDetailCursors({});
    };
    const refresh = async () => {
        await Promise.all([
            queryClient.invalidateQueries({ queryKey: ["m3", kind, siteId] }),
            queryClient.invalidateQueries({ queryKey: ["m3", "chain", siteId] }),
            queryClient.invalidateQueries({ queryKey: ["m3", "incident", siteId] }),
            queryClient.invalidateQueries({ queryKey: ["m3", "incident-events", siteId] }),
        ]);
    };
    const runAction = async (action: () => Promise<unknown>) => {
        setError("");
        try {
            await action();
            await refresh();
        } catch (reason) {
            if (reason instanceof WorkspaceRequestError && reason.status === 409) {
                setError(t("m3Stale"));
                await refresh();
                return;
            }
            setError(reason instanceof Error ? reason.message : t("m3ActionError"));
        }
    };

    const chainItems = (!chains.isError ? chains.data?.items : undefined) ?? [];
    const chainCounts = {
        open: chainItems.filter((item) => item.state === "open").length,
        promoted: chainItems.filter((item) => item.state === "promoted").length,
        dismissed: chainItems.filter((item) => item.state === "dismissed").length,
    };
    const visibleChains = chainItems.filter((item) => item.state === chainView);
    const incidentItems = (!incidents.isError ? incidents.data?.items : undefined) ?? [];
    const selectedIncidentIndex = incidentItems.findIndex(
        (item) => item.incident_id === selectedIncidentId,
    );
    const selectedIncidentSummary =
        selectedIncidentIndex >= 0 ? incidentItems[selectedIncidentIndex] : undefined;
    const openIncident = (id: string) => {
        setSelection({ kind: "incident", id });
        setEventCursor("");
        setDetailCursors({});
    };
    const investigate = onInvestigate
        ? async () => {
              if (!incident.data) return;
              contextAbort.current?.abort();
              const controller = new AbortController();
              contextAbort.current = controller;
              const requestedScope = activeScope.current;
              try {
                  const context = await getIncidentContext(
                      {
                          siteId,
                          incidentId: incident.data.incident.incident_id,
                          evidenceRevision: incident.data.incident.evidence_head,
                      },
                      controller.signal,
                  );
                  if (controller.signal.aborted || activeScope.current !== requestedScope) return;
                  const request = field(context.question_draft, "request");
                  const question = field(request, "question");
                  const environment = field(request, "environment_id");
                  if (
                      typeof question !== "string" ||
                      typeof environment !== "string" ||
                      environment !== siteId
                  ) {
                      setError(t("m3ContextInvalid"));
                      return;
                  }
                  onInvestigate(question, environment);
              } catch (reason) {
                  if (controller.signal.aborted || activeScope.current !== requestedScope) return;
                  if (reason instanceof WorkspaceRequestError && reason.status === 409) {
                      setError(t("m3Stale"));
                      await refresh();
                  } else {
                      setError(reason instanceof Error ? reason.message : t("m3ActionError"));
                  }
              }
          }
        : undefined;

    return (
        <div className="m3-page m3-pp">
            {!siteId && (
                <div className="alert" role="status">
                    {t("noSites")}
                </div>
            )}
            {error && (
                <div className="alert error" role="alert">
                    {error}
                </div>
            )}
            {kind === "chains" ? (
                <>
                    <p className="m3-pp-intro">{t("chainsDescription")}</p>
                    <div className="tab-bar">
                        <ViewTabs
                            label={t("chainViews")}
                            value={chainView}
                            onChange={(value) => {
                                setChainView(value);
                                setSelection(null);
                            }}
                            tabs={[
                                { id: "open", label: t("chainOpen"), count: chainCounts.open },
                                { id: "promoted", label: t("chainPromoted"), count: chainCounts.promoted },
                                { id: "dismissed", label: t("chainDismissed"), count: chainCounts.dismissed },
                            ]}
                        />
                        <span className="queue-pp-tab-spacer" />
                        <button className="btn compact" type="button" onClick={() => void chains.refetch()}>
                            {t("refresh")}
                        </button>
                    </div>
                    <section className="pp-panel m3-pp-table-panel" aria-labelledby="chain-list-heading">
                        <h2 id="chain-list-heading" className="sr-only">
                            {t("m3Candidates")}
                        </h2>
                        {chains.isLoading ? <p className="m3-pp-empty" role="status">{t("loading")}</p> : null}
                        {chains.isError ? (
                            <LoadError
                                message={failureMessage(chains.error, t)}
                                retry={() => void chains.refetch()}
                                t={t}
                            />
                        ) : null}
                        {!chains.isLoading && !chains.isError && (
                            <div className="pp-table-scroll">
                                <table className="pp-table m3-pp-chain-table">
                                    <thead>
                                        <tr>
                                            <th scope="col">{t("chainPattern")}</th>
                                            <th scope="col">{t("chainStages")}</th>
                                            <th scope="col">{t("chainLinkStrength")}</th>
                                            <th scope="col" className="is-num">
                                                {t("m3Score")}
                                            </th>
                                            <th scope="col">{t("chainStarted")}</th>
                                        </tr>
                                    </thead>
                                    <tbody>
                                        {visibleChains.map((item) => {
                                            const stages = chainStages(item.stages);
                                            const matched = stages.filter((stage) => stage.outcome === "matched");
                                            const missing = stages.filter((stage) => stage.outcome !== "matched");
                                            const groups = new Set(matched.map((stage) => stage.groupId).filter(Boolean));
                                            const selected =
                                                selection?.kind === "chain" && selection.id === item.chain_id;
                                            return (
                                                <tr key={item.chain_id} data-selected={selected || undefined}>
                                                    <td>
                                                        <button
                                                            type="button"
                                                            className="m3-list-item m3-pp-row-link"
                                                            aria-current={selected ? "true" : undefined}
                                                            onClick={() => setSelection({ kind: "chain", id: item.chain_id })}
                                                        >
                                                            <span className="cell-main">{patternName(item.rule_id)}</span>
                                                            <span className="m3-pp-row-meta">
                                                                <span>
                                                                    {groups.size} {t(groups.size === 1 ? "chainGroupOne" : "chainGroupMany")}
                                                                </span>
                                                                <span>v{item.rule_version}</span>
                                                                {item.weak_heuristic && <span>{t("m3WeakEvidence")}</span>}
                                                            </span>
                                                        </button>
                                                    </td>
                                                    <td>
                                                        <StageBar stages={stages} />
                                                        <span className="cell-sub">
                                                            {t("chainMatchedOf")
                                                                .replace("{matched}", String(matched.length))
                                                                .replace("{total}", String(stages.length))}
                                                            {missing.length > 0 &&
                                                                `, ${missing.map((stage) => stageName(stage.stageId)).join(", ").toLocaleLowerCase()} ${t("chainMissingWord")}`}
                                                        </span>
                                                    </td>
                                                    <td>
                                                        <LinkStrength value={item.score} t={t} />
                                                    </td>
                                                    <td className="is-num">
                                                        {item.score_available ? formatScore(item.score) : "\u2014"}
                                                    </td>
                                                    <td className="num">{fmtDate(item.created_at, locale)}</td>
                                                </tr>
                                            );
                                        })}
                                        {visibleChains.length === 0 && (
                                            <tr>
                                                <td colSpan={5} className="pp-table-empty">
                                                    {t("m3NoCandidates")}
                                                </td>
                                            </tr>
                                        )}
                                    </tbody>
                                </table>
                            </div>
                        )}
                        {!chains.isError && chains.data?.next_cursor && (
                            <div className="pp-panel-foot">
                                <button
                                    className="btn compact"
                                    onClick={() => setChainCursor(chains.data?.next_cursor ?? "")}
                                >
                                    {t("nextPage")}
                                </button>
                            </div>
                        )}
                    </section>
                    {selection?.kind === "chain" && (
                        <section className="pp-panel m3-pp-chain-detail" aria-labelledby="chain-detail-heading">
                            {chain.isLoading ? (
                                <p role="status">{t("loading")}</p>
                            ) : chain.isError ? (
                                <LoadError
                                    message={failureMessage(chain.error, t)}
                                    retry={() => void chain.refetch()}
                                    t={t}
                                />
                            ) : chain.data ? (
                                <ChainDetailView
                                    key={chain.data.chain_id}
                                    detail={chain.data}
                                    locale={locale}
                                    t={t}
                                    onSearchStage={onSearchAlerts}
                                    onPromote={(title) =>
                                        void runAction(() =>
                                            promoteChain(chain.data!.chain_id, {
                                                site_id: siteId,
                                                expected_revision: chain.data!.revision_digest,
                                                expected_manifest_id: chain.data!.manifest_id,
                                                expected_decision_version: chain.data!.decision_version,
                                                title_override: title || null,
                                            }),
                                        )
                                    }
                                    onDismiss={(reason) =>
                                        void runAction(() =>
                                            dismissChain(chain.data!.chain_id, {
                                                site_id: siteId,
                                                expected_revision: chain.data!.revision_digest,
                                                expected_manifest_id: chain.data!.manifest_id,
                                                expected_decision_version: chain.data!.decision_version,
                                                reason,
                                            }),
                                        )
                                    }
                                />
                            ) : null}
                        </section>
                    )}
                </>
            ) : selection?.kind === "incident" ? (
                <section
                    className="m3-pp-incident m3-incident-detail"
                    aria-labelledby="incident-detail-heading"
                    ref={incidentPanel}
                    tabIndex={-1}
                >
                    <div className="m3-pp-incident-nav">
                        <button
                            className="pp-link m3-incident-back"
                            type="button"
                            onClick={() => {
                                resetIncidentSelection();
                                requestAnimationFrame(() => incidentList.current?.focus());
                            }}
                        >
                            <ChevronLeft size={14} aria-hidden="true" />
                            {t("m3BackToIncidents")}
                        </button>
                        {selectedIncidentIndex >= 0 && (
                            <>
                                <span className="m3-pp-incident-position">
                                    {t("incidentPosition")
                                        .replace("{index}", String(selectedIncidentIndex + 1))
                                        .replace("{total}", String(incidentItems.length))}
                                </span>
                                <button
                                    className="btn compact"
                                    type="button"
                                    disabled={selectedIncidentIndex <= 0}
                                    onClick={() => openIncident(incidentItems[selectedIncidentIndex - 1]!.incident_id)}
                                >
                                    {t("previous")}
                                </button>
                                <button
                                    className="btn compact"
                                    type="button"
                                    disabled={selectedIncidentIndex >= incidentItems.length - 1}
                                    onClick={() => openIncident(incidentItems[selectedIncidentIndex + 1]!.incident_id)}
                                >
                                    {t("next")}
                                </button>
                            </>
                        )}
                    </div>
                    {incident.isLoading ? (
                        <p role="status">{t("loading")}</p>
                    ) : incident.isError ? (
                        <LoadError
                            message={failureMessage(incident.error, t)}
                            retry={() => void incident.refetch()}
                            t={t}
                        />
                    ) : incident.data ? (
                        <IncidentDetailView
                            key={`${incident.data.incident.incident_id}-${incident.data.incident.work_version}-${incidentCursorKey(detailCursors)}`}
                            data={incident.data}
                            summary={selectedIncidentSummary}
                            chains={chainsForIncident.data?.items ?? []}
                            events={events.isError ? [] : (events.data?.events ?? [])}
                            eventsNext={events.isError ? null : (events.data?.next_cursor ?? null)}
                            eventsLoading={events.isLoading}
                            eventsError={events.isError ? failureMessage(events.error, t) : ""}
                            siteId={siteId}
                            locale={locale}
                            t={t}
                            onOpenChain={(id) => onOpenChain?.(id)}
                            onAction={(command) =>
                                void runAction(() =>
                                    incidentAction(incident.data!.incident.incident_id, command),
                                )
                            }
                            onMoreEvents={() => setEventCursor(events.data?.next_cursor ?? "")}
                            onMoreDetail={(name, cursor) =>
                                setDetailCursors((previous) => ({ ...previous, [name]: cursor }))
                            }
                            onInvestigate={investigate}
                        />
                    ) : null}
                </section>
            ) : (
                <>
                    <div className="tab-bar">
                        <ViewTabs
                            label={t("m3IncidentFilters")}
                            value={incidentStatus ?? "all"}
                            onChange={(value) => {
                                setIncidentStatus(value === "all" ? undefined : value);
                                setIncidentCursor("");
                                resetIncidentSelection();
                            }}
                            tabs={[
                                { id: "all" as const, label: t("queueViewAll") },
                                { id: "new" as const, label: t("newStatus") },
                                { id: "in_progress" as const, label: t("inProgress") },
                                { id: "resolved" as const, label: t("resolved") },
                                { id: "closed" as const, label: t("closed") },
                            ]}
                        />
                        <span className="queue-pp-tab-spacer" />
                        <label className="pp-check m3-assignment-filter">
                            <input
                                type="checkbox"
                                checked={unassignedOnly}
                                onChange={(event) => {
                                    setUnassignedOnly(event.target.checked);
                                    setIncidentCursor("");
                                    resetIncidentSelection();
                                }}
                            />
                            {t("m3UnassignedOnly")}
                        </label>
                        <label className="queue-pp-filter sr-only">
                            {t("m3IncidentStatusFilter")}
                            <select
                                value={incidentStatus ?? ""}
                                onChange={(event) => {
                                    setIncidentStatus(parseIncidentStatus(event.target.value));
                                    setIncidentCursor("");
                                    resetIncidentSelection();
                                }}
                            >
                                <option value="">{t("allStatuses")}</option>
                                {Object.entries(incidentStatusLabels).map(([value, label]) => (
                                    <option key={value} value={value}>
                                        {t(label)}
                                    </option>
                                ))}
                            </select>
                        </label>
                        <button className="btn compact" type="button" onClick={() => void incidents.refetch()}>
                            {t("refresh")}
                        </button>
                    </div>
                    <section
                        className="pp-panel m3-pp-table-panel m3-incident-list"
                        aria-labelledby="incident-list-heading"
                        ref={incidentList}
                        tabIndex={-1}
                    >
                        <h2 id="incident-list-heading" className="sr-only">
                            {t("m3Incidents")}
                        </h2>
                        {incidents.isLoading ? <p className="m3-pp-empty" role="status">{t("loading")}</p> : null}
                        {incidents.isError ? (
                            <LoadError
                                message={failureMessage(incidents.error, t)}
                                retry={() => void incidents.refetch()}
                                t={t}
                            />
                        ) : null}
                        {!incidents.isLoading && !incidents.isError && (
                            <div className="pp-table-scroll">
                                <table className="pp-table">
                                    <thead>
                                        <tr>
                                            <th scope="col">{t("m3Incidents")}</th>
                                            <th scope="col">{t("m3Status")}</th>
                                            <th scope="col">{t("m3Owner")}</th>
                                            <th scope="col" className="is-num">
                                                {t("m3Priority")}
                                            </th>
                                            <th scope="col">{t("incidentOpened")}</th>
                                        </tr>
                                    </thead>
                                    <tbody>
                                        {incidentItems.map((item) => (
                                            <tr key={item.incident_id}>
                                                <td>
                                                    <button
                                                        className="m3-list-item m3-pp-row-link"
                                                        type="button"
                                                        onClick={() => openIncident(item.incident_id)}
                                                    >
                                                        <span className="cell-main">{item.title}</span>
                                                    </button>
                                                    <IdChip kind="incident" value={item.incident_id} copy={false} />
                                                </td>
                                                <td>
                                                    <StateTag value={item.status} label={t(incidentStatusLabels[item.status])} />
                                                </td>
                                                <td>{item.owner_key ?? t("m3Unassigned")}</td>
                                                <td className="is-num">
                                                    {item.priority === null ? "\u2014" : formatScore(item.priority)}
                                                </td>
                                                <td className="num">
                                                    {fmtDate(item.created_at, locale)}
                                                    <span className="cell-sub">{t("incidentBy")} {item.created_by}</span>
                                                </td>
                                            </tr>
                                        ))}
                                        {incidentItems.length === 0 && (
                                            <tr>
                                                <td colSpan={5} className="pp-table-empty">
                                                    {t(incidentStatus || unassignedOnly ? "m3NoMatchingIncidents" : "m3NoIncidents")}
                                                </td>
                                            </tr>
                                        )}
                                    </tbody>
                                </table>
                            </div>
                        )}
                        {!incidents.isError && incidents.data?.next_cursor && (
                            <div className="pp-panel-foot">
                                <button
                                    className="btn compact"
                                    onClick={() => setIncidentCursor(incidents.data?.next_cursor ?? "")}
                                >
                                    {t("nextPage")}
                                </button>
                            </div>
                        )}
                    </section>
                    <details className="pp-panel m3-pp-create m3-create-disclosure">
                        <summary>
                            <span className="t-sub">{t("m3CreateIncident")}</span>
                        </summary>
                        <CreateIncidentForm
                            siteId={siteId}
                            t={t}
                            onCreate={(body) =>
                                void runAction(async () => {
                                    const result = await createIncident(body);
                                    await refresh();
                                    if (result.incident_id) openIncident(result.incident_id);
                                })
                            }
                        />
                    </details>
                </>
            )}
        </div>
    );
}


type StageView = { ordinal: number; stageId: string; outcome: string; groupId: string | null };

function chainStages(stages: ReadonlyArray<Record<string, unknown>>): StageView[] {
    return stages
        .map((stage, index) => ({
            ordinal: typeof stage.ordinal === "number" ? stage.ordinal : index + 1,
            stageId: typeof stage.stage_id === "string" ? stage.stage_id : `stage_${index + 1}`,
            outcome: typeof stage.outcome === "string" ? stage.outcome : "missing",
            groupId: typeof stage.group_id === "string" ? stage.group_id : null,
        }))
        .sort((left, right) => left.ordinal - right.ordinal);
}

const ACRONYMS = new Set(["ssh", "ip", "ldap", "rdp", "dns", "smb", "fim", "vpn", "sql", "http"]);
/** "linux.ssh_bruteforce_to_persistence" reads "SSH brute force to persistence". */
function patternName(ruleId: string): string {
    const tail = ruleId.includes(".") ? ruleId.slice(ruleId.lastIndexOf(".") + 1) : ruleId;
    const words = tail
        .replace(/bruteforce/gi, "brute_force")
        .split(/[_\-\s]+/)
        .filter(Boolean)
        .map((word) => (ACRONYMS.has(word.toLowerCase()) ? word.toUpperCase() : word.toLowerCase()));
    const text = words.join(" ");
    return text ? text.charAt(0).toUpperCase() + text.slice(1) : ruleId;
}

function stageName(stageId: string): string {
    return patternName(stageId);
}

function StageBar({ stages }: { stages: StageView[] }) {
    return (
        <span className="stage-bar" aria-hidden="true">
            {stages.map((stage) => (
                <span key={stage.ordinal} data-outcome={stage.outcome === "matched" ? "matched" : "missing"} />
            ))}
        </span>
    );
}

function LinkStrength({ value, t }: { value: number | null; t: Translate }) {
    if (value === null) return <span className="t-secondary">—</span>;
    const strong = value >= 0.8;
    return (
        <Tag tone={strong ? "green" : "neutral"}>
            {t(strong ? "linkStrong" : "linkWeak")} · {value.toFixed(2)}
        </Tag>
    );
}

function ChainDetailView({
    detail,
    locale,
    t,
    onPromote,
    onDismiss,
    onSearchStage,
}: {
    detail: components["schemas"]["ChainCandidateDetail"];
    locale: Locale;
    t: Translate;
    onPromote: (title: string) => void;
    onDismiss: (reason: string) => void;
    onSearchStage?: (filters: AlertDrilldown) => void;
}) {
    const [title, setTitle] = useState("");
    const [reason, setReason] = useState("");
    const [dismissing, setDismissing] = useState(false);
    const result = detail.result;
    const reasons = field(result, "reasons");
    const reasonItems = Array.isArray(reasons) ? reasons : [];
    const orderToleranceApplied = field(result, "order_tolerance_applied") === true;
    const reasonTranslations: Readonly<Record<string, string>> = {
        "Actor continuity is unavailable for one or more selected stages":
            t("m3ReasonActorContinuity"),
        "Order tolerance applied to a syscheck persistence witness": t("m3ReasonOrderTolerance"),
    };
    const stages = chainStages(detail.stages);
    const pinList = scorePins(detail.score_pins);
    const pins = new Map(pinList.map((pin) => [pin.groupId, pin]));
    const usedEdges = chainEdges(detail.edges);
    const weakEdges = chainEdges(detail.weak_edges);
    const windowStart = field(result, "window_start");
    const strongest = usedEdges.reduce<number | null>(
        (best, edge) =>
            edge.confidence !== null && (best === null || edge.confidence > best) ? edge.confidence : best,
        null,
    );
    return (
        <>
            <div className="m3-pp-chain-head">
                <div>
                    <div className="m3-pp-chain-ids">
                        <StateTag value={detail.state} label={t(`chainState_${detail.state}`)} />
                        <IdChip kind="chain" value={detail.chain_id} />
                        <span className="t-secondary">
                            {t("m3Rule")} {detail.rule_id} v{detail.rule_version}
                            {orderToleranceApplied && ` · ${t("orderToleranceApplied")}`}
                        </span>
                    </div>
                    <h2 id="chain-detail-heading" className="t-page-title">
                        {patternName(detail.rule_id)}
                    </h2>
                    <p className="t-secondary">
                        {t("m3Score")} {detail.score_available ? formatScore(detail.score) : t("m3ScoreUnavailable")}
                        {strongest !== null && ` · ${t("chainLinkStrength").toLocaleLowerCase()} ${strongest.toFixed(2)}`}
                        {typeof windowStart === "string" && ` · ${t("chainStarted").toLocaleLowerCase()} ${fmtDate(windowStart, locale)}`}
                    </p>
                </div>
                {detail.state === "open" && (
                    <form
                        id="chain-promote-form"
                        className="m3-pp-chain-actions"
                        onSubmit={(event) => {
                            event.preventDefault();
                            onPromote(title.trim());
                        }}
                    >
                        <label className="m3-pp-title-field">
                            <span className="sr-only">{t("m3TitleOverride")}</span>
                            <input
                                aria-label={t("m3TitleOverride")}
                                maxLength={240}
                                value={title}
                                placeholder={t("m3TitleOverride")}
                                onChange={(event) => setTitle(event.target.value)}
                            />
                        </label>
                        <button
                            className="btn"
                            type="button"
                            aria-expanded={dismissing}
                            onClick={() => setDismissing(!dismissing)}
                        >
                            {t("dismissEllipsis")}
                        </button>
                        <button className="btn primary" type="submit">
                            {t("m3Promote")}
                        </button>
                    </form>
                )}
            </div>
            {detail.weak_heuristic && <p className="alert warning">{t("m3WeakEvidence")}</p>}
            {detail.state === "open" && dismissing && (
                <div className="pp-note m3-actions">
                    <form
                        id="chain-dismiss-form"
                        className="m3-pp-inline-form"
                        onSubmit={(event) => {
                            event.preventDefault();
                            if (reason.trim()) onDismiss(reason.trim());
                        }}
                    >
                        <label className="pp-field">
                            {t("m3DismissReason")}
                            <input
                                required
                                maxLength={512}
                                value={reason}
                                onChange={(event) => setReason(event.target.value)}
                            />
                        </label>
                        <button className="btn" type="submit">
                            {t("m3Dismiss")}
                        </button>
                    </form>
                </div>
            )}

            <section aria-labelledby="chain-stages-heading">
                <h3 id="chain-stages-heading" className="sr-only">
                    {t("m3OrderedStages")}
                </h3>
                {stages.length ? (
                    <ol className="m3-pp-stages">
                        {stages.map((stage) => {
                            const matched = stage.outcome === "matched";
                            const pin = stage.groupId ? pins.get(stage.groupId) : undefined;
                            return (
                                <li key={stage.ordinal} className="m3-pp-stage" data-outcome={matched ? "matched" : "missing"}>
                                    <div className="m3-pp-stage-head">
                                        <span className="m3-pp-stage-n num">{stage.ordinal}</span>
                                        <span className="cell-main">{stageName(stage.stageId)}</span>
                                        <Tag tone={matched ? "green" : "neutral"}>
                                            {t(matched ? "stageMatched" : "stageMissing")}
                                        </Tag>
                                    </div>
                                    {matched ? (
                                        <>
                                            {stage.groupId && (
                                                <div className="m3-pp-stage-meta">
                                                    <IdChip kind="group" value={stage.groupId} />
                                                    {pin && (
                                                        <span className="t-secondary">
                                                            {t("m3Score")} {formatScore(pin.score)}
                                                        </span>
                                                    )}
                                                </div>
                                            )}
                                        </>
                                    ) : (
                                        <>
                                            <p className="t-secondary">
                                                {t("watchingForStage").replace(
                                                    "{stage}",
                                                    stageName(stage.stageId).toLocaleLowerCase(),
                                                )}
                                            </p>
                                            {onSearchStage && (
                                                <button
                                                    type="button"
                                                    className="btn compact"
                                                    onClick={() =>
                                                        onSearchStage({
                                                            from: typeof windowStart === "string" ? windowStart : undefined,
                                                        })
                                                    }
                                                >
                                                    {t("searchAlertsForStage")}
                                                </button>
                                            )}
                                        </>
                                    )}
                                </li>
                            );
                        })}
                    </ol>
                ) : (
                    <p className="muted">{t("m3NoStageEvidence")}</p>
                )}
                {reasonItems.length > 0 && (
                    <ul className="m3-pp-reasons t-secondary">
                        {reasonItems
                            .filter(
                                (item) =>
                                    item !== "Order tolerance applied to a syscheck persistence witness",
                            )
                            .map((item, index) => {
                                const raw = printable(item);
                                const translated = Object.hasOwn(reasonTranslations, raw)
                                    ? reasonTranslations[raw]
                                    : undefined;
                                return <li key={`${index}-${raw}`}>{translated ?? raw}</li>;
                            })}
                    </ul>
                )}
            </section>
            {detail.assessment && <ChainAssessment assessment={detail.assessment} locale={locale} t={t} />}
            <div className="m3-pp-chain-columns">
                <section aria-labelledby="chain-links-heading">
                    <h3 id="chain-links-heading" className="t-sub">
                        {t("whyLinked")}
                    </h3>
                    {usedEdges.length === 0 && weakEdges.length === 0 ? (
                        <p className="muted">{t("m3NoLinks")}</p>
                    ) : (
                        <ul className="m3-pp-rows">
                            {usedEdges.map((edge, index) => (
                                <li key={`used-${index}`}>
                                    <Tag tone="blue">{t("linkUsed")}</Tag>
                                    <span className="m3-pp-row-text">{edge.reason}</span>
                                    <span className="num">{edge.confidence?.toFixed(2) ?? "\u2014"}</span>
                                </li>
                            ))}
                            {weakEdges.map((edge, index) => (
                                <li key={`weak-${index}`}>
                                    <Tag>{t("linkWeak")}</Tag>
                                    <span className="m3-pp-row-text">{edge.reason}</span>
                                    <span className="num">{edge.confidence?.toFixed(2) ?? "\u2014"}</span>
                                </li>
                            ))}
                        </ul>
                    )}
                </section>
                <section aria-labelledby="chain-pins-heading">
                    <h3 id="chain-pins-heading" className="t-sub">
                        {t("scoresUsed")}
                    </h3>
                    {pinList.length ? (
                        <>
                            <ul className="m3-pp-rows">
                                {pinList.map((pin) => (
                                    <li key={pin.groupId}>
                                        <IdChip kind="group" value={pin.groupId} copy={false} />
                                        <span className="m3-pp-row-text t-secondary">{pin.version}</span>
                                        <span className="num">{formatScore(pin.score)}</span>
                                    </li>
                                ))}
                            </ul>
                            <p className="t-secondary">{t("scoresPinnedNote")}</p>
                        </>
                    ) : (
                        <p className="muted">{t("m3NoScorePins")}</p>
                    )}
                </section>
            </div>
            <details className="m3-pp-record">
                <summary className="t-secondary">{t("m3RecordDetails")}</summary>
                <dl className="m3-meta">
                    <dt>{t("m3Manifest")}</dt>
                    <dd>
                        <IdValue value={detail.manifest_id} locale={locale} />
                    </dd>
                    <dt>{t("m3Revision")}</dt>
                    <dd>
                        <IdChip kind="revision" value={detail.revision_digest} />
                    </dd>
                </dl>
            </details>
        </>
    );
}


function ChainAssessment({
    assessment,
    locale,
    t,
}: {
    assessment: components["schemas"]["ChainAssessmentPreview"];
    locale: Locale;
    t: Translate;
}) {
    const stages = new Map(assessment.evidence.map((item) => [item.id, item]));
    const findings = assessment.outcome.findings ?? [];
    return (
        <section className="m3-chain-assessment" aria-labelledby="chain-assessment-heading">
            <header>
                <h3 id="chain-assessment-heading">{t("m3ChainAssessment")}</h3>
                <span className="muted">{t("m3ChainAssessmentPreview")}</span>
            </header>
            {findings.length === 0 ? (
                <p className="muted">{t("m3ChainAssessmentEmpty")}</p>
            ) : (
                <ul className="m3-chain-assessment-findings">
                    {findings.map((finding) => (
                        <li key={finding.id}>
                            <p>{finding.text[locale]}</p>
                            <ul className="m3-chain-assessment-citations" aria-label={t("m3OrderedStages")}>
                                {finding.evidence_ids.map((id) => {
                                    const stage = stages.get(id);
                                    return stage && (
                                        <li key={id}>
                                            {humanizeKey(String(stage.fields.stage_id))}
                                            <IdValue value={id} locale={locale} copy />
                                        </li>
                                    );
                                })}
                            </ul>
                        </li>
                    ))}
                </ul>
            )}
            <details>
                <summary>{t("m3NarrativeProvenance")}</summary>
                <dl className="m3-meta">
                    <dt>{t("m3ChainAssessmentModel")}</dt>
                    <dd>{assessment.provenance.provider} · {assessment.provenance.model}</dd>
                    <dt>{t("m3NarrativePackDigest")}</dt>
                    <dd><IdValue value={assessment.provenance.pack_digest} locale={locale} copy /></dd>
                </dl>
            </details>
        </section>
    );
}

function IncidentDetailView({
    data,
    summary,
    chains,
    onOpenChain,
    events,
    eventsNext,
    eventsLoading,
    eventsError,
    siteId,
    locale,
    t,
    onAction,
    onMoreEvents,
    onMoreDetail,
    onInvestigate,
}: {
    data: components["schemas"]["IncidentDetailResponse"];
    summary?: components["schemas"]["IncidentSummaryDTO"];
    chains: components["schemas"]["ChainCandidateDTO"][];
    onOpenChain: (chainId: string) => void;
    events: components["schemas"]["IncidentEventDTO"][];
    eventsNext: string | null;
    eventsLoading: boolean;
    eventsError: string;
    siteId: string;
    locale: Locale;
    t: Translate;
    onAction: (command: IncidentActionCommand) => void;
    onMoreEvents: () => void;
    onMoreDetail: (
        name: "history" | "comments" | "dispositions" | "membership",
        cursor: string,
    ) => void;
    onInvestigate?: () => Promise<void>;
}) {
    const [owner, setOwner] = useState(data.incident.owner_key ?? "");
    const [status, setStatus] = useState<IncidentStatus>(data.incident.status);
    const [comment, setComment] = useState("");
    const [addGroups, setAddGroups] = useState("");
    const [removeGroups, setRemoveGroups] = useState("");
    const [membershipError, setMembershipError] = useState("");
    const [disposition, setDisposition] = useState<DispositionLabel>("undetermined");
    const [reasonCode, setReasonCode] = useState("");
    const [note, setNote] = useState("");
    const incident = data.incident;
    const groupIds = (value: string) => value.split(/[\n,\s]+/).filter(Boolean);
    const work = { site_id: siteId, expected_work_version: incident.work_version };
    const samples = useSamples();
    const [entityFilter, setEntityFilter] = useState<string | null>(null);
    const [activeTab, setActiveTab] = useState<IncidentTab>("summary");
    const sectionRefs = useRef<Partial<Record<IncidentTab, HTMLElement | null>>>({});
    const groupTitles = new Map(data.members.map((member) => [member.group_id, member.title]));
    const memberIds = new Set(data.members.map((member) => member.group_id));
    const linkedChain = chains.find((candidate) =>
        chainStages(candidate.stages).some((stage) => stage.groupId && memberIds.has(stage.groupId)),
    );
    const scope = samples?.incidentScope[incident.incident_id] ?? deriveScope(events);
    const slas = samples?.incidentSla[incident.incident_id];
    const totalAlerts = data.members.reduce((sum, member) => sum + member.alert_count, 0);
    const summaryLine =
        samples?.incidentSummary[incident.incident_id] ??
        t("incidentSummaryFallback")
            .replace("{groups}", String(data.members.length))
            .replace("{alerts}", String(totalAlerts));
    const graph = samples?.entityGraph[incident.incident_id] ?? deriveGraph(events, t);
    const timeline = buildTimeline(events, data, t).filter(
        (item) => !entityFilter || item.entities.includes(entityFilter),
    );
    const jump = (tab: IncidentTab) => {
        setActiveTab(tab);
        sectionRefs.current[tab]?.scrollIntoView({ behavior: "smooth", block: "start" });
        if (tab === "notes") requestAnimationFrame(() => noteRef.current?.focus());
    };
    const noteRef = useRef<HTMLTextAreaElement>(null);
    const workRef = useRef<HTMLDivElement>(null);
    const dispositionRef = useRef<HTMLSelectElement>(null);
    return (
        <>
            <header className="m3-pp-incident-head">
                <div className="m3-pp-incident-title">
                    <div className="m3-pp-chain-ids">
                        <StateTag value={incident.status} label={t(incidentStatusLabels[incident.status])} />
                        <IdChip kind="incident" value={incident.incident_id} />
                        {summary && (
                            <span className="t-secondary">
                                {t("incidentOpenedBy")
                                    .replace("{when}", fmtDate(summary.created_at, locale))
                                    .replace("{who}", summary.created_by)}
                            </span>
                        )}
                    </div>
                    <h2 id="incident-detail-heading" className="t-title">
                        {incident.title}
                    </h2>
                    <p className="m3-pp-incident-summary">{summaryLine}</p>
                </div>
                <div className="m3-pp-chain-actions">
                    <button
                        className="btn"
                        type="button"
                        onClick={() => {
                            workRef.current?.scrollIntoView({ behavior: "smooth", block: "start" });
                            requestAnimationFrame(() => dispositionRef.current?.focus({ preventScroll: true }));
                        }}
                    >
                        {t("closeAsEllipsis")}
                    </button>
                    {onInvestigate && (
                        <button className="btn primary" type="button" onClick={() => void onInvestigate()}>
                            {t("m3Investigate")}
                        </button>
                    )}
                </div>
            </header>

            <dl className="fact-strip">
                <div>
                    <dt>{t("m3Priority")}</dt>
                    <dd className="fact-strip-big num">
                        {incident.priority === null ? t("scorePending") : formatScore(incident.priority)}
                    </dd>
                </div>
                <div>
                    <dt>{t("m3Owner")}</dt>
                    <dd className="ent">{incident.owner_key ?? t("m3Unassigned")}</dd>
                </div>
                <div>
                    <dt>{t("incidentScope")}</dt>
                    <dd>
                        {scope
                            ? t("incidentScopeValue")
                                  .replace("{hosts}", String(scope.hosts))
                                  .replace("{users}", String(scope.users))
                                  .replace("{ips}", String(scope.ips))
                            : t("notReportedShort")}
                    </dd>
                </div>
                <div>
                    <dt>{t("acknowledgeSla")}</dt>
                    <dd>
                        <SlaText sla={slas ? slaFrom(slas.acknowledge) : undefined} notReported={t("notReportedShort")} />
                    </dd>
                </div>
                <div>
                    <dt>{t("resolveSla")}</dt>
                    <dd>
                        <SlaText sla={slas ? slaFrom(slas.resolve) : undefined} notReported={t("notReportedShort")} />
                    </dd>
                </div>
            </dl>

            <details className="m3-pp-record m3-incident-record">
                <summary className="t-secondary">{t("m3RecordDetails")}</summary>
                <dl className="m3-meta">
                    <dt>{t("m3IncidentId")}</dt>
                    <dd>
                        <IdChip kind="incident" value={incident.incident_id} />
                    </dd>
                    <dt>{t("m3WorkVersion")}</dt>
                    <dd>{incident.work_version}</dd>
                    <dt>{t("m3EvidenceRevision")}</dt>
                    <dd>
                        <IdChip kind="revision" value={incident.evidence_head} />
                    </dd>
                </dl>
            </details>

            <div className="tab-bar m3-pp-section-tabs">
                <ViewTabs<IncidentTab>
                    label={t("incidentSections")}
                    value={activeTab}
                    onChange={jump}
                    tabs={[
                        { id: "summary", label: t("incidentTabSummary") },
                        { id: "graph", label: t("incidentTabGraph") },
                        { id: "evidence", label: t("incidentTabEvidence"), count: data.members.length },
                        { id: "activity", label: t("incidentTabActivity"), count: events.length + data.history.length },
                        { id: "notes", label: t("incidentTabNotes"), count: data.comments.length },
                    ]}
                />
            </div>

            <section
                className="pp-panel pp-panel-pad m3-pp-chain-panel"
                aria-labelledby="incident-chain-heading"
                ref={(node) => {
                    sectionRefs.current.summary = node;
                }}
            >
                <div className="m3-pp-section-head">
                    <h2 id="incident-chain-heading" className="t-section">
                        {t("attackChain")}
                    </h2>
                    {linkedChain && (
                        <>
                            <span className="t-secondary">
                                {patternName(linkedChain.rule_id)}, v{linkedChain.rule_version}
                            </span>
                            <button type="button" className="pp-link m3-pp-head-link" onClick={() => onOpenChain(linkedChain.chain_id)}>
                                {t("openChainCandidate")}
                            </button>
                        </>
                    )}
                </div>
                {linkedChain ? (
                    <ol className="stepper">
                        {chainStages(linkedChain.stages).map((stage) => {
                            const matched = stage.outcome === "matched";
                            return (
                                <li key={stage.ordinal} data-outcome={matched ? "matched" : "missing"}>
                                    <span className="stepper-bar" aria-hidden="true" />
                                    <span className="stepper-label">
                                        <span className="stepper-n num">{stage.ordinal}</span>
                                        <span className="cell-main">{stageName(stage.stageId)}</span>
                                    </span>
                                    <span className="t-secondary">
                                        {matched
                                            ? stage.groupId && groupTitles.get(stage.groupId)
                                                ? `${t("stageMatched")}: ${groupTitles.get(stage.groupId)}`
                                                : t("stageMatched")
                                            : t("stageNotSeen")}
                                    </span>
                                </li>
                            );
                        })}
                    </ol>
                ) : (
                    <p className="muted">{t("noChainForIncident")}</p>
                )}
            </section>

            <section
                className="pp-panel pp-panel-pad m3-pp-graph-panel"
                aria-labelledby="incident-graph-heading"
                ref={(node) => {
                    sectionRefs.current.graph = node;
                }}
            >
                <div className="m3-pp-section-head">
                    <h2 id="incident-graph-heading" className="t-section">
                        {t("incidentTabGraph")}
                    </h2>
                    <span className="t-secondary">{t("entityGraphNote")}</span>
                </div>
                {graph && graph.edges.length > 0 ? (
                    <EntityGraph
                        graph={graph}
                        active={entityFilter}
                        t={t}
                        onSelect={(label) => setEntityFilter((current) => (current === label ? null : label))}
                    />
                ) : (
                    <ChainGraphUnavailable locale={locale} />
                )}
            </section>

            <div className="pp-grid m3-pp-activity-row">
                <section
                    className="pp-panel pp-panel-pad m3-pp-timeline"
                    aria-labelledby="incident-timeline-heading"
                    ref={(node) => {
                        sectionRefs.current.activity = node;
                    }}
                >
                    <div className="m3-pp-section-head">
                        <h2 id="incident-timeline-heading" className="t-section">
                            {t("timelineHeading")}
                        </h2>
                        <span className="t-secondary">UTC</span>
                    </div>
                    {entityFilter && (
                        <p className="m3-pp-filter-note">
                            {t("filteredBy")} <span className="ent">{entityFilter}</span>
                            <button type="button" className="pp-link" onClick={() => setEntityFilter(null)}>
                                {t("clear")}
                            </button>
                        </p>
                    )}
                    {eventsLoading && <p role="status">{t("loading")}</p>}
                    {eventsError && <p role="alert">{eventsError}</p>}
                    <div role="region" aria-label={t("m3Timeline")}>
                        {!eventsLoading && !eventsError && timeline.length === 0 && (
                            <p className="muted">{t("m3NoEvents")}</p>
                        )}
                        <ol className="pp-timeline m3-timeline">
                            {timeline.map((item) => (
                                <li key={item.id} data-kind={item.kind}>
                                    <time dateTime={item.at} title={fmtDate(item.at, locale)}>
                                        {fmtTime(item.at, locale)}
                                    </time>
                                    <span className="pp-timeline-rail" aria-hidden="true">
                                        <span />
                                    </span>
                                    <div className="pp-timeline-body">
                                        <span className="cell-main">{item.title}</span>
                                        {Array.isArray(item.detail) ? (
                                            item.detail.length > 0 && (
                                                <span className="t-secondary pp-timeline-facts">
                                                    {item.detail.map((bit) => (
                                                        <span key={bit}>{bit}</span>
                                                    ))}
                                                </span>
                                            )
                                        ) : (
                                            item.detail && <span className="t-secondary">{item.detail}</span>
                                        )}
                                        {item.event && (
                                            <details className="disclosure m3-event">
                                                <summary className="t-secondary">{t("m3HistoryDetails")}</summary>
                                                <dl className="m3-meta">
                                                    <dt>{t("m3Alert")}</dt>
                                                    <dd>
                                                        <IdChip kind="alert" value={item.event.alert_key} />
                                                    </dd>
                                                    <dt>{t("group")}</dt>
                                                    <dd>{groupTitles.get(item.event.group_id) ?? <IdChip kind="group" value={item.event.group_id} />}</dd>
                                                    <dt>{t("m3MemberRevision")}</dt>
                                                    <dd>
                                                        <IdChip kind="revision" value={item.event.group_revision} />
                                                    </dd>
                                                </dl>
                                            </details>
                                        )}
                                    </div>
                                </li>
                            ))}
                        </ol>
                    </div>
                    {eventsNext && (
                        <button className="btn compact" onClick={onMoreEvents}>
                            {t("nextPage")}
                        </button>
                    )}
                    <form
                        className="m3-pp-note-form"
                        ref={(node) => {
                            sectionRefs.current.notes = node;
                        }}
                        onSubmit={(event) => {
                            event.preventDefault();
                            if (!comment.trim()) return;
                            onAction({ kind: "comment", body: { ...work, body: comment.trim() } });
                            setComment("");
                        }}
                    >
                        <label className="pp-field">
                            {t("m3Comment")}
                            <textarea
                                ref={noteRef}
                                rows={2}
                                value={comment}
                                placeholder={t("notePlaceholder")}
                                onChange={(event) => setComment(event.target.value)}
                                maxLength={4000}
                            />
                        </label>
                        <button className="btn compact" type="submit">
                            {t("m3AddComment")}
                        </button>
                    </form>
                </section>
                <NarrativePanel
                    key={`${siteId}:${incident.incident_id}:${incident.evidence_head}`}
                    siteId={siteId}
                    incidentId={incident.incident_id}
                    evidenceRevision={incident.evidence_head}
                    locale={locale}
                    t={t}
                    groupTitles={groupTitles}
                    onOpenGroup={() => jump("evidence")}
                />
            </div>
            <section
                className="pp-panel m3-pp-evidence"
                aria-labelledby="incident-members-heading"
                ref={(node) => {
                    sectionRefs.current.evidence = node;
                }}
            >
                <div className="pp-panel-head">
                    <div>
                        <h2 id="incident-members-heading" className="t-section">
                            {t("evidenceGroups")}
                        </h2>
                    </div>
                    <a href="#queue">{t("addGroupsFromQueue")}</a>
                </div>
                {data.members.length ? (
                    <div className="pp-table-scroll">
                        <table className="pp-table m3-pp-members-table">
                            <thead>
                                <tr>
                                    <th scope="col">{t("group")}</th>
                                    <th scope="col" className="is-num">
                                        {t("m3Alerts")}
                                    </th>
                                    <th scope="col" className="is-num">
                                        {t("storedScore")}
                                    </th>
                                    <th scope="col">{t("eventTime")}</th>
                                    <th scope="col">{t("addedBy")}</th>
                                    <th scope="col">{t("snapshot")}</th>
                                </tr>
                            </thead>
                            <tbody>
                                {data.members.map((member) => {
                                    const added = data.membership_intervals.find(
                                        (interval) => interval.group_id === member.group_id && !interval.removed_at,
                                    );
                                    return (
                                        <tr key={member.group_id}>
                                            <td>
                                                <span className="cell-main" title={member.title}>
                                                    {member.title}
                                                </span>
                                                <span className="cell-sub">
                                                    <IdChip kind="group" value={member.group_id} />
                                                </span>
                                            </td>
                                            <td className="is-num">{member.alert_count}</td>
                                            <td className="is-num">
                                                {member.score === null ? "\u2014" : formatScore(member.score)}
                                            </td>
                                            <td className="num">{fmtRange(member.first_ts, member.last_ts)}</td>
                                            <td className="t-secondary">
                                                {added
                                                    ? `${fmtTime(added.added_at, locale)} ${t("incidentBy")} ${added.added_by}`
                                                    : "\u2014"}
                                            </td>
                                            <td>
                                                <IdChip kind="revision" value={member.group_revision} />
                                            </td>
                                        </tr>
                                    );
                                })}
                            </tbody>
                        </table>
                    </div>
                ) : (
                    <p className="muted m3-pp-empty">{t("m3NoMembers")}</p>
                )}
                <div className="m3-pp-evidence-foot">
                <h3>{t("m3MembershipHistory")}</h3>
                {data.membership_intervals.length ? (
                    <EvidenceRows values={data.membership_intervals} locale={locale} />
                ) : (
                    <p className="muted">{t("m3NoMembershipHistory")}</p>
                )}
                {data.next_cursors.membership && (
                    <button
                        className="btn outline"
                        onClick={() =>
                            onMoreDetail("membership", data.next_cursors.membership ?? "")
                        }
                    >
                        {t("nextPage")}
                    </button>
                )}
                <details className="disclosure m3-membership-edit">
                    <summary>{t("m3EditMembership")}</summary>
                    <form
                        className="m3-inline-form"
                        onSubmit={(event) => {
                            event.preventDefault();
                            const add = groupIds(addGroups);
                            const remove = groupIds(removeGroups);
                            if (!add.length && !remove.length) return;
                            if (
                                add.length > 100 ||
                                remove.length > 100 ||
                                [...add, ...remove].some((id) => !isGroupId(id))
                            ) {
                                setMembershipError(t("m3InvalidGroups"));
                                return;
                            }
                            setMembershipError("");
                            onAction({
                                kind: "members",
                                body: { ...work, add_group_ids: add, remove_group_ids: remove },
                            });
                            setAddGroups("");
                            setRemoveGroups("");
                        }}
                    >
                        {membershipError && <p role="alert">{membershipError}</p>}
                        <label>
                            {t("m3AddGroups")}
                            <textarea
                                className="id-input"
                                value={addGroups}
                                onChange={(event) => setAddGroups(event.target.value)}
                                placeholder={t("m3GroupIdsHint")}
                            />
                        </label>
                        <label>
                            {t("m3RemoveGroups")}
                            <textarea
                                className="id-input"
                                value={removeGroups}
                                onChange={(event) => setRemoveGroups(event.target.value)}
                                placeholder={t("m3GroupIdsHint")}
                            />
                        </label>
                        <button className="btn outline" type="submit">
                            {t("m3UpdateMembership")}
                        </button>
                    </form>
                </details>
                </div>
            </section>
            <div className="m3-two-column pp-panel m3-pp-work" ref={workRef}>
                <section aria-labelledby="incident-work-heading">
                    <h3 id="incident-work-heading">{t("m3Work")}</h3>
                    <form
                        className="m3-inline-form"
                        onSubmit={(event) => {
                            event.preventDefault();
                            onAction({
                                kind: "assign",
                                body: { ...work, owner_key: owner.trim() || null },
                            });
                        }}
                    >
                        <label>
                            {t("m3Owner")}
                            <input
                                className="id-input"
                                maxLength={256}
                                value={owner}
                                onChange={(event) => setOwner(event.target.value)}
                            />
                        </label>
                        <button className="btn outline" type="submit">
                            {t("m3SaveOwner")}
                        </button>
                    </form>
                    <form
                        className="m3-inline-form"
                        onSubmit={(event) => {
                            event.preventDefault();
                            onAction({ kind: "status", body: { ...work, status } });
                        }}
                    >
                        <label>
                            {t("m3Status")}
                            <select
                                value={status}
                                onChange={(event) => {
                                    const nextStatus = parseIncidentStatus(event.target.value);
                                    if (nextStatus) setStatus(nextStatus);
                                }}
                            >
                                <option value="new">{t(incidentStatusLabels.new)}</option>
                                <option value="in_progress">{t(incidentStatusLabels.in_progress)}</option>
                                <option value="resolved">{t(incidentStatusLabels.resolved)}</option>
                                <option value="closed">{t(incidentStatusLabels.closed)}</option>
                            </select>
                        </label>
                        <button className="btn outline" type="submit">
                            {t("m3SaveStatus")}
                        </button>
                    </form>
                    <h4>{t("m3History")}</h4>
                    {data.history.length ? (
                        <ol className="m3-history m3-work-history">
                            {data.history.map((item) => (
                                <li key={item.history_id}>
                                    <strong>{item.action}</strong>
                                    <span>
                                        <code>{item.actor_key}</code> · {fmtDate(item.at, locale)} ·
                                        v{item.work_version}
                                    </span>
                                    <details className="disclosure">
                                        <summary>{t("m3HistoryDetails")}</summary>
                                        <EvidenceRows
                                            values={[item.before, item.after]}
                                            locale={locale}
                                        />
                                    </details>
                                </li>
                            ))}
                        </ol>
                    ) : (
                        <p className="muted">{t("m3NoHistory")}</p>
                    )}
                    {data.next_cursors.history && (
                        <button
                            className="btn outline"
                            onClick={() => onMoreDetail("history", data.next_cursors.history ?? "")}
                        >
                            {t("nextPage")}
                        </button>
                    )}
                </section>
                <section aria-labelledby="incident-disposition-heading">
                    <h3 id="incident-disposition-heading">{t("m3Disposition")}</h3>
                    <form
                        className="m3-inline-form"
                        onSubmit={(event) => {
                            event.preventDefault();
                            onAction({
                                kind: "disposition",
                                body: {
                                    ...work,
                                    expected_evidence_revision: incident.evidence_head,
                                    label: disposition,
                                    reason_code:
                                        disposition === "false_positive"
                                            ? reasonCode || null
                                            : null,
                                    note: note.trim() || null,
                                    propagate_to_members: false,
                                },
                            });
                        }}
                    >
                        <label>
                            {t("m3DispositionLabel")}
                            <select
                                ref={dispositionRef}
                                value={disposition}
                                onChange={(event) => {
                                    const nextLabel = parseDispositionLabel(event.target.value);
                                    if (nextLabel) setDisposition(nextLabel);
                                }}
                            >
                                <option value="true_positive">{t("truePositive")}</option>
                                <option value="benign_true_positive">
                                    {t("benignTruePositive")}
                                </option>
                                <option value="false_positive">{t("falsePositive")}</option>
                                <option value="duplicate">{t("m3Duplicate")}</option>
                                <option value="undetermined">{t("m3Undetermined")}</option>
                            </select>
                        </label>
                        <p className="muted m3-field-hint">{t("m3IncidentDispositionScope")}</p>
                        {disposition === "false_positive" && (
                            <label>
                                {t("m3FpReason")}
                                <select
                                    required
                                    value={reasonCode}
                                    onChange={(event) => setReasonCode(event.target.value)}
                                >
                                    <option value="">—</option>
                                    {[
                                        "expected_admin_activity",
                                        "known_scanner",
                                        "misconfigured_rule",
                                        "test_activity",
                                        "other",
                                    ].map((reason) => (
                                        <option key={reason} value={reason}>
                                            {t(`m3Reason_${reason}`)}
                                        </option>
                                    ))}
                                </select>
                            </label>
                        )}
                        <label>
                            {t("m3DispositionNote")}
                            <textarea
                                value={note}
                                required={
                                    disposition === "false_positive" && reasonCode === "other"
                                }
                                onChange={(event) => setNote(event.target.value)}
                                maxLength={2000}
                            />
                        </label>
                        <button className="btn primary" type="submit">
                            {t("m3SaveDisposition")}
                        </button>
                    </form>
                    <h4>{t("m3DispositionHistory")}</h4>
                    {data.dispositions.length ? (
                        <ol className="m3-history">
                            {data.dispositions.map((item) => (
                                <li key={item.disposition_id}>
                                    <strong>{t(`m3Disposition_${item.label}`)}</strong>
                                    <span>
                                        <code>{item.actor_key}</code> · {fmtDate(item.at, locale)} ·
                                        v{item.work_version}
                                    </span>
                                    {item.reason_code && (
                                        <p>
                                            {t("m3FpReason")}:{" "}
                                            {falsePositiveReasonText(t, item.reason_code)}
                                        </p>
                                    )}
                                    {item.note && <p>{item.note}</p>}
                                </li>
                            ))}
                        </ol>
                    ) : (
                        <p className="muted">{t("m3NoDispositions")}</p>
                    )}
                    {data.next_cursors.dispositions && (
                        <button
                            className="btn outline"
                            onClick={() =>
                                onMoreDetail("dispositions", data.next_cursors.dispositions ?? "")
                            }
                        >
                            {t("nextPage")}
                        </button>
                    )}
                </section>
            </div>
        </>
    );
}

function ChainGraphUnavailable({ locale }: { locale: Locale }) {
    const copy =
        locale === "es"
            ? {
                  title: "Grafo de entidades no disponible",
                  description:
                      "No hay relaciones entre entidades disponibles para este candidato. Las etapas y la evidencia aparecen a continuación.",
              }
            : {
                  title: "Entity graph unavailable",
                  description:
                      "No entity relationships are available for this candidate. Its stages and evidence are below.",
              };
    return (
        <section className="m3-graph-empty" aria-labelledby="chain-graph-heading">
            <div className="m3-graph-grid" aria-hidden="true" />
            <div className="m3-graph-empty-copy">
                <h3 id="chain-graph-heading">{copy.title}</h3>
                <p>{copy.description}</p>
            </div>
        </section>
    );
}

function CreateIncidentForm({
    siteId,
    t,
    onCreate,
}: {
    siteId: string;
    t: Translate;
    onCreate: (body: components["schemas"]["IncidentCreateRequest"]) => void;
}) {
    const [groupIdsText, setGroupIdsText] = useState("");
    const [title, setTitle] = useState("");
    const [owner, setOwner] = useState("");
    const [formError, setFormError] = useState("");
    return (
        <form
            className="m3-create"
            onSubmit={(event) => {
                event.preventDefault();
                const groupIds = [...new Set(groupIdsText.split(/[\n,\s]+/).filter(Boolean))];
                if (
                    !groupIds.length ||
                    groupIds.length > 100 ||
                    groupIds.some((id) => !/^[0-9a-f]{64}$/.test(id))
                ) {
                    setFormError(t("m3InvalidGroups"));
                    return;
                }
                setFormError("");
                onCreate({
                    site_id: siteId,
                    group_ids: groupIds,
                    title: title.trim() || null,
                    owner_key: owner.trim() || null,
                });
            }}
        >
            {formError && <p role="alert">{formError}</p>}
            <label>
                {t("m3GroupIds")}
                <textarea
                    className="id-input"
                    required
                    value={groupIdsText}
                    onChange={(event) => setGroupIdsText(event.target.value)}
                    placeholder={t("m3GroupIdsHint")}
                />
            </label>
            <label>
                {t("m3IncidentTitle")}
                <input
                    maxLength={240}
                    value={title}
                    onChange={(event) => setTitle(event.target.value)}
                />
            </label>
            <label>
                {t("m3Owner")}
                <input
                    className="id-input"
                    maxLength={256}
                    value={owner}
                    onChange={(event) => setOwner(event.target.value)}
                />
            </label>
            <button className="btn outline" type="submit">
                {t("m3Create")}
            </button>
        </form>
    );
}

/** `compact` shortens every long identifier, for narrow side cards. */
function EvidenceRows({
    values,
    locale,
    compact = false,
}: {
    values: unknown[];
    locale: Locale;
    compact?: boolean;
}) {
    return (
        <ul className="m3-evidence">
            {values.map((value, index) => (
                <li key={index}>
                    {isFlatRecord(value) ? (
                        <FlatEvidence value={value} locale={locale} compact={compact} />
                    ) : (
                        <pre>{printable(value)}</pre>
                    )}
                </li>
            ))}
        </ul>
    );
}

const ISO_TIMESTAMP = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}/;

/** One rendering per kind: muted dash for null, sans for numbers, prose and times, mono for ids. */
function FieldValue({
    value,
    locale,
    compact,
}: {
    value: string | number | boolean | null;
    locale: Locale;
    compact?: boolean;
}) {
    if (value === null) return <span className="null-value">{"\u2014"}</span>;
    if (typeof value !== "string") return <span className="field-number">{String(value)}</span>;
    if (ISO_TIMESTAMP.test(value)) return <span>{fmtDate(value)}</span>;
    if (/\s/.test(value)) return <span>{value}</span>;
    return <IdValue value={value} locale={locale} compact={compact} />;
}

/** Stage records lead with ordinal, stage and outcome; other fields follow as rows. */
type FlatField = string | number | boolean | null | Array<string | number | boolean | null>;

function FlatEvidence({
    value,
    locale,
    compact,
}: {
    value: Record<string, FlatField>;
    locale: Locale;
    compact?: boolean;
}) {
    const { ordinal, stage_id: stage, outcome, ...rest } = value;
    const staged = stage !== undefined && stage !== null;
    const restEntries = Object.entries(rest);
    const inline =
        staged && restEntries.length === 1 && !Array.isArray(restEntries[0][1])
            ? restEntries[0]
            : undefined;
    const fields = inline ? [] : Object.entries(staged ? rest : value);
    return (
        <>
            {staged && (
                <div className={inline ? "m3-stage-head m3-stage-row" : "m3-stage-head"}>
                    <span className="m3-stage-lead">
                        {ordinal !== undefined && ordinal !== null && (
                            <span className="m3-stage-ordinal">{String(ordinal)}</span>
                        )}
                        <code>{String(stage)}</code>
                        {outcome !== undefined && outcome !== null && (
                            <Tag
                                className="m3-stage-outcome"
                                tone={
                                    outcome === "matched"
                                        ? "green"
                                        : outcome === "missing"
                                          ? "amber"
                                          : "neutral"
                                }
                            >
                                {String(outcome)}
                            </Tag>
                        )}
                    </span>
                    {inline && (
                        <span className="m3-stage-field">
                            <span className="sr-only">{humanizeKey(inline[0])}</span>
                            <FieldValue
                                value={inline[1] as Exclude<FlatField, unknown[]>}
                                locale={locale}
                                compact={compact}
                            />
                        </span>
                    )}
                </div>
            )}
            {fields.length > 0 && (
                <dl className="m3-evidence-fields">
                    {fields.map(([key, field]) => (
                        <div key={key}>
                            <dt>{humanizeKey(key)}</dt>
                            <dd>
                                {Array.isArray(field) ? (
                                    field.map((item, index) => (
                                        <div key={index}>
                                            <FieldValue
                                                value={item}
                                                locale={locale}
                                                compact={compact}
                                            />
                                        </div>
                                    ))
                                ) : (
                                    <FieldValue value={field} locale={locale} compact={compact} />
                                )}
                            </dd>
                        </div>
                    ))}
                </dl>
            )}
        </>
    );
}

function LoadError({ message, retry, t }: { message: string; retry: () => void; t: Translate }) {
    return (
        <div className="alert error" role="alert">
            {message}{" "}
            <button className="btn outline" onClick={retry}>
                {t("retry")}
            </button>
        </div>
    );
}

function failureMessage(error: unknown, t: Translate): string {
    if (error instanceof WorkspaceRequestError) {
        if (error.status === 403) return t("denied");
        if (error.status === 503 || error.status === 0) return t("m3Unavailable");
        return error.message;
    }
    return error instanceof Error ? error.message : t("m3Unavailable");
}

function field(value: unknown, key: string): unknown {
    if (typeof value !== "object" || value === null || Array.isArray(value)) return undefined;
    return Reflect.get(value, key);
}

function incidentCursorKey(
    cursors: Partial<Record<"history" | "comments" | "dispositions" | "membership", string>>,
): string {
    return [cursors.history, cursors.comments, cursors.dispositions, cursors.membership].join("|");
}

function isGroupId(value: string): boolean {
    return /^[0-9a-f]{64}$/.test(value);
}

function parseIncidentStatus(value: string): IncidentStatus | undefined {
    switch (value) {
        case "new":
        case "in_progress":
        case "resolved":
        case "closed":
            return value;
        default:
            return undefined;
    }
}

function parseDispositionLabel(value: string): DispositionLabel | undefined {
    switch (value) {
        case "true_positive":
        case "benign_true_positive":
        case "false_positive":
        case "duplicate":
        case "undetermined":
            return value;
        default:
            return undefined;
    }
}

function incidentEventLabel(
    event: components["schemas"]["IncidentEventDTO"],
    t: Translate,
): string {
    const description = event.fields.rule_description;
    if (typeof description === "string" && description.trim()) return description;

    const stage = event.stages.find(({ stage_id }) => typeof stage_id === "string")?.stage_id;
    return typeof stage === "string" ? humanizeKey(stage) : t("m3Alert");
}

function StateTag({ value, label = value }: { value: string; label?: string }) {
    const tone = Object.hasOwn(statusTags, value)
        ? statusTags[value as WorkStatus]
        : value === "open"
          ? { tone: "blue" as const, dot: false }
          : { tone: "neutral" as const, dot: false };
    return <Tag {...tone}>{label}</Tag>;
}

function printable(value: unknown): string {
    if (typeof value === "string") return value;
    try {
        return JSON.stringify(value, null, 2) ?? "";
    } catch {
        return String(value);
    }
}

function formatScore(score: number | null): string {
    return score === null ? "—" : score.toString();
}

// Same browser-locale format as Alerts and Queue; incident evidence stays in UTC.
export function fmtDate(value: string, _locale?: Locale): string {
    const date = new Date(value);
    return Number.isNaN(date.getTime())
        ? value
        : new Intl.DateTimeFormat(undefined, {
              dateStyle: "medium",
              timeStyle: "short",
              timeZone: "UTC",
          }).format(date);
}

/** A first/last pair; a same-day range shows the date once and only the end time. */
export function fmtRange(first: string, last: string): string {
    const start = new Date(first);
    const end = new Date(last);
    if (Number.isNaN(start.getTime()) || Number.isNaN(end.getTime()))
        return `${fmtDate(first)} – ${fmtDate(last)}`;
    if (start.toISOString().slice(0, 10) !== end.toISOString().slice(0, 10))
        return `${fmtDate(first)} – ${fmtDate(last)}`;
    const clock = new Intl.DateTimeFormat(undefined, { timeStyle: "short", timeZone: "UTC" });
    return `${fmtDate(first)} – ${clock.format(end)}`;
}

function fmtTime(value: string, _locale?: Locale): string {
    const date = new Date(value);
    return Number.isNaN(date.getTime())
        ? value
        : new Intl.DateTimeFormat(undefined, {
              timeStyle: "short",
              timeZone: "UTC",
          }).format(date);
}

type IncidentTab = "summary" | "graph" | "evidence" | "activity" | "notes";
type EdgeView = { reason: string; confidence: number | null };
type PinView = { groupId: string; score: number | null; version: string };

function chainEdges(values: ReadonlyArray<Record<string, unknown>>): EdgeView[] {
    return values.map((edge) => ({
        reason:
            typeof edge.reason === "string"
                ? edge.reason
                : typeof edge.type === "string"
                  ? humanizeKey(edge.type)
                  : "",
        confidence: typeof edge.confidence === "number" ? edge.confidence : null,
    }));
}

function scorePins(values: ReadonlyArray<Record<string, unknown>>): PinView[] {
    return values
        .filter((pin) => typeof pin.group_id === "string")
        .map((pin) => ({
            groupId: pin.group_id as string,
            score: typeof pin.score === "number" ? pin.score : null,
            version: typeof pin.score_version === "string" ? pin.score_version : "",
        }));
}

type IncidentEvent = components["schemas"]["IncidentEventDTO"];

function eventField(event: IncidentEvent, key: string): string | null {
    const value = event.fields[key];
    return typeof value === "string" && value.trim() ? value : null;
}

function deriveScope(events: IncidentEvent[]): { hosts: number; users: number; ips: number } | null {
    if (!events.length) return null;
    const hosts = new Set<string>();
    const users = new Set<string>();
    const ips = new Set<string>();
    for (const event of events) {
        const host = eventField(event, "agent_name") ?? eventField(event, "agent_id");
        const user = eventField(event, "dst_user");
        const ip = eventField(event, "src_ip");
        if (host) hosts.add(host);
        if (user) users.add(user);
        if (ip) ips.add(ip);
    }
    return { hosts: hosts.size, users: users.size, ips: ips.size };
}

type GraphView = {
    nodes: { id: string; kind: "ip" | "host" | "user" | "expected"; label: string; detail: string }[];
    edges: { from: string; to: string; label: string; state: "seen" | "expected" }[];
};

/** Entity edges from the frozen events when the backend does not report them: source IP to user and host. */
function deriveGraph(events: IncidentEvent[], t: Translate): GraphView | null {
    const nodes = new Map<string, GraphView["nodes"][number]>();
    const counts = new Map<string, number>();
    for (const event of events) {
        const ip = eventField(event, "src_ip");
        const user = eventField(event, "dst_user");
        const host = eventField(event, "agent_name");
        if (ip) nodes.set(`ip:${ip}`, { id: `ip:${ip}`, kind: "ip", label: ip, detail: t("sourceIp") });
        if (user) nodes.set(`user:${user}`, { id: `user:${user}`, kind: "user", label: user, detail: t("user") });
        if (host) nodes.set(`host:${host}`, { id: `host:${host}`, kind: "host", label: host, detail: t("host") });
        if (ip && user) counts.set(`ip:${ip}>user:${user}`, (counts.get(`ip:${ip}>user:${user}`) ?? 0) + 1);
        if (ip && host) counts.set(`ip:${ip}>host:${host}`, (counts.get(`ip:${ip}>host:${host}`) ?? 0) + 1);
    }
    if (!counts.size) return null;
    return {
        nodes: [...nodes.values()],
        edges: [...counts.entries()].map(([key, count]) => {
            const [from, to] = key.split(">") as [string, string];
            return {
                from,
                to,
                label: `${count} ${t(count === 1 ? "alertSingular" : "alerts").toLocaleLowerCase()}`,
                state: "seen" as const,
            };
        }),
    };
}

const GRAPH_COLUMN = { ip: 0, host: 1, user: 1, expected: 2 } as const;

function EntityGraph({
    graph,
    active,
    t,
    onSelect,
}: {
    graph: GraphView;
    active: string | null;
    t: Translate;
    onSelect: (label: string) => void;
}) {
    const columns = [0, 1, 2].map((column) =>
        graph.nodes.filter((node) => GRAPH_COLUMN[node.kind] === column),
    );
    const position = new Map<string, { x: number; y: number }>();
    columns.forEach((nodes, column) => {
        nodes.forEach((node, index) => {
            const x = [14, 50, 86][column] ?? 50;
            const y = ((index + 1) / (nodes.length + 1)) * 100;
            position.set(node.id, { x, y });
        });
    });
    const summary = graph.edges
        .map((edge) => {
            const from = graph.nodes.find((node) => node.id === edge.from)?.label ?? edge.from;
            const to = graph.nodes.find((node) => node.id === edge.to)?.label ?? edge.to;
            return `${from} to ${to}, ${edge.label}`;
        })
        .join("; ");
    return (
        <>
            <div className="entity-graph-scroll">
                <div className="entity-graph" role="group" aria-label={`${t("incidentTabGraph")}: ${summary}`}>
                    <svg className="entity-graph-edges" viewBox="0 0 100 100" preserveAspectRatio="none" aria-hidden="true">
                        {graph.edges.map((edge) => {
                            const from = position.get(edge.from);
                            const to = position.get(edge.to);
                            if (!from || !to) return null;
                            return (
                                <line
                                    key={`${edge.from}-${edge.to}`}
                                    x1={from.x}
                                    y1={from.y}
                                    x2={to.x}
                                    y2={to.y}
                                    data-state={edge.state}
                                    vectorEffect="non-scaling-stroke"
                                />
                            );
                        })}
                    </svg>
                    {graph.edges.map((edge) => {
                        const from = position.get(edge.from);
                        const to = position.get(edge.to);
                        if (!from || !to) return null;
                        return (
                            <span
                                key={`label-${edge.from}-${edge.to}`}
                                className="entity-graph-label"
                                data-state={edge.state}
                                style={{ left: `${(from.x + to.x) / 2}%`, top: `${(from.y + to.y) / 2}%` }}
                            >
                                {edge.label}
                            </span>
                        );
                    })}
                    {graph.nodes.map((node) => {
                        const at = position.get(node.id);
                        if (!at) return null;
                        return (
                            <button
                                key={node.id}
                                type="button"
                                className="entity-node"
                                data-kind={node.kind}
                                aria-pressed={active === node.label}
                                style={{ left: `${at.x}%`, top: `${at.y}%` }}
                                onClick={() => node.kind !== "expected" && onSelect(node.label)}
                                disabled={node.kind === "expected"}
                            >
                                <EntityIcon kind={node.kind} />
                                <span>
                                    <span className="entity-node-label">{node.label}</span>
                                    <span className="entity-node-detail">{node.detail}</span>
                                </span>
                            </button>
                        );
                    })}
                </div>
            </div>
            <div className="entity-graph-legend">
                <span>
                    <span className="legend-line" data-state="seen" />
                    {t("edgeSeen")}
                </span>
                <span>
                    <span className="legend-line" data-state="expected" />
                    {t("edgeExpected")}
                </span>
                <span>{t("graphClickHint")}</span>
            </div>
        </>
    );
}

function EntityIcon({ kind }: { kind: GraphView["nodes"][number]["kind"] }) {
    const Icon = kind === "ip" ? Globe : kind === "host" ? Server : kind === "user" ? User : CircleDashed;
    return <Icon size={18} aria-hidden="true" />;
}

type TimelineItem = {
    id: string;
    at: string;
    kind: "alert" | "action" | "comment";
    title: string;
    detail: string | string[];
    entities: string[];
    event?: IncidentEvent;
};

function buildTimeline(
    events: IncidentEvent[],
    data: components["schemas"]["IncidentDetailResponse"],
    t: Translate,
): TimelineItem[] {
    const items: TimelineItem[] = [];
    for (const event of events) {
        const ip = eventField(event, "src_ip");
        const user = eventField(event, "dst_user");
        const host = eventField(event, "agent_name") ?? eventField(event, "agent_id");
        const bits = [
            event.rule_id ? `${t("rule")} ${event.rule_id}` : null,
            ip ? `${t("source")} ${ip}` : null,
            user ? `${t("user")} ${user}` : null,
            host ? `${t("host")} ${host}` : null,
        ].filter((bit): bit is string => !!bit);
        items.push({
            id: `event:${event.event_id}`,
            at: event.event_ts,
            kind: "alert",
            title: incidentEventLabel(event, t),
            detail: bits,
            entities: [ip, user, host].filter((value): value is string => !!value),
            event,
        });
    }
    for (const entry of data.history) {
        items.push({
            id: `history:${entry.history_id}`,
            at: entry.at,
            kind: "action",
            title: historyText(entry, t),
            detail: `${entry.actor_key} · v${entry.work_version}`,
            entities: [],
        });
    }
    for (const comment of data.comments) {
        items.push({
            id: `comment:${comment.comment_id}`,
            at: comment.at,
            kind: "comment",
            title: comment.body,
            detail: `${t("noteBy")} ${comment.actor_key}`,
            entities: [],
        });
    }
    return items.sort((left, right) => left.at.localeCompare(right.at));
}

function historyText(entry: components["schemas"]["IncidentDetailResponse"]["history"][number], t: Translate): string {
    const after = entry.after;
    const status = field(after, "status");
    if (entry.action === "status_changed" && typeof status === "string") {
        const key = (incidentStatusLabels as Record<string, string>)[status];
        return `${t("statusChangedTo")} ${key ? t(key) : status}`;
    }
    const owner = field(after, "owner_key");
    if (entry.action.includes("assign")) return `${t("assignedTo")} ${typeof owner === "string" ? owner : t("m3Unassigned")}`;
    return humanizeKey(entry.action);
}
