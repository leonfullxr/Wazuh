import { useEffect, useRef, useState } from "react";
import { useQuery, useQueryClient } from "@tanstack/react-query";
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
import { NarrativePanel } from "./NarrativePanel";
import "./incident-v2.css";

type Locale = "en" | "es";
type Translate = (key: string) => string;
type PageKind = "chains" | "incidents";
type GraphKind = "chain" | "incident";
type Selection = { kind: "chain"; id: string } | { kind: "incident"; id: string } | null;
type IncidentStatus = components["schemas"]["IncidentStatusRequest"]["status"];
type DispositionLabel = components["schemas"]["IncidentDispositionRequest"]["label"];

export function M3WorkspacePage({
    kind,
    siteId,
    locale,
    t,
    onInvestigate,
}: {
    kind: PageKind;
    siteId: string;
    locale: Locale;
    t: Translate;
    onInvestigate: (question: string, environmentId: string) => void;
}) {
    const queryClient = useQueryClient();
    const [selection, setSelection] = useState<Selection>(null);
    const [error, setError] = useState("");
    const [chainCursor, setChainCursor] = useState("");
    const [incidentCursor, setIncidentCursor] = useState("");
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
    const chains = useQuery({
        queryKey: ["m3", "chains", siteId, chainCursor],
        queryFn: ({ signal }) => listChains({ siteId, cursor: chainCursor || undefined }, signal),
        enabled: !!siteId && kind === "chains",
    });
    const incidents = useQuery({
        queryKey: ["m3", "incidents", siteId, incidentCursor],
        queryFn: ({ signal }) =>
            listIncidents({ siteId, cursor: incidentCursor || undefined }, signal),
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

    return (
        <div className="m3-page">
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
                <div className="m3-grid">
                    <section className="panel" aria-labelledby="chain-list-heading">
                        <div className="panel-head">
                            <h3 id="chain-list-heading">{t("m3Candidates")}</h3>
                            <button className="btn outline" onClick={() => void chains.refetch()}>
                                {t("refresh")}
                            </button>
                        </div>
                        {chains.isLoading ? <p role="status">{t("loading")}</p> : null}
                        {chains.isError ? (
                            <LoadError
                                message={failureMessage(chains.error, t)}
                                retry={() => void chains.refetch()}
                                t={t}
                            />
                        ) : null}
                        {!chains.isLoading && !chains.isError && chains.data?.items.length === 0 ? (
                            <p className="muted">{t("m3NoCandidates")}</p>
                        ) : null}
                        <ul className="m3-list">
                            {(!chains.isError ? chains.data?.items : undefined)?.map((item) => (
                                <li key={item.chain_id}>
                                    <button
                                        className="m3-list-item"
                                        aria-current={
                                            selection?.kind === "chain" &&
                                            selection.id === item.chain_id
                                                ? "true"
                                                : undefined
                                        }
                                        onClick={() =>
                                            setSelection({ kind: "chain", id: item.chain_id })
                                        }
                                    >
                                        <strong>{item.rule_id}</strong>
                                        <span>
                                            {item.state} · {t("m3Score")}:{" "}
                                            {item.score_available
                                                ? formatScore(item.score)
                                                : t("m3ScoreUnavailable")}
                                        </span>
                                        <small>
                                            {item.rule_version} · {item.chain_id}
                                        </small>
                                        {item.weak_heuristic && <em>{t("m3WeakEvidence")}</em>}
                                    </button>
                                </li>
                            ))}
                        </ul>
                        {!chains.isError && chains.data?.next_cursor && (
                            <button
                                className="btn outline"
                                onClick={() => setChainCursor(chains.data?.next_cursor ?? "")}
                            >
                                {t("nextPage")}
                            </button>
                        )}
                    </section>
                    <section className="panel m3-detail" aria-labelledby="chain-detail-heading">
                        {selection?.kind !== "chain" ? (
                            <EmptyDetail text={t("m3ChooseCandidate")} />
                        ) : chain.isLoading ? (
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
                </div>
            ) : (
                <div className="m3-grid">
                    <section className="panel" aria-labelledby="incident-list-heading">
                        <div className="panel-head">
                            <h3 id="incident-list-heading">{t("m3Incidents")}</h3>
                            <button
                                className="btn outline"
                                onClick={() => void incidents.refetch()}
                            >
                                {t("refresh")}
                            </button>
                        </div>
                        {incidents.isLoading ? <p role="status">{t("loading")}</p> : null}
                        {incidents.isError ? (
                            <LoadError
                                message={failureMessage(incidents.error, t)}
                                retry={() => void incidents.refetch()}
                                t={t}
                            />
                        ) : null}
                        {!incidents.isLoading &&
                        !incidents.isError &&
                        incidents.data?.items.length === 0 ? (
                            <p className="muted">{t("m3NoIncidents")}</p>
                        ) : null}
                        <ul className="m3-list">
                            {(!incidents.isError ? incidents.data?.items : undefined)?.map(
                                (item) => (
                                    <li key={item.incident_id}>
                                        <button
                                            className="m3-list-item"
                                            onClick={() => {
                                                setSelection({
                                                    kind: "incident",
                                                    id: item.incident_id,
                                                });
                                                setEventCursor("");
                                                setDetailCursors({});
                                            }}
                                            aria-current={
                                                selection?.kind === "incident" &&
                                                selection.id === item.incident_id
                                                    ? "true"
                                                    : undefined
                                            }
                                        >
                                            <strong>{item.title}</strong>
                                            <span>
                                                {item.status} · {t("m3Owner")}:{" "}
                                                {item.owner_key ?? t("m3Unassigned")}
                                            </span>
                                            <small>
                                                {item.incident_id} · v{item.work_version} · r
                                                {item.revision_seq}
                                            </small>
                                        </button>
                                    </li>
                                ),
                            )}
                        </ul>
                        {!incidents.isError && incidents.data?.next_cursor && (
                            <button
                                className="btn outline"
                                onClick={() => setIncidentCursor(incidents.data?.next_cursor ?? "")}
                            >
                                {t("nextPage")}
                            </button>
                        )}
                        <CreateIncidentForm
                            siteId={siteId}
                            t={t}
                            onCreate={(body) =>
                                void runAction(async () => {
                                    const result = await createIncident(body);
                                    await refresh();
                                    if (result.incident_id)
                                        setSelection({ kind: "incident", id: result.incident_id });
                                })
                            }
                        />
                    </section>
                    <section className="panel m3-detail" aria-labelledby="incident-detail-heading">
                        {selection?.kind !== "incident" ? (
                            <EmptyDetail text={t("m3ChooseIncident")} />
                        ) : incident.isLoading ? (
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
                                events={events.isError ? [] : (events.data?.events ?? [])}
                                eventsNext={
                                    events.isError ? null : (events.data?.next_cursor ?? null)
                                }
                                eventsLoading={events.isLoading}
                                eventsError={events.isError ? failureMessage(events.error, t) : ""}
                                siteId={siteId}
                                locale={locale}
                                t={t}
                                onAction={(command) =>
                                    void runAction(() =>
                                        incidentAction(
                                            incident.data!.incident.incident_id,
                                            command,
                                        ),
                                    )
                                }
                                onMoreEvents={() => setEventCursor(events.data?.next_cursor ?? "")}
                                onMoreDetail={(name, cursor) =>
                                    setDetailCursors((previous) => ({
                                        ...previous,
                                        [name]: cursor,
                                    }))
                                }
                                onInvestigate={async () => {
                                    contextAbort.current?.abort();
                                    const controller = new AbortController();
                                    contextAbort.current = controller;
                                    const requestedScope = activeScope.current;
                                    try {
                                        const context = await getIncidentContext(
                                            {
                                                siteId,
                                                incidentId: incident.data!.incident.incident_id,
                                                evidenceRevision:
                                                    incident.data!.incident.evidence_head,
                                            },
                                            controller.signal,
                                        );
                                        if (
                                            controller.signal.aborted ||
                                            activeScope.current !== requestedScope
                                        )
                                            return;
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
                                        if (
                                            controller.signal.aborted ||
                                            activeScope.current !== requestedScope
                                        )
                                            return;
                                        if (
                                            reason instanceof WorkspaceRequestError &&
                                            reason.status === 409
                                        ) {
                                            setError(t("m3Stale"));
                                            await refresh();
                                        } else {
                                            setError(
                                                reason instanceof Error
                                                    ? reason.message
                                                    : t("m3ActionError"),
                                            );
                                        }
                                    }
                                }}
                            />
                        ) : null}
                    </section>
                </div>
            )}
        </div>
    );
}

function ChainDetailView({
    detail,
    locale,
    t,
    onPromote,
    onDismiss,
}: {
    detail: components["schemas"]["ChainCandidateDetail"];
    locale: Locale;
    t: Translate;
    onPromote: (title: string) => void;
    onDismiss: (reason: string) => void;
}) {
    const [title, setTitle] = useState("");
    const [reason, setReason] = useState("");
    const result = detail.result;
    const missing = field(result, "missing_stages");
    const reasons = field(result, "reasons");
    const reasonItems = Array.isArray(reasons) ? reasons : [];
    const orderToleranceApplied = field(result, "order_tolerance_applied") === true;
    const reasonTranslations: Readonly<Record<string, string>> = {
        "Actor continuity is unavailable for one or more selected stages":
            t("m3ReasonActorContinuity"),
        "Order tolerance applied to a syscheck persistence witness": t("m3ReasonOrderTolerance"),
    };
    return (
        <>
            <h3 id="chain-detail-heading">{t("m3CandidateDetail")}</h3>
            <dl className="m3-meta">
                <dt>{t("m3CandidateId")}</dt>
                <dd>{detail.chain_id}</dd>
                <dt>{t("m3Rule")}</dt>
                <dd>
                    {detail.rule_id} · {detail.rule_version}
                </dd>
                <dt>{t("m3CandidateState")}</dt>
                <dd>{detail.state}</dd>
                <dt>{t("m3Score")}</dt>
                <dd>
                    {detail.score_available ? formatScore(detail.score) : t("m3ScoreUnavailable")}
                </dd>
                <dt>{t("m3Manifest")}</dt>
                <dd>
                    <code>{detail.manifest_id}</code>
                </dd>
                <dt>{t("m3Revision")}</dt>
                <dd>
                    <code>{detail.revision_digest}</code>
                </dd>
            </dl>
            {detail.weak_heuristic && <p className="alert warning">{t("m3WeakEvidence")}</p>}
            <GraphUnavailable kind="chain" locale={locale} />
            <section aria-labelledby="chain-stages-heading">
                <h4 id="chain-stages-heading">{t("m3OrderedStages")}</h4>
                {detail.stages.length ? (
                    <EvidenceRows values={detail.stages} />
                ) : (
                    <p className="muted">{t("m3NoStageEvidence")}</p>
                )}
                {Array.isArray(missing) && missing.length > 0 && (
                    <p>
                        {t("m3MissingStages")}: {missing.map((item) => printable(item)).join(", ")}
                    </p>
                )}
                {(reasonItems.length > 0 || orderToleranceApplied) && (
                    <div>
                        <h5>{t("m3Reasons")}</h5>
                        <ul>
                            {reasonItems
                                .filter(
                                    (item) =>
                                        item !==
                                        "Order tolerance applied to a syscheck persistence witness",
                                )
                                .map((item, index) => {
                                    const raw = printable(item);
                                    const translated = Object.hasOwn(reasonTranslations, raw)
                                        ? reasonTranslations[raw]
                                        : undefined;
                                    return <li key={`${index}-${raw}`}>{translated ?? raw}</li>;
                                })}
                            {orderToleranceApplied && <li>{t("m3ReasonOrderTolerance")}</li>}
                        </ul>
                    </div>
                )}
            </section>
            <section aria-labelledby="chain-links-heading">
                <h4 id="chain-links-heading">{t("m3Links")}</h4>
                {detail.edges.length ? (
                    <EvidenceRows values={detail.edges} />
                ) : (
                    <p className="muted">{t("m3NoLinks")}</p>
                )}
                {detail.weak_edges.length > 0 && (
                    <>
                        <h5>{t("m3WeakLinks")}</h5>
                        <EvidenceRows values={detail.weak_edges} />
                    </>
                )}
            </section>
            <section aria-labelledby="chain-pins-heading">
                <h4 id="chain-pins-heading">{t("m3ScorePins")}</h4>
                {detail.score_pins.length ? (
                    <EvidenceRows values={detail.score_pins} />
                ) : (
                    <p className="muted">{t("m3NoScorePins")}</p>
                )}
            </section>
            {detail.state === "open" && (
                <div className="m3-actions">
                    <form
                        onSubmit={(event) => {
                            event.preventDefault();
                            onPromote(title.trim());
                        }}
                    >
                        <label>
                            {t("m3TitleOverride")}
                            <input
                                maxLength={240}
                                value={title}
                                onChange={(event) => setTitle(event.target.value)}
                            />
                        </label>
                        <button className="btn primary" type="submit">
                            {t("m3Promote")}
                        </button>
                    </form>
                    <form
                        onSubmit={(event) => {
                            event.preventDefault();
                            if (reason.trim()) onDismiss(reason.trim());
                        }}
                    >
                        <label>
                            {t("m3DismissReason")}
                            <input
                                required
                                maxLength={512}
                                value={reason}
                                onChange={(event) => setReason(event.target.value)}
                            />
                        </label>
                        <button className="btn outline" type="submit">
                            {t("m3Dismiss")}
                        </button>
                    </form>
                </div>
            )}
        </>
    );
}

function IncidentDetailView({
    data,
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
    onInvestigate: () => Promise<void>;
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
    return (
        <>
            <div className="panel-head">
                <h3 id="incident-detail-heading">{incident.title}</h3>
                <button className="btn outline" onClick={() => void onInvestigate()}>
                    {t("m3Investigate")}
                </button>
            </div>
            <dl className="m3-meta">
                <dt>{t("m3IncidentId")}</dt>
                <dd>{incident.incident_id}</dd>
                <dt>{t("m3Status")}</dt>
                <dd>{incident.status}</dd>
                <dt>{t("m3Owner")}</dt>
                <dd>{incident.owner_key ?? t("m3Unassigned")}</dd>
                <dt>{t("m3WorkVersion")}</dt>
                <dd>{incident.work_version}</dd>
                <dt>{t("m3EvidenceRevision")}</dt>
                <dd>
                    <code>{incident.evidence_head}</code>
                </dd>
            </dl>
            <GraphUnavailable kind="incident" locale={locale} />
            <NarrativePanel
                key={`${siteId}:${incident.incident_id}:${incident.evidence_head}`}
                siteId={siteId}
                incidentId={incident.incident_id}
                evidenceRevision={incident.evidence_head}
                locale={locale}
                t={t}
            />
            <section aria-labelledby="incident-members-heading">
                <h4 id="incident-members-heading">{t("m3Members")}</h4>
                {data.members.length ? (
                    <div className="table-wrap">
                        <table>
                            <thead>
                                <tr>
                                    <th>{t("group")}</th>
                                    <th>{t("m3MemberRevision")}</th>
                                    <th>{t("m3Alerts")}</th>
                                    <th>{t("m3Score")}</th>
                                    <th>{t("eventTime")}</th>
                                </tr>
                            </thead>
                            <tbody>
                                {data.members.map((member) => (
                                    <tr key={member.group_id}>
                                        <td>
                                            <strong>{member.title}</strong>
                                            <small>{member.group_id}</small>
                                        </td>
                                        <td>
                                            <code>{member.group_revision}</code>
                                        </td>
                                        <td>{member.alert_count}</td>
                                        <td>
                                            {member.score === null
                                                ? t("m3ScoreUnavailable")
                                                : formatScore(member.score)}
                                        </td>
                                        <td>
                                            {fmtDate(member.first_ts, locale)} –{" "}
                                            {fmtDate(member.last_ts, locale)}
                                        </td>
                                    </tr>
                                ))}
                            </tbody>
                        </table>
                    </div>
                ) : (
                    <p className="muted">{t("m3NoMembers")}</p>
                )}
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
                            value={addGroups}
                            onChange={(event) => setAddGroups(event.target.value)}
                            placeholder={t("m3GroupIdsHint")}
                        />
                    </label>
                    <label>
                        {t("m3RemoveGroups")}
                        <textarea
                            value={removeGroups}
                            onChange={(event) => setRemoveGroups(event.target.value)}
                            placeholder={t("m3GroupIdsHint")}
                        />
                    </label>
                    <button className="btn outline" type="submit">
                        {t("m3UpdateMembership")}
                    </button>
                </form>
            </section>
            <section aria-labelledby="incident-timeline-heading">
                <h4 id="incident-timeline-heading">{t("m3Timeline")}</h4>
                {eventsLoading && <p role="status">{t("loading")}</p>}
                {eventsError && <p role="alert">{eventsError}</p>}
                {!eventsLoading && !eventsError && !events.length && (
                    <p className="muted">{t("m3NoEvents")}</p>
                )}
                <ol className="m3-timeline">
                    {events.map((event) => (
                        <li key={event.event_id}>
                            <time
                                dateTime={event.event_ts}
                                title={fmtDate(event.event_ts, locale)}
                                aria-label={fmtDate(event.event_ts, locale)}
                            >
                                {fmtTime(event.event_ts, locale)}
                            </time>
                            <span className="m3-timeline-marker" aria-hidden="true" />
                            <div className="m3-timeline-event">
                                <strong>{event.rule_id ?? t("m3Alert")}</strong>
                                <span>
                                    {event.alert_key} · {event.group_id}
                                </span>
                                {event.stages.length > 0 && <EvidenceRows values={event.stages} />}
                            </div>
                        </li>
                    ))}
                </ol>
                {eventsNext && (
                    <button className="btn outline" onClick={onMoreEvents}>
                        {t("nextPage")}
                    </button>
                )}
            </section>
            <div className="m3-two-column">
                <section aria-labelledby="incident-work-heading">
                    <h4 id="incident-work-heading">{t("m3Work")}</h4>
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
                                <option value="new">new</option>
                                <option value="in_progress">in_progress</option>
                                <option value="resolved">resolved</option>
                                <option value="closed">closed</option>
                            </select>
                        </label>
                        <button className="btn outline" type="submit">
                            {t("m3SaveStatus")}
                        </button>
                    </form>
                    <form
                        className="m3-inline-form"
                        onSubmit={(event) => {
                            event.preventDefault();
                            if (!comment.trim()) return;
                            onAction({ kind: "comment", body: { ...work, body: comment.trim() } });
                            setComment("");
                        }}
                    >
                        <label>
                            {t("m3Comment")}
                            <textarea
                                value={comment}
                                onChange={(event) => setComment(event.target.value)}
                                maxLength={4000}
                            />
                        </label>
                        <button className="btn outline" type="submit">
                            {t("m3AddComment")}
                        </button>
                    </form>
                    <h5>{t("m3History")}</h5>
                    {data.history.length ? (
                        <ol className="m3-history">
                            {data.history.map((item) => (
                                <li key={item.history_id}>
                                    <strong>{item.action}</strong>
                                    <span>
                                        {item.actor_key} · {fmtDate(item.at, locale)} · v
                                        {item.work_version}
                                    </span>
                                    <details>
                                        <summary>{t("m3HistoryDetails")}</summary>
                                        <EvidenceRows values={[item.before, item.after]} />
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
                    <h5>{t("m3Comments")}</h5>
                    {data.comments.length ? (
                        <ol className="m3-history">
                            {data.comments.map((item) => (
                                <li key={item.comment_id}>
                                    <p>{item.body}</p>
                                    <span>
                                        {item.actor_key} · {fmtDate(item.at, locale)} · v
                                        {item.work_version}
                                    </span>
                                </li>
                            ))}
                        </ol>
                    ) : (
                        <p className="muted">{t("m3NoComments")}</p>
                    )}
                    {data.next_cursors.comments && (
                        <button
                            className="btn outline"
                            onClick={() =>
                                onMoreDetail("comments", data.next_cursors.comments ?? "")
                            }
                        >
                            {t("nextPage")}
                        </button>
                    )}
                </section>
                <section aria-labelledby="incident-disposition-heading">
                    <h4 id="incident-disposition-heading">{t("m3Disposition")}</h4>
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
                        <p className="muted">{t("m3IncidentDispositionScope")}</p>
                        <button className="btn outline" type="submit">
                            {t("m3SaveDisposition")}
                        </button>
                    </form>
                    {data.dispositions.length ? (
                        <ol className="m3-history">
                            {data.dispositions.map((item) => (
                                <li key={item.disposition_id}>
                                    <strong>{t(`m3Disposition_${item.label}`)}</strong>
                                    <span>
                                        {item.actor_key} · {fmtDate(item.at, locale)} · v
                                        {item.work_version}
                                    </span>
                                    {item.reason_code && (
                                        <p>
                                            {t("m3FpReason")}: {item.reason_code}
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
                    <h5>{t("m3MembershipHistory")}</h5>
                    {data.membership_intervals.length ? (
                        <EvidenceRows values={data.membership_intervals} />
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
                </section>
            </div>
        </>
    );
}

function GraphUnavailable({ kind, locale }: { kind: GraphKind; locale: Locale }) {
    const copy =
        locale === "es"
            ? {
                  title: "Grafo de entidades no disponible",
                  incident:
                      "No hay relaciones entre entidades disponibles para este incidente. La cronología de eventos aparece a continuación.",
                  chain: "No hay relaciones entre entidades disponibles para este candidato. Las etapas y la evidencia aparecen a continuación.",
              }
            : {
                  title: "Entity graph unavailable",
                  incident:
                      "No entity relationships are available for this incident. The event timeline is below.",
                  chain: "No entity relationships are available for this candidate. Its stages and evidence are below.",
              };
    return (
        <section className="m3-graph-empty" aria-labelledby={`${kind}-graph-heading`}>
            <div className="m3-graph-grid" aria-hidden="true" />
            <div className="m3-graph-empty-copy">
                <h4 id={`${kind}-graph-heading`}>{copy.title}</h4>
                <p>{copy[kind]}</p>
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
            <h4>{t("m3CreateIncident")}</h4>
            {formError && <p role="alert">{formError}</p>}
            <label>
                {t("m3GroupIds")}
                <textarea
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
                    maxLength={256}
                    value={owner}
                    onChange={(event) => setOwner(event.target.value)}
                />
            </label>
            <button className="btn primary" type="submit">
                {t("m3Create")}
            </button>
        </form>
    );
}

function EvidenceRows({ values }: { values: unknown[] }) {
    return (
        <ul className="m3-evidence">
            {values.map((value, index) => (
                <li key={index}>
                    <pre>{printable(value)}</pre>
                </li>
            ))}
        </ul>
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

function EmptyDetail({ text }: { text: string }) {
    return (
        <div className="empty-state">
            <p>{text}</p>
        </div>
    );
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

function fmtDate(value: string, locale: Locale): string {
    const date = new Date(value);
    return Number.isNaN(date.getTime())
        ? value
        : new Intl.DateTimeFormat(locale, {
              dateStyle: "medium",
              timeStyle: "short",
              timeZone: "UTC",
          }).format(date);
}

function fmtTime(value: string, locale: Locale): string {
    const date = new Date(value);
    return Number.isNaN(date.getTime())
        ? value
        : new Intl.DateTimeFormat(locale, {
              hour: "2-digit",
              minute: "2-digit",
              second: "2-digit",
              hour12: false,
              timeZone: "UTC",
          }).format(date);
}
