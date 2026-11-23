import { useEffect, useMemo, useRef, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import {
    IdChip,
    KeyHints,
    ShareBar,
    SlaText,
    ViewTabs,
    slaFrom,
} from "../../components/ui/portfolio";
import { createIncident } from "../../api/workspace-m3";
import { useSamples } from "../workspace/samples";
import { Tag } from "../../components/ui/tag";
import { dispositionTags, statusTags } from "../../lib/semantic";
import { humanizeKey, isFlatRecord } from "../../lib/utils";
import { WorkspaceFailure, WorkspaceLoading } from "../workspace/WorkspaceStates";
import * as api from "../../api/workspace";
import type { DispositionLabel, GroupDetail, WorkStatus } from "../../api/workspace";
import "./queue-v2.css";
import "./queue-pp.css";
import { AssessmentPanel } from "./AssessmentPanel";
import type { Locale } from "../../i18n";
import { falsePositiveReasonText } from "../../i18n/workspace-copy";

type Translate = (key: string) => string;
type QueueFilterPatch = Record<string, string | null | undefined>;
type QueueView = "all" | "near_sla" | "new" | "in_progress" | "closed";
const ownerKeyStorage = "ai-soc:owner-key";
function readMyOwnerKey(): string {
    try {
        const stored = localStorage.getItem(ownerKeyStorage);
        if (stored) return stored;
    } catch {
        /* storage can be unavailable */
    }
    return import.meta.env.MODE === "live" ? "" : "analyst:demo";
}
const statusKeys: Record<WorkStatus, string> = {
    new: "newStatus",
    in_progress: "inProgress",
    resolved: "resolved",
    closed: "closed",
};
const fpReasons = [
    "expected_admin_activity",
    "known_scanner",
    "misconfigured_rule",
    "test_activity",
    "other",
] as const;

export function QueuePage({
    siteId,
    from,
    to,
    t,
    onOpenAlert,
    onFilters,
    locale,
    onInvestigate,
}: {
    siteId: string;
    from: string;
    to: string;
    t: Translate;
    onOpenAlert: (alertKey: string) => void;
    onFilters: (patch: QueueFilterPatch) => void;
    locale: Locale;
    onInvestigate?: (group: GroupDetail) => void;
}) {
    const queryClient = useQueryClient();
    const [selectedIds, setSelectedIds] = useState<Set<string>>(() => new Set());
    const [selectedId, setSelectedId] = useState<string | null>(null);
    const [bulkLabel, setBulkLabel] = useState<DispositionLabel>("undetermined");
    const [bulkReason, setBulkReason] = useState("");
    const [bulkNote, setBulkNote] = useState("");
    const [propagate, setPropagate] = useState(false);
    const [actionMessage, setActionMessage] = useState("");
    const [bulkMode, setBulkMode] = useState<"disposition" | null>(null);
    const [dispositionIntent, setDispositionIntent] = useState<{
        id: string;
        label: DispositionLabel;
    } | null>(null);
    const [me, setMeState] = useState(readMyOwnerKey);
    const setMe = (value: string) => {
        setMeState(value);
        try {
            localStorage.setItem(ownerKeyStorage, value);
        } catch {
            /* storage can be unavailable; the key stays for this session */
        }
    };
    const samples = useSamples();
    const detailRef = useRef<HTMLElement>(null);
    const params = useMemo(() => new URLSearchParams(location.search), [location.search]);
    const filterKey = params.toString();
    useEffect(() => {
        setSelectedIds(new Set());
        setActionMessage("");
    }, [filterKey, from, siteId, to]);
    useEffect(() => {
        setSelectedId(null);
    }, [siteId]);
    const filters: api.QueueFilters = {
        siteId,
        from,
        to,
        status: parseStatus(params.get("status")),
        ownerKey: params.get("owner_key") ?? undefined,
        unassigned: params.get("unassigned") === "true" ? true : undefined,
        minScore: numericParam(params.get("min_score")),
        ruleId: params.get("rule_id") ?? undefined,
        cursor: params.get("cursor") ?? undefined,
    };
    const view: QueueView =
        params.get("view") === "near_sla"
            ? "near_sla"
            : filters.status === "new" || filters.status === "in_progress" || filters.status === "closed"
              ? filters.status
              : "all";
    const queueQuery = useQuery({
        queryKey: ["workspace", "queue", filters],
        queryFn: ({ signal }) => api.listQueue(filters, signal),
    });
    const allFilters: api.QueueFilters = { ...filters, status: undefined };
    const allQuery = useQuery({
        queryKey: ["workspace", "queue", allFilters],
        queryFn: ({ signal }) => api.listQueue(allFilters, signal),
    });
    useEffect(() => {
        if (selectedId || !queueQuery.data?.items.length) return;
        if (!window.matchMedia?.("(min-width: 1100px)").matches) return;
        setSelectedId(queueQuery.data.items[0]?.group.group_id ?? null);
    }, [queueQuery.data, selectedId]);
    const detailQuery = useQuery({
        queryKey: ["workspace", "group", siteId, selectedId],
        queryFn: ({ signal }) => api.getGroup(siteId, selectedId ?? "", undefined, signal),
        enabled: selectedId !== null,
    });
    const detail = detailQuery.data;
    const memberPage = useMutation({
        mutationFn: ({ id, cursor }: { id: string; cursor: string }) =>
            api.getGroup(siteId, id, cursor),
        onSuccess: (next) => {
            queryClient.setQueryData<GroupDetail>(
                ["workspace", "group", siteId, next.group_id],
                (current) => {
                    if (!current) return next;
                    const known = new Set(current.members.items.map((alert) => alert.alert_key));
                    return {
                        ...next,
                        members: {
                            ...next.members,
                            items: [
                                ...current.members.items,
                                ...next.members.items.filter(
                                    (alert) => !known.has(alert.alert_key),
                                ),
                            ],
                        },
                    };
                },
            );
        },
        onError: (error) =>
            setActionMessage(error instanceof Error ? error.message : t("requestFailed")),
    });
    const invalidateQueue = () =>
        queryClient.invalidateQueries({ queryKey: ["workspace", "queue"] });
    const invalidateGroup = () =>
        queryClient.invalidateQueries({ queryKey: ["workspace", "group", siteId, selectedId] });
    const assign = useMutation({
        mutationFn: ({ id, owner }: { id: string; owner: string | null }) =>
            api.assignGroup(siteId, id, owner),
        onSuccess: (state, { id }) =>
            queryClient.setQueryData<GroupDetail>(["workspace", "group", siteId, id], (current) =>
                current ? { ...current, owner_key: state.owner_key, work_state: state } : current,
            ),
        onMutate: async ({ id, owner }) => {
            const key = ["workspace", "group", siteId, id];
            await queryClient.cancelQueries({ queryKey: key });
            const previous = queryClient.getQueryData<GroupDetail>(key);
            if (previous)
                queryClient.setQueryData<GroupDetail>(key, {
                    ...previous,
                    owner_key: owner,
                    work_state: { ...previous.work_state, owner_key: owner },
                });
            return { key, previous };
        },
        onError: (_error, _variables, context) => {
            if (context?.previous) queryClient.setQueryData(context.key, context.previous);
        },
        onSettled: () => {
            void invalidateQueue();
            void invalidateGroup();
        },
    });
    const status = useMutation({
        mutationFn: ({ id, next, expected }: { id: string; next: WorkStatus; expected: string }) =>
            api.updateGroupStatus(siteId, id, next, expected),
        onSuccess: (state, { id }) =>
            queryClient.setQueryData<GroupDetail>(["workspace", "group", siteId, id], (current) =>
                current ? { ...current, status: state.status, work_state: state } : current,
            ),
        onMutate: async ({ id, next }) => {
            const key = ["workspace", "group", siteId, id];
            await queryClient.cancelQueries({ queryKey: key });
            const previous = queryClient.getQueryData<GroupDetail>(key);
            if (previous)
                queryClient.setQueryData<GroupDetail>(key, {
                    ...previous,
                    status: next,
                    work_state: {
                        ...previous.work_state,
                        status: next,
                        updated_at: new Date().toISOString(),
                    },
                });
            return { key, previous };
        },
        onError: (_error, _variables, context) => {
            if (context?.previous) queryClient.setQueryData(context.key, context.previous);
        },
        onSettled: () => {
            void invalidateQueue();
            void invalidateGroup();
        },
    });
    const disposition = useMutation({
        mutationFn: ({
            id,
            label,
            reason,
            note,
            propagateToMembers,
        }: {
            id: string;
            label: DispositionLabel;
            reason: string | null;
            note: string | null;
            propagateToMembers: boolean;
        }) =>
            api.labelGroup(siteId, id, {
                label,
                reason_code: reason,
                note,
                propagate_to_members: propagateToMembers,
            }),
        onMutate: async () => {
            await queryClient.cancelQueries({ queryKey: ["workspace", "queue"] });
        },
        onSuccess: (saved, variables) => {
            const key = ["workspace", "group", siteId, variables.id];
            queryClient.setQueryData<GroupDetail>(key, (current) =>
                current ? { ...current, disposition: saved } : current,
            );
            queryClient.setQueriesData<api.QueuePage>(
                { queryKey: ["workspace", "queue"] },
                (current) =>
                    current
                        ? {
                              ...current,
                              items: current.items.map((row) =>
                                  row.group.group_id === variables.id
                                      ? {
                                            ...row,
                                            group: { ...row.group, disposition: saved },
                                        }
                                      : row,
                              ),
                          }
                        : current,
            );
        },
        onSettled: () => {
            void invalidateQueue();
            void invalidateGroup();
        },
    });
    const bulk = useMutation({
        mutationFn: ({ ids, action }: { ids: string[]; action: api.BulkAction }) =>
            api.bulkAction(siteId, ids, action),
        onSuccess: (result) => {
            setSelectedIds(new Set());
            setActionMessage(`${t("atomicAction")} (${result.updated})`);
        },
        onError: (error) =>
            setActionMessage(error instanceof Error ? error.message : t("requestFailed")),
        onSettled: () => {
            void invalidateQueue();
        },
    });

    const rows = queueQuery.data?.items ?? [];
    const allRows = allQuery.data?.items ?? rows;
    const slaFor = (groupId: string) => {
        const sample = samples?.groupSla[groupId];
        return sample ? slaFrom(sample) : undefined;
    };
    const nearSla = (groupId: string) => {
        const state = slaFor(groupId)?.state;
        return state === "near" || state === "breached";
    };
    const visibleRows = view === "near_sla" ? rows.filter((row) => nearSla(row.group.group_id)) : rows;
    const countBy = (status: WorkStatus) =>
        allRows.filter((row) => row.work_state.status === status).length;
    const tabs = [
        { id: "all" as const, label: t("queueViewAll"), count: allRows.length },
        {
            id: "near_sla" as const,
            label: t("queueViewNearSla"),
            count: samples ? allRows.filter((row) => nearSla(row.group.group_id)).length : null,
            tone: "amber" as const,
        },
        { id: "new" as const, label: t("newStatus"), count: countBy("new") },
        { id: "in_progress" as const, label: t("inProgress"), count: countBy("in_progress") },
        { id: "closed" as const, label: t("closed"), count: countBy("closed") },
    ];
    const activeId = selectedId;
    const selectedCount = selectedIds.size;
    const patchFilter = (key: string, value: string | null) =>
        onFilters({ [key]: value, cursor: null });
    const setView = (next: QueueView) => {
        if (next === "near_sla") onFilters({ view: "near_sla", status: null, cursor: null });
        else onFilters({ view: null, status: next === "all" ? null : next, cursor: null });
    };
    const doBulk = (action: api.BulkAction) => {
        if (selectedCount === 0 || selectedCount > 100) {
            setActionMessage(t("bulkLimit"));
            return;
        }
        bulk.mutate({ ids: [...selectedIds], action });
    };
    const bulkDisposition = () => {
        if (bulkLabel === "false_positive" && !bulkReason) {
            setActionMessage(t("reasonRequired"));
            return;
        }
        if (bulkReason === "other" && !bulkNote.trim()) {
            setActionMessage(t("otherNoteRequired"));
            return;
        }
        doBulk({
            kind: "disposition",
            label: bulkLabel,
            reason_code: bulkReason || null,
            note: bulkNote.trim() || null,
            propagate_to_members: propagate,
        });
    };
    const createFromSelection = (ids: string[]) => {
        if (ids.length === 0) return;
        void createIncident({ site_id: siteId, group_ids: ids, owner_key: me || null })
            .then(() => {
                setSelectedIds(new Set());
                setActionMessage(t("incidentCreated"));
                void queryClient.invalidateQueries({ queryKey: ["m3", "incidents", siteId] });
            })
            .catch((error: unknown) =>
                setActionMessage(error instanceof Error ? error.message : t("requestFailed")),
            );
    };

    // Queue shortcuts: J/K move, X select, A assign to me, F false positive, I create incident.
    const keyState = useRef({ visibleRows, activeId, selectedIds, me });
    keyState.current = { visibleRows, activeId, selectedIds, me };
    useEffect(() => {
        const onKey = (event: KeyboardEvent) => {
            if (event.metaKey || event.ctrlKey || event.altKey || event.defaultPrevented) return;
            const target = event.target as HTMLElement | null;
            if (target?.closest("input, select, textarea, [contenteditable], [role='dialog']")) return;
            const { visibleRows: list, activeId: current, selectedIds: picked, me: owner } =
                keyState.current;
            const index = list.findIndex((row) => row.group.group_id === current);
            const key = event.key.toLowerCase();
            if (key === "j" || key === "k") {
                const next = list[Math.min(list.length - 1, Math.max(0, index + (key === "j" ? 1 : -1)))];
                if (next) setSelectedId(next.group.group_id);
            } else if (key === "x" && current) {
                setSelectedIds((set) => {
                    const next = new Set(set);
                    if (next.has(current)) next.delete(current);
                    else next.add(current);
                    return next;
                });
            } else if (key === "a" && current && owner) {
                assign.mutate({ id: current, owner });
            } else if (key === "f" && current) {
                setDispositionIntent({ id: current, label: "false_positive" });
            } else if (key === "i") {
                createFromSelection(picked.size ? [...picked] : current ? [current] : []);
            } else return;
            event.preventDefault();
        };
        document.addEventListener("keydown", onKey);
        return () => document.removeEventListener("keydown", onKey);
        // eslint-disable-next-line react-hooks/exhaustive-deps
    }, []);

    return (
        <div className="workspace-page queue-pp">
            <div className="queue-pp-intro">
                <p>{t("queueDescription")}</p>
                <div className="queue-pp-sla-note">
                    {samples && (
                        <span>
                            {t("triageSlaTarget").replace("{minutes}", String(samples.triageTargetMinutes))}
                        </span>
                    )}
                    <a className="btn compact" href="#soc_operations">
                        {t("slaReport")}
                    </a>
                </div>
            </div>
            <div className="tab-bar queue-pp-tabs">
                <ViewTabs tabs={tabs} value={view} onChange={setView} label={t("savedViews")} />
                <span className="queue-pp-tab-spacer" />
                <label className="queue-pp-filter">
                    {t("owner")}
                    <input
                        className="id-input"
                        key={`owner-${filters.ownerKey ?? ""}`}
                        aria-label={t("owner")}
                        defaultValue={filters.ownerKey ?? ""}
                        placeholder={t("allOwners")}
                        maxLength={256}
                        onBlur={(event) => patchFilter("owner_key", event.target.value.trim() || null)}
                        onKeyDown={(event) => {
                            if (event.key === "Enter") event.currentTarget.blur();
                        }}
                    />
                </label>
                <label className="queue-pp-filter">
                    {t("score")}
                    <select
                        aria-label={t("score")}
                        value={params.get("min_score") ?? ""}
                        onChange={(event) => patchFilter("min_score", event.target.value || null)}
                    >
                        <option value="">0 to 100</option>
                        <option value="50">50 and above</option>
                        <option value="75">75 and above</option>
                    </select>
                </label>
                <label className="queue-pp-filter">
                    {t("filterRule")}
                    <input
                        className="id-input"
                        key={`rule-${filters.ruleId ?? ""}`}
                        aria-label={t("filterRule")}
                        defaultValue={filters.ruleId ?? ""}
                        placeholder="5763"
                        maxLength={128}
                        onBlur={(event) => patchFilter("rule_id", event.target.value.trim() || null)}
                        onKeyDown={(event) => {
                            if (event.key === "Enter") event.currentTarget.blur();
                        }}
                    />
                </label>
            </div>
            {selectedCount > 0 && (
                <div className="bulk-bar queue-pp-bulk" role="region" aria-label={t("bulkActions")}>
                    <span className="bulk-bar-count">
                        {t("selectedCount").replace("{count}", String(selectedCount))}
                    </span>
                    <span className="bulk-bar-note">{t("atomicAction")}</span>
                    <button
                        className="btn compact"
                        type="button"
                        disabled={!me || selectedCount > 100 || bulk.isPending}
                        onClick={() => doBulk({ kind: "assign", owner_key: me })}
                    >
                        {t("assignToMe")}
                    </button>
                    <button
                        className="btn compact"
                        type="button"
                        aria-expanded={bulkMode === "disposition"}
                        onClick={() => {
                            setBulkLabel("false_positive");
                            setBulkMode(bulkMode === "disposition" ? null : "disposition");
                        }}
                    >
                        {t("markFalsePositive")}
                    </button>
                    <select
                        className="queue-pp-bulk-status"
                        aria-label={t("bulkStatus")}
                        value=""
                        disabled={bulk.isPending}
                        onChange={(event) => {
                            const value = parseStatus(event.target.value);
                            if (value) doBulk({ kind: "status", status: value });
                        }}
                    >
                        <option value="">{t("changeStatus")}</option>
                        {statuses.map((value) => (
                            <option key={value} value={value}>
                                {t(statusKeys[value])}
                            </option>
                        ))}
                    </select>
                    <button
                        className="btn compact primary"
                        type="button"
                        onClick={() => createFromSelection([...selectedIds])}
                    >
                        {t("createIncident")}
                    </button>
                    <button
                        className="btn compact quiet"
                        type="button"
                        onClick={() => {
                            setSelectedIds(new Set());
                            setBulkMode(null);
                        }}
                    >
                        {t("clear")}
                    </button>
                    {bulkMode === "disposition" && (
                        <div className="queue-pp-bulk-form">
                            <label className="pp-field">
                                {t("disposition")}
                                <select
                                    value={bulkLabel}
                                    onChange={(event) => {
                                        const value = parseDispositionLabel(event.target.value);
                                        if (value) setBulkLabel(value);
                                    }}
                                >
                                    {dispositionLabels.map((value) => (
                                        <option key={value} value={value}>
                                            {t(labelKey(value))}
                                        </option>
                                    ))}
                                </select>
                            </label>
                            {bulkLabel === "false_positive" && (
                                <label className="pp-field">
                                    {t("reasonRequiredLabel")}
                                    <select value={bulkReason} onChange={(event) => setBulkReason(event.target.value)}>
                                        <option value="">{t("chooseReason")}</option>
                                        {fpReasons.map((value) => (
                                            <option key={value} value={value}>
                                                {falsePositiveReasonText(t, value)}
                                            </option>
                                        ))}
                                    </select>
                                </label>
                            )}
                            <label className="pp-field">
                                {t("m3DispositionNote")}
                                <input
                                    maxLength={2000}
                                    value={bulkNote}
                                    onChange={(event) => setBulkNote(event.target.value)}
                                />
                            </label>
                            <label className="pp-check">
                                <input
                                    type="checkbox"
                                    checked={propagate}
                                    onChange={(event) => setPropagate(event.target.checked)}
                                />
                                {t("propagate")}
                            </label>
                            <button
                                className="btn compact primary"
                                type="button"
                                disabled={selectedCount > 100 || bulk.isPending}
                                onClick={bulkDisposition}
                            >
                                {t("bulkDisposition")}
                            </button>
                        </div>
                    )}
                </div>
            )}
            {actionMessage && (
                <p className="workspace-action-message" role="status">
                    {actionMessage}
                </p>
            )}
            <div className="queue-pp-layout">
                {queueQuery.isLoading ? (
                    <WorkspaceLoading label={t("queue")} />
                ) : queueQuery.isError ? (
                    <WorkspaceFailure
                        error={queueQuery.error}
                        t={t}
                        onRetry={() => void queueQuery.refetch()}
                    />
                ) : (
                    <section className="pp-panel queue-pp-table-panel">
                        <div className="table-scroll pp-table-scroll" role="region" aria-label={t("groupsTitle")} tabIndex={0}>
                            <table className="pp-table queue-table queue-pp-table">
                                <thead>
                                    <tr>
                                        <th scope="col" className="queue-pp-check">
                                            <span className="sr-only">{t("selectGroups")}</span>
                                        </th>
                                        <th scope="col">{t("group")}</th>
                                        <th scope="col" className="queue-pp-score-col">
                                            {t("score")}
                                        </th>
                                        <th scope="col" className="queue-pp-sla-col">
                                            {t("triageSla")}
                                        </th>
                                        <th scope="col" className="is-num">
                                            {t("alerts")}
                                        </th>
                                        <th scope="col">{t("statusLabel")}</th>
                                    </tr>
                                </thead>
                                <tbody>
                                    {visibleRows.map(({ group, work_state: workState }) => {
                                        const selected = group.group_id === activeId;
                                        return (
                                            <tr key={group.group_id} data-selected={selected || undefined}>
                                                <td className="queue-pp-check">
                                                    <input
                                                        type="checkbox"
                                                        aria-label={`${t("selectGroups")} ${group.title}`}
                                                        checked={selectedIds.has(group.group_id)}
                                                        onChange={(event) =>
                                                            setSelectedIds((current) => {
                                                                const next = new Set(current);
                                                                if (event.target.checked) next.add(group.group_id);
                                                                else next.delete(group.group_id);
                                                                return next;
                                                            })
                                                        }
                                                    />
                                                </td>
                                                <td>
                                                    <button
                                                        className="group-link queue-pp-group"
                                                        type="button"
                                                        aria-pressed={selected}
                                                        onClick={() => setSelectedId(group.group_id)}
                                                    >
                                                        <span className="group-link-title">{group.title}</span>
                                                        <span className="queue-pp-meta">
                                                            {group.primary_entity && (
                                                                <span>
                                                                    {t("on")}{" "}
                                                                    <span className="ent">{group.primary_entity.value}</span>
                                                                </span>
                                                            )}
                                                            {group.rule_id && (
                                                                <span>
                                                                    {t("rule")} {group.rule_id}
                                                                </span>
                                                            )}
                                                            <span>{workState.owner_key ?? t("unassignedOwner")}</span>
                                                            <span>
                                                                {t("lastAlert")} {formatShortTime(group.last_ts)}
                                                            </span>
                                                        </span>
                                                    </button>
                                                </td>
                                                <td>
                                                    {group.score === null ? (
                                                        <span className="t-secondary">{t("scorePending")}</span>
                                                    ) : (
                                                        <span className="queue-pp-score">
                                                            <strong className="num">{group.score.toFixed(1)}</strong>
                                                            <ShareBar share={scorePercent(group.score) / 100} />
                                                        </span>
                                                    )}
                                                </td>
                                                <td>
                                                    <SlaText
                                                        sla={slaFor(group.group_id)}
                                                        bar
                                                        notReported={t("notReportedShort")}
                                                    />
                                                </td>
                                                <td className="is-num">{group.alert_count.toLocaleString()}</td>
                                                <td>
                                                    <span className="queue-pp-status">
                                                        <Tag {...statusTags[workState.status]}>
                                                            {t(statusKeys[workState.status])}
                                                        </Tag>
                                                        {group.disposition && (
                                                            <Tag {...dispositionTags[group.disposition.label]}>
                                                                {t(labelKey(group.disposition.label))}
                                                            </Tag>
                                                        )}
                                                    </span>
                                                </td>
                                            </tr>
                                        );
                                    })}
                                    {visibleRows.length === 0 && (
                                        <tr>
                                            <td colSpan={6} className="pp-table-empty">
                                                {t("queueEmptyView")}
                                            </td>
                                        </tr>
                                    )}
                                </tbody>
                            </table>
                        </div>
                        <div className="pp-panel-foot">
                            <KeyHints
                                hints={[
                                    { keys: ["J", "K"], label: t("keyMove") },
                                    { keys: ["X"], label: t("keySelect") },
                                    { keys: ["A"], label: t("assignToMe").toLocaleLowerCase() },
                                    { keys: ["F"], label: t("falsePositiveDisposition").toLocaleLowerCase() },
                                    { keys: ["I"], label: t("createIncident").toLocaleLowerCase() },
                                ]}
                            />
                            <span className="queue-pp-foot-count">
                                {visibleRows.length.toLocaleString()}{" "}
                                {t(visibleRows.length === 1 ? "rowLoaded" : "rowsLoaded")}
                            </span>
                            <span className="page-controls">
                                <button
                                    className="btn compact"
                                    type="button"
                                    disabled={!params.get("cursor")}
                                    onClick={() => patchFilter("cursor", null)}
                                >
                                    {t("previous")}
                                </button>
                                <button
                                    className="btn compact"
                                    type="button"
                                    disabled={!queueQuery.data?.next_cursor}
                                    onClick={() => patchFilter("cursor", queueQuery.data?.next_cursor ?? null)}
                                >
                                    {t("next")}
                                </button>
                            </span>
                        </div>
                    </section>
                )}
                <aside
                    className="pp-panel queue-pp-detail"
                    aria-label={detail?.title ?? t("group")}
                    ref={detailRef}
                    tabIndex={-1}
                >
                    {!activeId ? (
                        <p className="queue-pp-detail-empty">{t("queueSelectHint")}</p>
                    ) : detailQuery.isLoading ? (
                        <WorkspaceLoading label={t("group")} />
                    ) : detailQuery.isError ? (
                        <WorkspaceFailure error={detailQuery.error} t={t} onRetry={() => void detailQuery.refetch()} />
                    ) : detail ? (
                        <GroupPanel
                            key={detail.group_id}
                            detail={detail}
                            t={t}
                            locale={locale}
                            siteId={siteId}
                            me={me}
                            onMe={setMe}
                            intent={dispositionIntent?.id === detail.group_id ? dispositionIntent.label : null}
                            onInvestigate={onInvestigate ? () => onInvestigate(detail) : undefined}
                            busy={assign.isPending || status.isPending || disposition.isPending}
                            onOpenAlert={onOpenAlert}
                            membersLoading={memberPage.isPending}
                            onLoadMoreMembers={() => {
                                const cursor = detail.members.next_cursor;
                                if (cursor) memberPage.mutate({ id: detail.group_id, cursor });
                            }}
                            onAssign={(owner) =>
                                assign.mutate(
                                    { id: detail.group_id, owner },
                                    {
                                        onSuccess: () => setActionMessage(t("atomicAction")),
                                        onError: (error) => setActionMessage(error.message),
                                    },
                                )
                            }
                            onStatus={(next) =>
                                status.mutate(
                                    { id: detail.group_id, next, expected: detail.work_state.updated_at },
                                    {
                                        onSuccess: () => setActionMessage(t("atomicAction")),
                                        onError: (error) => setActionMessage(error.message),
                                    },
                                )
                            }
                            onDisposition={(value) =>
                                disposition.mutate(
                                    { id: detail.group_id, ...value },
                                    {
                                        onSuccess: () => setActionMessage(t("dispositionRecorded")),
                                        onError: (error) => setActionMessage(error.message),
                                    },
                                )
                            }
                        />
                    ) : null}
                </aside>
            </div>
        </div>
    );
}


const statuses: WorkStatus[] = ["new", "in_progress", "resolved", "closed"];
const dispositionLabels: DispositionLabel[] = [
    "true_positive",
    "benign_true_positive",
    "false_positive",
    "duplicate",
    "undetermined",
];
function parseStatus(value: string | null): WorkStatus | undefined {
    return statuses.find((status) => status === value);
}
function parseDispositionLabel(value: string): DispositionLabel | undefined {
    return dispositionLabels.find((label) => label === value);
}
function numericParam(value: string | null): number | undefined {
    if (!value) return undefined;
    const number = Number(value);
    return Number.isFinite(number) ? number : undefined;
}
function GroupPanel({
    detail: group,
    t,
    locale,
    siteId,
    me,
    onMe,
    intent,
    onInvestigate,
    busy,
    membersLoading,
    onLoadMoreMembers,
    onAssign,
    onStatus,
    onDisposition,
    onOpenAlert,
}: {
    detail: GroupDetail;
    t: Translate;
    locale: Locale;
    siteId: string;
    me: string;
    onMe: (value: string) => void;
    intent: DispositionLabel | null;
    onInvestigate?: () => void;
    busy: boolean;
    membersLoading: boolean;
    onLoadMoreMembers: () => void;
    onAssign: (owner: string | null) => void;
    onStatus: (status: WorkStatus) => void;
    onDisposition: (value: {
        label: DispositionLabel;
        reason: string | null;
        note: string | null;
        propagateToMembers: boolean;
    }) => void;
    onOpenAlert: (alertKey: string) => void;
}) {
    const [owner, setOwner] = useState(group.work_state.owner_key ?? "");
    const [label, setLabel] = useState<DispositionLabel | null>(intent);
    const [reason, setReason] = useState("");
    const [note, setNote] = useState("");
    const [propagate, setPropagate] = useState(true);
    const [suggestTuning, setSuggestTuning] = useState(false);
    const [meDraft, setMeDraft] = useState("");
    const [askMe, setAskMe] = useState(false);
    const [error, setError] = useState("");
    useEffect(() => {
        if (intent) setLabel(intent);
    }, [intent]);
    const host = group.primary_entity?.value;
    const ruleText = group.rule_id ? `${t("rule")} ${group.rule_id}` : null;
    const save = () => {
        if (!label) return;
        if (label === "false_positive" && !reason) {
            setError(t("reasonRequired"));
            return;
        }
        if (reason === "other" && !note.trim()) {
            setError(t("otherNoteRequired"));
            return;
        }
        setError("");
        const tuning =
            label === "false_positive" && suggestTuning && group.rule_id
                ? t("tuningSuggestionNote")
                      .replace("{rule}", group.rule_id)
                      .replace("{host}", host ?? t("anyHost"))
                : "";
        const fullNote = [note.trim(), tuning].filter(Boolean).join("\n");
        onDisposition({
            label,
            reason: label === "false_positive" ? reason || null : null,
            note: fullNote || null,
            propagateToMembers: label === "false_positive" ? propagate : false,
        });
    };
    const assignToMe = () => {
        if (me) onAssign(me);
        else setAskMe(true);
    };
    const window = `${formatShortTime(group.first_ts)} to ${formatShortTime(group.last_ts)}`;
    return (
        <div className="queue-pp-panel">
            <header className="queue-pp-panel-head">
                <div className="queue-pp-panel-ids">
                    <Tag {...statusTags[group.work_state.status]}>{t(statusKeys[group.work_state.status])}</Tag>
                    {group.disposition && (
                        <Tag {...dispositionTags[group.disposition.label]}>
                            {t(labelKey(group.disposition.label))}
                        </Tag>
                    )}
                    <IdChip kind="group" value={group.group_id} />
                </div>
                <h2 className="t-page-title">{group.title}</h2>
                <p className="queue-pp-summary">
                    {group.alert_count.toLocaleString()} {t("alerts").toLocaleLowerCase()}
                    {host && (
                        <>
                            {" "}
                            {t("on")} <span className="ent">{host}</span>
                        </>
                    )}
                    {ruleText && (
                        <>
                            {" "}
                            {t("fromRule")} {ruleText}
                        </>
                    )}
                    , {window}
                </p>
            </header>

            <section className="queue-pp-section" aria-labelledby="queue-triage-heading">
                <div className="queue-pp-section-head">
                    <h3 id="queue-triage-heading" className="t-sub">
                        {t("triage")}
                    </h3>
                    <span className="t-secondary">
                        {t("owner")}: {group.work_state.owner_key ?? t("unassignedOwner")}
                    </span>
                </div>
                <fieldset className="queue-pp-fieldset">
                    <legend>{t("disposition")}</legend>
                    <div className="choice-row">
                        {dispositionLabels.map((value) => (
                            <button
                                key={value}
                                type="button"
                                className="choice"
                                aria-pressed={label === value}
                                disabled={busy}
                                onClick={() => setLabel(value)}
                            >
                                {t(labelKey(value))}
                            </button>
                        ))}
                    </div>
                </fieldset>
                {label === "false_positive" && (
                    <div className="pp-note">
                        <label className="pp-field">
                            {t("reasonRequiredLabel")}
                            <select value={reason} disabled={busy} onChange={(event) => setReason(event.target.value)}>
                                <option value="">{t("chooseReason")}</option>
                                {fpReasons.map((value) => (
                                    <option key={value} value={value}>
                                        {falsePositiveReasonText(t, value)}
                                    </option>
                                ))}
                            </select>
                        </label>
                        <label className="pp-check">
                            <input
                                type="checkbox"
                                checked={propagate}
                                disabled={busy}
                                onChange={(event) => setPropagate(event.target.checked)}
                            />
                            {t("applyToAllAlerts").replace("{count}", group.alert_count.toLocaleString())}
                        </label>
                        {group.rule_id && (
                            <label className="pp-check">
                                <input
                                    type="checkbox"
                                    checked={suggestTuning}
                                    disabled={busy}
                                    onChange={(event) => setSuggestTuning(event.target.checked)}
                                />
                                {t("suggestTuning")
                                    .replace("{rule}", group.rule_id)
                                    .replace("{host}", host ?? t("anyHost"))}
                            </label>
                        )}
                    </div>
                )}
                {label && (
                    <label className="pp-field">
                        {t("m3DispositionNote")}
                        {reason === "other" ? "" : ` (${t("optional")})`}
                        <textarea
                            maxLength={2000}
                            rows={2}
                            disabled={busy}
                            value={note}
                            onChange={(event) => setNote(event.target.value)}
                        />
                    </label>
                )}
                {error && (
                    <p className="alert error" role="alert">
                        {error}
                    </p>
                )}
                <div className="queue-pp-actions">
                    <button className="btn primary" type="button" disabled={busy || !label} onClick={save}>
                        {t("saveDisposition")}
                    </button>
                    <button className="btn" type="button" disabled={busy} onClick={assignToMe}>
                        {t("assignToMe")}
                    </button>
                    <label className="queue-pp-status-select">
                        <span className="sr-only">{t("statusLabel")}</span>
                        <select
                            aria-label={t("statusLabel")}
                            disabled={busy}
                            value={group.work_state.status}
                            onChange={(event) => {
                                const value = parseStatus(event.target.value);
                                if (value) onStatus(value);
                            }}
                        >
                            {statuses.map((value) => (
                                <option key={value} value={value}>
                                    {t(statusKeys[value])}
                                </option>
                            ))}
                        </select>
                    </label>
                </div>
                {askMe && (
                    <form
                        className="queue-pp-me"
                        onSubmit={(event) => {
                            event.preventDefault();
                            const value = meDraft.trim();
                            if (!value) return;
                            onMe(value);
                            setAskMe(false);
                            onAssign(value);
                        }}
                    >
                        <label className="pp-field">
                            {t("yourOwnerKey")}
                            <input
                                className="id-input"
                                value={meDraft}
                                placeholder="analyst:name"
                                maxLength={256}
                                onChange={(event) => setMeDraft(event.target.value)}
                            />
                        </label>
                        <button className="btn compact" type="submit">
                            {t("assign")}
                        </button>
                    </form>
                )}
            </section>

            <div className="queue-pp-section queue-pp-assessment">
                <AssessmentPanel
                    siteId={siteId}
                    group={group}
                    locale={locale}
                    t={t}
                    onInvestigate={onInvestigate}
                />
            </div>

            <details className="queue-pp-section queue-pp-why">
                <summary>
                    <span className="t-sub">
                        {group.score === null
                            ? t("scorePending")
                            : t("whyItRanks").replace("{score}", group.score.toFixed(1))}
                    </span>
                    <span className="t-secondary">
                        {group.computation_version ?? ""} · {t("uncalibratedShort")}
                    </span>
                </summary>
                <ul className="queue-pp-components">
                    {group.components.map((component) => (
                        <li key={component.name}>
                            <div>
                                <span className="cell-main">{component.name}</span>
                                <span className="t-secondary">{component.explanation}</span>
                            </div>
                            {component.available ? (
                                <span className="num queue-pp-contribution" data-sign={component.contribution >= 0 ? "up" : "down"}>
                                    {component.contribution >= 0 ? "+" : ""}
                                    {component.contribution.toFixed(1)}
                                </span>
                            ) : (
                                <span className="t-secondary">{t("unavailableValue")}</span>
                            )}
                        </li>
                    ))}
                </ul>
                {group.input_digest && (
                    <p className="t-secondary queue-pp-digest">
                        {t("scoreDigest")}: <IdChip kind="revision" value={group.input_digest} />
                    </p>
                )}
            </details>

            <details className="queue-pp-section">
                <summary>
                    <span className="t-sub">{t("groupMembers")}</span>
                    <span className="t-secondary num">{group.alert_count.toLocaleString()}</span>
                </summary>
                <ul className="queue-pp-members">
                    {group.members.items.map((alert) => (
                        <li key={alert.alert_key}>
                            <button className="member-link" type="button" onClick={() => onOpenAlert(alert.alert_key)}>
                                <span className="cell-main">
                                    {alert.rule_description ?? (alert.rule_id ? `${t("rule")} ${alert.rule_id}` : t("alertSingular"))}
                                </span>
                                <span className="t-secondary">
                                    {(alert.agent_name ?? alert.agent_id) && (
                                        <>
                                            <span className="ent">{alert.agent_name ?? alert.agent_id}</span> ·{" "}
                                        </>
                                    )}
                                    {formatTime(alert.event_ts)}
                                </span>
                            </button>
                            <IdChip kind="alert" value={alert.alert_key} />
                        </li>
                    ))}
                </ul>
                {group.members.next_cursor && (
                    <button className="btn compact load-more" type="button" disabled={membersLoading} onClick={onLoadMoreMembers}>
                        {membersLoading ? t("loading") : t("loadMoreMembers")}
                    </button>
                )}
            </details>

            <details className="queue-pp-section">
                <summary>
                    <span className="t-sub">{t("enrichmentProvenance")}</span>
                    <span className="t-secondary num">{group.enrichments.length}</span>
                </summary>
                {group.enrichments.length === 0 ? (
                    <p className="t-secondary">{t("noData")}</p>
                ) : (
                    group.enrichments.map((item) => (
                        <div className="provenance-row" key={item.enrichment_id}>
                            <span className="cell-main">{item.source}</span>
                            <dl className="provenance-fields">
                                <div>
                                    <dt>{t("sourceVersion")}</dt>
                                    <dd>{item.source_version}</dd>
                                </div>
                                <div>
                                    <dt>{t("fetchedAt")}</dt>
                                    <dd>{formatTime(item.fetched_at)}</dd>
                                </div>
                                <div>
                                    <dt>{t("expiresAt")}</dt>
                                    <dd>{item.expires_at ? formatTime(item.expires_at) : "\u2014"}</dd>
                                </div>
                            </dl>
                            {isFlatRecord(item.value) ? (
                                <dl className="provenance-fields" aria-label={`${t("enrichmentProvenance")}: ${item.source}`}>
                                    {Object.entries(item.value).map(([key, field]) => (
                                        <div key={key}>
                                            <dt>{humanizeKey(key)}</dt>
                                            <dd>{Array.isArray(field) ? field.join(", ") : String(field)}</dd>
                                        </div>
                                    ))}
                                </dl>
                            ) : (
                                <pre tabIndex={0} role="group" aria-label={`${t("enrichmentProvenance")}: ${item.source}`}>
                                    {JSON.stringify(item.value, null, 2)}
                                </pre>
                            )}
                        </div>
                    ))
                )}
            </details>

            <details className="queue-pp-section">
                <summary>
                    <span className="t-sub">{t("reassign")}</span>
                </summary>
                <div className="queue-pp-reassign">
                    <label className="pp-field">
                        {t("owner")}
                        <input
                            className="id-input"
                            aria-label={t("owner")}
                            value={owner}
                            onChange={(event) => setOwner(event.target.value)}
                        />
                    </label>
                    <button
                        className="btn compact"
                        type="button"
                        disabled={busy || (!owner.trim() && !group.owner_key)}
                        onClick={() => onAssign(owner.trim() || null)}
                    >
                        {owner.trim() ? t("assign") : t("unassign")}
                    </button>
                </div>
                <p className="t-secondary">
                    {t("m3MemberRevision")}: <IdChip kind="revision" value={group.group_revision} />
                </p>
            </details>
        </div>
    );
}
function labelKey(label: DispositionLabel): string {
    switch (label) {
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
function scorePercent(score: number): number {
    return Math.min(100, Math.max(0, score));
}
function formatTime(value: string): string {
    return new Intl.DateTimeFormat(undefined, { dateStyle: "medium", timeStyle: "short" }).format(
        new Date(value),
    );
}

function formatShortTime(value: string): string {
    return new Intl.DateTimeFormat(undefined, { hour: "2-digit", minute: "2-digit" }).format(
        new Date(value),
    );
}
