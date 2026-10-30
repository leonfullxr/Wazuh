import { useEffect, useMemo, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Panel } from "../../components/ui/panel";
import { Sheet, SheetClose, SheetContent } from "../../components/ui/sheet";
import { Tag } from "../../components/ui/tag";
import { dispositionTags, statusTags } from "../../lib/semantic";
import { WorkspaceFailure, WorkspaceLoading } from "../workspace/WorkspaceStates";
import * as api from "../../api/workspace";
import type { DispositionLabel, GroupDetail, WorkStatus } from "../../api/workspace";
import "./queue-v2.css";

type Translate = (key: string) => string;
type QueueFilterPatch = Record<string, string | null | undefined>;
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
}: {
    siteId: string;
    from: string;
    to: string;
    t: Translate;
    onOpenAlert: (alertKey: string) => void;
    onFilters: (patch: QueueFilterPatch) => void;
}) {
    const queryClient = useQueryClient();
    const [selectedIds, setSelectedIds] = useState<Set<string>>(() => new Set());
    const [selectedId, setSelectedId] = useState<string | null>(null);
    const [ownerDraft, setOwnerDraft] = useState("");
    const [bulkLabel, setBulkLabel] = useState<DispositionLabel>("undetermined");
    const [bulkReason, setBulkReason] = useState("");
    const [bulkNote, setBulkNote] = useState("");
    const [propagate, setPropagate] = useState(false);
    const [actionMessage, setActionMessage] = useState("");
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
    const queueQuery = useQuery({
        queryKey: ["workspace", "queue", filters],
        queryFn: ({ signal }) => api.listQueue(filters, signal),
    });
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
        onSuccess: (saved, variables) => {
            const key = ["workspace", "group", siteId, variables.id];
            queryClient.setQueryData<GroupDetail>(key, (current) =>
                current ? { ...current, disposition: saved } : current,
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
    const selectedCount = selectedIds.size;
    const patchFilter = (key: string, value: string | null) =>
        onFilters({ [key]: value, cursor: null });
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

    return (
        <div className="workspace-page queue-v2">
            <div className="queue-v2-intro">
                <p className="page-description">{t("queueDescription")}</p>
                <Tag tone="amber">
                    {t("score")} · {t("uncalibrated")}
                </Tag>
            </div>
            <Panel className="workspace-panel queue-v2-filters">
                <div className="queue-filter-row">
                    <label>
                        {t("statusLabel")}
                        <select
                            aria-label={t("statusLabel")}
                            value={filters.status ?? ""}
                            onChange={(event) => patchFilter("status", event.target.value || null)}
                        >
                            <option value="">{t("allStatuses")}</option>
                            {statuses.map((value) => (
                                <option key={value} value={value}>
                                    {t(statusKeys[value])}
                                </option>
                            ))}
                        </select>
                    </label>
                    <label>
                        {t("owner")}
                        <input
                            key={`owner-${filters.ownerKey ?? ""}`}
                            aria-label={t("owner")}
                            defaultValue={filters.ownerKey ?? ""}
                            placeholder={t("allOwners")}
                            maxLength={256}
                            onBlur={(event) =>
                                patchFilter("owner_key", event.target.value.trim() || null)
                            }
                            onKeyDown={(event) => {
                                if (event.key === "Enter") event.currentTarget.blur();
                            }}
                        />
                    </label>
                    <label>
                        {t("score")}
                        <select
                            aria-label={t("score")}
                            value={params.get("min_score") ?? ""}
                            onChange={(event) =>
                                patchFilter("min_score", event.target.value || null)
                            }
                        >
                            <option value="">0–100</option>
                            <option value="50">≥ 50</option>
                            <option value="75">≥ 75</option>
                        </select>
                    </label>
                    <label>
                        {t("filterRule")}
                        <input
                            key={`rule-${filters.ruleId ?? ""}`}
                            aria-label={t("filterRule")}
                            defaultValue={filters.ruleId ?? ""}
                            maxLength={128}
                            onBlur={(event) =>
                                patchFilter("rule_id", event.target.value.trim() || null)
                            }
                            onKeyDown={(event) => {
                                if (event.key === "Enter") event.currentTarget.blur();
                            }}
                        />
                    </label>
                </div>
            </Panel>
            {selectedCount > 0 && (
                <Panel className="workspace-panel bulk-toolbar queue-v2-bulk">
                    <span>{t("selectedCount").replace("{count}", String(selectedCount))}</span>
                    <label>
                        {t("owner")}
                        <input
                            aria-label={t("owner")}
                            value={ownerDraft}
                            onChange={(event) => setOwnerDraft(event.target.value)}
                            placeholder="analyst:leon"
                        />
                    </label>
                    <button
                        className="btn outline"
                        type="button"
                        disabled={selectedCount > 100 || bulk.isPending}
                        onClick={() =>
                            doBulk({ kind: "assign", owner_key: ownerDraft.trim() || null })
                        }
                    >
                        {t("bulkAssign")}
                    </button>
                    <select
                        aria-label={t("bulkStatus")}
                        defaultValue=""
                        disabled={bulk.isPending}
                        onChange={(event) => {
                            const value = parseStatus(event.target.value);
                            if (value) doBulk({ kind: "status", status: value });
                        }}
                    >
                        <option value="">{t("bulkStatus")}</option>
                        {statuses.map((value) => (
                            <option key={value} value={value}>
                                {t(statusKeys[value])}
                            </option>
                        ))}
                    </select>
                    <label>
                        {t("disposition")}
                        <select
                            value={bulkLabel}
                            onChange={(event) => {
                                const value = parseDispositionLabel(event.target.value);
                                if (value) setBulkLabel(value);
                            }}
                        >
                            <option value="true_positive">{t("truePositive")}</option>
                            <option value="benign_true_positive">{t("benignTruePositive")}</option>
                            <option value="false_positive">{t("falsePositiveDisposition")}</option>
                            <option value="duplicate">{t("duplicate")}</option>
                            <option value="undetermined">{t("undetermined")}</option>
                        </select>
                    </label>
                    {bulkLabel === "false_positive" && (
                        <label>
                            {t("reason")}
                            <select
                                value={bulkReason}
                                onChange={(event) => setBulkReason(event.target.value)}
                            >
                                <option value="">—</option>
                                {fpReasons.map((value) => (
                                    <option key={value} value={value}>
                                        {value}
                                    </option>
                                ))}
                            </select>
                        </label>
                    )}
                    {(bulkLabel === "false_positive" || bulkReason === "other") && (
                        <label>
                            {t("reason")}
                            <input
                                maxLength={2000}
                                value={bulkNote}
                                onChange={(event) => setBulkNote(event.target.value)}
                            />
                        </label>
                    )}
                    <label className="propagate-control">
                        <input
                            type="checkbox"
                            checked={propagate}
                            onChange={(event) => setPropagate(event.target.checked)}
                        />
                        {t("propagate")}
                    </label>
                    <button
                        className="btn outline"
                        type="button"
                        disabled={selectedCount > 100 || bulk.isPending}
                        onClick={bulkDisposition}
                    >
                        {t("bulkDisposition")}
                    </button>
                </Panel>
            )}
            {actionMessage && (
                <p className="workspace-action-message" role="status">
                    {actionMessage}
                </p>
            )}
            {queueQuery.isLoading ? (
                <WorkspaceLoading label={t("queue")} />
            ) : queueQuery.isError ? (
                <WorkspaceFailure
                    error={queueQuery.error}
                    t={t}
                    onRetry={() => void queueQuery.refetch()}
                />
            ) : (
                <Panel className="workspace-panel table-panel queue-v2-table-panel">
                    <div className="table-scroll">
                        <table className="workspace-table queue-table">
                            <thead>
                                <tr>
                                    <th>
                                        <span className="sr-only">{t("selectGroups")}</span>
                                    </th>
                                    <th>{t("group")}</th>
                                    <th>{t("score")}</th>
                                    <th>{t("groupCount")}</th>
                                    <th>{t("groupLast")}</th>
                                    <th>{t("owner")}</th>
                                    <th>{t("statusLabel")}</th>
                                    <th>{t("disposition")}</th>
                                </tr>
                            </thead>
                            <tbody>
                                {rows.map(
                                    ({ group, work_state: workState, queue_reasons: reasons }) => (
                                        <tr key={group.group_id}>
                                            <td>
                                                <input
                                                    type="checkbox"
                                                    aria-label={`${t("selectGroups")} ${group.title}`}
                                                    checked={selectedIds.has(group.group_id)}
                                                    onChange={(event) =>
                                                        setSelectedIds((current) => {
                                                            const next = new Set(current);
                                                            if (event.target.checked)
                                                                next.add(group.group_id);
                                                            else next.delete(group.group_id);
                                                            return next;
                                                        })
                                                    }
                                                />
                                            </td>
                                            <td>
                                                <button
                                                    className="text-link group-link"
                                                    type="button"
                                                    onClick={() => setSelectedId(group.group_id)}
                                                >
                                                    {group.title}
                                                </button>
                                                <span className="table-secondary queue-v2-entity">
                                                    {group.primary_entity && (
                                                        <span>{group.primary_entity.kind}</span>
                                                    )}
                                                    <code>
                                                        {group.primary_entity?.value ??
                                                            group.rule_id ??
                                                            "—"}
                                                    </code>
                                                </span>
                                                {reasons.length > 0 && (
                                                    <span className="table-secondary queue-v2-reasons">
                                                        {reasons.join(" · ")}
                                                    </span>
                                                )}
                                            </td>
                                            <td>
                                                <div className="queue-v2-score">
                                                    <strong>
                                                        {group.score === null
                                                            ? t("scorePending")
                                                            : group.score.toFixed(1)}
                                                    </strong>
                                                    {group.score !== null && (
                                                        <span
                                                            className="queue-v2-score-track"
                                                            aria-hidden="true"
                                                        >
                                                            <span
                                                                style={{
                                                                    width: `${scorePercent(group.score)}%`,
                                                                }}
                                                            />
                                                        </span>
                                                    )}
                                                </div>
                                                <span className="table-secondary">
                                                    {group.computation_version?.split(":")[0] ??
                                                        t("scorePending")}
                                                </span>
                                            </td>
                                            <td>{group.alert_count.toLocaleString()}</td>
                                            <td>{formatTime(group.last_ts)}</td>
                                            <td>{workState.owner_key ?? t("unassigned")}</td>
                                            <td>
                                                <div>
                                                    <Tag {...statusTags[workState.status]}>
                                                        {t(statusKeys[workState.status])}
                                                    </Tag>
                                                </div>
                                            </td>
                                            <td>
                                                {group.disposition ? (
                                                    <div>
                                                        <Tag
                                                            {...dispositionTags[
                                                                group.disposition.label
                                                            ]}
                                                        >
                                                            {t(labelKey(group.disposition.label))}
                                                        </Tag>
                                                    </div>
                                                ) : (
                                                    "—"
                                                )}
                                            </td>
                                        </tr>
                                    ),
                                )}
                            </tbody>
                        </table>
                    </div>
                    {rows.length === 0 && <p className="muted">{t("noData")}</p>}
                    <div className="page-controls">
                        <button
                            className="btn outline"
                            type="button"
                            disabled={!params.get("cursor")}
                            onClick={() => patchFilter("cursor", null)}
                        >
                            {t("previous")}
                        </button>
                        <button
                            className="btn outline"
                            type="button"
                            disabled={!queueQuery.data?.next_cursor}
                            onClick={() =>
                                patchFilter("cursor", queueQuery.data?.next_cursor ?? null)
                            }
                        >
                            {t("next")}
                        </button>
                    </div>
                </Panel>
            )}
            <Sheet
                open={selectedId !== null}
                onOpenChange={(open) => {
                    if (!open) setSelectedId(null);
                }}
            >
                {selectedId && (
                    <SheetContent
                        title={detail?.title ?? t("group")}
                        closeLabel={t("detailsClose")}
                    >
                        {detailQuery.isLoading ? (
                            <WorkspaceLoading label={t("group")} />
                        ) : detailQuery.isError ? (
                            <WorkspaceFailure
                                error={detailQuery.error}
                                t={t}
                                onRetry={() => void detailQuery.refetch()}
                            />
                        ) : detail ? (
                            <GroupDrawer
                                detail={detail}
                                t={t}
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
                                        {
                                            id: detail.group_id,
                                            next,
                                            expected: detail.work_state.updated_at,
                                        },
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
                                            onSuccess: () => setActionMessage(t("atomicAction")),
                                            onError: (error) => setActionMessage(error.message),
                                        },
                                    )
                                }
                            />
                        ) : null}
                    </SheetContent>
                )}
            </Sheet>
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
function GroupDrawer({
    detail: group,
    t,
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
    const [label, setLabel] = useState<DispositionLabel>("undetermined");
    const [reason, setReason] = useState("");
    const [note, setNote] = useState("");
    const [propagate, setPropagate] = useState(false);
    const [error, setError] = useState("");
    const save = () => {
        if (label === "false_positive" && !reason) {
            setError(t("reasonRequired"));
            return;
        }
        if (reason === "other" && !note.trim()) {
            setError(t("otherNoteRequired"));
            return;
        }
        setError("");
        onDisposition({
            label,
            reason: reason || null,
            note: note.trim() || null,
            propagateToMembers: propagate,
        });
    };
    return (
        <div className="group-drawer-body queue-v2-drawer">
            <div className="queue-v2-drawer-meta">
                <code>{group.group_id}</code>
                <div>
                    <Tag {...statusTags[group.work_state.status]}>
                        {t(statusKeys[group.work_state.status])}
                    </Tag>
                    {group.disposition && (
                        <Tag {...dispositionTags[group.disposition.label]}>
                            {t(labelKey(group.disposition.label))}
                        </Tag>
                    )}
                </div>
            </div>
            <div className="group-score-card">
                <strong>{group.score === null ? t("scorePending") : group.score.toFixed(1)}</strong>
                <span>{t("score")}</span>
                <small>
                    {group.computation_version
                        ? `${t("uncalibratedShort")} · ${group.computation_version}`
                        : t("scorePendingDescription")}
                </small>
                {group.score !== null && (
                    <span className="queue-v2-drawer-score" aria-hidden="true">
                        <span style={{ width: `${scorePercent(group.score)}%` }} />
                    </span>
                )}
            </div>
            <dl className="alert-detail-list">
                <dt>{t("group")}</dt>
                <dd>
                    <code>{group.group_id}</code>
                </dd>
                <dt>{t("m3MemberRevision")}</dt>
                <dd>
                    <code>{group.group_revision}</code>
                </dd>
                <dt>{t("groupCount")}</dt>
                <dd>{group.alert_count}</dd>
                <dt>{t("groupFirst")}</dt>
                <dd>{formatTime(group.first_ts)}</dd>
                <dt>{t("groupLast")}</dt>
                <dd>{formatTime(group.last_ts)}</dd>
                <dt>{t("scoreVersion")}</dt>
                <dd>{group.computation_version ?? "—"}</dd>
                <dt>{t("scoreDigest")}</dt>
                <dd>
                    <code>{group.input_digest ?? "—"}</code>
                </dd>
                <dt>{t("statusLabel")}</dt>
                <dd>
                    {t(statusKeys[group.work_state.status])} ·{" "}
                    {formatTime(group.work_state.updated_at)}
                </dd>
                {group.primary_entity && (
                    <>
                        <dt>{group.primary_entity.kind}</dt>
                        <dd>
                            <code>{group.primary_entity.value}</code>
                        </dd>
                    </>
                )}
            </dl>
            <section className="drawer-section">
                <h3>{t("scoreExplanation")}</h3>
                <ul className="score-components">
                    {group.components.map((component) => (
                        <li key={component.name}>
                            <div>
                                <strong>{component.name}</strong>
                                <span>{component.explanation}</span>
                            </div>
                            <code>
                                {component.available
                                    ? component.contribution.toFixed(1)
                                    : t("unavailableScore")}
                            </code>
                            {component.evidence_ids.length > 0 && (
                                <small>
                                    {t("evidenceLabel")}: {component.evidence_ids.join(", ")}
                                </small>
                            )}
                        </li>
                    ))}
                </ul>
            </section>
            <section className="drawer-section">
                <h3>{t("enrichmentProvenance")}</h3>
                {group.enrichments.length === 0 ? (
                    <p>{t("noData")}</p>
                ) : (
                    group.enrichments.map((item) => (
                        <div className="provenance-row" key={item.enrichment_id}>
                            <strong>{item.source}</strong>
                            <span>
                                {t("sourceVersion")}: {item.source_version}
                            </span>
                            <span>
                                {t("fetchedAt")}: {formatTime(item.fetched_at)}
                            </span>
                            <span>
                                {t("expiresAt")}:{" "}
                                {item.expires_at ? formatTime(item.expires_at) : "—"}
                            </span>
                            <pre
                                tabIndex={0}
                                role="group"
                                aria-label={`${t("enrichmentProvenance")}: ${item.source}`}
                            >
                                {JSON.stringify(item.value, null, 2)}
                            </pre>
                        </div>
                    ))
                )}
            </section>
            <section className="drawer-section">
                <h3>{t("groupMembers")}</h3>
                {group.members.items.map((alert) => (
                    <button
                        className="member-link"
                        type="button"
                        key={alert.alert_key}
                        onClick={() => onOpenAlert(alert.alert_key)}
                    >
                        <span>{alert.rule_description ?? alert.rule_id ?? "Alert"}</span>
                        <code>{alert.alert_key}</code>
                        <small>
                            {alert.agent_name ?? alert.agent_id ?? "—"} ·{" "}
                            {formatTime(alert.event_ts)}
                        </small>
                    </button>
                ))}
            </section>
            {group.members.next_cursor && (
                <button
                    className="btn outline"
                    type="button"
                    disabled={membersLoading}
                    onClick={onLoadMoreMembers}
                >
                    {membersLoading ? t("loading") : t("loadMoreMembers")}
                </button>
            )}
            <section className="drawer-section">
                <h3>
                    {t("owner")} / {t("statusLabel")}
                </h3>
                <label>
                    {t("owner")}
                    <input
                        aria-label={t("owner")}
                        value={owner}
                        onChange={(event) => setOwner(event.target.value)}
                    />
                </label>
                <div className="drawer-actions">
                    <button
                        className="btn outline"
                        type="button"
                        disabled={busy}
                        onClick={() => onAssign(owner.trim() || null)}
                    >
                        {owner.trim() ? t("assign") : t("unassign")}
                    </button>
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
                </div>
            </section>
            <section className="drawer-section">
                <h3>{t("disposition")}</h3>
                <label>
                    {t("disposition")}
                    <select
                        aria-label={t("disposition")}
                        value={label}
                        disabled={busy}
                        onChange={(event) => {
                            const value = parseDispositionLabel(event.target.value);
                            if (value) setLabel(value);
                        }}
                    >
                        <option value="true_positive">{t("truePositive")}</option>
                        <option value="benign_true_positive">{t("benignTruePositive")}</option>
                        <option value="false_positive">{t("falsePositiveDisposition")}</option>
                        <option value="duplicate">{t("duplicate")}</option>
                        <option value="undetermined">{t("undetermined")}</option>
                    </select>
                </label>
                {label === "false_positive" && (
                    <label>
                        {t("reason")}
                        <select
                            value={reason}
                            disabled={busy}
                            onChange={(event) => setReason(event.target.value)}
                        >
                            <option value="">—</option>
                            {fpReasons.map((value) => (
                                <option key={value} value={value}>
                                    {value}
                                </option>
                            ))}
                        </select>
                    </label>
                )}
                {(label === "false_positive" || reason === "other") && (
                    <label>
                        {t("reason")}
                        <textarea
                            maxLength={2000}
                            disabled={busy}
                            value={note}
                            onChange={(event) => setNote(event.target.value)}
                        />
                    </label>
                )}
                <label className="propagate-control">
                    <input
                        type="checkbox"
                        checked={propagate}
                        disabled={busy}
                        onChange={(event) => setPropagate(event.target.checked)}
                    />
                    {t("propagate")}
                </label>
                {error && (
                    <p className="alert error" role="alert">
                        {error}
                    </p>
                )}
                <button className="btn primary" type="button" disabled={busy} onClick={save}>
                    {t("saveDisposition")}
                </button>
            </section>
            <SheetClose asChild>
                <button className="btn outline" type="button">
                    {t("detailsClose")}
                </button>
            </SheetClose>
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
            return "disposition";
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
