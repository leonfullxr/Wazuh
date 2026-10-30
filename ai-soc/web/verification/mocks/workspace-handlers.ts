import { http, HttpResponse } from "msw";
import {
    workspaceAlertDetails,
    workspaceAlerts,
    workspaceIngestionHealth,
    workspaceOverview,
    workspaceSites,
} from "./workspace-fixtures";
import {
    assetTags,
    groupDetails,
    opsMetrics,
    qualityMetrics,
    queueRows,
    updateMockDisposition,
    updateMockWorkState,
} from "./workspace-group-fixtures";
import type { components } from "../../../contracts/workspace/v1/types.ts";
import {
    validateAssignRequest,
    validateAssetUpsertRequest,
    validateBulkActionRequest,
    validateDispositionRequest,
    validateStatusRequest,
} from "../../src/api/generated/workspace-validators.js";
import {
    demoChain,
    demoChainDetail,
    demoIds,
    demoIncident,
    demoIncidentDetail,
    demoIncidentEvent,
    demoGroupId,
    makeIncident,
    makeNarrative,
    newDemoIncidentId,
} from "./workspace-incident-fixtures";

const chainState = {
    summary: structuredClone(demoChain),
    detail: structuredClone(demoChainDetail),
};
const incidentStore = new Map([[demoIncident.incident_id, structuredClone(demoIncidentDetail)]]);
export function resetM3WorkspaceMocks(): void {
    chainState.summary = structuredClone(demoChain);
    chainState.detail = structuredClone(demoChainDetail);
    incidentStore.clear();
    incidentStore.set(demoIncident.incident_id, structuredClone(demoIncidentDetail));
}

const error = (status: number, code: string, message: string) =>
    HttpResponse.json(
        {
            code,
            message,
            retryable: status >= 500,
            trace_id: "synthetic-workspace-trace",
            details: null,
        },
        { status },
    );
const state = (url: URL) => {
    const scenario = url.searchParams.get("scenario");
    if (scenario?.startsWith("workspace_")) return scenario.slice("workspace_".length);
    return url.searchParams.get("ws_state");
};

export const workspaceHandlers = [
    http.get("/v1/workspace/chains", ({ request }) => {
        const url = new URL(request.url);
        const mode = state(url);
        if (mode === "denied") return error(403, "WORKSPACE_DENIED", "Site access is denied.");
        if (mode === "error") return error(503, "UNAVAILABLE", "Chain candidates are unavailable.");
        const selected = url.searchParams.get("state");
        const items = selected && selected !== chainState.summary.state ? [] : [chainState.summary];
        return HttpResponse.json({ items, next_cursor: null, limit: 25 });
    }),
    http.get("/v1/workspace/chains/:chainId", ({ params, request }) => {
        const mode = state(new URL(request.url));
        if (mode === "denied") return error(403, "WORKSPACE_DENIED", "Chain access is denied.");
        if (mode === "error") return error(503, "UNAVAILABLE", "Chain evidence is unavailable.");
        if (String(params.chainId) !== chainState.detail.chain_id)
            return error(404, "RESOURCE_UNKNOWN", "Chain candidate not found.");
        return HttpResponse.json(chainState.detail);
    }),
    http.post("/v1/workspace/chains/:chainId/dismiss", async ({ params, request }) => {
        if (!hasWriteHeaders(request))
            return error(403, "CSRF_DENIED", "Write security headers are required.");
        const body = await readObject(request);
        if (String(params.chainId) !== chainState.detail.chain_id)
            return error(404, "RESOURCE_UNKNOWN", "Chain candidate not found.");
        if (!matchesChainPins(body))
            return error(
                409,
                "VERSION_CONFLICT",
                "Candidate evidence changed. Refresh and review.",
            );
        chainState.summary = {
            ...chainState.summary,
            state: "dismissed",
            decision_version: chainState.summary.decision_version + 1,
            updated_at: new Date().toISOString(),
        };
        chainState.detail = { ...chainState.detail, ...chainState.summary };
        return HttpResponse.json({
            chain_id: chainState.detail.chain_id,
            state: "dismissed",
            updated_at: chainState.summary.updated_at,
            version: chainState.summary.decision_version,
        });
    }),
    http.post("/v1/workspace/chains/:chainId/promote", async ({ params, request }) => {
        if (!hasWriteHeaders(request))
            return error(403, "CSRF_DENIED", "Write security headers are required.");
        const body = await readObject(request);
        if (String(params.chainId) !== chainState.detail.chain_id)
            return error(404, "RESOURCE_UNKNOWN", "Chain candidate not found.");
        if (!matchesChainPins(body))
            return error(
                409,
                "VERSION_CONFLICT",
                "Candidate evidence changed. Refresh and review.",
            );
        const title = stringField(body, "title_override");
        const groupIds = chainState.detail.stages
            .map((stage) => stringField(stage, "group_id"))
            .filter(isGroupId);
        const incidentId = newDemoIncidentId();
        const created = makeIncident(
            incidentId,
            groupIds.length ? groupIds : [demoGroupId],
            title ?? null,
            null,
        );
        incidentStore.set(incidentId, created);
        chainState.summary = {
            ...chainState.summary,
            state: "promoted",
            decision_version: chainState.summary.decision_version + 1,
            updated_at: new Date().toISOString(),
        };
        chainState.detail = { ...chainState.detail, ...chainState.summary };
        return HttpResponse.json({
            incident_id: incidentId,
            incident: created.incident,
            members: groupIds,
            chain_state: "promoted",
        });
    }),
    http.get("/v1/workspace/incidents", ({ request }) => {
        const url = new URL(request.url);
        const mode = state(url);
        if (mode === "denied") return error(403, "WORKSPACE_DENIED", "Incident access is denied.");
        if (mode === "error") return error(503, "UNAVAILABLE", "Incidents are unavailable.");
        const items = [...incidentStore.values()].map((item) => ({
            incident_id: item.incident.incident_id,
            title: item.incident.title,
            owner_key: item.incident.owner_key,
            status: item.incident.status,
            work_version: item.incident.work_version,
            evidence_head: item.incident.evidence_head,
            revision_seq: item.incident.revision_seq,
            priority: item.incident.priority,
            created_at: demoIds.now,
            created_by: "analyst:demo",
        }));
        return HttpResponse.json({ items, next_cursor: null, limit: 25 });
    }),
    http.post("/v1/workspace/incidents", async ({ request }) => {
        if (!hasWriteHeaders(request))
            return error(403, "CSRF_DENIED", "Write security headers are required.");
        const body = await readObject(request);
        const siteId = stringField(body, "site_id");
        const groupIds = arrayField(body, "group_ids");
        if (
            !siteId ||
            !groupIds ||
            groupIds.length < 1 ||
            groupIds.length > 100 ||
            !groupIds.every(isGroupId)
        )
            return error(422, "INVALID_REQUEST", "Incident creation request is invalid.");
        const incidentId = newDemoIncidentId();
        const title = stringField(body, "title");
        const owner = stringField(body, "owner_key");
        const created = makeIncident(incidentId, groupIds, title ?? null, owner ?? null);
        incidentStore.set(incidentId, created);
        return HttpResponse.json(
            {
                incident_id: incidentId,
                incident: created.incident,
                members: groupIds,
                work_version: 1,
                evidence_revision: created.incident.evidence_head,
            },
            { status: 201 },
        );
    }),
    http.get("/v1/workspace/incidents/:incidentId", ({ params, request }) => {
        const mode = state(new URL(request.url));
        if (mode === "denied") return error(403, "WORKSPACE_DENIED", "Incident access is denied.");
        if (mode === "error") return error(503, "UNAVAILABLE", "Incident detail is unavailable.");
        const found = incidentStore.get(String(params.incidentId));
        return found
            ? HttpResponse.json(found)
            : error(404, "RESOURCE_UNKNOWN", "Incident not found.");
    }),
    http.get("/v1/workspace/incidents/:incidentId/events", ({ params, request }) => {
        const url = new URL(request.url);
        const mode = state(url);
        if (mode === "denied") return error(403, "WORKSPACE_DENIED", "Incident access is denied.");
        if (mode === "error") return error(503, "UNAVAILABLE", "Incident timeline is unavailable.");
        const found = incidentStore.get(String(params.incidentId));
        if (!found) return error(404, "RESOURCE_UNKNOWN", "Incident not found.");
        const cursor = url.searchParams.get("cursor");
        return HttpResponse.json({
            events: cursor ? [] : [demoIncidentEvent],
            evidence_revision: found.incident.evidence_head,
            limit: 100,
            next_cursor: null,
        });
    }),
    http.get("/v1/workspace/incidents/:incidentId/narrative", ({ params, request }) => {
        const url = new URL(request.url);
        const mode = state(url);
        if (mode === "denied") return error(403, "WORKSPACE_DENIED", "Narrative access is denied.");
        if (mode === "error") return error(503, "UNAVAILABLE", "Narrative is unavailable.");
        if (String(params.incidentId) !== demoIds.incidentId)
            return error(404, "RESOURCE_UNKNOWN", "Incident narrative not found.");
        const requestedRevision = url.searchParams.get("evidence_revision") ?? undefined;
        if (requestedRevision && !/^[0-9a-f-]{36}$/.test(requestedRevision))
            return error(400, "INVALID_EVIDENCE_REVISION", "Evidence revision is malformed.");
        if (mode === "narrative_pending")
            return HttpResponse.json({
                ...makeNarrative({ status: "pending" }),
                evidence_revision: demoIds.evidenceRevision,
                is_current: true,
            });
        if (mode === "narrative_unavailable")
            return HttpResponse.json({
                ...makeNarrative({ status: "unavailable" }),
                evidence_revision: demoIds.evidenceRevision,
                is_current: true,
            });
        if (mode === "narrative_all_removed")
            return HttpResponse.json({
                ...makeNarrative({ allRemoved: true }),
                evidence_revision: demoIds.evidenceRevision,
                is_current: true,
            });
        return HttpResponse.json(
            makeNarrative({
                evidenceRevision: requestedRevision ?? demoIds.evidenceRevision,
            }),
        );
    }),
    http.get("/v1/workspace/incidents/:incidentId/context", ({ params, request }) => {
        const url = new URL(request.url);
        const mode = state(url);
        if (mode === "denied")
            return error(403, "WORKSPACE_DENIED", "Incident context access is denied.");
        if (mode === "error") return error(503, "UNAVAILABLE", "Incident context is unavailable.");
        const found = incidentStore.get(String(params.incidentId));
        if (!found) return error(404, "RESOURCE_UNKNOWN", "Incident not found.");
        return HttpResponse.json({
            evidence_revision: found.incident.evidence_head,
            evidence_digest: "9".repeat(64),
            from: null,
            to: null,
            entities: [{ kind: "user", role: "destination_user", value: "ops" }],
            sampled_alerts: [
                {
                    event_ts: demoIncidentEvent.event_ts,
                    alert_key: demoIncidentEvent.alert_key,
                    fields: demoIncidentEvent.fields,
                },
            ],
            sample_limit: 100,
            omitted_count: 0,
            omitted_count_is_lower_bound: false,
            omitted_entity_count: 0,
            omissions_capped: false,
            question_draft: {
                editable: true,
                request: {
                    question: `Investigate incident ${found.incident.incident_id} and its frozen evidence.`,
                    environment_id: url.searchParams.get("site_id"),
                    timezone: "UTC",
                },
            },
        });
    }),
    http.post("/v1/workspace/incidents/:incidentId/:action", async ({ params, request }) => {
        if (!hasWriteHeaders(request))
            return error(403, "CSRF_DENIED", "Write security headers are required.");
        const body = await readObject(request);
        const action = String(params.action);
        if (!["assign", "comment", "disposition", "members", "status"].includes(action))
            return error(404, "RESOURCE_UNKNOWN", "Incident action not found.");
        const incidentId = String(params.incidentId);
        const found = incidentStore.get(incidentId);
        if (!found) return error(404, "RESOURCE_UNKNOWN", "Incident not found.");
        const expected = numberField(body, "expected_work_version");
        if (expected !== found.incident.work_version)
            return error(409, "VERSION_CONFLICT", "Incident work changed. Refresh and review.");
        const oldIncident = found.incident;
        const version = oldIncident.work_version + 1;
        let next: typeof found = { ...found, incident: { ...oldIncident, work_version: version } };
        if (action === "assign") {
            const ownerKey = stringField(body, "owner_key");
            next = { ...next, incident: { ...next.incident, owner_key: ownerKey ?? null } };
        } else if (action === "status") {
            const nextStatus = stringField(body, "status");
            if (
                nextStatus !== "new" &&
                nextStatus !== "in_progress" &&
                nextStatus !== "resolved" &&
                nextStatus !== "closed"
            )
                return error(422, "INVALID_REQUEST", "Status is invalid.");
            next = { ...next, incident: { ...next.incident, status: nextStatus } };
        } else if (action === "members") {
            const add = (arrayField(body, "add_group_ids") ?? []).filter(isGroupId);
            const remove = (arrayField(body, "remove_group_ids") ?? []).filter(isGroupId);
            const members = next.members.filter((member) => !remove.includes(member.group_id));
            const currentIds = new Set(members.map((member) => member.group_id));
            const additions = add
                .filter((groupId) => !currentIds.has(groupId))
                .map((groupId) => ({
                    group_id: groupId,
                    group_revision: "f".repeat(64),
                    title: "Manually added group",
                    first_ts: demoIds.now,
                    last_ts: demoIds.now,
                    alert_count: 1,
                    score: null,
                    score_version: null,
                    score_digest: null,
                }));
            next = {
                ...next,
                members: [...members, ...additions],
                incident: {
                    ...next.incident,
                    evidence_head: crypto.randomUUID(),
                    revision_seq: next.incident.revision_seq + 1,
                },
            };
        } else if (action === "comment") {
            const bodyText = stringField(body, "body");
            if (!bodyText?.trim())
                return error(422, "INVALID_REQUEST", "Comment body is required.");
            next = {
                ...next,
                comments: [
                    ...next.comments,
                    {
                        comment_id: crypto.randomUUID(),
                        body: bodyText,
                        actor_key: "analyst:demo",
                        at: new Date().toISOString(),
                        evidence_revision: next.incident.evidence_head,
                        work_version: version,
                    },
                ],
            };
        } else if (action === "disposition") {
            const label = stringField(body, "label");
            const expectedEvidence = stringField(body, "expected_evidence_revision");
            if (expectedEvidence !== oldIncident.evidence_head)
                return error(
                    409,
                    "VERSION_CONFLICT",
                    "Incident evidence changed. Refresh and review.",
                );
            if (
                label !== "true_positive" &&
                label !== "benign_true_positive" &&
                label !== "false_positive" &&
                label !== "duplicate" &&
                label !== "undetermined"
            )
                return error(422, "INVALID_REQUEST", "Disposition label is invalid.");
            const reason = stringField(body, "reason_code");
            const note = stringField(body, "note");
            const reasons = [
                "expected_admin_activity",
                "known_scanner",
                "misconfigured_rule",
                "test_activity",
                "other",
            ];
            if (body.propagate_to_members === true)
                return error(422, "VALIDATION_ERROR", "Incident dispositions cannot propagate.");
            if (label === "false_positive" && (!reason || !reasons.includes(reason)))
                return error(
                    422,
                    "VALIDATION_ERROR",
                    "A supported false-positive reason is required.",
                );
            if (reason === "other" && !note?.trim())
                return error(422, "VALIDATION_ERROR", "Other requires a note.");
            next = {
                ...next,
                dispositions: [
                    ...next.dispositions,
                    {
                        disposition_id: crypto.randomUUID(),
                        evidence_revision: oldIncident.evidence_head,
                        work_version: version,
                        label,
                        reason_code: reason ?? null,
                        note: stringField(body, "note") ?? null,
                        actor_key: "analyst:demo",
                        at: new Date().toISOString(),
                    },
                ],
            };
        }
        const at = new Date().toISOString();
        next = {
            ...next,
            history: [
                ...next.history,
                {
                    history_id: crypto.randomUUID(),
                    work_version: version,
                    action,
                    before: {
                        owner_key: oldIncident.owner_key,
                        status: oldIncident.status,
                        work_version: oldIncident.work_version,
                    },
                    after: {
                        owner_key: next.incident.owner_key,
                        status: next.incident.status,
                        work_version: next.incident.work_version,
                        evidence_head: next.incident.evidence_head,
                    },
                    actor_key: "analyst:demo",
                    at,
                },
            ],
        };
        incidentStore.set(incidentId, next);
        return HttpResponse.json({
            incident_id: incidentId,
            incident: next.incident,
            members: next.members.map((member) => member.group_id),
            work_version: version,
            evidence_revision: next.incident.evidence_head,
        });
    }),
    http.get("/v1/workspace/sites", ({ request }) => {
        const mode = state(new URL(request.url));
        if (mode === "denied") return error(403, "WORKSPACE_DENIED", "Site access is denied.");
        if (mode === "error") return error(503, "UNAVAILABLE", "Workspace API is unavailable.");
        return HttpResponse.json(workspaceSites);
    }),
    http.get("/v1/workspace/overview", ({ request }) => {
        const url = new URL(request.url);
        const mode = state(url);
        if (mode === "denied") return error(403, "WORKSPACE_DENIED", "Site access is denied.");
        if (mode === "error") return error(503, "UNAVAILABLE", "Workspace API is unavailable.");
        const bounds = workspaceOverview(
            url.searchParams.get("from") ?? new Date(Date.now() - 86_400_000).toISOString(),
            url.searchParams.get("to") ?? new Date().toISOString(),
        );
        if (mode === "quiet") {
            bounds.totals.alerts = 0;
            bounds.hourly = bounds.hourly.map((bucket) => ({ ...bucket, count: 0 }));
            bounds.top_rules = [];
            bounds.top_agents = [];
            bounds.top_tactics = [];
            bounds.top_src_ips = [];
            bounds.top_users = [];
        }
        if (mode === "stalled") {
            bounds.freshness.state = "unreachable";
            bounds.freshness.last_success_at = null;
            bounds.freshness.lag_seconds = null;
        }
        return HttpResponse.json(bounds);
    }),
    http.get("/v1/workspace/alerts", ({ request }) => {
        const url = new URL(request.url);
        const mode = state(url);
        if (mode === "denied") return error(403, "WORKSPACE_DENIED", "Site access is denied.");
        if (mode === "error") return error(503, "UNAVAILABLE", "Workspace API is unavailable.");
        const rule = url.searchParams.get("rule_id");
        const agent = url.searchParams.get("agent_id");
        const minLevel = Number(url.searchParams.get("min_level") ?? 0);
        const maxLevel = Number(url.searchParams.get("max_level") ?? 15);
        const filtered = workspaceAlerts.filter(
            (alert) =>
                (!rule || alert.rule_id === rule) &&
                (!agent || alert.agent_id === agent) &&
                (alert.rule_level ?? 0) >= minLevel &&
                (alert.rule_level ?? 15) <= maxLevel &&
                (!url.searchParams.has("tactic") ||
                    alert.mitre_tactics.includes(url.searchParams.get("tactic") ?? "")) &&
                (!url.searchParams.has("entity") ||
                    (url.searchParams.get("entity_kind") === "ip" &&
                        alert.src_ip === url.searchParams.get("entity")) ||
                    (url.searchParams.get("entity_kind") === "user" &&
                        (alert.src_user === url.searchParams.get("entity") ||
                            alert.dst_user === url.searchParams.get("entity")))),
        );
        const pageSize = 2;
        const cursor = url.searchParams.get("cursor");
        const offset = cursor === "next" ? pageSize : 0;
        const items = filtered.slice(offset, offset + pageSize);
        return HttpResponse.json({
            items,
            next_cursor: filtered.length > offset + pageSize ? "next" : null,
            limit: 50,
        });
    }),
    http.get("/v1/workspace/alerts/:alertKey", ({ params, request }) => {
        const mode = state(new URL(request.url));
        if (mode === "denied") return error(403, "WORKSPACE_DENIED", "Site access is denied.");
        const key = decodeURIComponent(String(params.alertKey));
        const detail = workspaceAlertDetails.find((alert) => alert.alert_key === key);
        return detail
            ? HttpResponse.json(detail)
            : error(404, "RESOURCE_UNKNOWN", "Alert not found.");
    }),
    http.get("/v1/workspace/health/ingestion", ({ request }) => {
        const mode = state(new URL(request.url));
        if (mode === "denied") return error(403, "WORKSPACE_DENIED", "Site access is denied.");
        if (mode === "error") return error(503, "UNAVAILABLE", "Ingestion health is unavailable.");
        return HttpResponse.json(workspaceIngestionHealth(mode === "stalled"));
    }),
    http.get("/v1/workspace/queue", ({ request }) => {
        const url = new URL(request.url);
        const mode = state(url);
        if (mode === "denied") return error(403, "WORKSPACE_DENIED", "Site access is denied.");
        if (mode === "error") return error(503, "UNAVAILABLE", "Queue is unavailable.");
        const status = url.searchParams.get("status");
        const owner = url.searchParams.get("owner_key");
        const rule = url.searchParams.get("rule_id");
        const min = Number(url.searchParams.get("min_score") ?? 0);
        const items = queueRows.filter(
            ({ group, work_state }) =>
                (!status || work_state.status === status) &&
                (!owner || work_state.owner_key === owner) &&
                (!rule || group.rule_id === rule) &&
                (group.score === null ? min === 0 : group.score >= min),
        );
        return HttpResponse.json({ items, next_cursor: null, limit: 50 });
    }),
    http.get("/v1/workspace/groups/:groupId", ({ params, request }) => {
        const url = new URL(request.url);
        const mode = state(url);
        if (mode === "denied") return error(403, "WORKSPACE_DENIED", "Group access is denied.");
        const detail = groupDetails.get(String(params.groupId));
        if (!detail) return error(404, "RESOURCE_UNKNOWN", "Group not found.");
        if (mode === "provenance_scroll") {
            const [enrichment] = detail.enrichments;
            if (!enrichment) return HttpResponse.json(detail);
            const observations = Array.from({ length: 64 }, (_, index) => ({
                sequence: index + 1,
                status: "captured",
                source_ref: `workspace.snapshot.${String(index + 1).padStart(3, "0")}`,
                evidence_sha256: "ab".repeat(32),
            }));
            return HttpResponse.json({
                ...detail,
                enrichments: [
                    {
                        ...enrichment,
                        enrichment_id: `${enrichment.enrichment_id}-old`,
                        value: { snapshot: "older", observations },
                    },
                    {
                        ...enrichment,
                        enrichment_id: `${enrichment.enrichment_id}-new`,
                        value: { snapshot: "newer", observations },
                    },
                ],
            });
        }
        if (url.searchParams.get("member_cursor") === "members-next") {
            return HttpResponse.json({
                ...detail,
                members: {
                    items: [workspaceAlerts[2]],
                    next_cursor: null,
                    limit: 50,
                },
            });
        }
        return HttpResponse.json(detail);
    }),
    http.post("/v1/workspace/groups/:groupId/assign", async ({ params, request }) => {
        if (!hasWriteHeaders(request))
            return error(403, "CSRF_DENIED", "Write security headers are required.");
        const body: unknown = await request.json();
        if (!validateAssignRequest(body))
            return error(422, "INVALID_REQUEST", "Assignment request is invalid.");
        const current = groupDetails.get(String(params.groupId));
        if (!current) return error(404, "RESOURCE_UNKNOWN", "Group not found.");
        const next = {
            ...current.work_state,
            owner_key: body.owner_key,
            updated_at: new Date().toISOString(),
        };
        updateMockWorkState(current.group_id, next);
        return HttpResponse.json(next);
    }),
    http.post("/v1/workspace/groups/:groupId/status", async ({ params, request }) => {
        if (!hasWriteHeaders(request))
            return error(403, "CSRF_DENIED", "Write security headers are required.");
        const body: unknown = await request.json();
        if (!validateStatusRequest(body))
            return error(422, "INVALID_REQUEST", "Status request is invalid.");
        const current = groupDetails.get(String(params.groupId));
        if (!current) return error(404, "RESOURCE_UNKNOWN", "Group not found.");
        if (current.work_state.updated_at !== body.expected_updated_at)
            return error(409, "VERSION_CONFLICT", "Work state changed. Refresh and retry.");
        const next = {
            ...current.work_state,
            status: body.status,
            updated_at: new Date().toISOString(),
        };
        updateMockWorkState(current.group_id, next);
        return HttpResponse.json(next);
    }),
    http.post("/v1/workspace/groups/:groupId/disposition", async ({ params, request }) => {
        if (!hasWriteHeaders(request))
            return error(403, "CSRF_DENIED", "Write security headers are required.");
        const body: unknown = await request.json();
        if (!validateDispositionRequest(body))
            return error(422, "INVALID_REQUEST", "Disposition request is invalid.");
        const current = groupDetails.get(String(params.groupId));
        if (!current) return error(404, "RESOURCE_UNKNOWN", "Group not found.");
        const saved: components["schemas"]["Disposition"] = {
            disposition_id: crypto.randomUUID(),
            label: body.label,
            reason_code: body.reason_code ?? null,
            note: body.note ?? null,
            actor_key: "analyst:mock",
            at: new Date().toISOString(),
            propagate_to_members: body.propagate_to_members ?? false,
        };
        updateMockDisposition(current.group_id, saved);
        return HttpResponse.json(saved);
    }),
    http.post("/v1/workspace/bulk", async ({ request }) => {
        if (!hasWriteHeaders(request))
            return error(403, "CSRF_DENIED", "Write security headers are required.");
        const body: unknown = await request.json();
        if (!validateBulkActionRequest(body))
            return error(422, "INVALID_REQUEST", "Bulk request is invalid.");
        const items = body.group_ids.map((groupId: string) => {
            const current = groupDetails.get(groupId);
            if (!current) return { group_id: groupId, result: { updated: false } };
            if (body.action.kind === "assign" || body.action.kind === "status") {
                const stateValue =
                    body.action.kind === "assign"
                        ? {
                              ...current.work_state,
                              owner_key: body.action.owner_key,
                              updated_at: new Date().toISOString(),
                          }
                        : {
                              ...current.work_state,
                              status: body.action.status,
                              updated_at: new Date().toISOString(),
                          };
                updateMockWorkState(groupId, stateValue);
            } else {
                const saved: components["schemas"]["Disposition"] = {
                    disposition_id: crypto.randomUUID(),
                    label: body.action.label,
                    reason_code: body.action.reason_code ?? null,
                    note: body.action.note ?? null,
                    actor_key: "analyst:mock",
                    at: new Date().toISOString(),
                    propagate_to_members: body.action.propagate_to_members ?? false,
                };
                updateMockDisposition(groupId, saved);
            }
            return { group_id: groupId, result: { updated: true } };
        });
        return HttpResponse.json({
            updated: items.filter((item: { result: { updated: boolean } }) => item.result.updated)
                .length,
            items,
        });
    }),
    http.get("/v1/workspace/metrics/ops", ({ request }) => {
        const mode = state(new URL(request.url));
        if (mode === "denied") return error(403, "WORKSPACE_DENIED", "Metrics access is denied.");
        if (mode === "error")
            return error(503, "UNAVAILABLE", "Operational metrics are unavailable.");
        const url = new URL(request.url);
        return HttpResponse.json({
            ...opsMetrics,
            window: {
                ...opsMetrics.window,
                from: url.searchParams.get("from") ?? opsMetrics.window.from,
                to: url.searchParams.get("to") ?? opsMetrics.window.to,
            },
        });
    }),
    http.get("/v1/workspace/metrics/quality", ({ request }) => {
        const mode = state(new URL(request.url));
        if (mode === "denied") return error(403, "WORKSPACE_DENIED", "Metrics access is denied.");
        if (mode === "error") return error(503, "UNAVAILABLE", "Quality metrics are unavailable.");
        return HttpResponse.json(qualityMetrics);
    }),
    http.get("/v1/workspace/assets", ({ request }) => {
        const mode = state(new URL(request.url));
        if (mode === "denied") return error(403, "WORKSPACE_DENIED", "Asset access is denied.");
        if (mode === "error") return error(503, "UNAVAILABLE", "Asset tags are unavailable.");
        const q = new URL(request.url).searchParams.get("q")?.toLowerCase();
        const items = assetTags.filter(
            (asset) =>
                !q ||
                asset.entity_value.toLowerCase().includes(q) ||
                asset.tags.some((tag) => tag.toLowerCase().includes(q)),
        );
        return HttpResponse.json({ items, next_cursor: null, limit: 100 });
    }),
    http.put("/v1/workspace/assets", async ({ request }) => {
        if (!hasWriteHeaders(request))
            return error(403, "CSRF_DENIED", "Write security headers are required.");
        const body: unknown = await request.json();
        if (!validateAssetUpsertRequest(body))
            return error(422, "INVALID_REQUEST", "Asset tag request is invalid.");
        const existing = assetTags.find(
            (asset) => asset.site_id === body.site_id && asset.entity_id === body.entity_id,
        );
        if (!existing) return error(404, "RESOURCE_UNKNOWN", "Asset not found.");
        const saved: components["schemas"]["AssetTag"] = {
            ...existing,
            criticality: body.criticality,
            tags: body.tags,
            set_by: "analyst:mock",
            set_at: new Date().toISOString(),
        };
        assetTags.splice(assetTags.indexOf(existing), 1, saved);
        return HttpResponse.json(saved);
    }),
];

function hasWriteHeaders(request: Request): boolean {
    return Boolean(request.headers.get("X-SOC-CSRF") && request.headers.get("Idempotency-Key"));
}

async function readObject(request: Request): Promise<Record<string, unknown>> {
    try {
        const value: unknown = await request.json();
        return isRecord(value) ? value : {};
    } catch {
        return {};
    }
}

function isRecord(value: unknown): value is Record<string, unknown> {
    return typeof value === "object" && value !== null && !Array.isArray(value);
}

function stringField(value: Record<string, unknown>, key: string): string | undefined {
    const candidate = value[key];
    return typeof candidate === "string" ? candidate : undefined;
}

function numberField(value: Record<string, unknown>, key: string): number | undefined {
    const candidate = value[key];
    return typeof candidate === "number" && Number.isSafeInteger(candidate) ? candidate : undefined;
}

function arrayField(value: Record<string, unknown>, key: string): unknown[] | undefined {
    const candidate = value[key];
    return Array.isArray(candidate) ? candidate : undefined;
}

function isGroupId(value: unknown): value is string {
    return typeof value === "string" && /^[0-9a-f]{64}$/.test(value);
}

function matchesChainPins(value: Record<string, unknown>): boolean {
    return (
        value.expected_revision === chainState.detail.revision_digest &&
        value.expected_manifest_id === chainState.detail.manifest_id &&
        value.expected_decision_version === chainState.detail.decision_version &&
        typeof value.site_id === "string"
    );
}
