import type { components } from "../../../contracts/workspace/v1/types.ts";
import {
    validateAlertDetail,
    validateAlertPage,
    validateIngestionHealth,
    validateOverview,
    validateSitePage,
    validateWorkspaceError,
    validateQueuePage,
    validateGroupDetail,
    validateWorkState,
    validateDisposition,
    validateBulkActionResponse,
    validateAssetPage,
    validateAssetTag,
    validateOpsMetrics,
    validateQualityMetrics,
} from "./generated/workspace-validators.js";
import { currentCsrfToken } from "./client";

export type SiteSummary = components["schemas"]["SiteSummary"];
export type OverviewResponse = components["schemas"]["OverviewResponse"];
export type AlertSummary = components["schemas"]["AlertSummary"];
export type AlertDetail = components["schemas"]["AlertDetail"];
export type AlertPage = components["schemas"]["Page_AlertSummary_"];
export type SitePage = components["schemas"]["Page_SiteSummary_"];
export type IngestionHealthResponse = components["schemas"]["IngestionHealthResponse"];
export type QueuePage = components["schemas"]["Page_QueueSummary_"];
export type QueueSummary = components["schemas"]["QueueSummary"];
export type GroupDetail = components["schemas"]["GroupDetail"];
export type WorkState = components["schemas"]["WorkState"];
export type WorkStatus = components["schemas"]["WorkState"]["status"];
export type Disposition = components["schemas"]["Disposition"];
export type DispositionLabel = components["schemas"]["Disposition"]["label"];
export type ScoreComponent = components["schemas"]["ScoreComponent"];
export type OpsMetricsResponse = components["schemas"]["OpsMetricsResponse"];
export type QualityMetricsResponse = components["schemas"]["QualityMetricsResponse"];
export type AssetTag = components["schemas"]["AssetTag"];
export type AssetPage = components["schemas"]["Page_AssetTag_"];
export type MetricStats = components["schemas"]["MetricStats"];

export class WorkspaceRequestError extends Error {
    constructor(
        readonly status: number,
        readonly code: string | null,
        message: string,
    ) {
        super(message);
        this.name = "WorkspaceRequestError";
    }
}

type Validator<T> = (value: unknown) => value is T;

async function request<T>(path: string, validator: Validator<T>, signal?: AbortSignal): Promise<T> {
    const url = new URL(path, location.origin);
    if (import.meta.env.MODE !== "live") {
        const scenario = new URLSearchParams(location.search).get("scenario");
        if (scenario) url.searchParams.set("scenario", scenario);
    }
    const response = await fetch(`${url.pathname}${url.search}`, {
        method: "GET",
        headers: { Accept: "application/json" },
        credentials: "same-origin",
        signal,
    });
    let body: unknown = null;
    try {
        if (response.headers.get("Content-Type")?.toLowerCase().includes("application/json"))
            body = await response.json();
    } catch {
        body = null;
    }
    if (!response.ok) {
        const error = validateWorkspaceError(body) ? body : null;
        throw new WorkspaceRequestError(
            response.status,
            error?.code ?? null,
            error?.message ?? `Workspace request failed with HTTP ${response.status}`,
        );
    }
    if (!validator(body))
        throw new WorkspaceRequestError(
            response.status,
            "INVALID_RESPONSE",
            "The workspace returned an invalid response.",
        );
    return body;
}

async function writeRequest<T>(
    path: string,
    body: object,
    validator: Validator<T>,
    signal?: AbortSignal,
): Promise<T> {
    const token = currentCsrfToken();
    if (!token)
        throw new WorkspaceRequestError(
            0,
            "CSRF_UNAVAILABLE",
            "The session security token is unavailable. Refresh the page and try again.",
        );
    const url = new URL(path, location.origin);
    if (import.meta.env.MODE !== "live") {
        const scenario = new URLSearchParams(location.search).get("scenario");
        if (scenario) url.searchParams.set("scenario", scenario);
    }
    const response = await fetch(`${url.pathname}${url.search}`, {
        method: path.endsWith("/assets") ? "PUT" : "POST",
        headers: {
            Accept: "application/json",
            "Content-Type": "application/json",
            "X-SOC-CSRF": token,
            "Idempotency-Key": crypto.randomUUID(),
        },
        credentials: "same-origin",
        signal,
        body: JSON.stringify(body),
    });
    return decodeResponse(response, validator);
}

async function decodeResponse<T>(response: Response, validator: Validator<T>): Promise<T> {
    let body: unknown = null;
    try {
        if (response.headers.get("Content-Type")?.toLowerCase().includes("application/json"))
            body = await response.json();
    } catch {
        body = null;
    }
    if (!response.ok) {
        const error = validateWorkspaceError(body) ? body : null;
        throw new WorkspaceRequestError(
            response.status,
            error?.code ?? null,
            error?.message ?? `Workspace request failed with HTTP ${response.status}`,
        );
    }
    if (!validator(body))
        throw new WorkspaceRequestError(
            response.status,
            "INVALID_RESPONSE",
            "The workspace returned an invalid response.",
        );
    return body;
}

function query(values: Record<string, string | number | boolean | null | undefined>): string {
    const params = new URLSearchParams();
    for (const [key, value] of Object.entries(values)) {
        if (value !== null && value !== undefined && value !== "") params.set(key, String(value));
    }
    return params.toString();
}

export function listWorkspaceSites(signal?: AbortSignal) {
    return request<SitePage>("/v1/workspace/sites?limit=200", validateSitePage, signal);
}

export function getOverview(
    params: { siteId: string; from: string; to: string; timezone: string },
    signal?: AbortSignal,
) {
    const search = query({
        site_id: params.siteId,
        from: params.from,
        to: params.to,
        tz: params.timezone,
    });
    return request<OverviewResponse>(`/v1/workspace/overview?${search}`, validateOverview, signal);
}

export type AlertFilters = {
    siteId: string;
    from: string;
    to: string;
    ruleId?: string;
    agentId?: string;
    minLevel?: number;
    maxLevel?: number;
    tactic?: string;
    entityKind?: string;
    entity?: string;
    cursor?: string;
};

export function listAlerts(filters: AlertFilters, signal?: AbortSignal) {
    const search = query({
        site_id: filters.siteId,
        from: filters.from,
        to: filters.to,
        rule_id: filters.ruleId,
        agent_id: filters.agentId,
        min_level: filters.minLevel,
        max_level: filters.maxLevel,
        tactic: filters.tactic,
        entity_kind: filters.entityKind,
        entity: filters.entity,
        cursor: filters.cursor,
        limit: 50,
    });
    return request<AlertPage>(`/v1/workspace/alerts?${search}`, validateAlertPage, signal);
}

export function getAlert(siteId: string, alertKey: string, signal?: AbortSignal) {
    const search = query({ site_id: siteId });
    return request<AlertDetail>(
        `/v1/workspace/alerts/${encodeURIComponent(alertKey)}?${search}`,
        validateAlertDetail,
        signal,
    );
}

export function getIngestionHealth(siteId: string, signal?: AbortSignal) {
    const search = query({ site_id: siteId });
    return request<IngestionHealthResponse>(
        `/v1/workspace/health/ingestion?${search}`,
        validateIngestionHealth,
        signal,
    );
}

export type QueueFilters = {
    siteId: string;
    from: string;
    to: string;
    minScore?: number;
    maxScore?: number;
    status?: WorkStatus;
    ownerKey?: string;
    unassigned?: boolean;
    ruleId?: string;
    entityKind?: string;
    entity?: string;
    cursor?: string;
};

export function listQueue(filters: QueueFilters, signal?: AbortSignal) {
    const search = query({
        site_id: filters.siteId,
        from: filters.from,
        to: filters.to,
        min_score: filters.minScore,
        max_score: filters.maxScore,
        status: filters.status,
        owner_key: filters.ownerKey,
        unassigned: filters.unassigned,
        rule_id: filters.ruleId,
        entity_kind: filters.entityKind,
        entity: filters.entity,
        sort: "priority_desc",
        limit: 50,
        cursor: filters.cursor,
    });
    return request<QueuePage>(`/v1/workspace/queue?${search}`, validateQueuePage, signal);
}

export function getGroup(
    siteId: string,
    groupId: string,
    memberCursor?: string,
    signal?: AbortSignal,
) {
    const search = query({ site_id: siteId, member_limit: 50, member_cursor: memberCursor });
    return request<GroupDetail>(
        `/v1/workspace/groups/${encodeURIComponent(groupId)}?${search}`,
        validateGroupDetail,
        signal,
    );
}

export function assignGroup(
    siteId: string,
    groupId: string,
    ownerKey: string | null,
    signal?: AbortSignal,
) {
    return writeRequest<WorkState>(
        `/v1/workspace/groups/${encodeURIComponent(groupId)}/assign`,
        { site_id: siteId, owner_key: ownerKey },
        validateWorkState,
        signal,
    );
}

export function updateGroupStatus(
    siteId: string,
    groupId: string,
    status: WorkStatus,
    expectedUpdatedAt: string,
    signal?: AbortSignal,
) {
    return writeRequest<WorkState>(
        `/v1/workspace/groups/${encodeURIComponent(groupId)}/status`,
        { site_id: siteId, status, expected_updated_at: expectedUpdatedAt },
        validateWorkState,
        signal,
    );
}

export function labelGroup(
    siteId: string,
    groupId: string,
    body: {
        label: DispositionLabel;
        reason_code: string | null;
        note: string | null;
        propagate_to_members: boolean;
    },
    signal?: AbortSignal,
) {
    return writeRequest<Disposition>(
        `/v1/workspace/groups/${encodeURIComponent(groupId)}/disposition`,
        { site_id: siteId, ...body },
        validateDisposition,
        signal,
    );
}

export type BulkAction = components["schemas"]["BulkActionRequest"]["action"];
export function bulkAction(
    siteId: string,
    groupIds: string[],
    action: BulkAction,
    signal?: AbortSignal,
) {
    return writeRequest<components["schemas"]["BulkActionResponse"]>(
        "/v1/workspace/bulk",
        { site_id: siteId, group_ids: groupIds, action },
        validateBulkActionResponse,
        signal,
    );
}

export function getOpsMetrics(siteId: string, from: string, to: string, signal?: AbortSignal) {
    const search = query({ site_id: siteId, from, to, bucket: "hour" });
    return request<OpsMetricsResponse>(
        `/v1/workspace/metrics/ops?${search}`,
        validateOpsMetrics,
        signal,
    );
}

export function getQualityMetrics(siteId: string, from: string, to: string, signal?: AbortSignal) {
    const search = query({ site_id: siteId, from, to });
    return request<QualityMetricsResponse>(
        `/v1/workspace/metrics/quality?${search}`,
        validateQualityMetrics,
        signal,
    );
}

export function listAssets(siteId: string, searchValue = "", signal?: AbortSignal) {
    const search = query({ site_id: siteId, q: searchValue || undefined, limit: 100 });
    return request<components["schemas"]["Page_AssetTag_"]>(
        `/v1/workspace/assets?${search}`,
        validateAssetPage,
        signal,
    );
}

export function saveAsset(
    siteId: string,
    entityId: number,
    criticality: number,
    tags: string[],
    signal?: AbortSignal,
) {
    return writeRequest<AssetTag>(
        "/v1/workspace/assets",
        { site_id: siteId, entity_id: entityId, criticality, tags },
        validateAssetTag,
        signal,
    );
}

export function rangeBounds(range: "24h" | "7d" | "30d", now = Date.now()) {
    const duration = range === "24h" ? 86_400_000 : range === "7d" ? 604_800_000 : 2_592_000_000;
    return {
        from: new Date(now - duration).toISOString(),
        to: new Date(now).toISOString(),
    };
}
