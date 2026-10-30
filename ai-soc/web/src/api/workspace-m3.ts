import type { components } from "../../../contracts/workspace/v1/types.ts";
import {
    validateChainCandidateDetail,
    validateChainDismissResponse,
    validateChainPage,
    validateIncidentActionResponse,
    validateIncidentContextResponse,
    validateIncidentDetailResponse,
    validateIncidentEventsResponse,
    validateNarrativeReadResponse,
    validateIncidentPage,
    validateWorkspaceError,
} from "./generated/workspace-validators.js";
import { currentCsrfToken } from "./client";
import { WorkspaceRequestError } from "./workspace";

export type ChainPage = components["schemas"]["ChainPage"];
export type ChainDetail = components["schemas"]["ChainCandidateDetail"];
export type IncidentPage = components["schemas"]["IncidentPage"];
export type IncidentDetail = components["schemas"]["IncidentDetailResponse"];
export type IncidentEvents = components["schemas"]["IncidentEventsResponse"];
export type IncidentContext = components["schemas"]["IncidentContextResponse"];
export type IncidentAction = components["schemas"]["IncidentActionResponse"];
export type IncidentNarrative = components["schemas"]["NarrativeReadResponse"];
type IncidentActionRequests = {
    assign: components["schemas"]["IncidentAssignRequest"];
    comment: components["schemas"]["IncidentCommentRequest"];
    disposition: components["schemas"]["IncidentDispositionRequest"];
    members: components["schemas"]["IncidentMembersRequest"];
    status: components["schemas"]["IncidentStatusRequest"];
};
export type IncidentActionCommand = {
    [Action in keyof IncidentActionRequests]: {
        kind: Action;
        body: IncidentActionRequests[Action];
    };
}[keyof IncidentActionRequests];
export type ChainListParams = {
    siteId: string;
    state?: string;
    ruleId?: string;
    diagnostic?: string;
    minScore?: number;
    maxScore?: number;
    from?: string;
    to?: string;
    cursor?: string;
};
export type IncidentListParams = {
    siteId: string;
    status?: string;
    ownerKey?: string;
    unassigned?: boolean;
    minPriority?: number;
    maxPriority?: number;
    from?: string;
    to?: string;
    cursor?: string;
};

type Validator<T> = (value: unknown) => value is T;

function query(values: Record<string, string | number | boolean | undefined>): string {
    const params = new URLSearchParams();
    for (const [key, value] of Object.entries(values)) {
        if (value !== undefined && value !== "") params.set(key, String(value));
    }
    if (import.meta.env.MODE !== "live") {
        const scenario = new URLSearchParams(location.search).get("scenario");
        if (scenario) params.set("scenario", scenario);
    }
    return params.toString();
}

async function decode<T>(response: Response, validate: Validator<T>): Promise<T> {
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
    if (!validate(body))
        throw new WorkspaceRequestError(
            response.status,
            "INVALID_RESPONSE",
            "The workspace returned an invalid response.",
        );
    return body;
}

async function get<T>(path: string, validate: Validator<T>, signal?: AbortSignal): Promise<T> {
    const response = await fetch(path, {
        method: "GET",
        headers: { Accept: "application/json" },
        credentials: "same-origin",
        signal,
    });
    return decode(response, validate);
}

async function post<T>(
    path: string,
    body: object,
    validate: Validator<T>,
    signal?: AbortSignal,
): Promise<T> {
    const token = currentCsrfToken();
    if (!token)
        throw new WorkspaceRequestError(
            0,
            "CSRF_UNAVAILABLE",
            "The session security token is unavailable. Refresh the page and try again.",
        );
    const response = await fetch(path, {
        method: "POST",
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
    return decode(response, validate);
}

export function listChains(params: ChainListParams, signal?: AbortSignal) {
    return get<ChainPage>(
        `/v1/workspace/chains?${query({
            site_id: params.siteId,
            state: params.state,
            rule_id: params.ruleId,
            diagnostic: params.diagnostic,
            min_score: params.minScore,
            max_score: params.maxScore,
            from: params.from,
            to: params.to,
            limit: 25,
            cursor: params.cursor,
        })}`,
        validateChainPage,
        signal,
    );
}

export function getChain(siteId: string, chainId: string, signal?: AbortSignal) {
    return get<ChainDetail>(
        `/v1/workspace/chains/${encodeURIComponent(chainId)}?${query({ site_id: siteId })}`,
        validateChainCandidateDetail,
        signal,
    );
}

export function dismissChain(
    chainId: string,
    body: components["schemas"]["ChainDismissRequest"],
    signal?: AbortSignal,
) {
    return post(
        `/v1/workspace/chains/${encodeURIComponent(chainId)}/dismiss`,
        body,
        validateChainDismissResponse,
        signal,
    );
}

export function promoteChain(
    chainId: string,
    body: components["schemas"]["ChainPromoteRequest"],
    signal?: AbortSignal,
) {
    return post(
        `/v1/workspace/chains/${encodeURIComponent(chainId)}/promote`,
        body,
        validateIncidentActionResponse,
        signal,
    );
}

export function listIncidents(params: IncidentListParams, signal?: AbortSignal) {
    return get<IncidentPage>(
        `/v1/workspace/incidents?${query({
            site_id: params.siteId,
            status: params.status,
            owner_key: params.ownerKey,
            unassigned: params.unassigned,
            min_priority: params.minPriority,
            max_priority: params.maxPriority,
            from: params.from,
            to: params.to,
            limit: 25,
            cursor: params.cursor,
        })}`,
        validateIncidentPage,
        signal,
    );
}

export function createIncident(
    body: components["schemas"]["IncidentCreateRequest"],
    signal?: AbortSignal,
) {
    return post("/v1/workspace/incidents", body, validateIncidentActionResponse, signal);
}

export function getIncident(
    siteId: string,
    incidentId: string,
    cursors: Partial<Record<"history" | "comments" | "dispositions" | "membership", string>> = {},
    signal?: AbortSignal,
) {
    return get<IncidentDetail>(
        `/v1/workspace/incidents/${encodeURIComponent(incidentId)}?${query({
            site_id: siteId,
            limit: 50,
            history_cursor: cursors.history,
            comments_cursor: cursors.comments,
            dispositions_cursor: cursors.dispositions,
            membership_cursor: cursors.membership,
        })}`,
        validateIncidentDetailResponse,
        signal,
    );
}

export function getIncidentEvents(
    params: {
        siteId: string;
        incidentId: string;
        evidenceRevision: string;
        from?: string | null;
        to?: string | null;
        cursor?: string | null;
    },
    signal?: AbortSignal,
) {
    return get<IncidentEvents>(
        `/v1/workspace/incidents/${encodeURIComponent(params.incidentId)}/events?${query({
            site_id: params.siteId,
            evidence_revision: params.evidenceRevision,
            from: params.from ?? undefined,
            to: params.to ?? undefined,
            limit: 100,
            cursor: params.cursor ?? undefined,
        })}`,
        validateIncidentEventsResponse,
        signal,
    ).then((result) => {
        if (result.evidence_revision !== params.evidenceRevision)
            throw new WorkspaceRequestError(
                409,
                "EVIDENCE_REVISION_MISMATCH",
                "The timeline belongs to a different frozen evidence revision.",
            );
        return result;
    });
}

export function getIncidentNarrative(
    params: { siteId: string; incidentId: string; evidenceRevision?: string },
    signal?: AbortSignal,
) {
    return get<IncidentNarrative>(
        `/v1/workspace/incidents/${encodeURIComponent(params.incidentId)}/narrative?${query({
            site_id: params.siteId,
            evidence_revision: params.evidenceRevision,
        })}`,
        validateNarrativeReadResponse,
        signal,
    ).then((narrative) => {
        if (
            narrative.incident_id !== params.incidentId ||
            (params.evidenceRevision && narrative.evidence_revision !== params.evidenceRevision)
        ) {
            throw new WorkspaceRequestError(
                200,
                "INVALID_RESPONSE",
                "The workspace returned a narrative for a different evidence revision.",
            );
        }
        return narrative;
    });
}

export function getIncidentContext(
    params: { siteId: string; incidentId: string; evidenceRevision: string },
    signal?: AbortSignal,
) {
    return get<IncidentContext>(
        `/v1/workspace/incidents/${encodeURIComponent(params.incidentId)}/context?${query({
            site_id: params.siteId,
            evidence_revision: params.evidenceRevision,
            sample_limit: 100,
        })}`,
        validateIncidentContextResponse,
        signal,
    ).then((result) => {
        if (result.evidence_revision !== params.evidenceRevision)
            throw new WorkspaceRequestError(
                409,
                "EVIDENCE_REVISION_MISMATCH",
                "The context belongs to a different frozen evidence revision.",
            );
        return result;
    });
}

export function incidentAction(
    incidentId: string,
    command: IncidentActionCommand,
    signal?: AbortSignal,
) {
    return post(
        `/v1/workspace/incidents/${encodeURIComponent(incidentId)}/${command.kind}`,
        command.body,
        validateIncidentActionResponse,
        signal,
    );
}
