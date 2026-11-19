import type {
    Answer,
    AskRequest,
    BootstrapResponse,
    DomainError,
    ErrorResponse,
    FeedbackQueued,
    FeedbackRequest,
    FetchResult,
    PageRequest,
} from "../../../contracts/v1/generated/types.ts";
import {
    validateAnswer,
    validateBootstrapResponse,
    validateFeedbackQueued,
    validateFetchResult,
} from "./generated/validators.js";
import { signalLocalSessionExpiry } from "./local-session";

export type LocalBootstrapResponse = Omit<BootstrapResponse, "mode" | "models" | "provenance"> & {
    mode: "local";
    models: [];
    provenance: null;
};

export type RuntimeBootstrapResponse = BootstrapResponse | LocalBootstrapResponse;

export class ApiError extends Error {
    readonly domainError: DomainError | null;
    readonly status: number;
    readonly retryAfter: string | null;
    readonly clientCode: "INVALID_RESPONSE" | null;
    constructor(
        error: DomainError | null,
        status: number,
        retryAfter: string | null,
        clientCode: "INVALID_RESPONSE" | null = null,
    ) {
        super(error?.message ?? "the service returned an unexpected response");
        this.name = "ApiError";
        this.domainError = error;
        this.status = status;
        this.retryAfter = retryAfter;
        this.clientCode = clientCode;
    }
}

let csrfToken: string | null = null;
let csrfGeneration = 0;
let bootstrapPromise: Promise<RuntimeBootstrapResponse> | null = null;
let refreshPromise: Promise<RuntimeBootstrapResponse> | null = null;
const bootstrapListeners = new Set<(data: RuntimeBootstrapResponse) => void>();

const responseValidators: Record<string, (data: unknown) => boolean> = {
    "/v1/questions": validateAnswer,
    "/v1/fetches/page": validateFetchResult,
    "/v1/feedback": validateFeedbackQueued,
};

async function decode<T>(response: Response, path: string): Promise<T> {
    let data: unknown = null;
    try {
        if (response.headers.get("Content-Type")?.toLowerCase().includes("application/json"))
            data = await response.json();
    } catch {
        data = null;
    }
    if (!response.ok) {
        if (response.status === 401) signalLocalSessionExpiry();
        const body = data as (ErrorResponse & Partial<DomainError>) | null;
        const error =
            body && typeof body === "object" && "error" in body
                ? body.error
                : body &&
                    "code" in body &&
                    "message" in body &&
                    "retryable" in body &&
                    "trace_id" in body
                  ? (body as DomainError)
                  : null;
        if (error) {
            const retryAfter = response.headers.get("Retry-After");
            const apiError = new ApiError(error, response.status, retryAfter);
            throw apiError;
        }
        throw new Error(`Request failed with HTTP ${response.status}`);
    }
    const valid =
        path === "/v1/bootstrap"
            ? validateRuntimeBootstrapResponse(data)
            : responseValidators[path]?.(data);
    if (!valid) {
        throw new ApiError(null, response.status, null, "INVALID_RESPONSE");
    }
    return data as T;
}

async function request<T>(
    path: string,
    body?: object,
    signal?: AbortSignal,
    retryAuth = false,
    retried = false,
    idempotencyKey?: string,
): Promise<T> {
    const usedGeneration = csrfGeneration;
    const usedToken = csrfToken;
    const headers = new Headers({ Accept: "application/json" });
    const init: RequestInit = {
        method: body === undefined ? "GET" : "POST",
        headers,
        credentials: "same-origin",
        signal,
    };
    if (body !== undefined) {
        headers.set("Content-Type", "application/json");
        headers.set("X-SOC-CSRF", usedToken ?? "");
        if (idempotencyKey) headers.set("Idempotency-Key", idempotencyKey);
        init.body = JSON.stringify(body);
    }
    try {
        return await decode<T>(await fetch(path, init), path);
    } catch (error) {
        if (
            retryAuth &&
            !retried &&
            error instanceof ApiError &&
            error.domainError !== null &&
            ["CSRF_DENIED", "AUTH_EXPIRED"].includes(error.domainError.code)
        ) {
            if (usedGeneration === csrfGeneration) await waitForRefresh(refreshBootstrap(), signal);
            if (signal?.aborted) throw new DOMException("The request was aborted.", "AbortError");
            return request<T>(path, body, signal, false, true, idempotencyKey);
        }
        throw error;
    }
}

function waitForRefresh<T>(refresh: Promise<T>, signal?: AbortSignal): Promise<T> {
    if (!signal) return refresh;
    if (signal.aborted)
        return Promise.reject(new DOMException("The request was aborted.", "AbortError"));
    return new Promise<T>((resolve, reject) => {
        const abort = () => {
            signal.removeEventListener("abort", abort);
            reject(new DOMException("The request was aborted.", "AbortError"));
        };
        signal.addEventListener("abort", abort, { once: true });
        refresh.then(
            (value) => {
                signal.removeEventListener("abort", abort);
                resolve(value);
            },
            (error: unknown) => {
                signal.removeEventListener("abort", abort);
                reject(error);
            },
        );
    });
}

export function bootstrap(): Promise<RuntimeBootstrapResponse> {
    bootstrapPromise ??= request<RuntimeBootstrapResponse>("/v1/bootstrap")
        .then((result) => {
            installBootstrap(result);
            return result;
        })
        .catch((error: unknown) => {
            bootstrapPromise = null;
            throw error;
        });
    return bootstrapPromise;
}
function installBootstrap(result: RuntimeBootstrapResponse) {
    csrfToken = result.csrf_token ?? null;
    csrfGeneration += 1;
    for (const listener of bootstrapListeners) listener(result);
}
export function currentCsrfToken(): string | null {
    return csrfToken;
}
function refreshBootstrap(): Promise<RuntimeBootstrapResponse> {
    refreshPromise ??= request<RuntimeBootstrapResponse>("/v1/bootstrap")
        .then((result) => {
            installBootstrap(result);
            return result;
        })
        .finally(() => {
            refreshPromise = null;
        });
    return refreshPromise;
}
export function onBootstrapRefresh(listener: (data: RuntimeBootstrapResponse) => void): () => void {
    bootstrapListeners.add(listener);
    return () => bootstrapListeners.delete(listener);
}

function validateRuntimeBootstrapResponse(data: unknown): data is RuntimeBootstrapResponse {
    if (validateBootstrapResponse(data)) return true;
    if (!isRecord(data)) return false;
    if (data.mode !== "local" || data.provenance !== null) return false;
    if (!Array.isArray(data.models) || data.models.length !== 0) return false;

    return validateBootstrapResponse({
        ...data,
        mode: "live",
        provenance: localValidationProvenance,
    });
}

function isRecord(value: unknown): value is Record<string, unknown> {
    return typeof value === "object" && value !== null && !Array.isArray(value);
}

const localValidationProvenance = {
    content_repository: "https://local.invalid",
    content_sha: "0000000000000000000000000000000000000000",
    docs_manifest_sha256: "0000000000000000000000000000000000000000000000000000000000000000",
    docs_origin: "https://local.invalid",
    image_digest: `sha256:${"0".repeat(64)}`,
    pack_sha256: "0000000000000000000000000000000000000000000000000000000000000000",
    service_sha: "0000000000000000000000000000000000000000",
} satisfies BootstrapResponse["provenance"];
export function ask(
    body: AskRequest,
    options: { idempotencyKey?: string; signal?: AbortSignal } = {},
): Promise<Answer> {
    return request<Answer>(
        "/v1/questions",
        body,
        options.signal,
        true,
        false,
        options.idempotencyKey,
    );
}
export function page(
    body: PageRequest,
    options: { signal?: AbortSignal } = {},
): Promise<FetchResult> {
    return request<FetchResult>("/v1/fetches/page", body, options.signal, true);
}
export function feedback(
    body: FeedbackRequest,
    options: { signal?: AbortSignal } = {},
): Promise<FeedbackQueued> {
    return request<FeedbackQueued>("/v1/feedback", body, options.signal, true);
}
