export type LocalSession = {
    authenticated: boolean;
    modelEnabled: boolean;
};

export type LocalRuntime = { kind: "not-local" } | { kind: "local"; session: LocalSession };

export const localSessionExpiredEvent = "ai-soc:local-session-expired";

export function signalLocalSessionExpiry(): void {
    window.dispatchEvent(new Event(localSessionExpiredEvent));
}

export class LocalSessionError extends Error {
    readonly kind: "invalid-key" | "unavailable";

    constructor(kind: "invalid-key" | "unavailable") {
        super(
            kind === "invalid-key"
                ? "The access key is not valid."
                : "The local console is unavailable.",
        );
        this.name = "LocalSessionError";
        this.kind = kind;
    }
}

export async function getLocalRuntime(signal?: AbortSignal): Promise<LocalRuntime> {
    const response = await fetch("/v1/local/session", {
        method: "GET",
        credentials: "same-origin",
        headers: { Accept: "application/json" },
        signal,
    });
    if (response.status === 404) return { kind: "not-local" };
    if (!response.ok) throw new LocalSessionError("unavailable");

    let payload: unknown;
    try {
        payload = await response.json();
    } catch {
        throw new LocalSessionError("unavailable");
    }
    if (!isLocalSessionPayload(payload)) throw new LocalSessionError("unavailable");
    return {
        kind: "local",
        session: {
            authenticated: payload.authenticated,
            modelEnabled: payload.model_enabled,
        },
    };
}

function isLocalSessionPayload(
    value: unknown,
): value is { authenticated: boolean; model_enabled: boolean } {
    if (typeof value !== "object" || value === null || Array.isArray(value)) return false;
    const keys = Object.keys(value);
    return (
        keys.length === 2 &&
        keys.includes("authenticated") &&
        keys.includes("model_enabled") &&
        "authenticated" in value &&
        typeof value.authenticated === "boolean" &&
        "model_enabled" in value &&
        typeof value.model_enabled === "boolean"
    );
}

export async function signInLocal(key: string, signal?: AbortSignal): Promise<void> {
    const response = await fetch("/v1/local/session", {
        method: "POST",
        credentials: "same-origin",
        headers: {
            Accept: "application/json",
            "Content-Type": "application/json",
        },
        body: JSON.stringify({ key }),
        signal,
    });
    if (response.status === 204) return;
    if (response.status === 401) throw new LocalSessionError("invalid-key");
    throw new LocalSessionError("unavailable");
}
