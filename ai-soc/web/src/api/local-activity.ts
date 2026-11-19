import { signalLocalSessionExpiry } from "./local-session";

export type LocalModelActivity = {
    model: string | null;
    attempts: number;
    completed: number;
    failed: number;
};

export async function getLocalModelActivity(
    siteId: string,
    signal?: AbortSignal,
): Promise<LocalModelActivity> {
    const search = new URLSearchParams({ site_id: siteId });
    const response = await fetch(`/v1/local/activity?${search}`, {
        method: "GET",
        credentials: "same-origin",
        headers: { Accept: "application/json" },
        signal,
    });
    if (!response.ok) {
        if (response.status === 401) signalLocalSessionExpiry();
        throw new Error("Local model activity is unavailable.");
    }

    let payload: unknown;
    try {
        payload = await response.json();
    } catch {
        throw new Error("Local model activity returned an invalid response.");
    }
    if (!isLocalModelActivity(payload))
        throw new Error("Local model activity returned an invalid response.");
    return payload;
}

function isLocalModelActivity(value: unknown): value is LocalModelActivity {
    if (typeof value !== "object" || value === null || Array.isArray(value)) return false;
    const keys = Object.keys(value);
    if (
        keys.length !== 4 ||
        !keys.includes("model") ||
        !keys.includes("attempts") ||
        !keys.includes("completed") ||
        !keys.includes("failed")
    )
        return false;
    if (!("model" in value) || (value.model !== null && typeof value.model !== "string"))
        return false;
    return (
        "attempts" in value &&
        isNonNegativeInteger(value.attempts) &&
        "completed" in value &&
        isNonNegativeInteger(value.completed) &&
        "failed" in value &&
        isNonNegativeInteger(value.failed)
    );
}

function isNonNegativeInteger(value: unknown): value is number {
    return typeof value === "number" && Number.isInteger(value) && value >= 0;
}
