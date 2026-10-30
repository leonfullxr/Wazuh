import type {
    AskRequest,
    EmptyProof,
    FetchResult,
    ResolvedWindow,
    TopicAnswer,
    Visibility,
} from "../../../../contracts/v1/generated/types.ts";
import { fmt } from "../../i18n/answer-copy";
import type { Locale } from "../../i18n";

function bytes(text: string) {
    return new TextEncoder().encode(text).length;
}
export function countLabel(fetch: FetchResult, locale: Locale) {
    const c = fetch.count;
    if (!c) return "-";
    const amount = c.relation === "gte" ? `>= ${c.value}` : `= ${c.value}`;
    return `${amount}${c.approximate ? ` (${fmt(locale, "approx")})` : ""}`;
}
export function date(value: string | null | undefined, tz: string, locale: Locale) {
    if (!value) return "-";
    try {
        return new Intl.DateTimeFormat(locale === "es" ? "es-ES" : "en-GB", {
            day: "numeric",
            month: "short",
            year: "numeric",
            hour: "2-digit",
            minute: "2-digit",
            timeZoneName: "shortOffset",
            timeZone: tz,
        }).format(new Date(value));
    } catch {
        return value;
    }
}
export function byteCount(text: string) {
    return bytes(text);
}
export function formatCount(fetch: FetchResult, locale: Locale) {
    return countLabel(fetch, locale);
}
export function formatVisibility(value: Visibility, locale: Locale) {
    const labels: Record<Visibility, [string, string]> = {
        full: ["Full", "Completa"],
        filtered: ["Filtered", "Filtrada"],
        unknown: ["Unknown", "Desconocida"],
    };
    return labels[value][locale === "en" ? 0 : 1];
}
export function formatWindow(window: ResolvedWindow, timezone: string, locale: Locale) {
    return `${date(window.start, timezone, locale)} - ${date(window.end, timezone, locale)} (${window.source_text})`;
}
export function resolveCitation(block: TopicAnswer, id: string) {
    return block.tables.flatMap((table) => table.items).find((item) => item.evidence_id === id);
}
export function buildContinuationRequest(
    _question: string,
    environment_id: string,
    timezone: string,
    language_hint: Locale,
    followup_id: string | null | undefined,
    followup_revision: number | null | undefined,
    continue_topic_ids: string[],
): AskRequest {
    return {
        question:
            language_hint === "es"
                ? "continúa los juicios pendientes"
                : "continue the left-out judgments",
        environment_id,
        timezone,
        language_hint,
        followup_id,
        followup_revision,
        continue_topic_ids,
    };
}
export function fieldValue(value: unknown, kind?: string, tz = "UTC", locale: Locale = "en") {
    if (Array.isArray(value)) return value.join(", ");
    if (value === null || value === undefined) return "-";
    if (kind === "date" && typeof value === "string") return date(value, tz, locale);
    return String(value);
}
export function safeDocumentUrl(value: string): string | null {
    try {
        const url = new URL(value);
        return url.protocol === "https:" ? url.toString() : null;
    } catch {
        return null;
    }
}

// docs/architecture.md: a zero result counts as empty only when the index is confirmed, visibility
// is full, the window has data and the matching filter is identified. Anything less is unconfirmed.
export function emptyProofQualified(proof: EmptyProof | null | undefined): boolean {
    return (
        !!proof &&
        proof.index_exists === "confirmed" &&
        proof.visibility === "full" &&
        proof.consistency === "coherent" &&
        proof.window_has_data === "confirmed" &&
        (proof.matched_nothing.length > 0 || proof.combination_zero === true)
    );
}
