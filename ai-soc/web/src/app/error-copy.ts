import { ApiError } from "../api/client";
import { fmt } from "../i18n/answer-copy";
import type { Locale } from "../i18n";
import { errorCopy } from "../i18n/answer-enums";

export function errorText(error: unknown, locale: Locale) {
    if (error instanceof ApiError) {
        if (error.clientCode === "INVALID_RESPONSE") return fmt(locale, "unexpectedResponse");
        if (!error.domainError) return fmt(locale, "error");
        const message =
            errorCopy[error.domainError.code]?.[locale === "en" ? 0 : 1] ??
            error.domainError.message;
        const retry =
            error.retryAfter ??
            (error.domainError.details?.retry_after_seconds
                ? String(error.domainError.details.retry_after_seconds)
                : null);
        return `${error.domainError.code}: ${message}${retry ? ` (${retry} s)` : ""}`;
    }
    return error instanceof Error ? error.message : fmt(locale, "error");
}
