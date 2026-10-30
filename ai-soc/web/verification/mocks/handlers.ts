import { http, HttpResponse } from "msw";
import {
    allAnswers,
    answered,
    bootstrapFixture,
    feedbackQueued,
    pageResponses,
    singleTopicAnswers,
} from "./fixtures";
import { judgment } from "./fixture-builders";
import { hash } from "./fixture-builders";
import type {
    Answer,
    AskRequest,
    FetchResult,
    PageRequest,
} from "../../../contracts/v1/generated/types.ts";
import { workspaceHandlers } from "./workspace-handlers";

type CursorOwner = {
    question_id: string;
    environment_id: string;
    topic_id: string;
    fetch_id: string;
    page: number;
    snapshot_key: string;
    scope_hash: string;
};
export class MockCursorRegistry {
    private readonly issued = new Map<string, CursorOwner>();
    private readonly expired = new Set<string>();
    issue(cursor: string, owner: CursorOwner, expired = false) {
        this.issued.set(cursor, owner);
        if (expired) this.expired.add(cursor);
    }
    consume(cursor: string, environment_id: string): CursorOwner | "expired" | "foreign" {
        const issued = this.issued.get(cursor);
        if (!issued || this.expired.has(cursor)) return "expired";
        if (issued.environment_id !== environment_id) return "foreign";
        return issued;
    }
    clear() {
        this.issued.clear();
        this.expired.clear();
    }
}
export function cursorFailure(cursor: string, failure: "expired" | "foreign") {
    if (failure === "foreign")
        return {
            status: 410,
            code: "CURSOR_EXPIRED",
            message: "The synthetic cursor has expired.",
        } as const;
    return cursor.startsWith("synthetic-")
        ? ({
              status: 410,
              code: "CURSOR_EXPIRED",
              message: "The synthetic cursor has expired.",
          } as const)
        : ({ status: 400, code: "BAD_REQUEST", message: "The cursor is malformed." } as const);
}
const cursors = new MockCursorRegistry();
export class ContinuationRegistry {
    private readonly answers = new Map<string, Answer>();
    register(answer: Answer) {
        if (answer.left_out.length && answer.followup_id)
            this.answers.set(answer.followup_id, answer);
    }
    get(id: string | undefined) {
        return id ? this.answers.get(id) : undefined;
    }
    clear() {
        this.answers.clear();
    }
}
const continuationAnchors = new ContinuationRegistry();
let bootstrapRequestCount = 0;
const selectedScenario = () =>
    typeof window === "undefined"
        ? null
        : new URLSearchParams(window.location.search).get("scenario");
const chooseScenario = (question: string) => {
    const explicit = selectedScenario();
    if (explicit && explicit !== "auto") return explicit;
    const value = question.toLowerCase();
    if (value.includes("ldap") && (value.includes("how many") || value.includes("count")))
        return "clarify";
    const ldap = value.includes("ldap");
    const auth = value.includes("authentication") || value.includes("auth");
    const vuln = value.includes("vulnerab") || value.includes("vuln");
    if (auth && vuln) return "natural_combined";
    if (ldap) return "natural_ldap";
    if (auth) return "natural_auth";
    if (vuln) return value.includes("investiga") ? "natural_vuln_es" : "natural_vuln";
    if (value.includes("weather")) return "refused";
    return "refused";
};
export const naturalAnswer = (scenario: string): Answer => {
    const ids: Record<string, string[]> = {
        natural_ldap: ["ldap"],
        natural_auth: ["auth_review"],
        natural_vuln: ["vuln_review"],
        natural_vuln_es: ["vuln_review"],
        natural_combined: ["auth_review", "vuln_review"],
    };
    const selected = ids[scenario];
    if (!selected) return allAnswers[scenario] ?? answered;
    if (selected.length === 1) {
        const captured = singleTopicAnswers[selected[0]!] ?? answered;
        return scenario === "natural_vuln_es" ? { ...captured, language: "es" } : captured;
    }
    const blocks = selected.map((topicId, ordinal) => ({
        ...singleTopicAnswers[topicId]!.blocks[0]!,
        ordinal,
    }));
    return {
        ...answered,
        blocks,
    };
};
export function buildErrorBody(status: number, code: string, message: string, retryAfter?: number) {
    return {
        code,
        message,
        retryable: status >= 500,
        trace_id: "1234567890abcdef1234567890abcdef",
        ...(retryAfter ? { details: { retry_after_seconds: retryAfter } } : {}),
    };
}
const fail = (status: number, code: string, message: string, retryAfter?: number) =>
    HttpResponse.json(buildErrorBody(status, code, message, retryAfter), {
        status,
        headers: retryAfter ? { "Retry-After": String(retryAfter) } : undefined,
    });

export function buildContinuationAnswer(parent: Answer, selected: string[]): Answer {
    const blocks = answered.blocks
        .filter((block) => selected.includes(block.topic_id))
        .map((block) => ({
            ...block,
            judgment: judgment(
                block.topic_id,
                block.tables.flatMap((table) => table.items)[0]?.evidence_id ?? "",
                "validated",
            ),
        }));
    return {
        ...answered,
        question_id: crypto.randomUUID(),
        environment_id: parent.environment_id,
        status: blocks.every((block) => ["validated", "no_findings"].includes(block.judgment.state))
            ? "answered"
            : "partial",
        blocks,
        left_out: [],
        followup_id: crypto.randomUUID(),
        followup_revision: 1,
        feedback_receipt: `synthetic-feedback-${crypto.randomUUID()}`,
    };
}
export function makeMockAnswer<T extends Answer>(source: T): T {
    const questionId = crypto.randomUUID();
    const seed = Number.parseInt(questionId.slice(0, 8), 16);
    const evidenceIds = new Map<string, string>();
    const remember = (id: string) => {
        if (!evidenceIds.has(id)) evidenceIds.set(id, `ev1_${hash(seed + evidenceIds.size)}`);
        return evidenceIds.get(id)!;
    };
    for (const block of source.blocks) {
        for (const table of block.tables) {
            for (const row of table.rows) remember(row.evidence_id);
            for (const item of table.items) remember(item.evidence_id);
            for (const bucket of table.buckets ?? []) remember(bucket.evidence_id);
        }
        for (const finding of block.judgment.sentences)
            for (const id of finding.evidence_ids) remember(id);
    }
    const checkEvidenceIds = new Map<string, string>();
    const visibleIds = new Set(evidenceIds.values());
    let checkSequence = 0;
    const rememberCheck = (id: string) => {
        if (!checkEvidenceIds.has(id)) {
            let candidate = `ev1_${hash(seed + 2_000_000 + checkSequence++)}`;
            while (visibleIds.has(candidate))
                candidate = `ev1_${hash(seed + 2_000_000 + checkSequence++)}`;
            checkEvidenceIds.set(id, candidate);
        }
        return checkEvidenceIds.get(id)!;
    };
    let fetchSequence = 0;
    const remapSnapshot = <S extends { key: string }>(value: S, key: string): S => ({
        ...value,
        key,
    });
    return {
        ...source,
        question_id: questionId,
        followup_id: source.left_out.length ? crypto.randomUUID() : source.followup_id,
        trace_id: crypto.randomUUID().replaceAll("-", ""),
        feedback_receipt: `synthetic-feedback-${crypto.randomUUID()}`,
        blocks: source.blocks.map((block) => ({
            ...block,
            checks: block.checks.map((check) => ({
                ...check,
                evidence_ids: check.evidence_ids.map(rememberCheck),
            })),
            judgment: {
                ...block.judgment,
                sentences: block.judgment.sentences.map((finding) => ({
                    ...finding,
                    evidence_ids: finding.evidence_ids.map(remember),
                })),
            },
            tables: block.tables.map((table) => {
                const sequence = fetchSequence++;
                const snapshotKey = hash(seed + 900_000 + sequence);
                const scopeHash = hash(seed + 300_000 + sequence);
                return {
                    ...table,
                    snapshot: remapSnapshot(table.snapshot, snapshotKey),
                    scope: { ...table.scope, snapshot: table.snapshot.kind },
                    empty_proof: table.empty_proof
                        ? {
                              ...table.empty_proof,
                              snapshot: remapSnapshot(table.empty_proof.snapshot, snapshotKey),
                          }
                        : null,
                    rows: table.rows.map((row) => ({
                        ...row,
                        evidence_id: remember(row.evidence_id),
                    })),
                    items: table.items.map((item) => ({
                        ...item,
                        evidence_id: remember(item.evidence_id),
                        scope_hash: scopeHash,
                        snapshot: remapSnapshot(item.snapshot, snapshotKey),
                        source: (() => {
                            const source = item.source as unknown as Record<string, unknown>;
                            return {
                                ...item.source,
                                ...(typeof source.parent_evidence_id === "string"
                                    ? { parent_evidence_id: remember(source.parent_evidence_id) }
                                    : {}),
                                ...(typeof source.page_evidence_id === "string"
                                    ? { page_evidence_id: remember(source.page_evidence_id) }
                                    : {}),
                            } as typeof item.source;
                        })(),
                    })),
                    buckets: table.buckets?.map((bucket) => ({
                        ...bucket,
                        evidence_id: remember(bucket.evidence_id),
                    })),
                };
            }),
        })),
    } as T;
}
export function buildUnavailablePage(source: FetchResult): FetchResult {
    return {
        ...source,
        state: "unavailable",
        rows: [],
        items: [],
        count: null,
        next_cursor: null,
        error: {
            code: "EVIDENCE_LIMIT",
            message: "The page exceeded the available evidence limit.",
            retryable: true,
            trace_id: "1234567890abcdef1234567890abcdef",
        },
        message: "The page exceeded the available evidence limit.",
    };
}

export function personalizePageResponse(response: FetchResult, owner: CursorOwner): FetchResult {
    const pageSeed = Number.parseInt(owner.question_id.slice(0, 8), 16) + owner.page * 10_000;
    const ids = new Map<string, string>();
    const pageId = (id: string) => {
        if (!ids.has(id)) ids.set(id, `ev1_${hash(pageSeed + ids.size)}`);
        return ids.get(id)!;
    };
    return {
        ...response,
        snapshot: { ...response.snapshot, key: owner.snapshot_key },
        scope: { ...response.scope, snapshot: response.snapshot.kind },
        rows: response.rows.map((row) => ({ ...row, evidence_id: pageId(row.evidence_id) })),
        items: response.items.map((item) => ({
            ...item,
            evidence_id: pageId(item.evidence_id),
            scope_hash: owner.scope_hash,
            snapshot: { ...item.snapshot, key: owner.snapshot_key },
        })),
        buckets: response.buckets?.map((bucket) => ({
            ...bucket,
            evidence_id: pageId(bucket.evidence_id),
        })),
    };
}

export function isValidContinuation(
    parent: Answer | undefined,
    request: Partial<
        Pick<
            AskRequest,
            | "question"
            | "language_hint"
            | "environment_id"
            | "followup_revision"
            | "continue_topic_ids"
        >
    >,
): boolean {
    const cue =
        request.language_hint === "es"
            ? "continúa los juicios pendientes"
            : "continue the left-out judgments";
    if (
        !parent ||
        parent.followup_revision !== request.followup_revision ||
        parent.environment_id !== request.environment_id ||
        request.question?.toLowerCase().trim() !== cue
    )
        return false;
    const retryable = new Set(
        parent.left_out.filter((left) => left.retryable).map((left) => left.topic_id),
    );
    const ids = request.continue_topic_ids;
    return (
        ids === null ||
        (Array.isArray(ids) &&
            ids.length > 0 &&
            new Set(ids).size === ids.length &&
            ids.every((id) => retryable.has(id)))
    );
}
export function continuationFailure(
    parent: Answer | undefined,
    request: Partial<
        Pick<
            AskRequest,
            | "question"
            | "language_hint"
            | "environment_id"
            | "followup_revision"
            | "continue_topic_ids"
        >
    >,
) {
    if (!parent) return { status: 410, code: "FOLLOWUP_EXPIRED" } as const;
    if (parent.followup_revision !== request.followup_revision)
        return { status: 409, code: "FOLLOWUP_CONFLICT" } as const;
    if (!isValidContinuation(parent, request))
        return { status: 422, code: "INVALID_CONTINUATION" } as const;
    return null;
}
export const handlers = [
    ...workspaceHandlers,
    http.get("/v1/bootstrap", async () => {
        bootstrapRequestCount += 1;
        if (
            typeof window !== "undefined" &&
            new URLSearchParams(window.location.search).get("delay_bootstrap") === "1"
        )
            await new Promise((resolve) => setTimeout(resolve, 400));
        if (selectedScenario() === "cancel_refresh" && bootstrapRequestCount > 1)
            return new Promise(() => {});
        if (selectedScenario() === "capability_refresh" && bootstrapRequestCount > 1)
            return HttpResponse.json(
                {
                    ...bootstrapFixture,
                    csrf_token: "synthetic-refreshed-csrf-token",
                    models: [bootstrapFixture.models[1]!],
                    sites: [{ id: "refreshed-site", label: "Refreshed site" }],
                },
                { headers: { "Cache-Control": "no-store" } },
            );
        if (selectedScenario() === "no_sites")
            return HttpResponse.json({ ...bootstrapFixture, sites: [] });
        return selectedScenario() === "bootstrap_unavailable"
            ? fail(503, "DEPENDENCY_UNAVAILABLE", "Synthetic bootstrap service is unavailable.")
            : HttpResponse.json(bootstrapFixture, {
                  headers: { "Cache-Control": "no-store" },
              });
    }),
    http.post("/v1/questions", async ({ request }) => {
        if (!request.headers.get("X-SOC-CSRF"))
            return fail(403, "CSRF_DENIED", "CSRF token required.");
        if (
            ["cancel_refresh", "capability_refresh"].includes(selectedScenario() ?? "") &&
            request.headers.get("X-SOC-CSRF") === "synthetic-csrf-token"
        )
            return fail(403, "CSRF_DENIED", "The synthetic CSRF token expired.");
        const body = (await request.json()) as {
            question?: string;
            environment_id?: string;
            language_hint?: "en" | "es";
            followup_id?: string;
            followup_revision?: number;
            continue_topic_ids?: string[] | null;
        };
        const scenario = chooseScenario(body.question ?? "");
        if (
            typeof window !== "undefined" &&
            new URLSearchParams(window.location.search).get("delay_ask") === "1"
        )
            await new Promise((resolve) => setTimeout(resolve, 500));
        if (scenario === "audit_unavailable")
            return fail(503, "AUDIT_UNAVAILABLE", "Synthetic audit service is unavailable.");
        if (scenario === "busy")
            return fail(429, "RATE_LIMITED", "Synthetic request limit reached.", 60);
        if (
            scenario === "kev" ||
            (typeof window !== "undefined" &&
                new URLSearchParams(window.location.search).get("kev") === "1")
        )
            return HttpResponse.json(makeMockAnswer(answered), {
                headers: { "Cache-Control": "no-store" },
            });
        if (body.followup_id || body.followup_revision || body.continue_topic_ids) {
            if (
                typeof window !== "undefined" &&
                new URLSearchParams(window.location.search).get("expire_followup") === "1"
            )
                return fail(410, "FOLLOWUP_EXPIRED", "The continuation anchor has expired.");
            const parent = continuationAnchors.get(body.followup_id);
            const failure = continuationFailure(parent, body);
            if (failure)
                return fail(
                    failure.status,
                    failure.code,
                    failure.code === "FOLLOWUP_EXPIRED"
                        ? "The continuation anchor has expired."
                        : failure.code === "FOLLOWUP_CONFLICT"
                          ? "The continuation revision is stale."
                          : "The continuation selection is invalid.",
                );
            const parentAnswer = parent!;
            const selected = new Set(
                body.continue_topic_ids ??
                    parentAnswer.left_out
                        .filter((left) => left.retryable)
                        .map((left) => left.topic_id),
            );
            const continued = makeMockAnswer(buildContinuationAnswer(parentAnswer, [...selected]));
            continued.trace_id = crypto.randomUUID().replaceAll("-", "");
            continued.feedback_receipt = `synthetic-feedback-${crypto.randomUUID()}`;
            return HttpResponse.json(continued, { headers: { "Cache-Control": "no-store" } });
        }
        const selected = naturalAnswer(scenario);
        let emitted = makeMockAnswer(selected);
        if (scenario === "paged") {
            emitted = {
                ...emitted,
                blocks: emitted.blocks.map((block) => ({
                    ...block,
                    tables: block.tables.map((table) => {
                        if (!table.next_cursor) return table;
                        const cursor = `synthetic-${crypto.randomUUID()}`;
                        cursors.issue(cursor, {
                            question_id: emitted.question_id,
                            environment_id: emitted.environment_id,
                            topic_id: block.topic_id,
                            fetch_id: table.fetch_id,
                            page: 1,
                            snapshot_key: table.snapshot.key,
                            scope_hash: table.items[0]?.scope_hash ?? hash(0),
                        });
                        return { ...table, next_cursor: cursor };
                    }),
                })),
            };
        }
        continuationAnchors.register(emitted);
        return HttpResponse.json(emitted, {
            headers: { "Cache-Control": "no-store" },
        });
    }),
    http.post("/v1/fetches/page", async ({ request }) => {
        if (!request.headers.get("X-SOC-CSRF"))
            return fail(403, "CSRF_DENIED", "CSRF token required.");
        const body = (await request.json()) as PageRequest;
        if (
            typeof window !== "undefined" &&
            new URLSearchParams(window.location.search).get("delay_page") === "1"
        )
            await new Promise((resolve) => setTimeout(resolve, 700));
        if (
            typeof window !== "undefined" &&
            new URLSearchParams(window.location.search).get("page_unavailable") === "1"
        ) {
            const source = pageResponses[0]!;
            const unavailable = buildUnavailablePage(source);
            return HttpResponse.json(unavailable);
        }
        const owner = cursors.consume(body.cursor, body.environment_id);
        if (owner === "expired") {
            const error = cursorFailure(body.cursor, owner);
            return fail(error.status, error.code, error.message);
        }
        if (owner === "foreign") {
            const error = cursorFailure(body.cursor, owner);
            return fail(error.status, error.code, error.message);
        }
        const response = pageResponses[owner.page - 1];
        if (!response) return fail(410, "CURSOR_EXPIRED", "The synthetic cursor has expired.");
        const nextCursor =
            owner.page < pageResponses.length
                ? `synthetic-${owner.question_id}-${owner.page + 1}`
                : `synthetic-expired-${owner.question_id}`;
        cursors.issue(
            nextCursor,
            { ...owner, page: owner.page + 1 },
            owner.page >= pageResponses.length,
        );
        const personalized = personalizePageResponse(response, owner);
        return HttpResponse.json({
            ...personalized,
            topic_id: owner.topic_id,
            fetch_id: owner.fetch_id,
            next_cursor: nextCursor,
            scope: { ...personalized.scope, environment_id: owner.environment_id },
        });
    }),
    http.post("/v1/feedback", async ({ request }) => {
        if (!request.headers.get("X-SOC-CSRF"))
            return fail(403, "CSRF_DENIED", "CSRF token required.");
        if (selectedScenario() === "feedback_unavailable")
            return fail(503, "FEEDBACK_UNAVAILABLE", "Synthetic feedback service is unavailable.");
        return HttpResponse.json(feedbackQueued, { status: 202 });
    }),
];
export function resetMockPages(): void {
    cursors.clear();
}
