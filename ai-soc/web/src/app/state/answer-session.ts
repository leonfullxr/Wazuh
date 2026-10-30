import { useReducer } from "react";
import type {
    Answer,
    AskRequest,
    ErrorCode,
    FetchResult,
} from "../../../../contracts/v1/generated/types.ts";

export type PageContext = {
    question_id: string;
    environment_id: string;
    topic_id: string;
    fetch_id: string;
    cursor: string;
};
export type FeedbackResult =
    | { kind: "queued"; feedback_id: string }
    | { kind: "error"; code: ErrorCode };
export const pageStateKey = (topic_id: string, fetch_id: string) => `${topic_id}:${fetch_id}`;
function mergeChecks(current: FetchResult["checks"], incoming: FetchResult["checks"]) {
    return [
        ...current,
        ...incoming.filter(
            (check) =>
                !current.some(
                    (existing) =>
                        existing.code === check.code &&
                        existing.name === check.name &&
                        existing.outcome === check.outcome,
                ),
        ),
    ];
}
export type AnswerRecord = {
    answer: Answer;
    question: string;
    replay_request: AskRequest;
    environment_id: string;
    parent_question_id: string | null;
    continuation_selection: string[];
    feedback_draft: string;
    feedback_result: FeedbackResult | null;
    page_errors: Record<string, string>;
    paging: Record<string, string>;
    at: string;
};
export type AnswerHistoryItem = AnswerRecord;
export function replayEnvironment(
    item: AnswerHistoryItem,
    sites: readonly { id: string }[],
): string | null {
    return sites.some((site) => site.id === item.environment_id) ? item.environment_id : null;
}
export type AnswerSession = {
    records: Record<string, AnswerRecord>;
    active_question_id: string | null;
    history: AnswerHistoryItem[];
};
export const initialAnswerSession: AnswerSession = {
    records: {},
    active_question_id: null,
    history: [],
};
export type PageContextAction = PageContext & { request_id: string };
export type AnswerSessionAction =
    | {
          type: "record";
          answer: Answer;
          question: string;
          replay_request?: AskRequest;
          parent_question_id?: string | null;
          at: string;
      }
    | { type: "activate"; question_id: string }
    | { type: "selection"; question_id: string; selection: string[] }
    | { type: "feedback-draft"; question_id: string; draft: string }
    | { type: "feedback-result"; question_id: string; result: FeedbackResult | null }
    | { type: "page-start"; context: PageContextAction }
    | { type: "page-success"; context: PageContextAction; page: FetchResult }
    | { type: "page-error"; context: PageContextAction; error: string };

export function pageMatchesContext(answer: Answer | null, context: PageContext, page: FetchResult) {
    if (
        !answer ||
        answer.question_id !== context.question_id ||
        answer.environment_id !== context.environment_id ||
        page.topic_id !== context.topic_id ||
        page.fetch_id !== context.fetch_id ||
        page.scope.environment_id !== context.environment_id
    )
        return false;
    const table = answer.blocks
        .find((block) => block.topic_id === context.topic_id)
        ?.tables.find((entry) => entry.fetch_id === context.fetch_id);
    return table?.next_cursor === context.cursor;
}

function withoutCursor(answer: Answer, topic_id: string, fetch_id: string): Answer {
    return {
        ...answer,
        blocks: answer.blocks.map((block) =>
            block.topic_id !== topic_id
                ? block
                : {
                      ...block,
                      tables: block.tables.map((table) =>
                          table.fetch_id !== fetch_id ? table : { ...table, next_cursor: null },
                      ),
                  },
        ),
    };
}

function patchRecord(
    state: AnswerSession,
    id: string,
    patch: (record: AnswerRecord) => AnswerRecord,
) {
    const record = state.records[id];
    if (!record) return state;
    const updated = patch(record);
    return {
        ...state,
        records: { ...state.records, [id]: updated },
        history: state.history.map((item) => (item.answer.question_id === id ? updated : item)),
    };
}

export function answerSessionReducer(
    state: AnswerSession,
    action: AnswerSessionAction,
): AnswerSession {
    if (action.type === "record") {
        const record: AnswerRecord = {
            answer: action.answer,
            question: action.question,
            replay_request:
                action.replay_request ??
                ({
                    question: action.question,
                    environment_id: action.answer.environment_id,
                } satisfies AskRequest),
            environment_id: action.answer.environment_id,
            parent_question_id: action.parent_question_id ?? null,
            continuation_selection: [],
            feedback_draft: "",
            feedback_result: null,
            page_errors: {},
            paging: {},
            at: action.at,
        };
        return {
            records: { ...state.records, [action.answer.question_id]: record },
            active_question_id: action.answer.question_id,
            history: [record, ...state.history],
        };
    }
    if (action.type === "activate")
        return state.records[action.question_id]
            ? { ...state, active_question_id: action.question_id }
            : state;
    if (action.type === "selection")
        return patchRecord(state, action.question_id, (r) => ({
            ...r,
            continuation_selection: action.selection,
        }));
    if (action.type === "feedback-draft")
        return patchRecord(state, action.question_id, (r) => ({
            ...r,
            feedback_draft: action.draft,
        }));
    if (action.type === "feedback-result")
        return patchRecord(state, action.question_id, (r) => ({
            ...r,
            feedback_result: action.result,
        }));
    const context = action.context;
    const record = state.records[context.question_id];
    if (!record || record.environment_id !== context.environment_id) return state;
    const target = record.answer.blocks
        .find((b) => b.topic_id === context.topic_id)
        ?.tables.find((table) => table.fetch_id === context.fetch_id);
    if (!target) return state;
    const key = pageStateKey(context.topic_id, context.fetch_id);
    if (action.type === "page-start") {
        if (target.next_cursor !== context.cursor) return state;
        return patchRecord(state, context.question_id, (r) => ({
            ...r,
            paging: { ...r.paging, [key]: context.request_id },
            page_errors: { ...r.page_errors, [key]: "" },
        }));
    }
    if (record.paging[key] !== context.request_id) return state;
    if (target.next_cursor !== context.cursor)
        return patchRecord(state, context.question_id, (r) => ({
            ...r,
            paging: { ...r.paging, [key]: "" },
        }));
    if (action.type === "page-error") {
        // An expired cursor is terminal: keep the loaded rows but stop offering it.
        const expired = action.error.startsWith("CURSOR_EXPIRED");
        return patchRecord(state, context.question_id, (r) => ({
            ...r,
            answer: expired
                ? withoutCursor(r.answer, context.topic_id, context.fetch_id)
                : r.answer,
            paging: { ...r.paging, [key]: "" },
            page_errors: { ...r.page_errors, [key]: action.error },
        }));
    }
    if (!pageMatchesContext(record.answer, context, action.page))
        return patchRecord(state, context.question_id, (r) => ({
            ...r,
            paging: { ...r.paging, [key]: "" },
            page_errors: {
                ...r.page_errors,
                [key]: "Page response did not match the requested fetch.",
            },
        }));
    const page = action.page;
    if (page.state === "denied" || page.state === "unavailable" || page.state === "empty") {
        const detail = page.error
            ? `${page.error.code}: ${page.error.message}`
            : (page.message ?? page.state);
        const answer = {
            ...record.answer,
            blocks: record.answer.blocks.map((block) =>
                block.topic_id !== context.topic_id
                    ? block
                    : {
                          ...block,
                          tables: block.tables.map((table) =>
                              table.fetch_id !== context.fetch_id
                                  ? table
                                  : {
                                        ...table,
                                        next_cursor: page.next_cursor,
                                        checks: mergeChecks(table.checks, page.checks),
                                        message: page.message ?? table.message,
                                    },
                          ),
                      },
            ),
        };
        return patchRecord(state, context.question_id, (r) => ({
            ...r,
            answer,
            paging: { ...r.paging, [key]: "" },
            page_errors: { ...r.page_errors, [key]: detail },
        }));
    }
    const answer = {
        ...record.answer,
        blocks: record.answer.blocks.map((block) =>
            block.topic_id !== context.topic_id
                ? block
                : {
                      ...block,
                      tables: block.tables.map((table) =>
                          table.fetch_id !== context.fetch_id
                              ? table
                              : {
                                    ...table,
                                    state: page.state,
                                    scope: {
                                        ...table.scope,
                                        visibility: page.scope.visibility,
                                        snapshot: page.scope.snapshot,
                                        displayed_rows: table.rows.length + page.rows.length,
                                    },
                                    rows: [...table.rows, ...page.rows],
                                    items: [...table.items, ...page.items],
                                    checks: mergeChecks(table.checks, page.checks),
                                    count: page.count ?? table.count,
                                    next_cursor: page.next_cursor,
                                    message: page.message ?? table.message,
                                    snapshot_at: page.snapshot_at,
                                    snapshot: page.snapshot,
                                },
                      ),
                  },
        ),
    };
    const notice =
        page.state === "filtered" || page.scope.visibility === "filtered" ? "filteredPage" : "";
    return patchRecord(state, context.question_id, (r) => ({
        ...r,
        answer,
        paging: { ...r.paging, [key]: "" },
        page_errors: { ...r.page_errors, [key]: notice },
    }));
}

export function useAnswerSession() {
    const [state, dispatch] = useReducer(answerSessionReducer, initialAnswerSession);
    const active = state.active_question_id
        ? (state.records[state.active_question_id] ?? null)
        : null;
    return { ...state, active, answer: active?.answer ?? null, dispatch };
}
