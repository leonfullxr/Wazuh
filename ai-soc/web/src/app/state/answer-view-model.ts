import type {
    Answer,
    EvidenceItem,
    TopicAnswer,
} from "../../../../contracts/v1/generated/types.ts";
import type { AnswerHistoryItem } from "./answer-session";

export function evidenceById(answer: Answer | null) {
    const items = new Map<string, EvidenceItem>();
    for (const block of answer?.blocks ?? [])
        for (const fetch of block.tables)
            for (const item of fetch.items) items.set(item.evidence_id, item);
    return items;
}

export function topicsFromHistory(history: AnswerHistoryItem[]) {
    const topics = new Map<string, { block: TopicAnswer; count: number; last: Answer }>();
    for (const item of history.slice().reverse())
        for (const block of item.answer.blocks) {
            const previous = topics.get(block.topic_id);
            topics.set(block.topic_id, {
                block,
                count: (previous?.count ?? 0) + 1,
                last: item.answer,
            });
        }
    return [...topics.values()];
}
