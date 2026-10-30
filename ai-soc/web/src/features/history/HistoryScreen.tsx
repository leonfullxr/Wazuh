import { Clock3 } from "lucide-react";
import type { AnswerHistoryItem } from "../../app/state/answer-session";
import type { Locale } from "../../i18n";
import { words } from "../../i18n/answer-copy";
import { StatusPill } from "../../components/ui/status-pill";
import { date } from "../../app/state/answer-format";

export function HistoryScreen({
    history,
    locale,
    t,
    onOpen,
    onAskAgain,
    pending,
}: {
    history: AnswerHistoryItem[];
    locale: Locale;
    t: (key: keyof typeof words.en) => string;
    onOpen: (item: AnswerHistoryItem) => void;
    onAskAgain: (item: AnswerHistoryItem) => void;
    pending: boolean;
}) {
    return (
        <section className="panel history-panel">
            {history.length === 0 ? (
                <div className="empty-state">
                    <Clock3 />
                    <h2>{t("none")}</h2>
                    <p>{t("emptyHistory")}</p>
                </div>
            ) : (
                history
                    .filter(
                        (item) =>
                            !item.parent_question_id ||
                            !history.some(
                                (candidate) =>
                                    candidate.answer.question_id === item.parent_question_id,
                            ),
                    )
                    .map((item) =>
                        renderHistoryItem(item, 0, history, locale, t, onOpen, onAskAgain, pending),
                    )
            )}
        </section>
    );
}

function renderHistoryItem(
    item: AnswerHistoryItem,
    depth: number,
    history: AnswerHistoryItem[],
    locale: Locale,
    t: (key: keyof typeof words.en) => string,
    onOpen: (item: AnswerHistoryItem) => void,
    onAskAgain: (item: AnswerHistoryItem) => void,
    pending: boolean,
): React.ReactNode {
    return (
        <div className="history-group" key={item.answer.question_id}>
            <article
                className={`history-row${depth > 0 ? " history-child" : ""}`}
                data-depth={Math.min(depth, 8)}
            >
                <button className="history-open" onClick={() => onOpen(item)}>
                    <time>
                        {date(item.at, Intl.DateTimeFormat().resolvedOptions().timeZone, locale)}
                    </time>
                    <strong>{item.question}</strong>
                    <span className="history-meta">
                        <StatusPill
                            tone={
                                item.answer.status === "answered"
                                    ? "positive"
                                    : item.answer.status === "partial"
                                      ? "warning"
                                      : "neutral"
                            }
                        >
                            {t(item.answer.status)}
                        </StatusPill>
                        {item.answer.blocks.map((block) => (
                            <code key={block.topic_id}>{block.topic_id}</code>
                        ))}
                        {item.answer.left_out.length > 0 && (
                            <span>
                                {item.answer.left_out.length} {t("leftOut")}
                            </span>
                        )}
                    </span>
                </button>
                <button className="btn outline" disabled={pending} onClick={() => onAskAgain(item)}>
                    {t("retry")}
                </button>
            </article>
            {history
                .filter((child) => child.parent_question_id === item.answer.question_id)
                .map((child) =>
                    renderHistoryItem(
                        child,
                        depth + 1,
                        history,
                        locale,
                        t,
                        onOpen,
                        onAskAgain,
                        pending,
                    ),
                )}
        </div>
    );
}
