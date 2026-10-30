import { ChevronRight, Files } from "lucide-react";
import type {
    Answer,
    CheckOutcome,
    TopicAnswer,
} from "../../../../contracts/v1/generated/types.ts";
import type { Locale } from "../../i18n";
import { words, localeEnum } from "../../i18n/answer-copy";
import { judgments, outcomes } from "../../i18n/answer-enums";
import { StatusPill } from "../../components/ui/status-pill";
import { safeDocumentUrl } from "../../app/state/answer-format";

export type SessionTopic = { block: TopicAnswer; count: number; last: Answer };
export function TopicsScreen({
    topics,
    locale,
    t,
}: {
    topics: SessionTopic[];
    locale: Locale;
    t: (key: keyof typeof words.en) => string;
}) {
    return (
        <section className="panel">
            <p className="panel-note">{t("topicNote")}</p>
            {topics.length === 0 ? (
                <div className="empty-state">
                    <Files />
                    <h2>{t("emptyTopics")}</h2>
                </div>
            ) : (
                topics.map(({ block, count }) => (
                    <article className="topic-list-row" key={block.topic_id}>
                        <div>
                            <h2>
                                {block.document?.heading ?? (
                                    <code className="mono">{block.topic_id}</code>
                                )}
                            </h2>
                            <code>{block.topic_id}</code>
                        </div>
                        <span>
                            {count} {t("timesSeen")}
                        </span>
                        <StatusPill>
                            {localeEnum(judgments, block.judgment.state, locale)}
                        </StatusPill>
                        <span className="check-summary">
                            {Object.entries(
                                block.checks.reduce(
                                    (counts, check) => ({
                                        ...counts,
                                        [check.outcome]: (counts[check.outcome] ?? 0) + 1,
                                    }),
                                    {} as Record<string, number>,
                                ),
                            )
                                .map(
                                    ([outcome, amount]) =>
                                        `${localeEnum(outcomes, outcome as CheckOutcome, locale)} ${amount}`,
                                )
                                .join(" | ") || "-"}
                        </span>
                        {block.document && safeDocumentUrl(block.document.url) && (
                            <a
                                target="_blank"
                                rel="noopener"
                                href={safeDocumentUrl(block.document.url)!}
                            >
                                {block.document.heading}
                                <ChevronRight size={14} />
                            </a>
                        )}
                    </article>
                ))
            )}
        </section>
    );
}
