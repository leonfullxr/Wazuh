import { useState } from "react";
import { Check, Copy } from "lucide-react";
import type { Answer, EvidenceItem } from "../../../../contracts/v1/generated/types.ts";
import { Tag } from "../../components/ui/tag";
import { answerStatusTags, judgmentStateTags } from "../../lib/semantic";
import { words, localeEnum, stateWord } from "../../i18n/answer-copy";
import { judgments, reasons } from "../../i18n/answer-enums";
import type { Locale } from "../../i18n";
import { TopicSection } from "./TopicSection";
export function AnswerView({
    answer,
    question,
    parentQuestion,
    onOpenParent,
    continuationTopics,
    locale,
    timezone,
    t,
    mapped,
    onEvidence,
    onPage,
    pageErrors,
    pagePending,
    checked,
    setChecked,
    onContinue,
    questionPending,
    headingRef,
}: {
    answer: Answer;
    question: string;
    parentQuestion?: string;
    onOpenParent?: () => void;
    continuationTopics: string[];
    locale: Locale;
    timezone: string;
    t: (k: keyof typeof words.en) => string;
    mapped: Map<string, EvidenceItem>;
    onEvidence: (i: EvidenceItem, e: HTMLElement) => void;
    onPage: (topicId: string, fetchId: string, cursor: string) => void;
    pageErrors: Record<string, string>;
    pagePending: boolean;
    checked: string[];
    setChecked: React.Dispatch<React.SetStateAction<string[]>>;
    onContinue: () => void;
    questionPending: boolean;
    headingRef: React.RefObject<HTMLHeadingElement | null>;
}) {
    return (
        <>
            <section className="answer-summary panel" aria-live="polite">
                <h2 id="answer-heading" ref={headingRef} tabIndex={-1} className="sr-only">
                    {answer.status === "answered" || answer.status === "partial"
                        ? words[locale].answerHeading
                        : answer.status === "clarify"
                          ? words[locale].clarificationNeeded
                          : words[locale].refusedHeading}
                </h2>
                <div className="answer-status">
                    <Tag {...answerStatusTags[answer.status]}>{t(answer.status)}</Tag>
                    <span>
                        {answer.status === "refused"
                            ? `${answer.message ?? ""} ${t("unmappedQuestion")}`.trim()
                            : (answer.message ?? "")}
                    </span>
                </div>
                <div className="ids-row">
                    <span>
                        {t("environment")}: <code>{answer.environment_id}</code>
                    </span>
                    <span>
                        {t("questionId")} <code>{answer.question_id}</code>
                        <CopyButton value={answer.question_id} t={t} />
                    </span>
                    <span>
                        {t("traceId")} <code>{answer.trace_id}</code>
                        <CopyButton value={answer.trace_id} t={t} />
                    </span>
                    <a href="#status">
                        {t("provenance")}: {answer.provenance.content_sha.slice(0, 8)} /{" "}
                        {answer.provenance.pack_sha256.slice(0, 8)}
                    </a>
                </div>
                {question && (
                    <p className="original-question">
                        <strong>{t("originalQuestion")}:</strong> {question}
                    </p>
                )}
                {parentQuestion && onOpenParent && (
                    <p className="original-question">
                        {t("continuedFrom")}:{" "}
                        <button className="text-link" onClick={onOpenParent}>
                            {parentQuestion}
                        </button>
                    </p>
                )}
                {continuationTopics.length > 0 && (
                    <p className="original-question" data-testid="continuation-topics">
                        <strong>{t("selectedTopics")}:</strong> {continuationTopics.join(", ")}
                    </p>
                )}
            </section>
            {answer.left_out.length > 0 && (
                <section className="panel leftout" aria-labelledby="left-out-title">
                    <h2 id="left-out-title">{t("leftOut")}</h2>
                    {answer.left_out.map((left, index) => (
                        <div
                            className="leftout-row"
                            key={`${left.topic_id}-${left.stage}-${index}`}
                        >
                            <label className={left.retryable ? "" : "disabled-choice"}>
                                <input
                                    type="checkbox"
                                    disabled={!left.retryable}
                                    checked={checked.includes(left.topic_id)}
                                    onChange={(event) =>
                                        setChecked((previous) =>
                                            event.target.checked
                                                ? [...previous, left.topic_id]
                                                : previous.filter((id) => id !== left.topic_id),
                                        )
                                    }
                                />
                                <code className="mono">{left.topic_id}</code>
                            </label>
                            <span>{stateWord(left.stage, locale)}</span>
                            <span>{localeEnum(reasons, left.reason, locale)}</span>
                            <span>{left.retryable ? t("retryable") : t("notRetryable")}</span>
                            {!left.retryable && <small>{t("continueWhy")}</small>}
                        </div>
                    ))}
                    {checked.length > 0 && (
                        <button
                            className="btn primary"
                            onClick={onContinue}
                            disabled={questionPending}
                        >
                            {t("continue")}
                        </button>
                    )}
                </section>
            )}
            {answer.status === "clarify" && answer.clarify && (
                <section className="panel clarify">
                    <h2>{t("clarificationNeeded")}</h2>
                    <p>{answer.clarify.question}</p>
                    <p>
                        {stateWord(answer.clarify.kind, locale)}
                        {answer.clarify.suggested_topic && `  |  ${answer.clarify.suggested_topic}`}
                    </p>
                    <div>
                        {answer.clarify.slots.map((s) => (
                            <span className="chip" key={s}>
                                {s}
                            </span>
                        ))}
                    </div>
                    <p className="muted">{t("originalQuestionKept")}</p>
                </section>
            )}
            {answer.status !== "clarify" && answer.blocks.length > 0 && (
                <>
                    <nav className="topic-jump" aria-label={t("jump")}>
                        {answer.blocks
                            .slice()
                            .sort((a, b) => a.ordinal - b.ordinal)
                            .map((b) => (
                                <a key={b.topic_id} href={`#topic-${CSS.escape(b.topic_id)}`}>
                                    <span>{b.ordinal + 1}</span>
                                    {b.document?.heading ?? (
                                        <code className="mono">{b.topic_id}</code>
                                    )}
                                    <Tag {...judgmentStateTags[b.judgment.state]}>
                                        {localeEnum(judgments, b.judgment.state, locale)}
                                    </Tag>
                                </a>
                            ))}
                    </nav>
                    {answer.blocks
                        .slice()
                        .sort((a, b) => a.ordinal - b.ordinal)
                        .map((b) => (
                            <TopicSection
                                key={`${b.topic_id}-${b.ordinal}`}
                                block={b}
                                locale={locale}
                                timezone={timezone}
                                t={t}
                                mapped={mapped}
                                onEvidence={onEvidence}
                                onPage={onPage}
                                pageErrors={pageErrors}
                                pagePending={pagePending}
                            />
                        ))}
                </>
            )}
        </>
    );
}
function CopyButton({ value, t }: { value: string; t: (k: keyof typeof words.en) => string }) {
    const [copied, setCopied] = useState(false);
    return (
        <button
            className="icon-button"
            aria-label={t("copyValue")}
            title={value}
            onClick={() => {
                void navigator.clipboard?.writeText(value);
                setCopied(true);
                setTimeout(() => setCopied(false), 1200);
            }}
        >
            {copied ? <Check size={14} /> : <Copy size={14} />}
            <span className="sr-only" aria-live="polite">
                {copied ? t("copied") : ""}
            </span>
        </button>
    );
}
