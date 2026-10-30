import { useState } from "react";
import { AlertCircle, Check, CircleHelp, FileText } from "lucide-react";
import type {
    EvidenceItem,
    JudgmentState,
    TopicAnswer,
} from "../../../../contracts/v1/generated/types.ts";
import { Tag } from "../../components/ui/tag";
import { judgmentStateTags } from "../../lib/semantic";
import type { Locale } from "../../i18n";
import {
    words,
    localeEnum,
    stateWord,
    removedFindingsCopy,
    evidenceCheckNames,
} from "../../i18n/answer-copy";
import { judgments, removed } from "../../i18n/answer-enums";
import {
    countLabel,
    date,
    emptyProofQualified,
    formatVisibility,
    resolveCitation,
    safeDocumentUrl,
} from "../../app/state/answer-format";
import { pageStateKey } from "../../app/state/answer-session";
import {
    EmptyExplanation,
    EvidenceChip,
    EvidenceDataTable,
    OutcomePill,
} from "./EvidenceDataTable";
export function TopicSection({
    block,
    locale,
    timezone,
    t,
    mapped,
    onEvidence,
    onPage,
    pageErrors,
    pagePending,
}: {
    block: TopicAnswer;
    locale: Locale;
    timezone: string;
    t: (k: keyof typeof words.en) => string;
    mapped: Map<string, EvidenceItem>;
    onEvidence: (i: EvidenceItem, e: HTMLElement) => void;
    onPage: (topicId: string, fetchId: string, cursor: string) => void;
    pageErrors: Record<string, string>;
    pagePending: boolean;
}) {
    const [expanded, setExpanded] = useState<Record<string, boolean>>({});
    const sentence =
        block.judgment.state !== "validated"
            ? ((
                  {
                      no_findings: t("noAllClear"),
                      ingestion_unconfirmed: t("noAllClear"),
                      denial: t("denied"),
                      evidence_unavailable: t("unavailable"),
                  } as Partial<Record<JudgmentState, string>>
              )[block.judgment.state] ?? block.judgment.message)
            : null;
    const findItem = (id: string) => resolveCitation(block, id) ?? mapped.get(id);
    return (
        <section className="panel topic-section" id={`topic-${CSS.escape(block.topic_id)}`}>
            <header className="topic-header">
                <div>
                    <span className="eyebrow">
                        {t("topic")} {block.ordinal + 1}
                    </span>
                    <h2>
                        {block.document?.heading ?? <code className="mono">{block.topic_id}</code>}
                    </h2>
                    {block.document?.heading && <code>{block.topic_id}</code>}
                </div>
                <Tag {...judgmentStateTags[block.judgment.state]}>
                    {localeEnum(judgments, block.judgment.state, locale)}
                </Tag>
                {block.judgment.state !== "not_requested" && block.judgment.model_id && (
                    <span className="judgment-meta">
                        {t("model")}: {block.judgment.model_id}
                        {block.judgment.effort ? ` / ${block.judgment.effort}` : ""}
                    </span>
                )}
                {block.document && safeDocumentUrl(block.document.url) && (
                    <a target="_blank" rel="noopener" href={safeDocumentUrl(block.document.url)!}>
                        <FileText size={15} />
                        {t("document")}
                    </a>
                )}
            </header>
            {block.missing.length > 0 && (
                <p className="notice">
                    {t("missing")}:{" "}
                    {block.missing.map((item) => stateWord(item, locale)).join(", ")}
                </p>
            )}
            {block.judgment.sentences.length > 0 && (
                <div className="findings">
                    <h3>{t("findingList")}</h3>
                    {block.judgment.sentences.map((f) => (
                        <article className="finding" key={f.finding_id}>
                            <span className="finding-kind">
                                {f.kind === "observation" ? (
                                    <CircleHelp size={14} aria-hidden="true" />
                                ) : f.kind === "hypothesis" ? (
                                    <CircleHelp size={14} aria-hidden="true" />
                                ) : (
                                    <Check size={14} aria-hidden="true" />
                                )}{" "}
                                {f.kind === "observation"
                                    ? t("obs")
                                    : f.kind === "hypothesis"
                                      ? t("hyp")
                                      : t("rec")}
                            </span>
                            <p>{f.text}</p>
                            <div>
                                {f.evidence_ids.map((id) => (
                                    <button
                                        key={id}
                                        className="citation"
                                        aria-label={`${t("citation")}: ${id}`}
                                        onClick={(e) => {
                                            const row = document.getElementById(
                                                `evidence-${CSS.escape(id)}`,
                                            );
                                            if (row) {
                                                const details = row.closest(
                                                    "details",
                                                ) as HTMLDetailsElement | null;
                                                if (details) details.open = true;
                                                row.scrollIntoView({
                                                    behavior: matchMedia(
                                                        "(prefers-reduced-motion: reduce)",
                                                    ).matches
                                                        ? "instant"
                                                        : "smooth",
                                                    block: "center",
                                                });
                                                row.classList.add("highlight-row");
                                                setTimeout(
                                                    () => row.classList.remove("highlight-row"),
                                                    1600,
                                                );
                                            }
                                            const item = findItem(id);
                                            if (item) onEvidence(item, e.currentTarget);
                                        }}
                                    >
                                        {findItem(id)
                                            ? id.slice(0, 16)
                                            : `${t("notView")}: ${id.slice(0, 16)}`}
                                    </button>
                                ))}
                            </div>
                        </article>
                    ))}
                </div>
            )}
            {block.judgment.removed.length > 0 && (
                <details className="removed">
                    <summary>{removedFindingsCopy(block.judgment.removed.length, locale)}</summary>
                    <ul>
                        {block.judgment.removed.map((r, i) => (
                            <li key={`${r.finding_id}-${i}`}>
                                {localeEnum(removed, r.reason, locale)}
                            </li>
                        ))}
                    </ul>
                </details>
            )}
            {sentence && (
                <p className="judgment-explainer">
                    <CircleHelp size={16} />
                    {sentence}
                </p>
            )}
            {block.checks.length > 0 && (
                <div className="checks">
                    <h3>{t("checks")}</h3>
                    <div
                        className="table-scroll"
                        role="region"
                        tabIndex={0}
                        aria-label={`${t("checks")} ${block.topic_id}`}
                    >
                        <table>
                            <thead>
                                <tr>
                                    <th>{t("outcome")}</th>
                                    <th>{t("check")}</th>
                                    <th>{t("message")}</th>
                                    <th>{t("tables")}</th>
                                </tr>
                            </thead>
                            <tbody>
                                {block.checks.map((c) => (
                                    <tr key={c.check_id}>
                                        <td>
                                            <OutcomePill outcome={c.outcome} locale={locale} />
                                        </td>
                                        <td>{c.label}</td>
                                        <td>{c.message}</td>
                                        <td>
                                            {c.evidence_ids.map((id) => (
                                                <EvidenceChip
                                                    id={id}
                                                    key={id}
                                                    isCheckRecord
                                                    mapped={mapped}
                                                    onEvidence={onEvidence}
                                                    t={t}
                                                />
                                            ))}
                                        </td>
                                    </tr>
                                ))}
                            </tbody>
                        </table>
                    </div>
                </div>
            )}
            {block.tables.map((fetch) => (
                <details
                    key={fetch.fetch_id}
                    className="fetch-table"
                    open={expanded[fetch.fetch_id] ?? true}
                >
                    <summary
                        onClick={(e) => {
                            e.preventDefault();
                            setExpanded((v) => ({
                                ...v,
                                [fetch.fetch_id]: !(v[fetch.fetch_id] ?? true),
                            }));
                        }}
                    >
                        <strong>{fetch.fetch_id}</strong>
                        <span>{stateWord(fetch.state, locale)}</span>
                        <span>{countLabel(fetch, locale)}</span>
                        {fetch.count?.approximate && <span>{t("approx")}</span>}
                        <span>
                            {t("visibility")}: {formatVisibility(fetch.scope.visibility, locale)}
                        </span>
                        {fetch.scope.visibility !== "full" && <AlertCircle size={14} />}
                        {pageErrors[pageStateKey(block.topic_id, fetch.fetch_id)] && (
                            <span className="summary-warning">
                                <AlertCircle size={14} aria-hidden="true" />
                                {t("pagingStopped")}
                            </span>
                        )}
                        {fetch.state === "empty" && !emptyProofQualified(fetch.empty_proof) && (
                            <span className="summary-warning">
                                <AlertCircle size={14} aria-hidden="true" />
                                {t("emptyUnconfirmedShort")}
                            </span>
                        )}
                        <span>
                            {date(fetch.window.start, timezone, locale)} -{" "}
                            {date(fetch.window.end, timezone, locale)} ({fetch.window.source_text})
                        </span>
                        <span>
                            {date(fetch.snapshot_at ?? fetch.snapshot.at, timezone, locale)}
                        </span>
                        {(fetch.snapshot.kind === "first_page_only" || fetch.next_cursor) && (
                            <span>{t("firstPage")}</span>
                        )}
                    </summary>
                    {fetch.checks.length > 0 && (
                        <div
                            className="fetch-checks"
                            aria-label={`${t("checks")} ${fetch.fetch_id}`}
                        >
                            {fetch.checks.map((check) => (
                                <div className="fetch-check" key={`${check.code}:${check.name}`}>
                                    <span className="fetch-check-outcome">
                                        {check.outcome === "passed" ? (
                                            <Check size={14} aria-hidden="true" />
                                        ) : check.outcome === "failed" ? (
                                            <AlertCircle size={14} aria-hidden="true" />
                                        ) : (
                                            <CircleHelp size={14} aria-hidden="true" />
                                        )}
                                        {locale === "en"
                                            ? check.outcome === "passed"
                                                ? "Passed"
                                                : check.outcome === "failed"
                                                  ? "Failed"
                                                  : "Unknown"
                                            : check.outcome === "passed"
                                              ? "Superada"
                                              : check.outcome === "failed"
                                                ? "Fallida"
                                                : "Desconocida"}
                                    </span>
                                    <span>
                                        {localeEnum(evidenceCheckNames, check.name, locale)}
                                    </span>
                                    <code>{check.code}</code>
                                    {check.name === "duplicate_source" && (
                                        <p>{t("duplicateSourceDisclosure")}</p>
                                    )}
                                </div>
                            ))}
                        </div>
                    )}
                    {fetch.state === "empty" ||
                    (fetch.empty_proof != null && fetch.rows.length === 0) ? (
                        <EmptyExplanation fetch={fetch} t={t} locale={locale} />
                    ) : null}
                    {(fetch.state === "filtered" ||
                        fetch.state === "denied" ||
                        fetch.state === "unavailable") && (
                        <div className="alert warning">
                            <AlertCircle size={16} />
                            <span>
                                {fetch.state === "filtered"
                                    ? t("filteredWarn")
                                    : fetch.error?.code
                                      ? `${fetch.error.code}: ${fetch.error.message}`
                                      : stateWord(fetch.state, locale)}
                            </span>
                        </div>
                    )}
                    {fetch.rows.length > 0 && (
                        <>
                            <p className="muted table-note">{t("loadedSort")}</p>
                            <EvidenceDataTable
                                fetch={fetch}
                                locale={locale}
                                timezone={timezone}
                                findItem={findItem}
                                onEvidence={onEvidence}
                                t={t}
                            />
                        </>
                    )}
                    {(fetch.buckets?.length ?? 0) > 0 && (
                        <div
                            className="bucket-list table-scroll"
                            role="region"
                            tabIndex={0}
                            aria-label={`${t("buckets")} ${fetch.fetch_id}`}
                        >
                            <table>
                                <caption>
                                    {t("buckets")}, {t("completeness")}:{" "}
                                    {stateWord(fetch.bucket_completeness ?? "unknown", locale)}
                                </caption>
                                <thead>
                                    <tr>
                                        <th scope="col">{t("key")}</th>
                                        <th scope="col">{t("count")}</th>
                                    </tr>
                                </thead>
                                <tbody>
                                    {(fetch.buckets ?? []).map((bucket) => (
                                        <tr key={bucket.evidence_id}>
                                            <td className="mono">{String(bucket.key)}</td>
                                            <td>
                                                {countLabel(
                                                    { ...fetch, count: bucket.count },
                                                    locale,
                                                )}
                                            </td>
                                        </tr>
                                    ))}
                                </tbody>
                            </table>
                        </div>
                    )}
                    {fetch.message && (
                        <p className="fetch-message">
                            {fetch.next_cursor
                                ? fetch.message
                                : `${t("pagingStopped")}: ${fetch.message}`}
                        </p>
                    )}
                    {pageErrors[pageStateKey(block.topic_id, fetch.fetch_id)] && (
                        <div
                            className={
                                pageErrors[pageStateKey(block.topic_id, fetch.fetch_id)] ===
                                "filteredPage"
                                    ? "alert warning"
                                    : "alert error"
                            }
                            role="alert"
                        >
                            {pageErrors[pageStateKey(block.topic_id, fetch.fetch_id)] ===
                            "filteredPage"
                                ? t("filteredPageNotice")
                                : pageErrors[
                                        pageStateKey(block.topic_id, fetch.fetch_id)
                                    ]?.startsWith("CURSOR_EXPIRED")
                                  ? `CURSOR_EXPIRED: ${t("retryExpired")}`
                                  : pageErrors[pageStateKey(block.topic_id, fetch.fetch_id)]}
                        </div>
                    )}
                    {fetch.next_cursor && (
                        <button
                            className="btn outline"
                            onClick={() =>
                                onPage(block.topic_id, fetch.fetch_id, fetch.next_cursor!)
                            }
                            disabled={pagePending}
                        >
                            {pagePending ? t("running") : t("loadMore")}
                        </button>
                    )}
                </details>
            ))}
        </section>
    );
}
