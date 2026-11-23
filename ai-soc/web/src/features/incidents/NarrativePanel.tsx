import { useState, type ReactNode } from "react";
import { TriangleAlert } from "lucide-react";
import { IdChip } from "../../components/ui/portfolio";
import { useQuery } from "@tanstack/react-query";
import type { components } from "../../../../contracts/workspace/v1/types.ts";
import { getIncidentNarrative } from "../../api/workspace-m3";
import { WorkspaceRequestError } from "../../api/workspace";
import { fmt } from "../../i18n/answer-copy";
import { CopyValue } from "../investigate/CopyValue";
import { fmtDate } from "./M3WorkspacePage";

type Locale = "en" | "es";
type Translate = (key: string) => string;
type Citation = components["schemas"]["CitationReference"];
type Fact =
    | components["schemas"]["IncidentReference"]
    | components["schemas"]["GroupFact"]
    | components["schemas"]["AlertFact"];

export function NarrativePanel({
    siteId,
    incidentId,
    evidenceRevision,
    locale,
    t,
    groupTitles = new Map(),
    onOpenGroup,
}: {
    siteId: string;
    incidentId: string;
    evidenceRevision: string;
    locale: Locale;
    t: Translate;
    groupTitles?: ReadonlyMap<string, string>;
    onOpenGroup?: (groupId: string) => void;
}) {
    const [selectedCitation, setSelectedCitation] = useState<Citation | null>(null);
    const narrative = useQuery({
        queryKey: ["m3", "narrative", siteId, incidentId, evidenceRevision],
        queryFn: ({ signal }) =>
            getIncidentNarrative({ siteId, incidentId, evidenceRevision }, signal),
        enabled: Boolean(siteId && incidentId),
        retry: false,
        refetchInterval: (query) => {
            const status = query.state.data?.status;
            return status === "pending" ||
                status === "deferred" ||
                status === "running" ||
                status === "retrying"
                ? 3000
                : false;
        },
    });
    const data = narrative.isError ? undefined : narrative.data;
    const summary = data?.summary;
    const removals = data?.removals ?? summary?.removals ?? [];

    return (
        <section aria-labelledby="incident-narrative-heading" className="m3-narrative pp-panel pp-panel-pad">
            <div className="narrative-head">
                <h2 id="incident-narrative-heading" className="t-section">
                    {t("m3Narrative")}
                </h2>
                <button className="btn compact" onClick={() => void narrative.refetch()}>
                    {t("refresh")}
                </button>
            </div>
            {narrative.isLoading && <p role="status">{t("loading")}</p>}
            {narrative.isError && (
                <p className="alert error" role="alert">
                    {narrativeFailure(narrative.error, t)}
                </p>
            )}
            {data && (
                <>
                    {!data.is_current && (
                        <p className="alert warning" role="status">
                            {t("m3NarrativeHistorical")}
                        </p>
                    )}
                    <p className="m3-trust-note narrative-warning">
                        <TriangleAlert size={16} aria-hidden="true" />
                        <span>
                            <TrustNote text={t("m3NarrativeTrust")} />
                        </span>
                    </p>
                    {removals.length > 0 && (
                        <div>
                            <h3 className="t-sub">{t("m3NarrativeRemovals")}</h3>
                            <ul>
                                {removals.map((removal, index) => (
                                    <li key={`${removal.selection_digest}-${index}`}>
                                        {t(`m3NarrativeRemoval_${removal.reason}`)} ·{" "}
                                        <code>{removal.selection_digest}</code>
                                    </li>
                                ))}
                            </ul>
                        </div>
                    )}
                    {data.reason_code && (
                        <p>
                            {t("m3NarrativeReason")}: <code>{data.reason_code}</code>
                        </p>
                    )}
                    {data.status !== "available" && (
                        <p className="muted">
                            {t(
                                data.reason_code === "all_removed"
                                    ? "m3NarrativeAllRemoved"
                                    : "m3NarrativeNoSummary",
                            )}
                        </p>
                    )}
                    {data.status === "available" && !summary && (
                        <p className="alert warning" role="status">
                            {t("m3NarrativeMissingSummary")}
                        </p>
                    )}
                    {summary && (
                        <section aria-label={locale === "es" ? summary.label_es : summary.label_en}>
                            <h3 className="sr-only">
                                {locale === "es" ? summary.label_es : summary.label_en}
                            </h3>
                            {summary.status === "all_removed" ? (
                                <p className="muted">{t("m3NarrativeAllRemoved")}</p>
                            ) : summary.status === "invalid_structure" ? (
                                <p className="muted">{t("m3NarrativeInvalid")}</p>
                            ) : (
                                <p className="m3-narrative-text">
                                    <HashText
                                        text={
                                            locale === "es"
                                                ? summary.rendered_es
                                                : summary.rendered_en
                                        }
                                        locale={locale}
                                        groupTitles={groupTitles}
                                        onOpenGroup={onOpenGroup}
                                    />{" "}
                                    {summary.citations.map((citation, index) => (
                                        <button
                                            key={`${citation.kind}:${citation.fact_id}`}
                                            type="button"
                                            className="cite-chip"
                                            aria-label={`${t("sourceNumber")} ${index + 1}`}
                                            onClick={() => setSelectedCitation(citation)}
                                        >
                                            {index + 1}
                                        </button>
                                    ))}
                                </p>
                            )}
                            {summary.static_error && (
                                <p>
                                    {t("m3NarrativeStaticError")}: {summary.static_error}
                                </p>
                            )}
                            {summary.citations.length > 0 && (
                                <div className="narrative-sources">
                                    <h3 className="narrative-sources-title">{t("narrativeSources")}</h3>
                                    <ul className="m3-citations">
                                        {summary.citations.map((citation, index) => {
                                            const fact = findFact(data?.evidence, citation);
                                            const open = selectedCitation?.fact_id === citation.fact_id;
                                            return (
                                                <li key={`${citation.kind}:${citation.fact_id}`}>
                                                    <button
                                                        type="button"
                                                        className="narrative-source"
                                                        aria-pressed={open}
                                                        aria-label={`${t(`m3Citation_${citation.kind}`)} ${index + 1}: ${factWords(fact, citation, groupTitles, t)}`}
                                                        onClick={() =>
                                                            setSelectedCitation(open ? null : citation)
                                                        }
                                                    >
                                                        <span className="narrative-source-n num">
                                                            {index + 1}
                                                        </span>
                                                        <span className="narrative-source-text">
                                                            {factWords(fact, citation, groupTitles, t)}
                                                        </span>
                                                    </button>
                                                    <IdChip kind="fact" value={citation.fact_id} />
                                                    {open && (
                                                        <div className="m3-citation-detail" aria-live="polite">
                                                            <h4 className="sr-only">{t("m3CitationEvidence")}</h4>
                                                            {fact ? (
                                                                <FactDetails fact={fact} citation={citation} t={t} />
                                                            ) : (
                                                                <p>{t("m3CitationMissing")}</p>
                                                            )}
                                                        </div>
                                                    )}
                                                </li>
                                            );
                                        })}
                                    </ul>
                                </div>
                            )}
                            <NarrativeFeedback t={t} />
                        </section>
                    )}
                    {/* Generation provenance is secondary to the summary and evidence, so it starts folded. */}
                    <details className="m3-provenance disclosure">
                        <summary>{t("m3NarrativeProvenance")}</summary>
                        <dl className="m3-meta">
                            <dt>{t("m3EvidenceRevision")}</dt>
                            <dd>
                                <IdValue value={data.evidence_revision} locale={locale} />
                            </dd>
                            <dt>{t("m3NarrativeStatus")}</dt>
                            <dd>{t(`m3Narrative_${data.status}`)}</dd>
                            {data.provider_id && data.model_id && (
                                <>
                                    <dt>{t("m3ChainAssessmentModel")}</dt>
                                    <dd>{data.provider_id} · {data.model_id}</dd>
                                </>
                            )}
                            <dt>{t("m3NarrativeGeneration")}</dt>
                            <dd>
                                {data.generation_id ? (
                                    <IdValue value={data.generation_id} locale={locale} />
                                ) : (
                                    <code>{t("m3NotReported")}</code>
                                )}
                            </dd>
                            <dt>{t("m3NarrativeGenerationDigest")}</dt>
                            <dd>
                                {data.generation_digest ? (
                                    <IdValue value={data.generation_digest} locale={locale} />
                                ) : (
                                    <code>{t("m3NotReported")}</code>
                                )}
                            </dd>
                            <dt>{t("m3NarrativePackDigest")}</dt>
                            <dd>
                                {data.pack_digest ? (
                                    <IdValue value={data.pack_digest} locale={locale} />
                                ) : (
                                    <code>{t("m3NotReported")}</code>
                                )}
                            </dd>
                            {data.evidence && (
                                <>
                                    <dt>{t("m3NarrativeFrozenPackDigest")}</dt>
                                    <dd>
                                        <IdValue
                                            value={data.evidence.content_digest}
                                            locale={locale}
                                        />
                                    </dd>
                                </>
                            )}
                            {summary && (
                                <>
                                    <dt>{t("m3NarrativeValidatedPackDigest")}</dt>
                                    <dd>
                                        <IdValue value={summary.pack_digest} locale={locale} />
                                    </dd>
                                </>
                            )}
                            <dt>{t("m3NarrativeCompleted")}</dt>
                            <dd>
                                {data.completed_at
                                    ? new Intl.DateTimeFormat(undefined, {
                                          dateStyle: "medium",
                                          timeStyle: "short",
                                      }).format(new Date(data.completed_at))
                                    : t("m3NotReported")}
                            </dd>
                            <dt>{t("m3NarrativeUsage")}</dt>
                            <dd>
                                {tokenUsage(data.usage.input_tokens, t("m3NarrativeInput"), t)} ·{" "}
                                {tokenUsage(
                                    data.usage.cached_input_tokens,
                                    t("m3NarrativeCachedInput"),
                                    t,
                                )}{" "}
                                · {tokenUsage(data.usage.output_tokens, t("m3NarrativeOutput"), t)}
                            </dd>
                        </dl>
                        {data.evidence && (
                            <dl className="m3-meta">
                                <dt>{t("m3NarrativeFrozenPack")}</dt>
                                <dd>
                                    <IdValue value={data.evidence.content_digest} locale={locale} />
                                </dd>
                            </dl>
                        )}
                    </details>
                </>
            )}
        </section>
    );
}

function FactDetails({ fact, citation, t }: { fact: Fact; citation: Citation; t: Translate }) {
    if (citation.kind === "incident" && "incident_id" in fact) {
        return (
            <dl className="m3-meta">
                <dt>{t("m3IncidentId")}</dt>
                <dd>
                    <code>{fact.incident_id}</code>
                </dd>
                <dt>{t("m3EvidenceRevision")}</dt>
                <dd>
                    <code>{fact.incident_revision_id}</code>
                </dd>
                <dt>{t("m3Site")}</dt>
                <dd>{fact.site_id}</dd>
            </dl>
        );
    }
    if (citation.kind === "group" && "group_revision" in fact && "score_digest" in fact) {
        return (
            <dl className="m3-meta">
                <dt>{t("group")}</dt>
                <dd>
                    <code>{fact.group_id}</code>
                </dd>
                <dt>{t("m3MemberRevision")}</dt>
                <dd>
                    <code>{fact.group_revision}</code>
                </dd>
                <dt>{t("m3Score")}</dt>
                <dd>{fact.score === null ? t("m3ScoreUnavailable") : fact.score}</dd>
                <dt>{t("m3ScoreVersion")}</dt>
                <dd>{fact.score_version ?? t("m3NotReported")}</dd>
                <dt>{t("m3ScoreDigest")}</dt>
                <dd>
                    <code>{fact.score_digest ?? t("m3NotReported")}</code>
                </dd>
                <dt>{t("m3Alerts")}</dt>
                <dd>{fact.alert_count}</dd>
            </dl>
        );
    }
    if (citation.kind === "alert" && "source_hash" in fact) {
        return (
            <dl className="m3-meta">
                <dt>{t("m3Alert")}</dt>
                <dd>
                    <code>{fact.alert_key}</code>
                </dd>
                <dt>{t("group")}</dt>
                <dd>
                    <code>{fact.group_id}</code>
                </dd>
                <dt>{t("m3MemberRevision")}</dt>
                <dd>
                    <code>{fact.group_revision}</code>
                </dd>
                <dt>{t("eventTime")}</dt>
                <dd>{fact.event_at}</dd>
                <dt>{t("rule")}</dt>
                <dd>{fact.rule_id ?? t("m3NotReported")}</dd>
                <dt>{t("m3SourceHash")}</dt>
                <dd>
                    <code>{fact.source_hash}</code>
                </dd>
            </dl>
        );
    }
    return <p>{t("m3CitationMissing")}</p>;
}

function findFact(
    pack: components["schemas"]["FrozenIncidentPack"] | null | undefined,
    citation: Citation,
): Fact | undefined {
    if (!pack) return undefined;
    if (citation.kind === "incident")
        return pack.incident_reference.reference_id === citation.fact_id
            ? pack.incident_reference
            : undefined;
    if (citation.kind === "group")
        return pack.group_facts.find((fact) => fact.fact_id === citation.fact_id);
    return pack.alert_facts.find((fact) => fact.fact_id === citation.fact_id);
}

function tokenUsage(value: number | null | undefined, label: string, t: Translate): string {
    return `${label}: ${value ?? t("m3NotReported")}`;
}

function narrativeFailure(error: unknown, t: Translate): string {
    if (error instanceof WorkspaceRequestError) {
        if (error.status === 403) return t("denied");
        if (error.status === 503 || error.status === 0) return t("m3Unavailable");
        return error.message;
    }
    return error instanceof Error ? error.message : t("m3Unavailable");
}

/** Long ids keep their head and tail; the full value stays in the title. */
export function compactId(value: string): string {
    return value.length > 24 ? `${value.slice(0, 12)}\u2026${value.slice(-8)}` : value;
}

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

/** Identifiers (hashes, UUIDs, or `copy`) get a trailing copy button; long hashes show head and
 * tail with the full value in the title. Short scalars stay plain code. */
export function IdValue({
    value,
    locale,
    copy = false,
    compact = false,
}: {
    value: string;
    locale: Locale;
    copy?: boolean;
    compact?: boolean;
}) {
    const long = value.length > (compact ? 24 : 40) && !value.includes("://");
    if (!long && !copy && !UUID.test(value)) return <code>{value}</code>;
    return (
        <CopyValue
            value={value}
            displayValue={long ? compactId(value) : value}
            t={(key) => fmt(locale, key)}
        />
    );
}

// Long hex hashes, ISO times, and lowercase hyphenated host ids such as agent-042 or web-01.
const PROSE_TOKEN =
    /\b[0-9a-f]{32,}\b|\d{4}-\d{2}-\d{2}T\d{2}:\d{2}(?::\d{2}(?:\.\d+)?)?(?:Z|[+-]\d{2}:\d{2})?|\b[a-z][a-z0-9]*(?:-[a-z0-9]+)*-\d+\b|(?<=\b(?:[Rr]ule|[Rr]egla) )\d+\b/g;

/** Prose keeps its words and never shows a hash: a group hash reads as the group's name and
 * links to it, ISO times read as dates, rules read "Rule 5763" and host ids read as entities. */
export function HashText({
    text,
    locale,
    groupTitles = new Map(),
    onOpenGroup,
}: {
    text: string;
    locale: Locale;
    groupTitles?: ReadonlyMap<string, string>;
    onOpenGroup?: (groupId: string) => void;
}) {
    const parts: ReactNode[] = [];
    let last = 0;
    for (const match of text.matchAll(PROSE_TOKEN)) {
        const start = match.index ?? 0;
        if (start > last) parts.push(text.slice(last, start));
        const token = match[0];
        if (/^\d{4}-/.test(token)) {
            parts.push(
                <time key={start} dateTime={token}>
                    {fmtDate(token, locale)}
                </time>,
            );
        } else if (/^[0-9a-f]{32,}$/.test(token)) {
            const title = groupTitles.get(token);
            parts.push(
                title ? (
                    onOpenGroup ? (
                        <button key={start} type="button" className="narrative-entity-link" onClick={() => onOpenGroup(token)}>
                            {title}
                        </button>
                    ) : (
                        <span key={start} className="ent">
                            {title}
                        </span>
                    )
                ) : (
                    <IdChip key={start} kind="group" value={token} copy={false} />
                ),
            );
        } else if (/^\d+$/.test(token)) {
            parts.push(token);
        } else {
            parts.push(
                <span key={start} className="ent">
                    {token}
                </span>,
            );
        }
        last = start + token.length;
    }
    if (last < text.length) parts.push(text.slice(last));
    return <>{parts}</>;
}

function factWords(
    fact: Fact | undefined,
    citation: Citation,
    groupTitles: ReadonlyMap<string, string>,
    t: Translate,
): string {
    if (!fact) return t("m3CitationMissing");
    if (citation.kind === "group" && "group_revision" in fact && "score_digest" in fact) {
        const name = groupTitles.get(fact.group_id) ?? t("group");
        const score = fact.score === null ? t("m3ScoreUnavailable") : String(fact.score);
        return `${name}: ${t("m3Score").toLocaleLowerCase()} ${score}${fact.score_version ? `, ${t("versionWord")} ${fact.score_version}` : ""}`;
    }
    if (citation.kind === "alert" && "source_hash" in fact) {
        return `${t("m3Alert")}: ${fact.rule_id ? `${t("rule")} ${fact.rule_id}` : t("m3Alert")}, ${fmtDate(fact.event_at)}`;
    }
    return t("m3Citation_incident");
}

function NarrativeFeedback({ t }: { t: Translate }) {
    const [answer, setAnswer] = useState<"yes" | "no" | null>(null);
    const [reason, setReason] = useState("");
    const [sent, setSent] = useState(false);
    if (sent)
        return (
            <p className="narrative-feedback t-secondary" role="status">
                {t("narrativeFeedbackThanks")}
            </p>
        );
    return (
        <div className="narrative-feedback">
            <span>{t("narrativeAccurate")}</span>
            <button
                type="button"
                className="btn compact"
                aria-pressed={answer === "yes"}
                onClick={() => {
                    setAnswer("yes");
                    setSent(true);
                }}
            >
                {t("yes")}
            </button>
            <button
                type="button"
                className="btn compact"
                aria-pressed={answer === "no"}
                onClick={() => setAnswer("no")}
            >
                {t("narrativeReportProblem")}
            </button>
            {answer === "no" && (
                <form
                    className="narrative-feedback-form"
                    onSubmit={(event) => {
                        event.preventDefault();
                        if (reason.trim()) setSent(true);
                    }}
                >
                    <label className="pp-field">
                        {t("narrativeWhatWrong")}
                        <input
                            maxLength={500}
                            value={reason}
                            onChange={(event) => setReason(event.target.value)}
                        />
                    </label>
                    <button className="btn compact primary" type="submit">
                        {t("send")}
                    </button>
                </form>
            )}
        </div>
    );
}

/** Only the lead sentence of the trust note is bold; the rest reads as normal guidance. */
function TrustNote({ text }: { text: string }) {
    const cut = text.indexOf(". ");
    if (cut < 0) return <strong>{text}</strong>;
    return (
        <>
            <strong>{text.slice(0, cut + 1)}</strong> {text.slice(cut + 2)}
        </>
    );
}
