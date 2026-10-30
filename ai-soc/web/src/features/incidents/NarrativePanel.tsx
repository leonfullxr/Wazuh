import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import type { components } from "../../../../contracts/workspace/v1/types.ts";
import { getIncidentNarrative } from "../../api/workspace-m3";
import { WorkspaceRequestError } from "../../api/workspace";

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
}: {
    siteId: string;
    incidentId: string;
    evidenceRevision: string;
    locale: Locale;
    t: Translate;
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
    const selectedFact = selectedCitation ? findFact(data?.evidence, selectedCitation) : undefined;

    return (
        <section aria-labelledby="incident-narrative-heading" className="m3-narrative">
            <div className="panel-head">
                <h4 id="incident-narrative-heading">{t("m3Narrative")}</h4>
                <button className="btn outline" onClick={() => void narrative.refetch()}>
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
                    <p className="m3-trust-note">{t("m3NarrativeTrust")}</p>
                    <dl className="m3-meta">
                        <dt>{t("m3EvidenceRevision")}</dt>
                        <dd>
                            <code>{data.evidence_revision}</code>
                        </dd>
                        <dt>{t("m3NarrativeStatus")}</dt>
                        <dd>{t(`m3Narrative_${data.status}`)}</dd>
                        <dt>{t("m3NarrativeGeneration")}</dt>
                        <dd>
                            <code>{data.generation_id ?? t("m3NotReported")}</code>
                        </dd>
                        <dt>{t("m3NarrativeGenerationDigest")}</dt>
                        <dd>
                            <code>{data.generation_digest ?? t("m3NotReported")}</code>
                        </dd>
                        <dt>{t("m3NarrativePackDigest")}</dt>
                        <dd>
                            <code>{data.pack_digest ?? t("m3NotReported")}</code>
                        </dd>
                        {data.evidence && (
                            <>
                                <dt>{t("m3NarrativeFrozenPackDigest")}</dt>
                                <dd>
                                    <code>{data.evidence.content_digest}</code>
                                </dd>
                            </>
                        )}
                        {summary && (
                            <>
                                <dt>{t("m3NarrativeValidatedPackDigest")}</dt>
                                <dd>
                                    <code>{summary.pack_digest}</code>
                                </dd>
                            </>
                        )}
                        <dt>{t("m3NarrativeCompleted")}</dt>
                        <dd>
                            {data.completed_at
                                ? new Date(data.completed_at).toLocaleString(locale)
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
                    {removals.length > 0 && (
                        <div>
                            <h5>{t("m3NarrativeRemovals")}</h5>
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
                            <h5>{locale === "es" ? summary.label_es : summary.label_en}</h5>
                            {summary.status === "all_removed" ? (
                                <p className="muted">{t("m3NarrativeAllRemoved")}</p>
                            ) : summary.status === "invalid_structure" ? (
                                <p className="muted">{t("m3NarrativeInvalid")}</p>
                            ) : (
                                <p className="m3-narrative-text">
                                    {locale === "es" ? summary.rendered_es : summary.rendered_en}
                                </p>
                            )}
                            {summary.static_error && (
                                <p>
                                    {t("m3NarrativeStaticError")}:{" "}
                                    <code>{summary.static_error}</code>
                                </p>
                            )}
                            {summary.citations.length > 0 && (
                                <div>
                                    <h6>{t("m3NarrativeCitations")}</h6>
                                    <ul className="m3-citations">
                                        {summary.citations.map((citation) => (
                                            <li key={`${citation.kind}:${citation.fact_id}`}>
                                                <button
                                                    className="btn outline"
                                                    aria-pressed={
                                                        selectedCitation?.fact_id ===
                                                        citation.fact_id
                                                    }
                                                    onClick={() => setSelectedCitation(citation)}
                                                >
                                                    {t(`m3Citation_${citation.kind}`)} ·{" "}
                                                    <code>{citation.fact_id}</code>
                                                </button>
                                            </li>
                                        ))}
                                    </ul>
                                    {selectedCitation && (
                                        <div className="m3-citation-detail" aria-live="polite">
                                            <h6>{t("m3CitationEvidence")}</h6>
                                            {selectedFact ? (
                                                <FactDetails
                                                    fact={selectedFact}
                                                    citation={selectedCitation}
                                                    t={t}
                                                />
                                            ) : (
                                                <p>{t("m3CitationMissing")}</p>
                                            )}
                                        </div>
                                    )}
                                </div>
                            )}
                        </section>
                    )}
                    {data.evidence && (
                        <p className="muted">
                            {t("m3NarrativeFrozenPack")}:{" "}
                            <code>{data.evidence.content_digest}</code>
                        </p>
                    )}
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
