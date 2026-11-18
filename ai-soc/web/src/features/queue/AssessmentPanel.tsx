import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import * as api from "../../api/workspace";
import type { GroupDetail } from "../../api/workspace";
import type { Locale } from "../../i18n";
import { WorkspaceFailure, WorkspaceLoading } from "../workspace/WorkspaceStates";

const words = {
    en: {
        title: "AI assessment",
        preview: "Preview, not evaluated on real data",
        stale: "Stale assessment: the group has changed",
        pending: "Assessment pending",
        disabled: "The model layer is off for this site",
        no_assessment: "Not assessed",
        provider_unavailable: "AI unavailable",
        deterministic: "The score and deterministic evidence are complete.",
        context: "Context",
        complete: "complete",
        partial: "partial",
        thin: "thin",
        likely_malicious: "Likely malicious",
        benign: "Benign",
        needs_review: "Needs review",
        insufficient_evidence: "Insufficient evidence",
        findings_removed: "Findings removed",
        disagrees_with_score: "Disagrees with the score",
        pack_trimmed: "Pack trimmed",
        why: "Why it ranks here",
        for: "For",
        against: "Against",
        more: "Show more",
        next: "Next steps",
        investigate: "Investigate",
        citation: "Evidence",
        checked: "Checked",
        missing: "Missing",
        history: "Track record",
        removed: "Removed",
        provenance: "Provenance",
        reviews: "Assessment history",
        yourCall: "Your call",
        agree: "Agree",
        override: "Override",
        verdict: "Verdict",
        reason: "Reason",
        save: "Save review",
        saved: "Review saved",
        none: "None recorded",
        nothing: "Nothing matched",
        couldNot: "Could not check",
        reference: "Reference",
        knowledge: "Knowledge used",
        raw: "Raw record",
        lastAttempt: "Last attempt",
        severity: "Severity",
        true_positive: "True positive",
        false_positive: "False positive",
        benign_true_positive: "Benign true positive",
        duplicate: "Duplicate",
        undetermined: "Undetermined",
        window_from: "Window from",
        window_to: "Window to",
        conflicting: "Conflicting dispositions",
        reviewError: "Review could not be saved.",
        reasonRequired: "Enter a reason for the override.",
        invalid_json_or_schema: "The response did not pass structural validation.",
        no_supported_findings: "No supported findings survived validation.",
        missing_malicious_support: "No finding supports a malicious verdict.",
        insufficient_benign_coverage:
            "The evidence does not support a benign verdict for the whole group.",
        attempt_interrupted: "The previous attempt was interrupted.",
        credential: "The provider credential is unavailable.",
        timeout: "The provider timed out.",
        transport: "The provider could not be reached.",
        http_status: "The provider rejected the request.",
        rate_limit: "The provider rate limit was reached.",
    },
    es: {
        title: "Evaluación de IA",
        preview: "Vista previa, no evaluada con datos reales",
        stale: "Evaluación desactualizada: el grupo ha cambiado",
        pending: "Evaluación pendiente",
        disabled: "La capa de modelos está desactivada para este sitio",
        no_assessment: "Sin evaluación",
        provider_unavailable: "IA no disponible",
        deterministic: "La puntuación y la evidencia determinista están completas.",
        context: "Contexto",
        complete: "completo",
        partial: "parcial",
        thin: "escaso",
        likely_malicious: "Probablemente malicioso",
        benign: "Benigno",
        needs_review: "Requiere revisión",
        insufficient_evidence: "Evidencia insuficiente",
        findings_removed: "Hallazgos eliminados",
        disagrees_with_score: "Discrepa de la puntuación",
        pack_trimmed: "Paquete recortado",
        why: "Por qué ocupa esta posición",
        for: "A favor",
        against: "En contra",
        more: "Mostrar más",
        next: "Próximos pasos",
        investigate: "Investigar",
        citation: "Evidencia",
        checked: "Comprobado",
        missing: "Falta",
        history: "Historial previo",
        removed: "Eliminados",
        provenance: "Procedencia",
        reviews: "Historial de evaluaciones",
        yourCall: "Tu decisión",
        agree: "De acuerdo",
        override: "Cambiar veredicto",
        verdict: "Veredicto",
        reason: "Motivo",
        save: "Guardar revisión",
        saved: "Revisión guardada",
        none: "Nada registrado",
        nothing: "Sin coincidencias",
        couldNot: "No se pudo comprobar",
        reference: "Referencia",
        knowledge: "Conocimiento utilizado",
        raw: "Registro completo",
        lastAttempt: "Último intento",
        severity: "Gravedad",
        true_positive: "Positivo verdadero",
        false_positive: "Falso positivo",
        benign_true_positive: "Positivo verdadero benigno",
        duplicate: "Duplicado",
        undetermined: "Sin determinar",
        window_from: "Inicio del periodo",
        window_to: "Fin del periodo",
        conflicting: "Clasificaciones contradictorias",
        reviewError: "No se pudo guardar la revisión.",
        reasonRequired: "Introduce un motivo para cambiar el veredicto.",
        invalid_json_or_schema: "La respuesta no superó la validación estructural.",
        no_supported_findings: "Ningún hallazgo fundamentado superó la validación.",
        missing_malicious_support: "Ningún hallazgo respalda un veredicto malicioso.",
        insufficient_benign_coverage:
            "La evidencia no respalda un veredicto benigno para todo el grupo.",
        attempt_interrupted: "El intento anterior se interrumpió.",
        credential: "La credencial del proveedor no está disponible.",
        timeout: "El proveedor agotó el tiempo de espera.",
        transport: "No se pudo contactar con el proveedor.",
        http_status: "El proveedor rechazó la solicitud.",
        rate_limit: "Se alcanzó el límite de solicitudes del proveedor.",
    },
} satisfies Record<Locale, Record<string, string>>;

export function AssessmentPanel({
    siteId,
    group,
    locale,
    t,
    onInvestigate,
}: {
    siteId: string;
    group: GroupDetail;
    locale: Locale;
    t: (key: string) => string;
    onInvestigate?: () => void;
}) {
    const copy = words[locale];
    const queryClient = useQueryClient();
    const assessment = useQuery({
        queryKey: ["workspace", "assessment", siteId, group.group_id],
        queryFn: ({ signal }) => api.getAssessment(siteId, group.group_id, signal),
    });
    const [decision, setDecision] = useState<"agree" | "override">("agree");
    const [verdict, setVerdict] = useState<
        "benign" | "needs_review" | "likely_malicious" | "insufficient_evidence"
    >("needs_review");
    const [reason, setReason] = useState("");
    const [showMore, setShowMore] = useState(false);
    const [reasonError, setReasonError] = useState(false);
    const review = useMutation({
        mutationFn: (requestId: string) =>
            api.reviewAssessment(siteId, group.group_id, {
                request_id: requestId,
                decision,
                verdict: decision === "override" ? verdict : null,
                reason: reason.trim(),
            }),
        onSuccess: () => {
            setReason("");
            void queryClient.invalidateQueries({
                queryKey: ["workspace", "assessment", siteId, group.group_id],
            });
        },
    });
    if (assessment.isLoading) return <WorkspaceLoading label={copy.title} />;
    if (assessment.isError)
        return (
            <WorkspaceFailure
                error={assessment.error}
                t={t}
                onRetry={() => void assessment.refetch()}
            />
        );
    const detail = assessment.data;
    if (!detail) return null;
    const { summary, outcome } = detail;
    if (summary.state === "shadow" || summary.state === "not_selected") return null;
    if (summary.state === "disabled" || summary.state === "pending") {
        return (
            <section className="drawer-section" aria-label={copy.title}>
                <h3>{copy.title}</h3>
                <p>{copy[summary.state]}</p>
            </section>
        );
    }
    const reasonLabels: Readonly<Record<string, string>> = copy;
    const findings = outcome?.findings ?? [];
    const evidence = new Map(detail.evidence.map((item) => [item.id, item]));
    const citation = (id: string) => {
        const item = evidence.get(id);
        if (!item) return null;
        return (
            <details key={id}>
                <summary>
                    {copy.citation}: {id}
                </summary>
                <dl>
                    {Object.entries(item.fields).map(([key, value]) => (
                        <div key={key}>
                            <dt>{key}</dt>
                            <dd>
                                {typeof value === "string" ||
                                typeof value === "number" ||
                                typeof value === "boolean"
                                    ? String(value)
                                    : JSON.stringify(value)}
                            </dd>
                        </div>
                    ))}
                </dl>
            </details>
        );
    };
    const findingSection = (stance: "malicious" | "benign", label: string, icon: string) => {
        const relevant = findings.filter((finding) => finding.stance === stance);
        const visible = stance === "malicious" && !showMore ? relevant.slice(0, 3) : relevant;
        return (
            <section>
                <h4>
                    {icon} {label}
                </h4>
                {visible.length ? (
                    visible.map((finding) => (
                        <div key={finding.id}>
                            <p>{finding.text[locale]}</p>
                            {finding.evidence_ids.map(citation)}
                        </div>
                    ))
                ) : (
                    <p>{copy.none}</p>
                )}
                {stance === "malicious" && relevant.length > 3 && !showMore && (
                    <button type="button" onClick={() => setShowMore(true)}>
                        {copy.more} ({relevant.length - 3})
                    </button>
                )}
            </section>
        );
    };
    return (
        <section className="drawer-section" aria-label={copy.title}>
            <h3>{copy.title}</h3>
            {summary.state === "preview" && <a href="#ai_quality">{t("developmentScorecard")}</a>}
            <p>
                <strong>{copy[summary.state]}</strong>
            </p>
            {summary.state === "provider_unavailable" && (
                <p>
                    {copy.deterministic}{" "}
                    {detail.provenance && `${copy.lastAttempt}: ${detail.provenance.finished_at}`}
                </p>
            )}
            {outcome?.reason && <p>{reasonLabels[outcome.reason] ?? outcome.reason}</p>}
            {(summary.state === "preview" || summary.state === "stale") && summary.verdict && (
                <p>
                    <strong>{copy[summary.verdict]}</strong>
                </p>
            )}
            {(summary.state === "preview" || summary.state === "stale") && summary.band && (
                <p>
                    {copy.context}: {copy[summary.band]}
                </p>
            )}
            {outcome?.flags?.map((flag) => (
                <span key={flag}> ⚑ {copy[flag]} </span>
            ))}
            {(summary.state === "preview" || summary.state === "stale") &&
                outcome?.status === "accepted" && (
                    <>
                        <section>
                            <h4>{copy.why}</h4>
                            <ul>
                                {group.components
                                    .filter((item) => item.available)
                                    .sort(
                                        (a, b) =>
                                            Math.abs(b.contribution) - Math.abs(a.contribution),
                                    )
                                    .slice(0, 3)
                                    .map((item) => (
                                        <li key={item.name}>
                                            {item.explanation}: {item.contribution >= 0 ? "+" : ""}
                                            {item.contribution.toFixed(1)}
                                        </li>
                                    ))}
                            </ul>
                        </section>
                        {findingSection("malicious", copy.for, "+")}
                        {findingSection("benign", copy.against, "−")}
                        <section>
                            <h4>{copy.next}</h4>
                            {outcome.next_steps?.map((step) => (
                                <div key={step.step_id}>
                                    <p>{step.text[locale]}</p>
                                    {step.evidence_ids.map(citation)}
                                </div>
                            ))}
                            {onInvestigate && (
                                <button
                                    className="btn outline"
                                    type="button"
                                    onClick={onInvestigate}
                                >
                                    {copy.investigate}
                                </button>
                            )}
                        </section>
                        {summary.state === "preview" && detail.request_id && (
                            <form
                                aria-label={copy.yourCall}
                                onSubmit={(event) => {
                                    event.preventDefault();
                                    if (decision === "override" && !reason.trim()) {
                                        setReasonError(true);
                                        return;
                                    }
                                    setReasonError(false);
                                    if (detail.request_id) review.mutate(detail.request_id);
                                }}
                            >
                                <fieldset>
                                    <legend>{copy.yourCall}</legend>
                                    <label>
                                        <input
                                            type="radio"
                                            name="assessment-decision"
                                            checked={decision === "agree"}
                                            onChange={() => setDecision("agree")}
                                        />{" "}
                                        {copy.agree}
                                    </label>{" "}
                                    <label>
                                        <input
                                            type="radio"
                                            name="assessment-decision"
                                            checked={decision === "override"}
                                            onChange={() => setDecision("override")}
                                        />{" "}
                                        {copy.override}
                                    </label>
                                </fieldset>
                                {decision === "override" && (
                                    <label>
                                        {copy.verdict}
                                        <select
                                            name="verdict"
                                            value={verdict}
                                            onChange={(event) => {
                                                const selected = [
                                                    "benign",
                                                    "needs_review",
                                                    "likely_malicious",
                                                    "insufficient_evidence",
                                                ].find((v) => v === event.target.value);
                                                if (
                                                    selected === "benign" ||
                                                    selected === "needs_review" ||
                                                    selected === "likely_malicious" ||
                                                    selected === "insufficient_evidence"
                                                )
                                                    setVerdict(selected);
                                            }}
                                        >
                                            {(
                                                [
                                                    "benign",
                                                    "needs_review",
                                                    "likely_malicious",
                                                    "insufficient_evidence",
                                                ] as const
                                            ).map((v) => (
                                                <option value={v} key={v}>
                                                    {copy[v]}
                                                </option>
                                            ))}
                                        </select>
                                    </label>
                                )}
                                <label>
                                    {copy.reason}
                                    <textarea
                                        name="reason"
                                        value={reason}
                                        maxLength={1000}
                                        required={decision === "override"}
                                        aria-invalid={reasonError || undefined}
                                        aria-describedby={
                                            reasonError ? "assessment-reason-error" : undefined
                                        }
                                        onChange={(event) => {
                                            setReason(event.target.value);
                                            setReasonError(false);
                                        }}
                                    />
                                </label>
                                {reasonError && (
                                    <p id="assessment-reason-error" role="alert">
                                        {copy.reasonRequired}
                                    </p>
                                )}
                                <button
                                    type="submit"
                                    className="btn outline"
                                    disabled={review.isPending}
                                >
                                    {copy.save}
                                </button>
                                <p role="status">
                                    {review.isSuccess
                                        ? copy.saved
                                        : review.isError
                                          ? copy.reviewError
                                          : ""}
                                </p>
                            </form>
                        )}
                    </>
                )}
            <details>
                <summary>{copy.checked}</summary>
                <p>
                    {copy.nothing}:{" "}
                    {Object.entries(detail.gaps)
                        .filter(([, status]) => status === "empty")
                        .map(([name]) => name)
                        .join(", ") || copy.none}
                </p>
                <p>
                    {copy.couldNot}:{" "}
                    {Object.entries(detail.gaps)
                        .filter(([, status]) => status === "failed" || status === "stale")
                        .map(([name]) => name)
                        .join(", ") || copy.none}
                </p>
            </details>
            <details>
                <summary>{copy.missing}</summary>
                <p>
                    {[
                        ...detail.missing_fields,
                        ...Object.entries(detail.gaps)
                            .filter(([, status]) => status === "not_configured")
                            .map(([name]) => name),
                    ].join(", ") || copy.none}
                </p>
            </details>
            <details>
                <summary>{copy.history}</summary>
                {detail.evidence
                    .filter((item) => item.kind === "history")
                    .map((item) => (
                        <div key={item.id}>
                            {Object.entries(item.fields).map(([key, value]) => (
                                <p key={key}>
                                    {reasonLabels[key] ?? key}:{" "}
                                    {typeof value === "boolean"
                                        ? value
                                            ? "✓"
                                            : "—"
                                        : String(value ?? "—")}
                                </p>
                            ))}
                        </div>
                    ))}
            </details>
            <details>
                <summary>{copy.reviews}</summary>
                {detail.reviews.length ? (
                    detail.reviews.map((item) => (
                        <p key={item.review_id}>
                            {item.at} · {item.actor_key} · {copy[item.decision]} ·{" "}
                            {copy[item.verdict]} {item.reason && `· ${item.reason}`}
                        </p>
                    ))
                ) : (
                    <p>{copy.none}</p>
                )}
            </details>
            {detail.evidence.some((item) => item.kind === "knowledge") && (
                <details>
                    <summary>{copy.knowledge}</summary>
                    {detail.evidence
                        .filter((item) => item.kind === "knowledge")
                        .map((item) => (
                            <div key={item.id}>
                                <p>{copy.reference}</p>
                                {citation(item.id)}
                            </div>
                        ))}
                </details>
            )}
            <details>
                <summary>{copy.removed}</summary>
                {outcome?.removals?.map((item) => (
                    <p key={item.digest}>
                        {item.kind}: {item.reason}
                    </p>
                ))}
            </details>
            <details>
                <summary>{copy.provenance}</summary>
                {detail.provenance &&
                    Object.entries(detail.provenance).map(([key, value]) => (
                        <p key={key}>
                            {key}: {String(value ?? "—")}
                        </p>
                    ))}
            </details>
        </section>
    );
}

export function assessmentLabel(
    summary: api.AssessmentSummary | null | undefined,
    locale: Locale,
): string {
    if (
        !summary ||
        summary.state === "disabled" ||
        summary.state === "shadow" ||
        summary.state === "not_selected"
    )
        return "";
    const copy = words[locale];
    return [
        copy[summary.state],
        summary.verdict && copy[summary.verdict],
        summary.band && `${copy.context}: ${copy[summary.band]}`,
    ]
        .filter(Boolean)
        .join(" · ");
}
