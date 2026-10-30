import type { Answer, BootstrapResponse } from "../../../../contracts/v1/generated/types.ts";
import type { Locale } from "../../i18n";
import { words } from "../../i18n/answer-copy";
import { KevFreshnessNote } from "./EvidenceDataTable";
import { date } from "../../app/state/answer-format";
import { CopyValue } from "./CopyValue";
export function StatusScreen({
    bootstrap,
    answer,
    locale,
    t,
}: {
    bootstrap: BootstrapResponse | undefined;
    answer: Answer | null;
    locale: Locale;
    t: (k: keyof typeof words.en) => string;
}) {
    if (!bootstrap) return <section className="panel">{t("notReady")}</section>;
    return (
        <div className="status-grid">
            <section className="panel">
                <h2>{t("answerStatus")}</h2>
                <p>{bootstrap.mode === "live" ? t("live") : t("mode")}</p>
                <h3>{t("sites")}</h3>
                {bootstrap.sites.map((s) => (
                    <p key={s.id}>
                        {s.label} <code>{s.id}</code>
                    </p>
                ))}
            </section>
            <section className="panel">
                <h2>{t("models")}</h2>
                {bootstrap.models.map((m) => (
                    <article className="model-row" key={m.id}>
                        <h3>
                            {m.label} <code>{m.id}</code>
                        </h3>
                        <p>
                            {t("contextTokens")}: {m.context_tokens} | {t("maxOutput")}:{" "}
                            {m.max_output_tokens}
                        </p>
                        <p>
                            {t("efforts")}: {m.efforts.join(", ") || "-"}
                        </p>
                    </article>
                ))}
            </section>
            <section className="panel">
                <h2>{t("limits")}</h2>
                {Object.entries(bootstrap.limits).map(([k, v]) => (
                    <p key={k}>
                        <span>
                            {(
                                {
                                    question_bytes: "questionBytes",
                                    page_size: "pageSize",
                                    window_days: "windowDays",
                                    request_bytes: "requestBytes",
                                    plan_bytes: "planBytes",
                                } as Record<string, keyof typeof words.en>
                            )[k]
                                ? t(
                                      (
                                          {
                                              question_bytes: "questionBytes",
                                              page_size: "pageSize",
                                              window_days: "windowDays",
                                              request_bytes: "requestBytes",
                                              plan_bytes: "planBytes",
                                          } as Record<string, keyof typeof words.en>
                                      )[k],
                                  )
                                : k}
                        </span>
                        <strong className="numeric">{v}</strong>
                    </p>
                ))}
            </section>
            <section className="panel">
                <h2>{t("build")}</h2>
                {Object.entries(bootstrap.provenance).map(([k, v]) => (
                    <p key={k}>
                        <span>{k}</span>
                        <CopyValue value={String(v)} t={t} />
                    </p>
                ))}
            </section>
            <section className="panel freshness">
                <h2>{t("freshness")}</h2>
                <p>{t("statusFresh")}</p>
                {answer ? (
                    answer.blocks.flatMap((b) =>
                        b.tables.map((f) => (
                            <p key={`${b.topic_id}-${f.fetch_id}`}>
                                <strong>{f.fetch_id}</strong> |{" "}
                                {date(
                                    f.snapshot_at ?? f.snapshot.at,
                                    Intl.DateTimeFormat().resolvedOptions().timeZone,
                                    locale,
                                )}{" "}
                                |{" "}
                                {date(
                                    f.window.start,
                                    Intl.DateTimeFormat().resolvedOptions().timeZone,
                                    locale,
                                )}{" "}
                                -{" "}
                                {date(
                                    f.window.end,
                                    Intl.DateTimeFormat().resolvedOptions().timeZone,
                                    locale,
                                )}
                            </p>
                        )),
                    )
                ) : (
                    <p className="muted">{t("notReady")}</p>
                )}
                <KevFreshnessNote answer={answer} locale={locale} t={t} />
            </section>
        </div>
    );
}
