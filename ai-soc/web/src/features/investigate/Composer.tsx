import { LoaderCircle, Search, AlertCircle } from "lucide-react";
import type { BootstrapResponse } from "../../../../contracts/v1/generated/types.ts";
import { words } from "../../i18n/answer-copy";
import { byteCount } from "../../app/state/answer-format";

export function Composer({
    bootstrap,
    question,
    setQuestion,
    model,
    setModel,
    effort,
    setEffort,
    canAsk,
    pending,
    elapsed,
    requestError,
    expiredReplay,
    onAskOriginalSeparately,
    t,
    onSubmit,
    onCancel,
}: {
    bootstrap: BootstrapResponse | undefined;
    question: string;
    setQuestion: (value: string) => void;
    model: string;
    setModel: (value: string) => void;
    effort: string;
    setEffort: (value: string) => void;
    canAsk: boolean;
    pending: boolean;
    elapsed: number;
    requestError: string;
    expiredReplay: boolean;
    t: (key: keyof typeof words.en) => string;
    onSubmit: () => void;
    onCancel: () => void;
    onAskOriginalSeparately: () => void;
}) {
    const activeModels = bootstrap?.models ?? [];
    const activeModel = activeModels.find((candidate) => candidate.id === model);
    const byteLimit = bootstrap?.limits.question_bytes ?? 16384;
    return (
        <section className="panel composer" aria-labelledby="composer-title">
            <div className="section-title">
                <h2 id="composer-title">{t("question")}</h2>
                <span className={byteCount(question) > byteLimit ? "danger" : "muted"}>
                    {byteCount(question)} / {byteLimit} {t("byteLimit")}
                </span>
            </div>
            <textarea
                value={question}
                onChange={(event) => setQuestion(event.target.value)}
                onKeyDown={(event) => {
                    if ((event.ctrlKey || event.metaKey) && event.key === "Enter" && canAsk)
                        onSubmit();
                }}
                maxLength={65536}
                placeholder={t("questionPlaceholder")}
                aria-label={t("question")}
            />
            <div className="composer-controls">
                {bootstrap && bootstrap.sites.length === 0 && (
                    <p className="alert error" role="status">
                        {t("noSitesAvailable")}
                    </p>
                )}
                <label>
                    {t("model")}
                    <select
                        id="model-select"
                        value={model}
                        onChange={(event) => {
                            setModel(event.target.value);
                            setEffort("");
                        }}
                    >
                        <option value="">{t("defaultModel")}</option>
                        {activeModels.map((candidate) => (
                            <option key={candidate.id} value={candidate.id}>
                                {candidate.label}
                            </option>
                        ))}
                    </select>
                </label>
                {activeModel?.efforts.length ? (
                    <label>
                        {t("effort")}
                        <select value={effort} onChange={(event) => setEffort(event.target.value)}>
                            <option value="">{t("selectEffort")}</option>
                            {activeModel.efforts.map((item) => (
                                <option key={item}>{item}</option>
                            ))}
                        </select>
                    </label>
                ) : null}
                <span className="muted timezone">
                    {t("timezone")}: {Intl.DateTimeFormat().resolvedOptions().timeZone}
                </span>
                <button className="btn primary" disabled={!canAsk} onClick={onSubmit}>
                    {pending ? (
                        <>
                            <LoaderCircle className="spin" size={16} />
                            {t("running")}
                        </>
                    ) : (
                        <>
                            <Search size={16} />
                            {t("ask")}
                        </>
                    )}
                </button>
                <span className="muted submit-hint">{t("submitHint")}</span>
            </div>
            {pending && (
                <div className="progress-line" aria-live="polite">
                    <span className="indeterminate" />
                    <span>
                        {t("running")} | {elapsed}s
                    </span>
                    <button className="btn outline" onClick={onCancel}>
                        {t("cancel")}
                    </button>
                    <span className="muted">{t("cancelNote")}</span>
                </div>
            )}
            {requestError && (
                <div className="alert error" role="alert">
                    <AlertCircle size={17} />
                    <div>
                        {requestError}
                        {expiredReplay && <p>{t("continuationExpired")}</p>}
                    </div>
                    {expiredReplay && (
                        <button className="btn outline" onClick={onAskOriginalSeparately}>
                            {t("askOriginalSeparately")}
                        </button>
                    )}
                </div>
            )}
        </section>
    );
}
