import { words } from "../../i18n/answer-copy";
import type { FeedbackResult } from "../../app/state/answer-session";
export function Feedback({
    t,
    note,
    setNote,
    result,
    onSend,
    pending,
}: {
    t: (k: keyof typeof words.en) => string;
    note: string;
    setNote: (v: string) => void;
    result: FeedbackResult | null;
    onSend: () => void;
    pending: boolean;
}) {
    return (
        <section className="panel feedback">
            <h2>{t("feedback")}</h2>
            <p>{t("feedbackWarning")}</p>
            <label>
                {t("note")}
                <textarea maxLength={1000} value={note} onChange={(e) => setNote(e.target.value)} />
            </label>
            <div className="feedback-actions">
                <span className="muted">{note.length} / 1000</span>
                <button className="btn outline" disabled={pending} onClick={onSend}>
                    {pending ? t("running") : t("sendFeedback")}
                </button>
            </div>
            {result?.kind === "queued" && (
                <p className="success-text" role="status">
                    {t("feedbackQueued")}: {result.feedback_id}
                </p>
            )}
            {result?.kind === "error" && (
                <p className="alert error" role="alert">
                    {result.code}: {t("feedbackExpiry")}
                </p>
            )}
            {!result && <small>{t("feedbackExpiry")}</small>}
        </section>
    );
}
