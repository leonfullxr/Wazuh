import { useEffect, useRef } from "react";
import { X } from "lucide-react";
import type { Answer, EvidenceItem } from "../../../../contracts/v1/generated/types.ts";
import type { Locale } from "../../i18n";
import { words, stateWord } from "../../i18n/answer-copy";
import { CopyValue } from "./CopyValue";
import { date, fieldValue, formatVisibility } from "../../app/state/answer-format";

export function evidenceFetch(answer: Answer | null, item: EvidenceItem) {
    return answer?.blocks
        .find((block) => block.topic_id === item.topic_id)
        ?.tables.find((fetch) => fetch.fetch_id === item.fetch_id);
}

export function EvidenceDrawer({
    item,
    answer,
    locale,
    timezone,
    t,
    onClose,
}: {
    item: EvidenceItem;
    answer: Answer | null;
    locale: Locale;
    timezone: string;
    t: (k: keyof typeof words.en) => string;
    onClose: () => void;
}) {
    const fetch = evidenceFetch(answer, item);
    const kindMap = new Map<string, string>(fetch?.columns.map((c) => [c.field, c.kind]) ?? []);
    const drawerRef = useRef<HTMLDivElement>(null);
    useEffect(() => {
        const drawer = drawerRef.current;
        const focusable = () =>
            Array.from(
                drawer?.querySelectorAll<HTMLElement>(
                    "button, a, input, select, textarea, [tabindex]:not([tabindex='-1'])",
                ) ?? [],
            );
        focusable()[0]?.focus();
        const trap = (event: KeyboardEvent) => {
            if (event.key !== "Tab") return;
            const items = focusable();
            if (!items.length) return;
            if (event.shiftKey && document.activeElement === items[0]) {
                event.preventDefault();
                items.at(-1)?.focus();
            } else if (!event.shiftKey && document.activeElement === items.at(-1)) {
                event.preventDefault();
                items[0]?.focus();
            }
        };
        drawer?.addEventListener("keydown", trap);
        return () => drawer?.removeEventListener("keydown", trap);
    }, []);
    return (
        <div
            className="drawer-backdrop"
            onMouseDown={(e) => {
                if (e.target === e.currentTarget) onClose();
            }}
        >
            <div
                ref={drawerRef}
                className="evidence-drawer"
                role="dialog"
                aria-modal="true"
                aria-labelledby="drawer-title"
            >
                <div className="drawer-header">
                    <div>
                        <span className="eyebrow">{t("details")}</span>
                        <h2 id="drawer-title">{item.evidence_id}</h2>
                    </div>
                    <button className="icon-button" aria-label={t("remove")} onClick={onClose}>
                        <X size={18} />
                    </button>
                </div>
                <dl>
                    <dt>{t("kind")}</dt>
                    <dd>{stateWord(item.kind, locale)}</dd>
                    <dt>{t("topic")}</dt>
                    <dd>{item.topic_id}</dd>
                    <dt>{t("fetch")}</dt>
                    <dd>{item.fetch_id ?? item.check_id ?? "-"}</dd>
                    {Object.entries(item.values).map(([k, v]) => (
                        <div className="drawer-value" key={k}>
                            <dt>{k}</dt>
                            <dd>
                                {Array.isArray(v) ? (
                                    <ul>
                                        {v.map((entry, index) => (
                                            <li key={`${k}-${index}`}>{String(entry)}</li>
                                        ))}
                                    </ul>
                                ) : (
                                    fieldValue(v, kindMap.get(k), timezone, locale)
                                )}
                            </dd>
                        </div>
                    ))}
                    <dt>{t("source")}</dt>
                    <dd>
                        {"index_alias" in item.source ? (
                            `${item.source.index_alias} / ${item.source.record_id}`
                        ) : "template_id" in item.source ? (
                            `${item.source.template_id}  |  ${item.source.filters.map((f) => `${f.field} ${f.op} ${String(f.value)}`).join(", ")}  |  ${date(item.source.window.start, timezone, locale)} - ${date(item.source.window.end, timezone, locale)}`
                        ) : "probe_kind" in item.source ? (
                            item.source.probe_kind
                        ) : "operand_ids" in item.source ? (
                            <span className="citations">
                                {item.source.operand_ids.map((id) => (
                                    <span className="chip" key={id}>
                                        {id}
                                    </span>
                                ))}
                            </span>
                        ) : (
                            JSON.stringify(item.source)
                        )}
                    </dd>
                    <dt>{t("snapshot")}</dt>
                    <dd>
                        {stateWord(item.snapshot.kind, locale)} |{" "}
                        {date(item.snapshot.at, timezone, locale)} |{" "}
                        {date(item.snapshot.expires_at, timezone, locale)}
                    </dd>
                    <dt>{t("visibility")}</dt>
                    <dd>{formatVisibility(item.visibility, locale)}</dd>
                    <dt>{t("scope")}</dt>
                    <dd className="mono">
                        {item.scope_hash}
                        <CopyValue value={item.scope_hash} t={t} />
                    </dd>
                </dl>
            </div>
        </div>
    );
}
