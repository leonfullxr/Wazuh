import { useState } from "react";
import { Copy } from "lucide-react";
import { words } from "../../i18n/answer-copy";

function copyName(action: string, value: string): string {
    const shown = value.trim();
    if (!shown) return action;
    const short = shown.length > 60 ? `${shown.slice(0, 28)}…${shown.slice(-12)}` : shown;
    return `${action}, ${short}`;
}

export function CopyValue({
    value,
    displayValue = value,
    t,
}: {
    value: string;
    displayValue?: string;
    t: (key: keyof typeof words.en) => string;
}) {
    const [show, setShow] = useState(false);
    const named = displayValue.trim() ? displayValue : value;
    return (
        <button
            type="button"
            className="mono copy-value"
            title={value}
            aria-label={show ? t("copied") : copyName(t("copyValue"), named)}
            onClick={() => {
                void (async () => {
                    try {
                        await navigator.clipboard?.writeText(value);
                    } catch {
                        return;
                    }
                    setShow(true);
                    setTimeout(() => setShow(false), 1000);
                })();
            }}
        >
            <span className="copy-value-text">{show ? t("copied") : displayValue}</span>
            <Copy size={13} aria-hidden="true" />
        </button>
    );
}
