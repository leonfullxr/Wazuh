import { useState } from "react";
import { Copy } from "lucide-react";
import { words } from "../../i18n/answer-copy";

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
    return (
        <button
            type="button"
            className="mono copy-value"
            title={value}
            aria-label={show ? t("copied") : t("copyValue")}
            onClick={() => {
                void navigator.clipboard?.writeText(value);
                setShow(true);
                setTimeout(() => setShow(false), 1000);
            }}
        >
            {show ? t("copied") : displayValue}
            <Copy size={13} />
        </button>
    );
}
