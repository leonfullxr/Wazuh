import { useRef, useState } from "react";
import * as Dialog from "@radix-ui/react-dialog";
import type { Locale } from "../i18n";
import "./custom-range.css";

function utcInput(value: string): string {
    const date = new Date(value);
    if (Number.isNaN(date.getTime())) return "";
    const pad = (part: number) => String(part).padStart(2, "0");
    return `${date.getUTCFullYear()}-${pad(date.getUTCMonth() + 1)}-${pad(date.getUTCDate())}T${pad(date.getUTCHours())}:${pad(date.getUTCMinutes())}:${pad(date.getUTCSeconds())}`;
}

function parseUtc(value: string, original: string): number {
    if (!value) return NaN;
    const normalized = value.length === 16 ? `${value}:00` : value;
    const originalTime = Date.parse(original);
    if (Number.isFinite(originalTime) && normalized === utcInput(original)) return originalTime;
    const time = Date.parse(`${normalized}Z`);
    return Number.isFinite(time) && utcInput(new Date(time).toISOString()) === normalized
        ? time
        : NaN;
}

export function CustomRange({
    from,
    to,
    locale,
    active,
    onApply,
}: {
    from: string;
    to: string;
    locale: Locale;
    active: boolean;
    onApply: (range: { from: string; to: string }) => void;
}) {
    const [open, setOpen] = useState(false);
    const [start, setStart] = useState("");
    const [end, setEnd] = useState("");
    const [error, setError] = useState(false);
    const trigger = useRef<HTMLButtonElement>(null);
    const firstInput = useRef<HTMLInputElement>(null);
    const es = locale === "es";
    function toggle() {
        if (!open) {
            setStart(utcInput(from));
            setEnd(utcInput(to));
            setError(false);
        }
        setOpen(!open);
    }
    function apply() {
        const startTime = parseUtc(start, from);
        const endTime = parseUtc(end, to);
        if (
            !Number.isFinite(startTime) ||
            !Number.isFinite(endTime) ||
            endTime <= startTime ||
            endTime - startTime > 30 * 86400000 ||
            endTime > Date.now()
        ) {
            setError(true);
            return;
        }
        onApply({ from: new Date(startTime).toISOString(), to: new Date(endTime).toISOString() });
        setOpen(false);
        trigger.current?.focus();
    }
    return (
        <Dialog.Root open={open} onOpenChange={setOpen}>
            <div className="custom-range">
                <Dialog.Trigger asChild>
                    <button
                        ref={trigger}
                        type="button"
                        className="custom-range-trigger"
                        aria-expanded={open}
                        aria-pressed={active}
                        aria-haspopup="dialog"
                        aria-controls="custom-range-panel"
                        onClick={toggle}
                    >
                        {es ? "Personalizado" : "Custom"}
                    </button>
                </Dialog.Trigger>
                {open && (
                    <Dialog.Content
                        asChild
                        aria-label={es ? "Intervalo personalizado" : "Custom time range"}
                        aria-describedby={undefined}
                        onOpenAutoFocus={(event) => {
                            event.preventDefault();
                            firstInput.current?.focus();
                        }}
                    >
                        <form
                            id="custom-range-panel"
                            className="custom-range-panel"
                            onSubmit={(event) => {
                                event.preventDefault();
                                apply();
                            }}
                        >
                            <p>{es ? "Horas en UTC" : "Times in UTC"}</p>
                            <label>
                                {es ? "Desde" : "From"}
                                <input
                                    ref={firstInput}
                                    type="datetime-local"
                                    step="1"
                                    value={start}
                                    onChange={(event) => {
                                        setStart(event.target.value);
                                        setError(false);
                                    }}
                                    required
                                />
                            </label>
                            <label>
                                {es ? "Hasta" : "To"}
                                <input
                                    type="datetime-local"
                                    step="1"
                                    value={end}
                                    onChange={(event) => {
                                        setEnd(event.target.value);
                                        setError(false);
                                    }}
                                    required
                                />
                            </label>
                            {error && (
                                <p role="alert">
                                    {es
                                        ? "Elige horas válidas, con inicio anterior al final, hasta 30 días y sin fechas futuras."
                                        : "Choose valid times with the start before the end, spanning at most 30 days and ending in the past."}
                                </p>
                            )}
                            <button type="submit" className="btn primary">
                                {es ? "Aplicar" : "Apply"}
                            </button>
                            <button
                                type="button"
                                className="btn outline"
                                onClick={() => {
                                    setOpen(false);
                                    trigger.current?.focus();
                                }}
                            >
                                {es ? "Cerrar" : "Close"}
                            </button>
                        </form>
                    </Dialog.Content>
                )}
            </div>
        </Dialog.Root>
    );
}
