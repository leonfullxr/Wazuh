import { useState, type ReactNode } from "react";
import { Check, Copy } from "lucide-react";
import { cn } from "./cn";

// Shared pieces of the PortfolioProof console: ID chips, SLA text, kbd hints,
// share bars and the summary strip. Styles live in styles/portfolio.css.

export const idPrefixes = {
    group: "grp_",
    incident: "inc_",
    chain: "chn_",
    alert: "alt_",
    fact: "fact_",
    revision: "rev_",
    request: "req_",
} as const;
export type IdKind = keyof typeof idPrefixes;

const idNames: Record<IdKind, string> = {
    group: "group ID",
    incident: "incident ID",
    chain: "chain candidate ID",
    alert: "alert ID",
    fact: "fact ID",
    revision: "snapshot ID",
    request: "request ID",
};

export function shortId(value: string): string {
    const bare = value
        .replace(/^(grp|inc|chn|alt|fact|rev|req)_/, "")
        .replace(/^(sha256|revision|digest|synthetic):/, "")
        .replace(/^(group|chain|incident|alert)[-_:]/, "");
    return bare.replace(/[^A-Za-z0-9]/g, "").slice(0, 6) || bare.slice(0, 6);
}

/** A typed, shortened ID with its full value in `title` and an optional copy button. */
export function IdChip({
    kind,
    value,
    copy = true,
    className,
}: {
    kind: IdKind;
    value: string;
    copy?: boolean;
    className?: string;
}) {
    const [copied, setCopied] = useState(false);
    const name = idNames[kind];
    return (
        <span className={cn("id-chip-wrap", className)}>
            <span className="id-chip" title={`Full ${name}: ${value}`}>
                <span className="id-chip-prefix">{idPrefixes[kind]}</span>
                {shortId(value)}
            </span>
            {copy && (
                <button
                    type="button"
                    className="icon-button id-chip-copy"
                    aria-label={copied ? "Copied" : `Copy full ${name}`}
                    onClick={() => {
                        void navigator.clipboard?.writeText(value).then(
                            () => {
                                setCopied(true);
                                setTimeout(() => setCopied(false), 1200);
                            },
                            () => undefined,
                        );
                    }}
                >
                    {copied ? (
                        <Check size={14} aria-hidden="true" />
                    ) : (
                        <Copy size={14} aria-hidden="true" />
                    )}
                </button>
            )}
        </span>
    );
}

export type SlaState = "met" | "near" | "open" | "breached";
export type Sla = {
    state: SlaState;
    /** Words, never colour alone: "22 min left", "Met in 14 min", "Breached by 8 min". */
    text: string;
    /** Share of the target already used, 0..1. */
    used?: number;
};

export function minutesText(minutes: number): string {
    const m = Math.max(0, Math.round(minutes));
    if (m < 60) return `${m} min`;
    const h = Math.floor(m / 60);
    const rest = m % 60;
    return rest ? `${h} h ${rest} min` : `${h} h`;
}

/** Derive SLA wording from a due time, or from a met duration. */
export function slaFrom({
    dueAt,
    startedAt,
    metAt,
    now = Date.now(),
}: {
    dueAt: string;
    startedAt?: string;
    metAt?: string | null;
    now?: number;
}): Sla {
    const due = Date.parse(dueAt);
    const start = startedAt ? Date.parse(startedAt) : NaN;
    const total = Number.isFinite(start) ? due - start : NaN;
    if (metAt) {
        const met = Date.parse(metAt);
        const took = Number.isFinite(start) ? (met - start) / 60000 : 0;
        if (met <= due) return { state: "met", text: `Met in ${minutesText(took)}`, used: 1 };
        return { state: "breached", text: `Breached by ${minutesText((met - due) / 60000)}`, used: 1 };
    }
    if (now > due) return { state: "breached", text: `Breached by ${minutesText((now - due) / 60000)}`, used: 1 };
    const left = due - now;
    const used = Number.isFinite(total) && total > 0 ? 1 - left / total : undefined;
    const near = Number.isFinite(total) && total > 0 ? left / total < 0.5 : false;
    return { state: near ? "near" : "open", text: `${minutesText(left / 60000)} left`, used };
}

export function SlaText({
    sla,
    bar = false,
    notReported = "Not reported",
}: {
    sla: Sla | undefined;
    bar?: boolean;
    notReported?: string;
}) {
    if (!sla) return <span className="sla-text sla-missing">{notReported}</span>;
    return (
        <span className="sla-cell">
            <span className="sla-text" data-sla={sla.state}>
                {sla.text}
            </span>
            {bar && (
                <span className="sla-bar" aria-hidden="true">
                    <span
                        data-sla={sla.state}
                        style={{ width: `${Math.round(Math.min(1, Math.max(0, sla.used ?? 1)) * 100)}%` }}
                    />
                </span>
            )}
        </span>
    );
}

export function Kbd({ children }: { children: ReactNode }) {
    return <kbd className="kbd">{children}</kbd>;
}

export function KeyHints({ hints }: { hints: ReadonlyArray<{ keys: string[]; label: string }> }) {
    return (
        <span className="key-hints">
            {hints.map((hint) => (
                <span key={hint.label} className="key-hint">
                    {hint.keys.map((key) => (
                        <Kbd key={key}>{key}</Kbd>
                    ))}
                    {hint.label}
                </span>
            ))}
        </span>
    );
}

/** A thin share-of-total bar. `share` is 0..1. */
export function ShareBar({
    share,
    muted = false,
    className,
}: {
    share: number;
    muted?: boolean;
    className?: string;
}) {
    const width = `${Math.round(Math.min(1, Math.max(0, share)) * 100)}%`;
    return (
        <span className={cn("share-bar", className)} aria-hidden="true">
            <span className={muted ? "is-muted" : undefined} style={{ width }} />
        </span>
    );
}

export type StripItem = { label: string; value: ReactNode; note?: ReactNode };

/** Summary figures between two hairlines, no card around each figure. */
export function SummaryStrip({
    items,
    label,
    className,
}: {
    items: ReadonlyArray<StripItem>;
    label: string;
    className?: string;
}) {
    return (
        <section className={cn("summary-strip", className)} aria-label={label}>
            {items.map((item) => (
                <div key={item.label} className="summary-strip-item">
                    <span className="summary-strip-label">{item.label}</span>
                    <span className="summary-strip-value">
                        <strong>{item.value}</strong>
                        {item.note !== undefined && <span>{item.note}</span>}
                    </span>
                </div>
            ))}
        </section>
    );
}

/** Saved-view or section tabs: 40px, 13/500, accent underline, count after the label. */
export function ViewTabs<T extends string>({
    tabs,
    value,
    onChange,
    label,
}: {
    tabs: ReadonlyArray<{ id: T; label: string; count?: number | null; tone?: "amber" }>;
    value: T;
    onChange: (value: T) => void;
    label: string;
}) {
    return (
        <div className="view-tabs" role="tablist" aria-label={label}>
            {tabs.map((tab) => (
                <button
                    key={tab.id}
                    type="button"
                    role="tab"
                    aria-selected={value === tab.id}
                    className="view-tab"
                    onClick={() => onChange(tab.id)}
                >
                    {tab.label}
                    {typeof tab.count === "number" && (
                        <span className="view-tab-count" data-tone={tab.tone}>
                            {tab.count}
                        </span>
                    )}
                </button>
            ))}
        </div>
    );
}

export const workStatusKeys = {
    new: "newStatus",
    in_progress: "inProgress",
    resolved: "resolved",
    closed: "closed",
} as const;
export const workStatusTones = {
    new: "blue",
    in_progress: "amber",
    resolved: "green",
    closed: "neutral",
} as const;
