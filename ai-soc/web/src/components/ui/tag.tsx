import type { HTMLAttributes, ReactNode } from "react";
import { cn } from "./cn";
import type { TagTone } from "../../lib/semantic";

// One quiet pill for every tone: neutral surface and text, with a small dot carrying the state.
// Only states that matter get colour (good, warning, bad, and the accent for "new/info").
const toneDots = {
    neutral: null,
    blue: "bg-[var(--text-2)]",
    green: "bg-[var(--dot-good)]",
    amber: "bg-[var(--dot-warn)]",
    orange: "bg-[var(--dot-warn)]",
    red: "bg-[var(--dot-bad)]",
    purple: null,
    teal: null,
} satisfies Record<TagTone, string | null>;

const severityClasses = {
    neutral: "",
    blue: "",
    green: "border-[var(--severity-green-border)] bg-[var(--severity-green-bg)] text-[var(--severity-green-text)]",
    amber: "border-[var(--severity-amber-border)] bg-[var(--severity-amber-bg)] text-[var(--severity-amber-text)]",
    orange: "border-[var(--severity-orange-border)] bg-[var(--severity-orange-bg)] text-[var(--severity-orange-text)]",
    red: "border-[var(--severity-red-border)] bg-[var(--severity-red-bg)] text-[var(--severity-red-text)]",
    purple: "",
    teal: "",
} satisfies Record<TagTone, string>;

export type TagProps = Omit<HTMLAttributes<HTMLSpanElement>, "children"> & {
    children: ReactNode;
    tone?: TagTone;
    dot?: boolean;
    mono?: boolean;
    variant?: "quiet" | "severity";
};

export function Tag({
    children,
    tone = "neutral",
    dot = false,
    mono = false,
    variant = "quiet",
    className,
    ...props
}: TagProps) {
    void dot;
    const dotClass = toneDots[tone] ?? "bg-[var(--text-muted)]";
    const bad = tone === "red";
    return (
        <span
            className={cn(
                "tag inline-flex h-[20px] max-w-full shrink-0 items-center gap-[6px] whitespace-nowrap rounded-[var(--radius-tag)] border border-[var(--tag-neutral-border)] bg-[var(--tag-neutral-bg)] px-[7px] text-[12px] font-medium leading-none text-[var(--tag-neutral-text)]",
                bad && "font-semibold text-[var(--text)]",
                variant === "severity" && severityClasses[tone],
                mono && "font-mono",
                className,
            )}
            data-tone={tone}
            data-variant={variant}
            {...props}
        >
            {dotClass && (
                <span
                    aria-hidden="true"
                    className={cn("shrink-0 rounded-full", bad ? "size-2" : "size-1.5", dotClass)}
                />
            )}
            {children}
        </span>
    );
}
