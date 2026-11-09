import type { HTMLAttributes, ReactNode } from "react";
import { cn } from "./cn";
import type { TagTone } from "../../lib/semantic";

// One quiet pill for every tone: neutral surface and text, with a small dot carrying the state.
// Only states that matter get colour (good, warning, bad, and the accent for "new/info").
const toneDots = {
    neutral: null,
    blue: "bg-[var(--accent)]",
    green: "bg-[var(--dot-good)]",
    amber: "bg-[var(--dot-warn)]",
    orange: "bg-[var(--dot-warn)]",
    red: "bg-[var(--dot-bad)]",
    purple: null,
    teal: null,
} satisfies Record<TagTone, string | null>;

export type TagProps = Omit<HTMLAttributes<HTMLSpanElement>, "children"> & {
    children: ReactNode;
    tone?: TagTone;
    dot?: boolean;
    mono?: boolean;
};

export function Tag({
    children,
    tone = "neutral",
    dot = false,
    mono = false,
    className,
    ...props
}: TagProps) {
    const dotClass = toneDots[tone] ?? (dot ? "bg-[var(--text-muted)]" : null);
    const bad = tone === "red";
    return (
        <span
            className={cn(
                "tag inline-flex h-[20px] max-w-full shrink-0 items-center gap-[6px] whitespace-nowrap rounded-[var(--radius-tag)] border border-[var(--tag-neutral-border)] bg-[var(--tag-neutral-bg)] px-[7px] text-[12px] font-medium leading-none text-[var(--tag-neutral-text)]",
                bad && "font-semibold text-[var(--text)]",
                mono && "font-mono",
                className,
            )}
            data-tone={tone}
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
