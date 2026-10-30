import type { HTMLAttributes, ReactNode } from "react";
import { cn } from "./cn";
import type { TagTone } from "../../lib/semantic";

const toneClasses = {
    neutral:
        "border-[var(--tag-neutral-border)] bg-[var(--tag-neutral-bg)] text-[var(--tag-neutral-text)]",
    blue: "border-[var(--tag-blue-border)] bg-[var(--tag-blue-bg)] text-[var(--tag-blue-text)]",
    green: "border-[var(--tag-green-border)] bg-[var(--tag-green-bg)] text-[var(--tag-green-text)]",
    amber: "border-[var(--tag-amber-border)] bg-[var(--tag-amber-bg)] text-[var(--tag-amber-text)]",
    orange: "border-[var(--tag-orange-border)] bg-[var(--tag-orange-bg)] text-[var(--tag-orange-text)]",
    red: "border-[var(--tag-red-border)] bg-[var(--tag-red-bg)] text-[var(--tag-red-text)]",
    purple: "border-[var(--tag-purple-border)] bg-[var(--tag-purple-bg)] text-[var(--tag-purple-text)]",
    teal: "border-[var(--tag-teal-border)] bg-[var(--tag-teal-bg)] text-[var(--tag-teal-text)]",
} satisfies Record<TagTone, string>;

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
    return (
        <span
            className={cn(
                "inline-flex h-5 max-w-full shrink-0 items-center gap-1.5 whitespace-nowrap rounded-[var(--radius-tag)] border px-1.5 text-xs font-medium leading-none",
                toneClasses[tone],
                mono && "font-mono",
                className,
            )}
            {...props}
        >
            {dot && <span aria-hidden="true" className="size-1.5 rounded-full bg-current" />}
            {children}
        </span>
    );
}
