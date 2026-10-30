import type { ReactNode } from "react";
import { cn } from "./cn";
import { AlertCircle, Check, Circle, X } from "lucide-react";
export function Badge({ children, className }: { children: ReactNode; className?: string }) {
    return (
        <span
            className={cn(
                "inline-flex items-center rounded-full border border-[var(--stroke)] bg-[var(--bg-secondary)] px-2.5 py-1 text-xs font-medium text-[var(--text-tertiary)]",
                className,
            )}
        >
            {children}
        </span>
    );
}
export function StatusPill({
    children,
    tone = "neutral",
}: {
    children: ReactNode;
    tone?: "positive" | "negative" | "warning" | "neutral";
}) {
    const tones = {
        positive: "status-pill-positive",
        negative: "status-pill-negative",
        warning: "status-pill-warning",
        neutral: "status-pill-neutral",
    };
    const Icon =
        tone === "positive"
            ? Check
            : tone === "negative"
              ? X
              : tone === "warning"
                ? AlertCircle
                : Circle;
    return (
        <span className={cn("status-pill", tones[tone])}>
            <Icon aria-hidden="true" size={12} />
            {children}
        </span>
    );
}
