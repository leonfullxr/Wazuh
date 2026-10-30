import type { ReactNode } from "react";
import type { TagTone } from "../../lib/semantic";
import { Tag } from "./tag";
type StatusPillTone = "positive" | "negative" | "warning" | "neutral";
export function Badge({ children, className }: { children: ReactNode; className?: string }) {
    return <Tag className={className}>{children}</Tag>;
}
export function StatusPill({
    children,
    tone = "neutral",
}: {
    children: ReactNode;
    tone?: StatusPillTone;
}) {
    const tones = {
        positive: "green",
        negative: "red",
        warning: "amber",
        neutral: "neutral",
    } satisfies Record<StatusPillTone, TagTone>;
    return (
        <Tag tone={tones[tone]} dot>
            {children}
        </Tag>
    );
}
