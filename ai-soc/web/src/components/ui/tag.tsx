import type { HTMLAttributes, ReactNode } from "react";
import { cn } from "./cn";
import type { TagTone } from "../../lib/semantic";

// Status colour lives only in small tags: a tinted ground, the status word and a dot.
// Colours come from [data-tone] rules in styles/portfolio.css.

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
    void mono;
    const showDot = dot || tone !== "neutral";
    return (
        <span
            className={cn("tag", className)}
            data-tone={tone}
            {...props}
        >
            {showDot && (
                <span aria-hidden="true" className="tag-dot" />
            )}
            {children}
        </span>
    );
}
