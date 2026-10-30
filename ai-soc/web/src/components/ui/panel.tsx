import type { HTMLAttributes } from "react";
import { cn } from "./cn";
export function Panel(props: HTMLAttributes<HTMLElement>) {
    return (
        <section
            {...props}
            className={cn(
                "rounded-panel border border-[var(--stroke-subtle)] bg-white p-6 shadow-panel",
                props.className,
            )}
        />
    );
}
