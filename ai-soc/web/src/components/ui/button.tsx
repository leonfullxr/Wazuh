import * as React from "react";
import { Slot } from "@radix-ui/react-slot";
import { cva, type VariantProps } from "class-variance-authority";
import { cn } from "./cn";
const styles = cva(
    "inline-flex h-9 items-center justify-center gap-1.5 whitespace-nowrap rounded-control border px-3 text-sm font-medium transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent disabled:pointer-events-none disabled:opacity-50",
    {
        variants: {
            variant: {
                primary:
                    "border-[var(--text-tertiary)] bg-[var(--text)] text-[var(--bg)] hover:bg-[var(--text-tertiary)]",
                outline:
                    "border-[var(--stroke-strong)] bg-[var(--bg)] text-[var(--text-secondary)] hover:border-[var(--text-muted)]",
                ghost: "border-transparent bg-transparent text-ink hover:bg-surface-subtle",
            },
        },
        defaultVariants: { variant: "primary" },
    },
);
export interface ButtonProps
    extends React.ButtonHTMLAttributes<HTMLButtonElement>,
        VariantProps<typeof styles> {
    asChild?: boolean;
}
export const Button = React.forwardRef<HTMLButtonElement, ButtonProps>(
    ({ className, variant, asChild = false, ...props }, ref) => {
        const Comp = asChild ? Slot : "button";
        return <Comp ref={ref} className={cn(styles({ variant, className }))} {...props} />;
    },
);
Button.displayName = "Button";
