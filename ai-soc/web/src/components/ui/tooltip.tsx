import * as TooltipPrimitive from "@radix-ui/react-tooltip";
export function Tooltip({ children, content }: { children: React.ReactNode; content: string }) {
    return (
        <TooltipPrimitive.Provider delayDuration={400}>
            <TooltipPrimitive.Root>
                <TooltipPrimitive.Trigger asChild>{children}</TooltipPrimitive.Trigger>
                <TooltipPrimitive.Portal>
                    <TooltipPrimitive.Content
                        sideOffset={6}
                        className="z-50 rounded-md bg-[var(--text)] px-2 py-1 text-xs text-[var(--bg)]"
                    >
                        {content}
                        <TooltipPrimitive.Arrow className="fill-[var(--text)]" />
                    </TooltipPrimitive.Content>
                </TooltipPrimitive.Portal>
            </TooltipPrimitive.Root>
        </TooltipPrimitive.Provider>
    );
}
