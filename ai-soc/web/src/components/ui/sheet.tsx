import * as Dialog from "@radix-ui/react-dialog";
import type { ReactNode } from "react";
import { X } from "lucide-react";
export const Sheet = Dialog.Root;
export const SheetTrigger = Dialog.Trigger;
export const SheetClose = Dialog.Close;
export function SheetContent({
    children,
    title,
    restoreFocus,
    closeLabel = "Close",
}: {
    children: ReactNode;
    title: string;
    restoreFocus?: () => void;
    closeLabel?: string;
}) {
    return (
        <Dialog.Portal>
            <div aria-hidden="true" className="fixed inset-0 z-40 bg-black/20 pointer-events-auto" />
            <Dialog.Content
                aria-describedby={undefined}
                className="fixed inset-y-0 right-0 z-50 w-full max-w-sm overflow-y-auto border-l border-[var(--stroke-subtle)] bg-[var(--bg)] p-6 shadow-float"
                onCloseAutoFocus={(event) => {
                    if (restoreFocus) {
                        event.preventDefault();
                        restoreFocus();
                    }
                }}
            >
                <Dialog.Title className="mb-4 font-semibold">{title}</Dialog.Title>
                <Dialog.Close className="sheet-close" aria-label={closeLabel}>
                    <X size={18} aria-hidden="true" />
                </Dialog.Close>
                {children}
            </Dialog.Content>
        </Dialog.Portal>
    );
}
