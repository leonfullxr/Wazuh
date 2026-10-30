import * as Dialog from "@radix-ui/react-dialog";
import type { ReactNode } from "react";
export const Sheet = Dialog.Root;
export const SheetTrigger = Dialog.Trigger;
export const SheetClose = Dialog.Close;
export function SheetContent({
    children,
    title,
    restoreFocus,
}: {
    children: ReactNode;
    title: string;
    restoreFocus?: () => void;
}) {
    return (
        <Dialog.Portal>
            <Dialog.Overlay className="fixed inset-0 z-40 bg-black/20" />
            <Dialog.Content
                aria-describedby={undefined}
                className="fixed inset-y-0 right-0 z-50 w-full max-w-sm overflow-y-auto border-l border-[var(--stroke-subtle)] bg-white p-6 shadow-float focus-visible:outline-none"
                onCloseAutoFocus={(event) => {
                    if (restoreFocus) {
                        event.preventDefault();
                        restoreFocus();
                    }
                }}
            >
                <Dialog.Title className="mb-4 font-semibold">{title}</Dialog.Title>
                {children}
            </Dialog.Content>
        </Dialog.Portal>
    );
}
