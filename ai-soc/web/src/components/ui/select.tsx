import * as SelectPrimitive from "@radix-ui/react-select";
import { Check, ChevronDown } from "lucide-react";
export const Select = SelectPrimitive.Root;
export const SelectValue = SelectPrimitive.Value;
export const SelectTrigger = SelectPrimitive.Trigger;
export function SelectContent({ children }: { children: React.ReactNode }) {
    return (
        <SelectPrimitive.Portal>
            <SelectPrimitive.Content
                position="popper"
                className="z-50 min-w-32 rounded-control border border-[var(--stroke)] bg-[var(--surface)] p-1 shadow-float"
            >
                <SelectPrimitive.Viewport>{children}</SelectPrimitive.Viewport>
            </SelectPrimitive.Content>
        </SelectPrimitive.Portal>
    );
}
export function SelectItem({ value, children }: { value: string; children: React.ReactNode }) {
    return (
        <SelectPrimitive.Item
            value={value}
            className="flex cursor-pointer items-center justify-between rounded-md px-2 py-1.5 text-sm outline-none focus:bg-[var(--surface-subtle)]"
        >
            <SelectPrimitive.ItemText>{children}</SelectPrimitive.ItemText>
            <SelectPrimitive.ItemIndicator>
                <Check className="size-4" />
            </SelectPrimitive.ItemIndicator>
        </SelectPrimitive.Item>
    );
}
export function SelectIcon() {
    return (
        <SelectPrimitive.Icon>
            <ChevronDown className="size-4" />
        </SelectPrimitive.Icon>
    );
}
