import { CircleAlert, FolderOpen } from "lucide-react";
export function Skeleton({ className = "" }: { className?: string }) {
    return (
        <div
            aria-hidden="true"
            className={`animate-pulse rounded-md bg-[var(--surface-subtle)] ${className}`}
        />
    );
}
export function EmptyState({ title, description }: { title: string; description: string }) {
    return (
        <div className="flex min-h-48 flex-col items-center justify-center gap-2 text-center">
            <FolderOpen aria-hidden="true" className="size-5 text-[var(--text-muted)]" />
            <h2 className="font-semibold">{title}</h2>
            <p className="max-w-md text-sm text-[var(--text-muted)]">{description}</p>
        </div>
    );
}
export function ErrorState({ title, description }: { title: string; description: string }) {
    return (
        <div
            role="alert"
            className="flex gap-3 rounded-panel border border-rose-200 bg-rose-50 p-4 text-rose-900"
        >
            <CircleAlert aria-hidden="true" className="size-5 shrink-0" />
            <div>
                <h2 className="font-semibold">{title}</h2>
                <p className="text-sm">{description}</p>
            </div>
        </div>
    );
}
