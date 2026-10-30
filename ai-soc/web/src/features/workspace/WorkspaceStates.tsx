import { ErrorState, EmptyState, Skeleton } from "../../components/ui/states";
import { WorkspaceRequestError } from "../../api/workspace";

export function WorkspaceLoading({ label }: { label: string }) {
    return (
        <div aria-label={label} aria-busy="true" className="workspace-loading" role="status">
            <Skeleton className="h-20 w-full" />
            <Skeleton className="h-44 w-full" />
            <Skeleton className="h-64 w-full" />
        </div>
    );
}

export function WorkspaceFailure({
    error,
    t,
    onRetry,
}: {
    error: unknown;
    t: (key: string) => string;
    onRetry: () => void;
}) {
    const denied = error instanceof WorkspaceRequestError && error.status === 403;
    return (
        <div className="workspace-failure">
            <ErrorState
                title={t(denied ? "denied" : "unavailableTitle")}
                description={error instanceof Error ? error.message : t("requestFailed")}
            />
            <button className="btn outline" onClick={onRetry} type="button">
                {t("retry")}
            </button>
        </div>
    );
}

export function QuietSiteState({ t }: { t: (key: string) => string }) {
    return <EmptyState title={t("quietTitle")} description={t("quietDescription")} />;
}

export function UnavailableFeature({
    title,
    description,
}: {
    title: string;
    description: string;
}) {
    return (
        <section className="panel workspace-unavailable" role="status">
            <span className="eyebrow">UNAVAILABLE</span>
            <h2>{title}</h2>
            <p>{description}</p>
        </section>
    );
}
