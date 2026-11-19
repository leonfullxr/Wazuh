import { CircleHelp } from "lucide-react";
import type { Route } from "./Navigation";
type Translate = (key: string) => string;

export function PageHeading({ route, t }: { route: Route; t: Translate }) {
    const descriptions: Partial<Record<Route, string>> = {
        overview: "overviewDescription",
        alerts: "alertsDescription",
        queue: "queueDescription",
        investigate: "evidenceReview",
    };
    const description = descriptions[route];

    return (
        <header className="page-head">
            <h1>{t(route)}</h1>
            {description && <p>{t(description)}</p>}
        </header>
    );
}

export function EmptyInvestigate({ t }: { t: Translate }) {
    return (
        <section className="panel empty-state">
            <CircleHelp />
            <h2>{t("askToReview")}</h2>
            <p>{t("answerDescription")}</p>
        </section>
    );
}
