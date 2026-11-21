import type { Route } from "./Navigation";
type Translate = (key: string) => string;

export function PageHeading({ route, t }: { route: Route; t: Translate }) {
    return (
        <header className="page-head">
            <h1>{t(route)}</h1>
        </header>
    );
}

export function EmptyInvestigate({ t }: { t: Translate }) {
    return (
        <section className="panel empty-state">
            <h2>{t("askToReview")}</h2>
            <p>{t("answerDescription")}</p>
        </section>
    );
}
