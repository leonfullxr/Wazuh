import { CircleHelp, type LucideIcon } from "lucide-react";
import type { Route } from "./Navigation";
type Translate = (key: string) => string;

export function PageHeading({
    route,
    icon: Icon,
    t,
}: {
    route: Route;
    icon: LucideIcon;
    t: Translate;
}) {
    return (
        <>
            <div className="page-head">
                <div>
                    <span className="page-icon" aria-hidden="true">
                        <Icon size={17} />
                    </span>
                    <h2>{t(route)}</h2>
                </div>
            </div>
            {route === "investigate" && <p className="page-description">{t("evidenceReview")}</p>}
        </>
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
