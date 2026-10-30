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
        <div className="page-head">
            <div>
                <Icon size={20} />
                <h2>{t(route)}</h2>
            </div>
            {route === "investigate" && <span className="muted">{t("evidenceReview")}</span>}
        </div>
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
