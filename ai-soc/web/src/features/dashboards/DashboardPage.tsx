import { Panel } from "../../components/ui/panel";
import "./dashboard-v2.css";

type Translate = (key: string) => string;
export type DashboardKind = "ai_quality" | "soc_operations";

const widgets = {
    ai_quality: [
        ["aiQualitySummary", "aiQualitySummaryEmpty"],
        ["answerOutcomes", "answerOutcomesEmpty"],
        ["judgmentBreakdown", "judgmentBreakdownEmpty"],
        ["whereTimeGoes", "whereTimeGoesEmpty"],
        ["validatorRemovals", "validatorRemovalsEmpty"],
        ["topicQuality", "topicQualityEmpty"],
        ["answersNeedReview", "answersNeedReviewEmpty"],
    ],
    soc_operations: [
        ["socOperationsSummary", "socOperationsSummaryEmpty"],
        ["backlogFlow", "backlogFlowEmpty"],
        ["triageFunnel", "triageFunnelEmpty"],
        ["openWorkAge", "openWorkAgeEmpty"],
        ["analystLoad", "analystLoadEmpty"],
        ["tuningCandidates", "tuningCandidatesEmpty"],
    ],
} as const satisfies Record<DashboardKind, ReadonlyArray<readonly [string, string]>>;

export function DashboardPage({ kind, t }: { kind: DashboardKind; t: Translate }) {
    const description =
        kind === "ai_quality" ? t("aiQualityDescription") : t("socOperationsDescription");

    return (
        <div className="workspace-page dashboard-v2">
            <p className="page-description">{description}</p>
            <Panel className="workspace-panel dashboard-v2-available">
                <div>
                    <h2>{t("availableMetrics")}</h2>
                    <p>{t("availableMetricsDescription")}</p>
                </div>
                <a className="btn outline" href="#metrics">
                    {t("openMetrics")}
                </a>
            </Panel>
            <div className="dashboard-v2-grid">
                {widgets[kind].map(([titleKey, emptyKey]) => (
                    <Panel className="workspace-panel dashboard-v2-widget" key={titleKey}>
                        <div className="dashboard-v2-widget-heading">
                            <h2>{t(titleKey)}</h2>
                            <span>{t("notReported")}</span>
                        </div>
                        <div className="dashboard-v2-empty">
                            <strong>{t("noDashboardData")}</strong>
                            <p>{t(emptyKey)}</p>
                        </div>
                    </Panel>
                ))}
            </div>
        </div>
    );
}
