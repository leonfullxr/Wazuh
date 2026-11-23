import { Panel } from "../../components/ui/panel";
import { useSamples } from "../workspace/samples";
import { OperationsDashboard, QualityDashboard } from "./DashboardCharts";
import "./dashboard-v2.css";
import "./dashboard-pp.css";

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
    const samples = useSamples();
    if (samples)
        return (
            <div className="workspace-page dashboard-pp">
                <p className="dash-sample-note">
                    <span className="dot" data-tone="warn" />
                    {t("sampleValuesNote")}
                </p>
                {kind === "ai_quality" ? (
                    <QualityDashboard data={samples.quality} t={t} />
                ) : (
                    <OperationsDashboard data={samples.operations} t={t} />
                )}
            </div>
        );

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
            <Panel className="workspace-panel dashboard-v2-index">
                <h2>{t("noDashboardData")}</h2>
                <p>{t("notReported")}</p>
                <ul>
                    {widgets[kind].map(([titleKey, emptyKey]) => (
                        <li key={titleKey}>
                            <h3>{t(titleKey)}</h3>
                            <p>{t(emptyKey)}</p>
                        </li>
                    ))}
                </ul>
            </Panel>
        </div>
    );
}
