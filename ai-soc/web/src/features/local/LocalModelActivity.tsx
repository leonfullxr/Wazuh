import { useQuery } from "@tanstack/react-query";
import { Activity, Bot, CheckCircle2, CircleX } from "lucide-react";
import { getLocalModelActivity } from "../../api/local-activity";
import "./local-model-activity.css";

type Translate = (key: string) => string;

export function LocalModelActivity({ siteId, t }: { siteId: string; t: Translate }) {
    const activity = useQuery({
        queryKey: ["local", "model-activity", siteId],
        queryFn: ({ signal }) => getLocalModelActivity(siteId, signal),
        enabled: siteId.length > 0,
        refetchInterval: 30_000,
    });

    return (
        <section className="local-model-activity" aria-labelledby="local-model-activity-title">
            <div className="local-model-activity-title">
                <span className="local-model-activity-icon">
                    <Activity size={16} aria-hidden="true" />
                </span>
                <div>
                    <h2 id="local-model-activity-title">{t("localModelActivity")}</h2>
                    <p>{t("localModelActivityDescription")}</p>
                </div>
            </div>
            {activity.isLoading ? (
                <p className="local-model-activity-state" role="status">
                    {t("localModelActivityLoading")}
                </p>
            ) : activity.isError || !activity.data ? (
                <p className="local-model-activity-state">{t("localModelActivityUnavailable")}</p>
            ) : (
                <dl>
                    <div className="local-model-name">
                        <dt>
                            <Bot size={14} aria-hidden="true" /> {t("localModel")}
                        </dt>
                        <dd>{activity.data.model ?? t("modelOffShort")}</dd>
                    </div>
                    <div>
                        <dt>{t("localModelAttempts")}</dt>
                        <dd>{activity.data.attempts.toLocaleString()}</dd>
                    </div>
                    <div>
                        <dt>
                            <CheckCircle2 size={14} aria-hidden="true" /> {t("localModelCompleted")}
                        </dt>
                        <dd>{activity.data.completed.toLocaleString()}</dd>
                    </div>
                    <div>
                        <dt>
                            <CircleX size={14} aria-hidden="true" /> {t("localModelFailed")}
                        </dt>
                        <dd>{activity.data.failed.toLocaleString()}</dd>
                    </div>
                </dl>
            )}
        </section>
    );
}
