import { Tag } from "../../components/ui/tag";
import { ShareBar, SummaryStrip } from "../../components/ui/portfolio";
import type { DemoSamples } from "../workspace/samples";

type Translate = (key: string) => string;
type Quality = DemoSamples["quality"];
type Operations = DemoSamples["operations"];

const pct = (value: number) => `${Math.round(value * 100)}%`;
const width = (value: number, max: number) => ({ width: `${max ? (value / max) * 100 : 0}%` });

function Panel({
    id,
    title,
    note,
    badge,
    className,
    children,
}: {
    id: string;
    title: string;
    note?: string;
    badge?: string;
    className?: string;
    children: React.ReactNode;
}) {
    return (
        <section className={`pp-panel pp-panel-pad dash-panel ${className ?? ""}`} aria-labelledby={id}>
            <div className="dash-panel-head">
                <h2 id={id} className="t-section">
                    {title}
                </h2>
                {badge && <Tag tone="blue">{badge}</Tag>}
            </div>
            {note && <p className="t-secondary dash-panel-note">{note}</p>}
            {children}
        </section>
    );
}

function Legend({ items }: { items: ReadonlyArray<{ label: string; series: string }> }) {
    return (
        <div className="dash-legend">
            {items.map((item) => (
                <span key={item.label}>
                    <i data-series={item.series} aria-hidden="true" />
                    {item.label}
                </span>
            ))}
        </div>
    );
}

export function QualityDashboard({ data, t }: { data: Quality; t: Translate }) {
    const outcomeKeys = ["answered", "partial", "clarify", "refused"] as const;
    const outcomeLabels = {
        answered: t("outcomeAnswered"),
        partial: t("outcomePartial"),
        clarify: t("outcomeClarify"),
        refused: t("outcomeRefused"),
    };
    const dayMax = Math.max(...data.outcomes.map((day) => outcomeKeys.reduce((sum, key) => sum + day[key], 0)));
    const total = data.outcomes.reduce((sum, day) => sum + outcomeKeys.reduce((s, key) => s + day[key], 0), 0);
    const agreed = data.verdicts.rows.reduce((sum, row) => sum + row.agreed, 0);
    const overruled = data.verdicts.rows.reduce((sum, row) => sum + row.overruled, 0);
    const timingMax = Math.max(...data.timing.map((row) => row.p90));
    const removalMax = Math.max(...data.removals.map((row) => row.count));
    return (
        <div className="pp-stack dash">
            <SummaryStrip
                label={t("aiQualitySummary")}
                items={data.summary.map((item) => ({ label: item.label, value: item.value, note: item.note }))}
            />
            <div className="pp-grid">
                <Panel id="dash-outcomes" title={t("answerOutcomes")} note={t("answerOutcomesNote")} className="pp-wide">
                    <Legend items={outcomeKeys.map((key, index) => ({ label: outcomeLabels[key], series: String(index + 3) }))} />
                    <div
                        className="dash-columns"
                        role="img"
                        aria-label={`${t("answerOutcomes")}: ${total} ${t("answersWord")} ${t("overSevenDays")}`}
                    >
                        {data.outcomes.map((day) => {
                            const sum = outcomeKeys.reduce((s, key) => s + day[key], 0);
                            return (
                                <div key={day.day} className="dash-column">
                                    <span className="dash-column-total num">{sum}</span>
                                    <span className="dash-column-stack" style={{ height: `${(sum / dayMax) * 100}%` }}>
                                        {outcomeKeys.map((key, index) => (
                                            <span key={key} data-series={index + 3} style={{ flexGrow: day[key] }} />
                                        ))}
                                    </span>
                                    <span className="dash-column-label">{day.day}</span>
                                </div>
                            );
                        })}
                    </div>
                </Panel>
                <Panel id="dash-verdicts" title={t("verdictVsAnalyst")} badge={t("newBadge")} className="pp-narrow">
                    <p className="dash-big">
                        <strong className="num">{pct(data.verdicts.agreement)}</strong>
                        <span>
                            {t("agreeOf").replace("{agreed}", String(agreed)).replace("{total}", String(agreed + overruled))}
                        </span>
                    </p>
                    <table className="dash-mini-table">
                        <thead>
                            <tr>
                                <th scope="col">{t("aiSaid")}</th>
                                <th scope="col" className="is-num">
                                    {t("analystAgreed")}
                                </th>
                                <th scope="col" className="is-num">
                                    {t("overruled")}
                                </th>
                            </tr>
                        </thead>
                        <tbody>
                            {data.verdicts.rows.map((row) => (
                                <tr key={row.verdict}>
                                    <td>{row.verdict}</td>
                                    <td className="is-num">{row.agreed}</td>
                                    <td className="is-num">{row.overruled}</td>
                                </tr>
                            ))}
                        </tbody>
                    </table>
                    <a className="pp-link dash-foot-link" href="#queue">
                        {t("reviewOverruled").replace("{count}", String(overruled))}
                    </a>
                </Panel>
            </div>
            <div className="pp-grid">
                <Panel id="dash-judgment" title={t("judgmentBreakdown")}>
                    <div className="dash-hundred" role="img" aria-label={data.judgment.map((row) => `${row.label} ${pct(row.share)}`).join(", ")}>
                        {data.judgment.map((row, index) => (
                            <span key={row.label} data-series={index === 3 ? "bad" : String(index + 3)} style={{ flexGrow: row.share }} />
                        ))}
                    </div>
                    <ul className="dash-rows">
                        {data.judgment.map((row, index) => (
                            <li key={row.label}>
                                <i data-series={index === 3 ? "bad" : String(index + 3)} aria-hidden="true" />
                                <span className="dash-row-main">
                                    <span className="cell-main">{row.label}</span>
                                    <span className="t-secondary">{row.note}</span>
                                </span>
                                <span className="num dash-row-value">{pct(row.share)}</span>
                            </li>
                        ))}
                    </ul>
                </Panel>
                <Panel id="dash-timing" title={t("whereTimeGoes")} note={t("whereTimeGoesNote")}>
                    <ul className="dash-rows">
                        {data.timing.map((row) => (
                            <li key={row.label} className="dash-timing-row">
                                <span className="dash-row-label">{row.label}</span>
                                <span className="dash-timing-track" aria-hidden="true">
                                    <span style={width(row.p50, timingMax)} />
                                    <i style={{ left: `${(row.p90 / timingMax) * 100}%` }} />
                                </span>
                                <span className="num t-secondary dash-row-value">
                                    {row.p50.toFixed(1)} s / {row.p90.toFixed(1)} s
                                </span>
                            </li>
                        ))}
                    </ul>
                </Panel>
                <Panel id="dash-removals" title={t("validatorRemovals")}>
                    <ul className="dash-rows">
                        {data.removals.map((row) => (
                            <li key={row.label} className="dash-bar-row">
                                <span className="dash-row-main">
                                    <span>{row.label}</span>
                                    <ShareBar share={row.count / removalMax} />
                                </span>
                                <span className="num dash-row-value">{row.count}</span>
                            </li>
                        ))}
                    </ul>
                </Panel>
            </div>
            <section className="pp-panel dash-table-panel" aria-labelledby="dash-topics">
                <div className="pp-panel-head">
                    <div>
                        <h2 id="dash-topics" className="t-section">
                            {t("topicQuality")}
                        </h2>
                    </div>
                </div>
                <div className="pp-table-scroll">
                    <table className="pp-table">
                        <thead>
                            <tr>
                                <th scope="col">{t("topicWord")}</th>
                                <th scope="col" className="is-num">{t("questionsWord")}</th>
                                <th scope="col" className="is-num">{t("validatedWord")}</th>
                                <th scope="col" className="is-num">{t("removalsWord")}</th>
                                <th scope="col" className="is-num">{t("helpfulWord")}</th>
                                <th scope="col">{t("commonFailure")}</th>
                            </tr>
                        </thead>
                        <tbody>
                            {data.topics.map((row) => (
                                <tr key={row.name}>
                                    <td className="cell-main">{row.name}</td>
                                    <td className="is-num">{row.questions}</td>
                                    <td className="is-num">{pct(row.validated)}</td>
                                    <td className="is-num">{row.removals}</td>
                                    <td className="is-num">{pct(row.helpful)}</td>
                                    <td className="t-secondary">{row.failure}</td>
                                </tr>
                            ))}
                        </tbody>
                    </table>
                </div>
            </section>
            <section className="pp-panel dash-table-panel" aria-labelledby="dash-review" id="review">
                <div className="pp-panel-head">
                    <div>
                        <h2 id="dash-review" className="t-section">
                            {t("answersNeedReview")}
                        </h2>
                    </div>
                </div>
                <ul className="dash-review">
                    {data.review.map((row) => (
                        <li key={row.question}>
                            <span className="dash-row-main">
                                <span className="cell-main">{row.question}</span>
                                <span className="t-secondary">{row.meta}</span>
                            </span>
                            <Tag tone={row.tone as "red" | "amber" | "neutral"}>{row.reason}</Tag>
                            <a className="btn compact" href="#history">
                                {t("openAnswer")}
                            </a>
                        </li>
                    ))}
                </ul>
            </section>
        </div>
    );
}

export function OperationsDashboard({ data, t }: { data: Operations; t: Translate }) {
    const flowMax = Math.max(...data.flow.flatMap((day) => [day.opened, day.closed]));
    const funnelMax = data.funnel[0]?.count ?? 1;
    const ageMax = Math.max(...data.age.map((row) => row.levels.reduce((sum, value) => sum + value, 0)));
    const levelLabels = [t("level") + " 0-6", t("level") + " 7-9", t("level") + " 10-12", t("level") + " 13-15"];
    return (
        <div className="pp-stack dash">
            <SummaryStrip
                label={t("socOperationsSummary")}
                items={data.summary.map((item) => ({
                    label: item.label,
                    value: item.value,
                    note: item.tone ? <span className="dash-delta" data-tone={item.tone}>{item.note}</span> : item.note,
                }))}
            />
            <section className="pp-panel dash-table-panel" aria-labelledby="dash-sla">
                <div className="pp-panel-head">
                    <div>
                        <h2 id="dash-sla" className="t-section">
                            {t("slaHealth")}
                        </h2>
                        <p>{t("slaHealthNote")}</p>
                    </div>
                    <Tag tone="blue">{t("newBadge")}</Tag>
                </div>
                <div className="pp-table-scroll">
                    <table className="pp-table">
                        <thead>
                            <tr>
                                <th scope="col">{t("measureWord")}</th>
                                <th scope="col">{t("targetWord")}</th>
                                <th scope="col" className="is-num">p50</th>
                                <th scope="col" className="is-num">p90</th>
                                <th scope="col" className="share-col">{t("withinTarget")}</th>
                                <th scope="col" className="is-num">{t("missedWord")}</th>
                            </tr>
                        </thead>
                        <tbody>
                            {data.sla.map((row) => (
                                <tr key={row.label}>
                                    <td className="cell-main">{row.label}</td>
                                    <td>{row.target}</td>
                                    <td className="is-num">{row.p50}</td>
                                    <td className="is-num">{row.p90}</td>
                                    <td>
                                        <span className="dash-within">
                                            <ShareBar share={row.within} />
                                            <span className="t-secondary">{row.withinText}</span>
                                        </span>
                                    </td>
                                    <td className="is-num">
                                        <span className="sla-text" data-sla={row.missed ? "breached" : "met"}>
                                            {row.missed ? t("missedCount").replace("{count}", String(row.missed)) : t("noneMissed")}
                                        </span>
                                    </td>
                                </tr>
                            ))}
                        </tbody>
                    </table>
                </div>
            </section>
            <div className="pp-grid">
                <Panel id="dash-flow" title={t("backlogFlow")} note={t("backlogFlowNote")} className="pp-wide">
                    <Legend items={[{ label: t("openedWord"), series: "1" }, { label: t("closedWord"), series: "2" }]} />
                    <div className="dash-columns dash-pairs" role="img" aria-label={data.flow.map((day) => `${day.day}: ${day.opened} ${t("openedWord")}, ${day.closed} ${t("closedWord")}`).join("; ")}>
                        {data.flow.map((day) => {
                            const net = day.opened - day.closed;
                            return (
                                <div key={day.day} className="dash-column">
                                    <span className="dash-pair">
                                        <span data-series="1" style={{ height: `${(day.opened / flowMax) * 100}%` }} />
                                        <span data-series="2" style={{ height: `${(day.closed / flowMax) * 100}%` }} />
                                    </span>
                                    <span className="dash-column-label">{day.day}</span>
                                    <span className="dash-delta num" data-tone={net > 0 ? "warn" : net < 0 ? "good" : undefined}>
                                        {net > 0 ? `+${net}` : net < 0 ? `-${-net}` : "0"}
                                    </span>
                                </div>
                            );
                        })}
                    </div>
                </Panel>
                <Panel id="dash-funnel" title={t("triageFunnel")} className="pp-narrow">
                    <ul className="dash-rows">
                        {data.funnel.map((row, index) => {
                            const previous = data.funnel[index - 1];
                            return (
                                <li key={row.label} className="dash-bar-row">
                                    <span className="dash-row-main">
                                        <span>
                                            {row.label}
                                            {previous && (
                                                <span className="t-secondary"> · {pct(row.count / previous.count)}</span>
                                            )}
                                        </span>
                                        <ShareBar share={row.count / funnelMax} />
                                    </span>
                                    <span className="num dash-row-value">{row.count}</span>
                                </li>
                            );
                        })}
                    </ul>
                </Panel>
            </div>
            <Panel id="dash-age" title={t("openWorkAge")} note={t("openWorkAgeNote")}>
                <Legend items={levelLabels.map((label, index) => ({ label, series: `sev${index + 1}` }))} />
                <ul className="dash-rows">
                    {data.age.map((row) => {
                        const sum = row.levels.reduce((total, value) => total + value, 0);
                        return (
                            <li key={row.label} className="dash-age-row">
                                <span className="dash-row-label">{row.label}</span>
                                <span className="dash-age-track" aria-label={`${row.label}: ${sum}`} role="img">
                                    <span style={width(sum, ageMax)}>
                                        {row.levels.map((value, index) => (
                                            <span key={index} data-series={`sev${index + 1}`} style={{ flexGrow: value }} />
                                        ))}
                                    </span>
                                </span>
                                <span className="num dash-row-value">{sum}</span>
                            </li>
                        );
                    })}
                </ul>
            </Panel>
            <div className="pp-grid">
                <section className="pp-panel dash-table-panel" aria-labelledby="dash-load">
                    <div className="pp-panel-head">
                        <div>
                            <h2 id="dash-load" className="t-section">
                                {t("analystLoad")}
                            </h2>
                        </div>
                    </div>
                    <div className="pp-table-scroll">
                        <table className="pp-table">
                            <thead>
                                <tr>
                                    <th scope="col">{t("owner")}</th>
                                    <th scope="col" className="is-num">{t("openWord")}</th>
                                    <th scope="col" className="is-num">{t("actionsWord")}</th>
                                    <th scope="col" className="is-num">{t("triageP50")}</th>
                                    <th scope="col" className="is-num">{t("slaMisses")}</th>
                                </tr>
                            </thead>
                            <tbody>
                                {data.load.map((row) => (
                                    <tr key={row.name}>
                                        <td className="ent">{row.name}</td>
                                        <td className="is-num">{row.open}</td>
                                        <td className="is-num">{row.actions ?? "\u2014"}</td>
                                        <td className="is-num">{row.p50 ?? "\u2014"}</td>
                                        <td className="is-num">
                                            <span className="sla-text" data-sla={row.missed ? "breached" : "met"}>
                                                {row.missed}
                                            </span>
                                        </td>
                                    </tr>
                                ))}
                            </tbody>
                        </table>
                    </div>
                </section>
                <section className="pp-panel dash-table-panel" aria-labelledby="dash-tuning">
                    <div className="pp-panel-head">
                        <div>
                            <h2 id="dash-tuning" className="t-section">
                                {t("tuningCandidates")}
                            </h2>
                            <p>{t("tuningCandidatesNote")}</p>
                        </div>
                    </div>
                    <ul className="dash-review">
                        {data.tuning.map((row) => (
                            <li key={row.rule}>
                                <span className="dash-row-main">
                                    <span className="cell-main">{row.name}</span>
                                    <span className="t-secondary">
                                        {t("rule")} {row.rule} {t("on")} <span className="ent">{row.host}</span> ·{" "}
                                        {t("closedAsFp")
                                            .replace("{closed}", String(row.closed))
                                            .replace("{total}", String(row.total))}
                                    </span>
                                    <span className="t-secondary">{row.reason}</span>
                                </span>
                                <button type="button" className="btn compact" disabled title={t("draftExceptionPending")}>
                                    {t("draftException")}
                                </button>
                            </li>
                        ))}
                    </ul>
                </section>
            </div>
        </div>
    );
}
