import { useEffect, useMemo, useRef, useState } from "react";
import { Search } from "lucide-react";
import type {
    Answer,
    AskRequest,
    BootstrapResponse,
    EvidenceItem,
} from "../../../contracts/v1/generated/types.ts";
import { useBootstrap, useAsk } from "../api/hooks";
import { useQuery } from "@tanstack/react-query";
import { listWorkspaceSites, WorkspaceRequestError } from "../api/workspace";
import { resolveWindow } from "./state/time-window";
import { byteCount, buildContinuationRequest } from "./state/answer-format";
import {
    replayEnvironment,
    useAnswerSession,
    type AnswerHistoryItem,
} from "./state/answer-session";
import { evidenceById, topicsFromHistory } from "./state/answer-view-model";
export {
    byteCount,
    buildContinuationRequest,
    formatCount,
    formatVisibility,
    formatWindow,
    resolveCitation,
    safeDocumentUrl,
} from "./state/answer-format";
import { ApiError, page as fetchPage, feedback as sendFeedback } from "../api/client";
import { makeKevAnswer } from "../api/kev-preview";
import { AnswerView } from "../features/investigate/AnswerView";
import { Composer } from "../features/investigate/Composer";
import { EvidenceDrawer } from "../features/investigate/EvidenceDrawer";
import { Feedback } from "../features/investigate/Feedback";
import { StatusScreen } from "../features/investigate/StatusScreen";
import { HistoryScreen } from "../features/history/HistoryScreen";
import { TopicsScreen } from "../features/topics/TopicsScreen";
import { initialLocale, saveLocale, type Locale } from "../i18n";
import { words, fmt } from "../i18n/answer-copy";
import { workspaceWords } from "../i18n/workspace-copy";
export { errorCopy, judgments, outcomes, reasons, removed } from "../i18n/answer-enums";

import {
    ContextHeader,
    dashboardNav,
    NavigationRail,
    nav,
    routeFromHash,
    type Route,
} from "./Navigation";
import { EmptyInvestigate, PageHeading } from "./PageHeading";
import { errorText } from "./error-copy";
import { OverviewPage, type AlertDrilldown } from "../features/overview/OverviewPage";
import { AlertsPage, type AlertFilterPatch } from "../features/alerts/AlertsPage";
import { QueuePage } from "../features/queue/QueuePage";
import { MetricsPage } from "../features/metrics/MetricsPage";
import { DashboardPage } from "../features/dashboards/DashboardPage";
import { M3WorkspacePage } from "../features/incidents/M3WorkspacePage";
import { ThemeProvider } from "../components/theme/theme-menu";
export function App() {
    return (
        <ThemeProvider>
            <AppContent />
        </ThemeProvider>
    );
}
function AppContent() {
    const [route, setRoute] = useState<Route>(() => routeFromHash() ?? "overview");
    const [locale, setLocale] = useState<Locale>(() => initialLocale());
    const [scenario, setScenario] = useState(
        () => new URLSearchParams(location.search).get("scenario") ?? "auto",
    );
    const [question, setQuestion] = useState("");
    const draftRevision = useRef(0);
    const [selectedSite, setSelectedSite] = useState(
        () => new URLSearchParams(location.search).get("site_id") ?? "",
    );
    const [timeRange, setTimeRange] = useState<"24h" | "7d" | "30d">(() => {
        const range = new URLSearchParams(location.search).get("range");
        return range === "7d" || range === "30d" ? range : "24h";
    });
    const [rangeAnchor, setRangeAnchor] = useState(() => Date.now());
    const [urlRevision, setUrlRevision] = useState(0);
    const [model, setModel] = useState("");
    const [effort, setEffort] = useState("");
    const { answer, active, history, dispatch } = useAnswerSession();
    const [selectedEvidence, setSelectedEvidence] = useState<{
        question_id: string;
        item: EvidenceItem;
    } | null>(null);
    const [drawerTrigger, setDrawerTrigger] = useState<HTMLElement | null>(null);
    const answerHeadingRef = useRef<HTMLHeadingElement>(null);
    const checked = active?.continuation_selection ?? [];
    const note = active?.feedback_draft ?? "";
    const [elapsed, setElapsed] = useState(0);
    const [requestError, setRequestError] = useState("");
    const [expiredReplay, setExpiredReplay] = useState<AnswerHistoryItem | null>(null);
    const [submissionPending, setSubmissionPending] = useState(false);
    const [feedbackPending, setFeedbackPending] = useState(false);
    const submissionLock = useRef(false);
    const abortRef = useRef<AbortController | null>(null);
    const ask = useAsk();
    const boot = useBootstrap();
    const sitesQuery = useQuery({
        queryKey: ["workspace", "sites"],
        queryFn: ({ signal }) => listWorkspaceSites(signal),
    });
    const bootstrap = boot.data as BootstrapResponse | undefined;
    const isMock = import.meta.env.MODE !== "live";
    const t = (key: string) => {
        const copy: Record<string, string> = workspaceWords[locale];
        if (key in copy) return copy[key] ?? key;
        return isAnswerCopyKey(key) ? fmt(locale, key) : key;
    };
    const canAsk =
        !!question.trim() &&
        byteCount(question) <= (bootstrap?.limits.question_bytes ?? 16384) &&
        !!bootstrap &&
        bootstrap.sites.length > 0 &&
        !ask.isPending &&
        !submissionPending;
    useEffect(() => {
        const change = () => {
            const next = routeFromHash();
            if (next) setRoute(next);
        };
        addEventListener("hashchange", change);
        return () => removeEventListener("hashchange", change);
    }, []);
    useEffect(() => {
        if (
            sitesQuery.error instanceof WorkspaceRequestError &&
            sitesQuery.error.status === 404 &&
            !window.location.hash
        ) {
            setRoute("investigate");
            window.location.hash = "#investigate";
        }
    }, [sitesQuery.error]);
    useEffect(() => {
        document.documentElement.lang = locale;
        saveLocale(locale);
    }, [locale]);
    useEffect(() => {
        document.title = `AI SOC | ${t(route)}`;
    }, [route, locale]);
    useEffect(() => {
        if (!bootstrap) return;
        const available = sitesQuery.data?.items ?? [];
        const nextSite = available.some((site) => site.site_id === selectedSite)
            ? selectedSite
            : (available[0]?.site_id ??
              (bootstrap.sites.some((site) => site.id === selectedSite)
                  ? selectedSite
                  : (bootstrap.sites[0]?.id ?? "")));
        if (nextSite !== selectedSite) setSelectedSite(nextSite);
        const activeModel = bootstrap.models.find((candidate) => candidate.id === model);
        const nextModel = activeModel ? model : (bootstrap.models[0]?.id ?? "");
        if (nextModel !== model) setModel(nextModel);
        const nextActiveModel = bootstrap.models.find((candidate) => candidate.id === nextModel);
        if (effort && !nextActiveModel?.efforts.some((candidate) => candidate === effort))
            setEffort("");
    }, [bootstrap, effort, model, selectedSite, sitesQuery.data]);
    useEffect(() => {
        const u = new URL(location.href);
        u.searchParams.set("scenario", scenario);
        historyReplace(u);
    }, [scenario]);
    useEffect(() => {
        const u = new URL(location.href);
        if (selectedSite) u.searchParams.set("site_id", selectedSite);
        u.searchParams.set("range", timeRange);
        historyReplace(u);
    }, [selectedSite, timeRange]);
    useEffect(() => {
        if (!ask.isPending && !submissionPending) {
            setElapsed(0);
            return;
        }
        const timer = setInterval(() => setElapsed((s) => s + 1), 1000);
        return () => clearInterval(timer);
    }, [ask.isPending, submissionPending]);
    useEffect(() => {
        if (answer?.status === "clarify" && answer.clarify?.kind === "model_selection") {
            document.getElementById("model-select")?.focus();
        }
    }, [answer?.question_id]);
    useEffect(() => {
        if (selectedEvidence && selectedEvidence.question_id !== answer?.question_id) {
            setSelectedEvidence(null);
            setDrawerTrigger(null);
            answerHeadingRef.current?.focus();
        }
    }, [answer?.question_id, selectedEvidence]);
    useEffect(() => {
        if (selectedEvidence) {
            const close = (e: KeyboardEvent) => {
                if (e.key === "Escape") {
                    setSelectedEvidence(null);
                    const trigger = drawerTrigger;
                    setDrawerTrigger(null);
                    if (selectedEvidence.question_id === answer?.question_id) trigger?.focus();
                    else answerHeadingRef.current?.focus();
                }
            };
            addEventListener("keydown", close);
            return () => removeEventListener("keydown", close);
        }
    }, [selectedEvidence, drawerTrigger, answer?.question_id]);
    function historyReplace(u: URL) {
        window.history.replaceState(null, "", u);
    }
    function navigate(next: Route) {
        setRoute(next);
        if (routeFromHash() !== next) location.hash = `#${next}`;
    }
    function updateUrl(patch: Record<string, string | null | undefined>, nextRoute?: Route) {
        const u = new URL(location.href);
        for (const [key, value] of Object.entries(patch)) {
            if (value === null || value === undefined || value === "") u.searchParams.delete(key);
            else u.searchParams.set(key, value);
        }
        historyReplace(u);
        setUrlRevision((revision) => revision + 1);
        if (nextRoute) navigate(nextRoute);
    }
    function openAlertDrilldown(filters: AlertDrilldown) {
        const clear = Object.fromEntries(
            [
                "rule_id",
                "agent_id",
                "min_level",
                "max_level",
                "tactic",
                "entity_kind",
                "entity",
                "cursor",
                "from",
                "to",
                "alert_key",
            ].map((key) => [key, null]),
        );
        updateUrl(
            {
                ...clear,
                ...Object.fromEntries(
                    Object.entries(filters).map(([key, value]) => [key, value?.toString()]),
                ),
            },
            "alerts",
        );
    }
    function updateAlertFilters(filters: AlertFilterPatch) {
        updateUrl(
            {
                rule_id: null,
                agent_id: null,
                min_level: null,
                max_level: null,
                tactic: null,
                entity_kind: null,
                entity: null,
                cursor: null,
                alert_key: null,
                ...Object.fromEntries(
                    Object.entries(filters).map(([key, value]) => [key, value?.toString()]),
                ),
            },
            "alerts",
        );
    }
    function updateQuestion(value: string) {
        draftRevision.current += 1;
        setQuestion(value);
    }
    async function submit(
        continuation?: boolean,
        replay?: AnswerHistoryItem,
        replayOriginalSeparately = false,
    ) {
        if (!bootstrap || submissionLock.current) return;
        if (replay) {
            const environment = replayEnvironment(replay, bootstrap.sites);
            if (!environment) {
                updateQuestion(replay.question);
                setRequestError(t("historySiteUnavailable"));
                navigate("investigate");
                return;
            }
            updateQuestion(replay.question);
        }
        if (!bootstrap.sites.length) return;
        if (
            continuation &&
            answer &&
            !bootstrap.sites.some((site) => site.id === answer.environment_id)
        ) {
            setRequestError(t("historySiteUnavailable"));
            return;
        }
        submissionLock.current = true;
        setSubmissionPending(true);
        setRequestError("");
        setExpiredReplay(null);
        if (answer)
            dispatch({ type: "feedback-result", question_id: answer.question_id, result: null });
        const site =
            continuation && answer
                ? answer.environment_id
                : replay
                  ? replay.environment_id
                  : bootstrap.sites.some((candidate) => candidate.id === selectedSite)
                    ? selectedSite
                    : bootstrap.sites[0]!.id;
        const selectedModel =
            bootstrap.models.find((candidate) => candidate.id === model) ?? bootstrap.models[0];
        const selectedEffort = selectedModel?.efforts.some((candidate) => candidate === effort)
            ? (effort as AskRequest["effort"])
            : undefined;
        const submittedQuestion =
            replay?.question ?? (continuation ? active?.question : question) ?? "";
        const submittedRevision = draftRevision.current;
        const body: AskRequest =
            replay && !replayOriginalSeparately
                ? replay.replay_request
                : continuation && answer && active
                  ? {
                        ...buildContinuationRequest(
                            active.question,
                            site,
                            Intl.DateTimeFormat().resolvedOptions().timeZone,
                            locale,
                            answer.followup_id,
                            answer.followup_revision,
                            checked,
                        ),
                        model_id: selectedModel?.id,
                        effort: selectedEffort,
                    }
                  : {
                        question: submittedQuestion,
                        environment_id: site,
                        timezone: Intl.DateTimeFormat().resolvedOptions().timeZone,
                        language_hint: locale,
                        model_id: selectedModel?.id,
                        effort: selectedEffort,
                    };
        const controller = new AbortController();
        abortRef.current = controller;
        try {
            const next = await ask.mutateAsync({
                request: body,
                idempotencyKey: crypto.randomUUID(),
                signal: controller.signal,
            });
            const previewEnabled =
                isMock &&
                (scenario === "kev" || new URLSearchParams(location.search).get("kev") === "1");
            const displayedAnswer = previewEnabled
                ? (makeKevAnswer(next) as unknown as Answer)
                : next;
            const parentQuestion = continuation
                ? (answer?.question_id ?? null)
                : replayOriginalSeparately
                  ? null
                  : (replay?.parent_question_id ?? null);
            const submitted = submittedQuestion;
            if (draftRevision.current === submittedRevision) setQuestion(submitted);
            dispatch({
                type: "record",
                answer: displayedAnswer,
                question: submitted,
                replay_request: body,
                parent_question_id: parentQuestion,
                at: new Date().toISOString(),
            });
        } catch (e) {
            if (!controller.signal.aborted) {
                setRequestError(errorText(e, locale));
                if (
                    replay &&
                    !replayOriginalSeparately &&
                    replay.replay_request.continue_topic_ids?.length &&
                    e instanceof ApiError &&
                    e.domainError?.code === "FOLLOWUP_EXPIRED"
                )
                    setExpiredReplay(replay);
            }
        } finally {
            submissionLock.current = false;
            setSubmissionPending(false);
        }
    }
    function selectAnswer(item: { answer: Answer; question: string }) {
        dispatch({ type: "activate", question_id: item.answer.question_id });
        updateQuestion(item.question);
        navigate("investigate");
    }
    function openEvidence(item: EvidenceItem, trigger: HTMLElement) {
        if (!answer) return;
        setDrawerTrigger(trigger);
        setSelectedEvidence({ question_id: answer.question_id, item });
    }
    const mapped = useMemo(() => evidenceById(answer), [answer]);
    const icon = [...nav, ...dashboardNav].find((n) => n.id === route)?.icon ?? Search;
    const PageIcon = icon;
    const allTopics = useMemo(() => topicsFromHistory(history), [history]);
    const queryParams = new URLSearchParams(location.search);
    const requestedRange = queryParams.get("range");
    const activeRange: "24h" | "7d" | "30d" =
        requestedRange === "7d" || requestedRange === "30d" ? requestedRange : timeRange;
    const requestedFrom = queryParams.get("from");
    const requestedTo = queryParams.get("to");
    const { from, to } = resolveWindow({
        range: activeRange,
        anchor: rangeAnchor,
        from: requestedFrom,
        to: requestedTo,
    });
    const site =
        sitesQuery.data?.items.find((candidate) => candidate.site_id === selectedSite) ??
        (bootstrap?.sites.find((candidate) => candidate.id === selectedSite)
            ? {
                  site_id: selectedSite,
                  label:
                      bootstrap.sites.find((candidate) => candidate.id === selectedSite)?.label ??
                      selectedSite,
              }
            : undefined);
    const alertFilters = {
        siteId: selectedSite,
        from,
        to,
        ruleId: queryParams.get("rule_id") ?? undefined,
        agentId: queryParams.get("agent_id") ?? undefined,
        minLevel: parseOptionalLevel(queryParams.get("min_level")),
        maxLevel: parseOptionalLevel(queryParams.get("max_level")),
        tactic: queryParams.get("tactic") ?? undefined,
        entityKind: queryParams.get("entity_kind") ?? undefined,
        entity: queryParams.get("entity") ?? undefined,
        cursor: queryParams.get("cursor") ?? undefined,
    };
    void urlRevision;
    async function loadPage(topicId: string, fetchId: string, cursor: string) {
        if (!answer) return;
        const request_id = crypto.randomUUID();
        const context = {
            question_id: answer.question_id,
            environment_id: answer.environment_id,
            topic_id: topicId,
            fetch_id: fetchId,
            cursor,
            request_id,
        };
        dispatch({ type: "page-start", context });
        try {
            const next = await fetchPage({ environment_id: answer.environment_id, cursor });
            dispatch({ type: "page-success", context, page: next });
        } catch (e) {
            dispatch({ type: "page-error", context, error: errorText(e, locale) });
        }
    }
    return (
        <div className="app-shell">
            <NavigationRail route={route} setRoute={navigate} t={t} />
            <div className="app-main">
                <ContextHeader
                    route={route}
                    onNavigate={navigate}
                    onSearch={openAlertDrilldown}
                    locale={locale}
                    setLocale={setLocale}
                    bootstrap={bootstrap}
                    sites={sitesQuery.data?.items ?? []}
                    modeState={boot.isLoading ? "loading" : boot.isError ? "unavailable" : null}
                    selectedSite={selectedSite}
                    setSelectedSite={setSelectedSite}
                    timeRange={activeRange}
                    customRange={queryParams.has("from") || queryParams.has("to")}
                    windowFrom={from}
                    windowTo={to}
                    onCustomRange={(range) =>
                        updateUrl({ from: range.from, to: range.to, cursor: null })
                    }
                    setTimeRange={(range) => {
                        setRangeAnchor(Date.now());
                        setTimeRange(range);
                        updateUrl({ range, from: null, to: null, cursor: null });
                    }}
                    isMock={isMock}
                    scenario={scenario}
                    setScenario={setScenario}
                    t={t}
                />
                <main id="main" className="workspace" tabIndex={-1}>
                    <PageHeading route={route} icon={PageIcon} t={t} />
                    {route === "overview" && (
                        <OverviewPage
                            site={site}
                            from={from}
                            to={to}
                            timezone={Intl.DateTimeFormat().resolvedOptions().timeZone}
                            t={t}
                            onDrilldown={openAlertDrilldown}
                        />
                    )}
                    {route === "alerts" && (
                        <AlertsPage
                            site={site}
                            filters={alertFilters}
                            linkedAlertKey={queryParams.get("alert_key")}
                            t={t}
                            onFilters={updateAlertFilters}
                            onCloseDetails={() => updateUrl({ alert_key: null })}
                            onInvestigate={(alert) => {
                                updateQuestion(
                                    `${alert.rule_description ?? alert.rule_id ?? "Alert"} on ${alert.agent_name ?? alert.agent_id ?? "the selected site"}`,
                                );
                                navigate("investigate");
                            }}
                        />
                    )}
                    {route === "queue" && (
                        <QueuePage
                            siteId={selectedSite}
                            from={from}
                            to={to}
                            t={t}
                            onOpenAlert={(alertKey) => updateUrl({ alert_key: alertKey }, "alerts")}
                            onFilters={(values) => updateUrl(values, "queue")}
                        />
                    )}
                    {route === "metrics" && (
                        <MetricsPage siteId={selectedSite} from={from} to={to} t={t} />
                    )}
                    {(route === "ai_quality" || route === "soc_operations") && (
                        <DashboardPage kind={route} t={t} />
                    )}
                    {(route === "chains" || route === "incidents") && (
                        <M3WorkspacePage
                            kind={route}
                            siteId={selectedSite}
                            locale={locale}
                            t={t}
                            onInvestigate={(draft, environmentId) => {
                                updateQuestion(draft);
                                if (
                                    bootstrap?.sites.some(
                                        (candidate) => candidate.id === environmentId,
                                    )
                                )
                                    setSelectedSite(environmentId);
                                navigate("investigate");
                            }}
                        />
                    )}
                    {route === "investigate" && (
                        <>
                            {boot.isError && (
                                <div className="alert error" role="alert">
                                    {t("bootstrapError")}{" "}
                                    <button
                                        className="btn outline"
                                        onClick={() => void boot.refetch()}
                                    >
                                        {t("retry")}
                                    </button>
                                </div>
                            )}
                            {boot.isLoading && (
                                <p className="muted" role="status">
                                    {t("loadingSettings")}
                                </p>
                            )}
                            <Composer
                                bootstrap={bootstrap}
                                question={question}
                                setQuestion={updateQuestion}
                                model={model}
                                setModel={setModel}
                                effort={effort}
                                setEffort={setEffort}
                                canAsk={canAsk}
                                pending={submissionPending || ask.isPending}
                                elapsed={elapsed}
                                requestError={requestError}
                                expiredReplay={expiredReplay !== null}
                                onAskOriginalSeparately={() => {
                                    if (expiredReplay) void submit(false, expiredReplay, true);
                                }}
                                t={t}
                                onSubmit={() => void submit()}
                                onCancel={() => {
                                    abortRef.current?.abort();
                                    ask.reset();
                                    setRequestError(t("cancelled"));
                                }}
                            />
                            {!answer && !ask.isPending && <EmptyInvestigate t={t} />}
                            {answer && (
                                <>
                                    <AnswerView
                                        answer={answer}
                                        question={active?.question ?? ""}
                                        parentQuestion={
                                            active?.parent_question_id
                                                ? history.find(
                                                      (item) =>
                                                          item.answer.question_id ===
                                                          active.parent_question_id,
                                                  )?.question
                                                : undefined
                                        }
                                        onOpenParent={
                                            active?.parent_question_id
                                                ? () => {
                                                      const parent = history.find(
                                                          (item) =>
                                                              item.answer.question_id ===
                                                              active.parent_question_id,
                                                      );
                                                      if (parent) selectAnswer(parent);
                                                  }
                                                : undefined
                                        }
                                        continuationTopics={
                                            active?.replay_request.continue_topic_ids ?? []
                                        }
                                        locale={locale}
                                        timezone={Intl.DateTimeFormat().resolvedOptions().timeZone}
                                        t={t}
                                        headingRef={answerHeadingRef}
                                        mapped={mapped}
                                        onEvidence={openEvidence}
                                        onPage={loadPage}
                                        pageErrors={active?.page_errors ?? {}}
                                        pagePending={Object.values(active?.paging ?? {}).some(
                                            Boolean,
                                        )}
                                        checked={checked}
                                        setChecked={(value) => {
                                            if (!answer) return;
                                            const selection =
                                                typeof value === "function"
                                                    ? value(checked)
                                                    : value;
                                            dispatch({
                                                type: "selection",
                                                question_id: answer.question_id,
                                                selection,
                                            });
                                        }}
                                        onContinue={() => void submit(true)}
                                        questionPending={submissionPending || ask.isPending}
                                    />
                                    <Feedback
                                        t={t}
                                        note={note}
                                        setNote={(draft) =>
                                            answer &&
                                            dispatch({
                                                type: "feedback-draft",
                                                question_id: answer.question_id,
                                                draft,
                                            })
                                        }
                                        result={active?.feedback_result ?? null}
                                        onSend={async () => {
                                            const owner = answer;
                                            if (feedbackPending) return;
                                            setFeedbackPending(true);
                                            try {
                                                const receipt = await sendFeedback({
                                                    environment_id: owner.environment_id,
                                                    question_id: owner.question_id,
                                                    feedback_receipt: owner.feedback_receipt,
                                                    kind: "wrong",
                                                    note: note || null,
                                                });
                                                dispatch({
                                                    type: "feedback-result",
                                                    question_id: owner.question_id,
                                                    result: {
                                                        kind: "queued",
                                                        feedback_id: receipt.feedback_id,
                                                    },
                                                });
                                            } catch (e) {
                                                dispatch({
                                                    type: "feedback-result",
                                                    question_id: owner.question_id,
                                                    result: {
                                                        kind: "error",
                                                        code:
                                                            e instanceof ApiError && e.domainError
                                                                ? e.domainError.code
                                                                : "INTERNAL",
                                                    },
                                                });
                                            } finally {
                                                setFeedbackPending(false);
                                            }
                                        }}
                                        pending={feedbackPending}
                                    />
                                </>
                            )}
                        </>
                    )}
                    {route === "history" && (
                        <HistoryScreen
                            history={history}
                            locale={locale}
                            t={t}
                            onOpen={selectAnswer}
                            onAskAgain={(original) => {
                                navigate("investigate");
                                void submit(false, original);
                            }}
                            pending={submissionPending || ask.isPending}
                        />
                    )}
                    {route === "topics" && (
                        <TopicsScreen topics={allTopics} locale={locale} t={t} />
                    )}
                    {route === "status" && (
                        <StatusScreen bootstrap={bootstrap} answer={answer} locale={locale} t={t} />
                    )}
                </main>
            </div>
            {selectedEvidence && selectedEvidence.question_id === answer?.question_id && (
                <EvidenceDrawer
                    item={selectedEvidence.item}
                    answer={answer}
                    locale={locale}
                    timezone={Intl.DateTimeFormat().resolvedOptions().timeZone}
                    t={t}
                    onClose={() => {
                        const trigger = drawerTrigger;
                        setSelectedEvidence(null);
                        setDrawerTrigger(null);
                        trigger?.focus();
                    }}
                />
            )}
        </div>
    );
}

function isAnswerCopyKey(key: string): key is keyof typeof words.en {
    return Object.hasOwn(words.en, key);
}

function parseOptionalLevel(value: string | null): number | undefined {
    if (value === null || value === "") return undefined;
    const level = Number(value);
    return Number.isInteger(level) && level >= 0 && level <= 15 ? level : undefined;
}
