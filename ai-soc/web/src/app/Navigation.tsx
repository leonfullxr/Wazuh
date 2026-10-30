import {
    Activity,
    BarChart3,
    Bell,
    BriefcaseBusiness,
    Clock3,
    Files,
    GitBranch,
    LayoutDashboard,
    ListTodo,
    Search,
    Shield,
} from "lucide-react";
import type { BootstrapResponse } from "../../../contracts/v1/generated/types.ts";
import type { Locale } from "../i18n";
import { StatusPill } from "../components/ui/status-pill";

export const nav = [
    { id: "overview", icon: LayoutDashboard },
    { id: "alerts", icon: Bell },
    { id: "queue", icon: ListTodo },
    { id: "chains", icon: GitBranch },
    { id: "incidents", icon: BriefcaseBusiness },
    { id: "metrics", icon: BarChart3 },
] as const;
const secondaryNav = [
    { id: "investigate", icon: Search },
    { id: "history", icon: Clock3 },
    { id: "topics", icon: Files },
    { id: "status", icon: Activity },
] as const;
export type Route = (typeof nav)[number]["id"] | (typeof secondaryNav)[number]["id"];
export function routeFromHash(): Route | null {
    const hash = location.hash.replace(/^#\/?/, "");
    if (!hash) return "overview";
    if (hash.startsWith("topic-")) return "investigate";
    return [...nav, ...secondaryNav].find((item) => item.id === hash)?.id ?? null;
}
type Translate = (key: string) => string;

export function NavigationRail({
    route,
    setRoute,
    t,
}: {
    route: Route;
    setRoute: (route: Route) => void;
    t: Translate;
}) {
    return (
        <>
            <a className="skip-link" href="#main">
                {t("skipLink")}
            </a>
            <aside className="rail">
                <div className="brand">
                    <span className="brand-mark">
                        <Shield size={16} />
                    </span>
                    <span>AI SOC</span>
                </div>
                <div className="rail-caption">{t("workspaceCaption")}</div>
                <nav aria-label={t("mainNavigation")}>
                    {nav.map((item) => (
                        <a
                            key={item.id}
                            href={`#${item.id}`}
                            aria-current={route === item.id ? "page" : undefined}
                            onClick={() => setRoute(item.id)}
                        >
                            <item.icon size={17} />
                            {t(item.id)}
                        </a>
                    ))}
                </nav>
                <div className="rail-caption secondary-caption">{t("secondaryTools")}</div>
                <nav aria-label={t("secondaryTools")}>
                    {secondaryNav.map((item) => (
                        <a
                            key={item.id}
                            href={`#${item.id}`}
                            aria-current={route === item.id ? "page" : undefined}
                            onClick={() => setRoute(item.id)}
                        >
                            <item.icon size={17} />
                            {t(item.id)}
                        </a>
                    ))}
                </nav>
                <div className="rail-bottom">
                    <StatusPill tone="neutral">{t("readOnly")}</StatusPill>
                </div>
            </aside>
        </>
    );
}

export function ContextHeader({
    route,
    locale,
    setLocale,
    bootstrap,
    sites,
    selectedSite,
    setSelectedSite,
    timeRange,
    setTimeRange,
    modeState,
    isMock,
    scenario,
    setScenario,
    t,
}: {
    route: Route;
    locale: Locale;
    setLocale: (locale: Locale) => void;
    bootstrap: BootstrapResponse | undefined;
    sites: { site_id: string; label: string }[];
    modeState: "loading" | "unavailable" | null;
    selectedSite: string;
    setSelectedSite: (site: string) => void;
    timeRange: "24h" | "7d" | "30d";
    setTimeRange: (range: "24h" | "7d" | "30d") => void;
    isMock: boolean;
    scenario: string;
    setScenario: (scenario: string) => void;
    t: Translate;
}) {
    return (
        <header className="topbar">
            <div className="top-title">
                <span>AI SOC / {t(route)}</span>
                <h1>{t(route)}</h1>
            </div>
            <div className="top-controls">
                <label>
                    {t("site")}
                    <select
                        aria-label={t("site")}
                        value={selectedSite}
                        onChange={(event) => setSelectedSite(event.target.value)}
                    >
                        {sites.length > 0
                            ? sites.map((site) => (
                                  <option key={site.site_id} value={site.site_id}>
                                      {site.label}
                                  </option>
                              ))
                            : (bootstrap?.sites ?? []).map((site) => (
                                  <option key={site.id} value={site.id}>
                                      {site.label}
                                  </option>
                              ))}
                    </select>
                </label>
                <label>
                    {t("range")}
                    <select
                        aria-label={t("range")}
                        value={timeRange}
                        onChange={(event) => {
                            const value = event.target.value;
                            if (value === "24h" || value === "7d" || value === "30d")
                                setTimeRange(value);
                        }}
                    >
                        <option value="24h">{t("last24h")}</option>
                        <option value="7d">{t("last7d")}</option>
                        <option value="30d">{t("last30d")}</option>
                    </select>
                </label>
                <label className="language-control">
                    <span className="sr-only">{t("language")}</span>
                    <select
                        value={locale}
                        onChange={(event) => setLocale(event.target.value as Locale)}
                        aria-label={t("language")}
                    >
                        <option value="en">EN</option>
                        <option value="es">ES</option>
                    </select>
                </label>
                <StatusPill tone="neutral">
                    {bootstrap
                        ? bootstrap.mode === "live"
                            ? t("live")
                            : t(isMock ? "mode" : "localQualification")
                        : t(modeState === "loading" ? "modeLoading" : "modeUnavailable")}
                </StatusPill>
                {isMock && (
                    <>
                        <StatusPill tone="warning">{t("synthetic")}</StatusPill>
                        <label>
                            {t("scenario")}
                            <select
                                aria-label={t("scenario")}
                                value={scenario}
                                onChange={(event) => setScenario(event.target.value)}
                            >
                                {[
                                    "auto",
                                    "answered",
                                    "partial",
                                    "clarify",
                                    "clarify_model",
                                    "refused",
                                    "filtered",
                                    "paged",
                                    "page_unavailable",
                                    "audit_unavailable",
                                    "bootstrap_unavailable",
                                    "feedback_unavailable",
                                    "busy",
                                    "kev",
                                    "workspace_quiet",
                                    "workspace_stalled",
                                    "workspace_error",
                                    "workspace_denied",
                                ].map((item) => (
                                    <option key={item} value={item}>
                                        {item === "auto" ? t("autoScenario") : item}
                                    </option>
                                ))}
                            </select>
                        </label>
                    </>
                )}
            </div>
            <nav className="mobile-nav" aria-label={t("mainNavigation")}>
                {nav.map((item) => (
                    <a
                        key={item.id}
                        href={`#${item.id}`}
                        aria-current={route === item.id ? "page" : undefined}
                    >
                        <item.icon size={16} />
                        {t(item.id)}
                    </a>
                ))}
            </nav>
            <nav className="mobile-nav secondary-mobile-nav" aria-label={t("secondaryTools")}>
                {secondaryNav.map((item) => (
                    <a
                        key={item.id}
                        href={`#${item.id}`}
                        aria-current={route === item.id ? "page" : undefined}
                    >
                        <item.icon size={16} />
                        {t(item.id)}
                    </a>
                ))}
            </nav>
        </header>
    );
}
