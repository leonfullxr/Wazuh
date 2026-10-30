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
    Menu,
    Search,
    Shield,
} from "lucide-react";
import type { LucideIcon } from "lucide-react";
import type { BootstrapResponse } from "../../../contracts/v1/generated/types.ts";
import type { Locale } from "../i18n";
import { StatusPill } from "../components/ui/status-pill";
import { Sheet, SheetClose, SheetContent, SheetTrigger } from "../components/ui/sheet";
import { ThemeMenu } from "../components/theme/theme-menu";
import { CommandPalette } from "./CommandPalette";
import { CustomRange } from "./CustomRange";
import type { AlertDrilldown } from "../features/overview/OverviewPage";

export const nav = [
    { id: "overview", icon: LayoutDashboard },
    { id: "alerts", icon: Bell },
    { id: "queue", icon: ListTodo },
    { id: "chains", icon: GitBranch },
    { id: "incidents", icon: BriefcaseBusiness },
] as const;
export const dashboardNav = [
    { id: "ai_quality", icon: BarChart3 },
    { id: "soc_operations", icon: BriefcaseBusiness },
    { id: "metrics", icon: BarChart3 },
] as const;
const secondaryNav = [
    { id: "investigate", icon: Search },
    { id: "history", icon: Clock3 },
    { id: "topics", icon: Files },
    { id: "status", icon: Activity },
] as const;
export type Route =
    | (typeof nav)[number]["id"]
    | (typeof dashboardNav)[number]["id"]
    | (typeof secondaryNav)[number]["id"];
const commandRoutes: readonly Route[] = [...nav, ...dashboardNav, ...secondaryNav].map(
    (item) => item.id,
);
export function routeFromHash(): Route | null {
    const hash = location.hash.replace(/^#\/?/, "");
    if (!hash) return "overview";
    if (hash.startsWith("topic-")) return "investigate";
    return [...nav, ...dashboardNav, ...secondaryNav].find((item) => item.id === hash)?.id ?? null;
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
                    <span>Wazuh AI SOC</span>
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
                <div className="rail-caption secondary-caption">{t("dashboards")}</div>
                <nav aria-label={t("dashboards")}>
                    {dashboardNav.map((item) => (
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
    customRange,
    windowFrom,
    windowTo,
    onCustomRange,
    modeState,
    isMock,
    scenario,
    setScenario,
    onNavigate,
    onSearch,
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
    customRange: boolean;
    windowFrom: string;
    windowTo: string;
    onCustomRange: (range: { from: string; to: string }) => void;
    isMock: boolean;
    scenario: string;
    setScenario: (scenario: string) => void;
    onNavigate: (route: Route) => void;
    onSearch: (filters: AlertDrilldown) => void;
    t: Translate;
}) {
    return (
        <header className="topbar">
            <Sheet>
                <SheetTrigger asChild>
                    <button
                        type="button"
                        className="mobile-menu-trigger"
                        aria-label={locale === "es" ? "Abrir navegación" : "Open navigation"}
                    >
                        <Menu size={18} aria-hidden="true" />
                    </button>
                </SheetTrigger>
                <SheetContent
                    title={locale === "es" ? "Navegación" : "Navigation"}
                    closeLabel={locale === "es" ? "Cerrar navegación" : "Close navigation"}
                >
                    <nav className="mobile-rail" aria-label={t("mainNavigation")}>
                        <MobileNavGroup
                            label={t("mainNavigation")}
                            items={nav}
                            route={route}
                            t={t}
                        />
                        <MobileNavGroup
                            label={t("dashboards")}
                            items={dashboardNav}
                            route={route}
                            t={t}
                        />
                        <MobileNavGroup
                            label={t("secondaryTools")}
                            items={secondaryNav}
                            route={route}
                            t={t}
                        />
                    </nav>
                </SheetContent>
            </Sheet>
            <div className="top-title">
                <span>AI SOC / {t(route)}</span>
                <h1>{t(route)}</h1>
            </div>
            <div className="top-controls">
                <CommandPalette
                    locale={locale}
                    routes={commandRoutes}
                    t={t}
                    onNavigate={onNavigate}
                    onSearch={onSearch}
                />
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
                <div className="range-segment" role="group" aria-label={t("range")}>
                    {(["24h", "7d", "30d"] as const).map((range) => (
                        <button
                            key={range}
                            type="button"
                            aria-pressed={!customRange && timeRange === range}
                            onClick={() => setTimeRange(range)}
                        >
                            {range}
                        </button>
                    ))}
                </div>
                <CustomRange
                    from={windowFrom}
                    to={windowTo}
                    locale={locale}
                    active={customRange}
                    onApply={onCustomRange}
                />
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
                <ThemeMenu locale={locale} />
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
        </header>
    );
}

function MobileNavGroup({
    label,
    items,
    route,
    t,
}: {
    label: string;
    items: ReadonlyArray<{ id: Route; icon: LucideIcon }>;
    route: Route;
    t: Translate;
}) {
    return (
        <div className="mobile-rail-section" aria-label={label} role="group">
            <span className="mobile-rail-label">{label}</span>
            {items.map((item) => (
                <SheetClose asChild key={item.id}>
                    <a href={`#${item.id}`} aria-current={route === item.id ? "page" : undefined}>
                        <item.icon size={16} aria-hidden="true" />
                        {t(item.id)}
                    </a>
                </SheetClose>
            ))}
        </div>
    );
}
