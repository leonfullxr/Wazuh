import { useEffect, useMemo, useRef, useState } from "react";
import type { Locale } from "../i18n";
import type { AlertDrilldown } from "../features/overview/OverviewPage";
import type { Route } from "./Navigation";
import "./command-palette.css";

type CommandAction =
    | { kind: "navigate"; id: Route; label: string; route: Route }
    | { kind: "search"; id: string; label: string; filters: AlertDrilldown };

export function CommandPalette({
    locale,
    routes,
    t,
    onNavigate,
    onSearch,
}: {
    locale: Locale;
    routes: readonly Route[];
    t: (key: string) => string;
    onNavigate: (route: Route) => void;
    onSearch: (filters: AlertDrilldown) => void;
}) {
    const [open, setOpen] = useState(false);
    const [query, setQuery] = useState("");
    const [activeIndex, setActiveIndex] = useState(0);
    const triggerRef = useRef<HTMLButtonElement>(null);
    const dialogRef = useRef<HTMLDialogElement>(null);
    const inputRef = useRef<HTMLInputElement>(null);
    const invokingElementRef = useRef<HTMLElement | null>(null);
    useEffect(() => {
        function keydown(event: KeyboardEvent) {
            if ((event.metaKey || event.ctrlKey) && event.key.toLowerCase() === "k") {
                event.preventDefault();
                if (
                    !open &&
                    document.activeElement instanceof HTMLElement &&
                    document.activeElement !== document.body
                ) {
                    invokingElementRef.current = document.activeElement;
                }
                setOpen(true);
            }
        }
        window.addEventListener("keydown", keydown);
        return () => window.removeEventListener("keydown", keydown);
    }, [open]);
    useEffect(() => {
        const dialog = dialogRef.current;
        if (!dialog) return;
        if (open && !dialog.open) {
            dialog.showModal();
            inputRef.current?.focus();
        } else if (!open && dialog.open) {
            dialog.close();
            const target = invokingElementRef.current;
            invokingElementRef.current = null;
            if (target?.isConnected) target.focus();
            else triggerRef.current?.focus();
        }
    }, [open]);
    const value = query.trim();
    const matches = routes.filter((route) =>
        t(route).toLocaleLowerCase().includes(value.toLocaleLowerCase()),
    );
    const spanish = locale === "es";
    const actions = useMemo<CommandAction[]>(() => {
        const navigation: CommandAction[] = matches.map((route) => ({
            kind: "navigate",
            id: route,
            label: t(route),
            route,
        }));
        if (!value) return navigation;
        const searchLabel = spanish ? "Buscar" : "Search";
        return [
            ...navigation,
            {
                kind: "search",
                id: "rule",
                label: `${searchLabel} ${spanish ? "Regla" : "Rule"}: ${value}`,
                filters: { rule_id: value },
            },
            {
                kind: "search",
                id: "agent",
                label: `${searchLabel} ${spanish ? "Agente" : "Agent"}: ${value}`,
                filters: { agent_id: value },
            },
            {
                kind: "search",
                id: "ip",
                label: `${searchLabel} IP: ${value}`,
                filters: { entity_kind: "ip", entity: value },
            },
            {
                kind: "search",
                id: "user",
                label: `${searchLabel} ${spanish ? "Usuario" : "User"}: ${value}`,
                filters: { entity_kind: "user", entity: value },
            },
        ];
    }, [matches, spanish, t, value]);
    const selectedIndex = actions.length === 0 ? -1 : Math.min(activeIndex, actions.length - 1);
    useEffect(() => setActiveIndex(0), [query, locale]);
    useEffect(() => {
        if (open && selectedIndex >= 0) {
            document
                .getElementById(`command-option-${selectedIndex}`)
                ?.scrollIntoView({ block: "nearest" });
        }
    }, [open, selectedIndex]);
    function close() {
        setOpen(false);
        setQuery("");
        setActiveIndex(0);
    }
    function run(action: CommandAction) {
        close();
        if (action.kind === "navigate") onNavigate(action.route);
        else onSearch(action.filters);
    }
    return (
        <>
            <button
                ref={triggerRef}
                className="command-trigger"
                type="button"
                aria-keyshortcuts="Control+K Meta+K"
                aria-label={spanish ? "Abrir búsqueda y navegación" : "Open search and navigation"}
                onClick={(event) => {
                    invokingElementRef.current = event.currentTarget;
                    setOpen(true);
                }}
            >
                Ctrl/⌘K
            </button>
            <dialog
                ref={dialogRef}
                className="command-dialog"
                aria-labelledby="command-title"
                onCancel={(event) => {
                    event.preventDefault();
                    close();
                }}
                onClick={(event) => {
                    if (event.target === event.currentTarget) close();
                }}
            >
                <h2 id="command-title">{spanish ? "Ir a o buscar" : "Navigate or search"}</h2>
                <input
                    ref={inputRef}
                    value={query}
                    onChange={(event) => setQuery(event.target.value)}
                    onKeyDown={(event) => {
                        if (actions.length === 0) return;
                        if (event.key === "ArrowDown") {
                            event.preventDefault();
                            setActiveIndex((index) => (index + 1) % actions.length);
                        } else if (event.key === "ArrowUp") {
                            event.preventDefault();
                            setActiveIndex(
                                (index) => (index - 1 + actions.length) % actions.length,
                            );
                        } else if (event.key === "Enter") {
                            const action = actions[selectedIndex];
                            if (!action) return;
                            event.preventDefault();
                            run(action);
                        }
                    }}
                    role="combobox"
                    aria-autocomplete="list"
                    aria-controls="command-results"
                    aria-expanded={open}
                    aria-activedescendant={
                        selectedIndex >= 0 ? `command-option-${selectedIndex}` : undefined
                    }
                    aria-label={spanish ? "Buscar" : "Search"}
                    placeholder={
                        spanish
                            ? "Buscar vistas, reglas, IP, usuarios o agentes"
                            : "Search views, rules, IPs, users or agents"
                    }
                />
                <div id="command-results" className="command-results" role="listbox">
                    {actions.map((action, index) => (
                        <button
                            id={`command-option-${index}`}
                            key={`${action.kind}-${action.id}`}
                            type="button"
                            role="option"
                            tabIndex={-1}
                            aria-selected={selectedIndex === index}
                            onMouseMove={() => setActiveIndex(index)}
                            onFocus={() => setActiveIndex(index)}
                            onClick={() => run(action)}
                        >
                            {action.kind === "search" ? (
                                <>
                                    {action.label.slice(0, -value.length)}
                                    <code>{value}</code>
                                </>
                            ) : (
                                action.label
                            )}
                        </button>
                    ))}
                </div>
                <button
                    type="button"
                    className="command-close"
                    aria-label={spanish ? "Cerrar" : "Close"}
                    onClick={close}
                >
                    ×
                </button>
            </dialog>
        </>
    );
}
