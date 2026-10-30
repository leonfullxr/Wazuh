import { createContext, useContext, useEffect, useState, type ReactNode } from "react";

const themeModes = ["system", "light", "dark"] as const;
export type ThemeMode = (typeof themeModes)[number];

const storageKey = "ai-soc-theme";
const darkQuery = "(prefers-color-scheme: dark)";

function isThemeMode(value: string | null): value is ThemeMode {
    return themeModes.some((mode) => mode === value);
}

function storedTheme(): ThemeMode {
    try {
        const value = localStorage.getItem(storageKey);
        return isThemeMode(value) ? value : "system";
    } catch {
        return "system";
    }
}

function resolvedTheme(mode: ThemeMode): "light" | "dark" {
    if (mode !== "system") return mode;
    return typeof window.matchMedia === "function" && window.matchMedia(darkQuery).matches
        ? "dark"
        : "light";
}

function applyTheme(mode: ThemeMode) {
    const resolved = resolvedTheme(mode);
    document.documentElement.classList.toggle("dark", resolved === "dark");
    document.documentElement.dataset.theme = mode;
}

export function applyInitialTheme() {
    applyTheme(storedTheme());
}

type ThemeContextValue = {
    mode: ThemeMode;
    setMode: (mode: ThemeMode) => void;
};

const ThemeContext = createContext<ThemeContextValue | null>(null);

export function ThemeProvider({ children }: { children: ReactNode }) {
    const [mode, setMode] = useState<ThemeMode>(storedTheme);

    useEffect(() => {
        applyTheme(mode);
        try {
            localStorage.setItem(storageKey, mode);
        } catch {
            // Storage can be unavailable in restricted browser contexts.
        }

        if (mode !== "system" || typeof window.matchMedia !== "function") return;
        const media = window.matchMedia(darkQuery);
        const onChange = () => applyTheme("system");
        media.addEventListener("change", onChange);
        return () => media.removeEventListener("change", onChange);
    }, [mode]);

    return <ThemeContext value={{ mode, setMode }}>{children}</ThemeContext>;
}

function useTheme() {
    const value = useContext(ThemeContext);
    if (!value) throw new Error("ThemeMenu must be rendered inside ThemeProvider");
    return value;
}

export function ThemeMenu({ locale }: { locale: "en" | "es" }) {
    const { mode, setMode } = useTheme();
    const names =
        locale === "es"
            ? { system: "Sistema", light: "Claro", dark: "Oscuro" }
            : { system: "System", light: "Light", dark: "Dark" };
    return (
        <fieldset className="theme-menu">
            <legend className="sr-only">{locale === "es" ? "Apariencia" : "Appearance"}</legend>
            {themeModes.map((item) => (
                <button
                    key={item}
                    type="button"
                    aria-pressed={mode === item}
                    aria-label={names[item]}
                    onClick={() => setMode(item)}
                >
                    {names[item][0]}
                </button>
            ))}
        </fieldset>
    );
}
