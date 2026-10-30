export type Locale = "en" | "es";
const en = {
    appName: "AI SOC",
    investigate: "Investigate",
    history: "History",
    topics: "Topics",
    status: "Status",
    workspace: "Analyst workspace",
    investigateTitle: "Investigate",
    investigateDescription: "Ask a question about your security data.",
    historyTitle: "History",
    topicsTitle: "Topics",
    statusTitle: "Status",
    placeholder: "This screen will be added in a later brief.",
    language: "Language",
    english: "English",
    spanish: "Spanish",
    mockLabel: "Synthetic mock data",
    scenario: "Scenario",
    menu: "Main navigation",
    workspaceLabel: "Workspace",
    details: "Details",
    actions: "Actions",
    noActions: "No actions available yet.",
    readOnly: "Read only",
    connectionUnavailable: "Connection unavailable",
};
export const dictionaries = {
    en,
    es: {
        appName: "AI SOC",
        investigate: "Investigar",
        history: "Historial",
        topics: "Temas",
        status: "Estado",
        workspace: "Espacio de análisis",
        investigateTitle: "Investigar",
        investigateDescription: "Haz una pregunta sobre tus datos de seguridad.",
        historyTitle: "Historial",
        topicsTitle: "Temas",
        statusTitle: "Estado",
        placeholder: "Esta pantalla se añadirá en una próxima etapa.",
        language: "Idioma",
        english: "Inglés",
        spanish: "Español",
        mockLabel: "Datos sintéticos de prueba",
        scenario: "Escenario",
        menu: "Navegación principal",
        workspaceLabel: "Espacio de trabajo",
        details: "Detalles",
        actions: "Acciones",
        noActions: "Aún no hay acciones disponibles.",
        readOnly: "Solo lectura",
        connectionUnavailable: "Conexión no disponible",
    },
} satisfies Record<Locale, typeof en>;
export type TranslationKey = keyof typeof en;
export function translate(locale: Locale, key: TranslationKey): string {
    return dictionaries[locale][key];
}
export function initialLocale(defaultLocale?: string): Locale {
    try {
        const saved = localStorage.getItem("ai-soc-language");
        if (saved === "en" || saved === "es") return saved;
    } catch {
        /* Storage can be disabled. */
    }
    if (defaultLocale === "es" || defaultLocale === "en") return defaultLocale;
    return navigator.language.toLowerCase().startsWith("es") ? "es" : "en";
}
export function saveLocale(locale: Locale): void {
    try {
        localStorage.setItem("ai-soc-language", locale);
    } catch {
        /* Keep the selection for this session. */
    }
}
