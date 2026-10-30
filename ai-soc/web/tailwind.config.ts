import type { Config } from "tailwindcss";

export default {
    content: ["./index.html", "./src/**/*.{ts,tsx}"],
    theme: {
        extend: {
            colors: {
                canvas: "var(--bg)",
                surface: "var(--surface)",
                ink: "var(--text)",
                muted: "var(--text-muted)",
                accent: "var(--accent)",
            },
            borderRadius: { control: "var(--radius-control)", panel: "var(--radius-card)" },
            fontFamily: {
                sans: ["var(--font-ui)"],
                display: ["var(--font-display)"],
                mono: ["var(--font-code)"],
            },
            boxShadow: { panel: "var(--shadow-panel)", float: "var(--shadow-float)" },
        },
    },
    plugins: [],
} satisfies Config;
