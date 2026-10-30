import { fileURLToPath, URL } from "node:url";
import react from "@vitejs/plugin-react";
import tailwindcss from "@tailwindcss/vite";
import { defineConfig } from "vite";

export default defineConfig({
    resolve: { alias: { "@": fileURLToPath(new URL("../src", import.meta.url)) } },
    plugins: [
        react(),
        tailwindcss(),
        {
            name: "verification-entry",
            transformIndexHtml: {
                order: "pre",
                handler(html) {
                    return html.replace("/src/main.tsx", "/verification/mock-entry.tsx");
                },
            },
        },
    ],
    publicDir: fileURLToPath(new URL("./public", import.meta.url)),
    build: { assetsInlineLimit: 0 },
    preview: {
        host: "localhost",
        headers: {
            "Content-Security-Policy":
                "default-src 'self'; script-src 'self'; style-src 'self'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'",
        },
    },
});
