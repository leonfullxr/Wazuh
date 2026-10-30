import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
import tailwindcss from "@tailwindcss/vite";

export default defineConfig({
    plugins: [
        react(),
        tailwindcss(),
        {
            name: "exclude-production-mocks",
            generateBundle(_options, bundle) {
                for (const artifact of Object.values(bundle)) {
                    if (artifact.fileName.endsWith("mockServiceWorker.js")) {
                        this.error("Mock service worker found in the production bundle");
                    }
                    if (artifact.type !== "chunk") continue;
                    for (const moduleId of artifact.moduleIds) {
                        if (
                            moduleId.includes("/src/mocks/") ||
                            moduleId.endsWith("/src/main-mock.tsx")
                        ) {
                            this.error(`Mock module found in the production bundle: ${moduleId}`);
                        }
                    }
                }
            },
        },
    ],
    publicDir: false,
    server: { host: "localhost", port: 5184, strictPort: true },
    preview: {
        host: "localhost",
        headers: {
            "Content-Security-Policy":
                "default-src 'self'; script-src 'self'; style-src 'self'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'",
        },
    },
    build: { assetsInlineLimit: 0 },
});
