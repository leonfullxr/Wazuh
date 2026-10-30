import { resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { defineConfig } from "@playwright/test";
import "./browser-environment";

process.env.PLAYWRIGHT_BROWSERS_PATH = resolve(
    fileURLToPath(new URL("../../build/tool-cache/playwright", import.meta.url)),
);

const port = 5186;

export default defineConfig({
    testDir: "./browser",
    testMatch: "csp.check.ts",
    reporter: "list",
    use: { baseURL: `http://localhost:${port}`, browserName: "chromium", headless: true },
    webServer: {
        command: `npm run build:verify && npm run preview:verify -- --port ${port} --strictPort`,
        url: `http://localhost:${port}`,
        reuseExistingServer: false,
        timeout: 120_000,
    },
});
