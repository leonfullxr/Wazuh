import { resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { defineConfig } from "@playwright/test";
import "./browser-environment";

process.env.PLAYWRIGHT_BROWSERS_PATH = resolve(
    fileURLToPath(new URL("../../build/tool-cache/playwright", import.meta.url)),
);

const port = Number(process.env.WEB_PORT ?? 5184);

export default defineConfig({
    testDir: "./browser",
    testMatch: ["routes.check.ts", "theme.check.ts", "investigate.check.ts", "m3.check.ts"],
    fullyParallel: false,
    reporter: "list",
    use: {
        baseURL: `http://localhost:${port}`,
        browserName: "chromium",
        headless: true,
        screenshot: "only-on-failure",
    },
    webServer: {
        command: `npm run build:verify && npm run preview:verify -- --port ${port} --strictPort`,
        url: `http://localhost:${port}`,
        reuseExistingServer: false,
        timeout: 120_000,
    },
});
