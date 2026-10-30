import { resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { defineConfig } from "@playwright/test";
import "./browser-environment";

process.env.PLAYWRIGHT_BROWSERS_PATH = resolve(
    fileURLToPath(new URL("../../build/tool-cache/playwright", import.meta.url)),
);

const port = 5184;

export default defineConfig({
    testDir: "./browser",
    testMatch: ["routes.check.ts", "theme.check.ts", "investigate.check.ts"],
    fullyParallel: false,
    reporter: "list",
    use: {
        baseURL: `http://localhost:${port}`,
        browserName: "chromium",
        headless: true,
        screenshot: "only-on-failure",
    },
    webServer: {
        command: `npm run dev:verify -- --port ${port} --strictPort`,
        url: `http://localhost:${port}`,
        reuseExistingServer: false,
        timeout: 30_000,
    },
});
