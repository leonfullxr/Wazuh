import { defineConfig } from "../../ui/node_modules/@playwright/test/index.mjs";
import { resolve } from "node:path";
import { fileURLToPath } from "node:url";

const repository = resolve(fileURLToPath(new URL("../..", import.meta.url)));

export default defineConfig({
  testDir: ".",
  testMatch: "real_routes.spec.ts",
  fullyParallel: false,
  retries: 0,
  reporter: [["junit"]],
  use: {
    baseURL: "http://127.0.0.1:8765",
    browserName: "chromium",
    extraHTTPHeaders: { "X-SOC-Fixture-Token": "fixture-browser-token" },
    trace: "retain-on-failure",
  },
  webServer: {
    command:
      `cd ${repository} && uv run --locked --offline uvicorn fixture_server:app --app-dir tests/e2e --host 127.0.0.1 --port 8765`,
    url: "http://127.0.0.1:8765/health/live",
    reuseExistingServer: false,
    timeout: 30_000,
  },
});
