import { execFileSync } from "node:child_process";
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const webRoot = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const root = resolve(webRoot, "..");
const input = resolve(root, "contracts/workspace/v1/openapi.json");
const output = resolve(root, "contracts/workspace/v1/types.ts");
const cli = resolve(webRoot, "node_modules/openapi-typescript/bin/cli.js");
const check = process.argv.includes("--check");
const tempDir = mkdtempSync(resolve(tmpdir(), "workspace-types-"));
const generatedPath = check ? resolve(tempDir, "types.ts") : output;

try {
    execFileSync(process.execPath, [cli, input, "--output", generatedPath], {
        cwd: webRoot,
        stdio: "inherit",
    });
    if (check) {
        let current = "";
        try {
            current = readFileSync(output, "utf8");
        } catch {
            // A missing artifact is reported as stale below.
        }
        if (current !== readFileSync(generatedPath, "utf8")) {
            console.error("Generated workspace types are stale. Run npm run workspace-types:generate.");
            process.exitCode = 1;
        }
    }
} finally {
    rmSync(tempDir, { recursive: true, force: true });
}
