import { mkdtempSync, rmSync } from "node:fs";

const browserTemp = mkdtempSync("/tmp/ai-soc-playwright-");
process.env.TMPDIR = browserTemp;
process.once("exit", () => rmSync(browserTemp, { force: true, recursive: true }));
