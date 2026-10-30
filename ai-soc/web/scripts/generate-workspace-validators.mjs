import { readFileSync, writeFileSync } from "node:fs";
import { resolve } from "node:path";
import Ajv2020 from "ajv/dist/2020.js";
import addFormats from "ajv-formats";
import standaloneCode from "ajv/dist/standalone/index.js";
import prettier from "prettier";

const root = process.cwd();
const specPath = resolve(root, "../contracts/workspace/v1/openapi.json");
const spec = JSON.parse(readFileSync(specPath, "utf8"));
const bundleId = "https://ai-soc.invalid/contracts/workspace/v1/openapi.json";
const rewrite = (value) => {
    if (Array.isArray(value)) return value.map(rewrite);
    if (value === null || typeof value !== "object") return value;
    const result = {};
    for (const [key, child] of Object.entries(value)) {
        if (key === "$id" || key === "discriminator") continue;
        result[key] =
            key === "$ref" && typeof child === "string"
                ? child.replace("#/components/schemas/", "#/$defs/")
                : rewrite(child);
    }
    return result;
};
const bundle = {
    $schema: "https://json-schema.org/draft/2020-12/schema",
    $id: bundleId,
    $defs: Object.fromEntries(
        Object.entries(spec.components.schemas).map(([name, schema]) => [name, rewrite(schema)]),
    ),
};
const validators = {
    validateNarrativeReadResponse: `${bundleId}#/$defs/NarrativeReadResponse`,
    validateChainPage: `${bundleId}#/$defs/ChainPage`,
    validateChainCandidateDetail: `${bundleId}#/$defs/ChainCandidateDetail`,
    validateChainDismissResponse: `${bundleId}#/$defs/ChainDismissResponse`,
    validateIncidentPage: `${bundleId}#/$defs/IncidentPage`,
    validateIncidentActionResponse: `${bundleId}#/$defs/IncidentActionResponse`,
    validateIncidentDetailResponse: `${bundleId}#/$defs/IncidentDetailResponse`,
    validateIncidentEventsResponse: `${bundleId}#/$defs/IncidentEventsResponse`,
    validateIncidentContextResponse: `${bundleId}#/$defs/IncidentContextResponse`,
    validateIncidentCommentDTO: `${bundleId}#/$defs/IncidentCommentDTO`,
    validateIncidentDispositionDTO: `${bundleId}#/$defs/IncidentDispositionDTO`,

    validateAlertDetail: `${bundleId}#/$defs/AlertDetail`,
    validateAlertContext: `${bundleId}#/$defs/GroupContextResponse`,
    validateAlertPage: `${bundleId}#/$defs/Page_AlertSummary_`,
    validateWorkspaceError: `${bundleId}#/$defs/ErrorResponse`,
    validateIngestionHealth: `${bundleId}#/$defs/IngestionHealthResponse`,
    validateOverview: `${bundleId}#/$defs/OverviewResponse`,
    validateSitePage: `${bundleId}#/$defs/Page_SiteSummary_`,
    validateQueuePage: `${bundleId}#/$defs/Page_QueueSummary_`,
    validateGroupDetail: `${bundleId}#/$defs/GroupDetail`,
    validateWorkState: `${bundleId}#/$defs/WorkState`,
    validateDisposition: `${bundleId}#/$defs/Disposition`,
    validateBulkActionResponse: `${bundleId}#/$defs/BulkActionResponse`,
    validateAssetPage: `${bundleId}#/$defs/Page_AssetTag_`,
    validateAssetTag: `${bundleId}#/$defs/AssetTag`,
    validateOpsMetrics: `${bundleId}#/$defs/OpsMetricsResponse`,
    validateQualityMetrics: `${bundleId}#/$defs/QualityMetricsResponse`,
    validateAssignRequest: `${bundleId}#/$defs/AssignRequest`,
    validateStatusRequest: `${bundleId}#/$defs/StatusRequest`,
    validateDispositionRequest: `${bundleId}#/$defs/DispositionRequest`,
    validateBulkActionRequest: `${bundleId}#/$defs/BulkActionRequest`,
    validateAssetUpsertRequest: `${bundleId}#/$defs/AssetTagUpsertRequest`,
};
const ajv = new Ajv2020({
    strict: true,
    discriminator: true,
    allErrors: true,
    code: { source: true, esm: true },
});
addFormats(ajv);
ajv.addSchema(bundle);
const generated = standaloneCode(ajv, validators)
    .replaceAll('require("ajv-formats/dist/formats").fullFormats', "fullFormats")
    .replaceAll('require("ajv/dist/runtime/ucs2length").default', "codePointLength")
    .replace(
        '"use strict";',
        '"use strict";\nimport { fullFormats } from "ajv-formats/dist/formats.js";\nconst codePointLength = (value) => Array.from(value).length;',
    );
const jsPath = resolve(root, "src/api/generated/workspace-validators.js");
const dtsPath = resolve(root, "src/api/generated/workspace-validators.d.ts");
const prettierConfig = await prettier.resolveConfig(jsPath);
const formatted = await prettier.format(`${generated}\n`, { ...prettierConfig, filepath: jsPath });
const declarations = [
    'export function validateNarrativeReadResponse(data: unknown): data is components["schemas"]["NarrativeReadResponse"] ;',
    'export function validateChainPage(data: unknown): data is components["schemas"]["ChainPage"] ;',
    'export function validateChainCandidateDetail(data: unknown): data is components["schemas"]["ChainCandidateDetail"] ;',
    'export function validateChainDismissResponse(data: unknown): data is components["schemas"]["ChainDismissResponse"] ;',
    'export function validateIncidentPage(data: unknown): data is components["schemas"]["IncidentPage"] ;',
    'export function validateIncidentActionResponse(data: unknown): data is components["schemas"]["IncidentActionResponse"] ;',
    'export function validateIncidentDetailResponse(data: unknown): data is components["schemas"]["IncidentDetailResponse"] ;',
    'export function validateIncidentEventsResponse(data: unknown): data is components["schemas"]["IncidentEventsResponse"] ;',
    'export function validateIncidentContextResponse(data: unknown): data is components["schemas"]["IncidentContextResponse"] ;',
    'export function validateIncidentCommentDTO(data: unknown): data is components["schemas"]["IncidentCommentDTO"] ;',
    'export function validateIncidentDispositionDTO(data: unknown): data is components["schemas"]["IncidentDispositionDTO"] ;',

    'import type { components } from "../../../contracts/workspace/v1/types.ts";',
    'export function validateAlertDetail(data: unknown): data is components["schemas"]["AlertDetail"] ;',
    'export function validateAlertContext(data: unknown): data is components["schemas"]["GroupContextResponse"] ;',
    'export function validateAlertPage(data: unknown): data is components["schemas"]["Page_AlertSummary_"] ;',
    'export function validateWorkspaceError(data: unknown): data is components["schemas"]["ErrorResponse"] ;',
    'export function validateIngestionHealth(data: unknown): data is components["schemas"]["IngestionHealthResponse"] ;',
    'export function validateOverview(data: unknown): data is components["schemas"]["OverviewResponse"] ;',
    'export function validateSitePage(data: unknown): data is components["schemas"]["Page_SiteSummary_"] ;',
    'export function validateQueuePage(data: unknown): data is components["schemas"]["Page_QueueSummary_"] ;',
    'export function validateGroupDetail(data: unknown): data is components["schemas"]["GroupDetail"] ;',
    'export function validateWorkState(data: unknown): data is components["schemas"]["WorkState"] ;',
    'export function validateDisposition(data: unknown): data is components["schemas"]["Disposition"] ;',
    'export function validateBulkActionResponse(data: unknown): data is components["schemas"]["BulkActionResponse"] ;',
    'export function validateAssetPage(data: unknown): data is components["schemas"]["Page_AssetTag_"] ;',
    'export function validateAssetTag(data: unknown): data is components["schemas"]["AssetTag"] ;',
    'export function validateOpsMetrics(data: unknown): data is components["schemas"]["OpsMetricsResponse"] ;',
    'export function validateQualityMetrics(data: unknown): data is components["schemas"]["QualityMetricsResponse"] ;',
    'export function validateAssignRequest(data: unknown): data is components["schemas"]["AssignRequest"] ;',
    'export function validateStatusRequest(data: unknown): data is components["schemas"]["StatusRequest"] ;',
    'export function validateDispositionRequest(data: unknown): data is components["schemas"]["DispositionRequest"] ;',
    'export function validateBulkActionRequest(data: unknown): data is components["schemas"]["BulkActionRequest"] ;',
    'export function validateAssetUpsertRequest(data: unknown): data is components["schemas"]["AssetTagUpsertRequest"] ;',
].join("\n");
const formattedDeclarations = await prettier.format(`${declarations}\n`, {
    ...prettierConfig,
    filepath: dtsPath,
});
if (process.argv.includes("--check")) {
    const currentJs = readFileSync(jsPath, "utf8");
    const currentDts = readFileSync(dtsPath, "utf8");
    if (currentJs !== formatted || currentDts !== formattedDeclarations) {
        console.error(
            "Generated workspace validators are stale. Run npm run workspace-validators:generate.",
        );
        process.exitCode = 1;
    }
} else {
    writeFileSync(jsPath, formatted);
    writeFileSync(dtsPath, formattedDeclarations);
}
