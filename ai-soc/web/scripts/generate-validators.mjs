import { readFileSync, mkdirSync, writeFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import Ajv2020 from "ajv/dist/2020.js";
import addFormats from "ajv-formats";
import standaloneCode from "ajv/dist/standalone/index.js";
import prettier from "prettier";

const root = process.cwd();
const schema = JSON.parse(
    readFileSync(resolve(root, "../contracts/v1/models.schema.json"), "utf8"),
);
// Ajv strictTypes does not infer an object's type from a sibling local $ref.
// Repeat only a type already required by the referenced frozen definition.
const repeatReferencedObjectTypes = (node) => {
    if (node === null || typeof node !== "object") return;
    if (
        typeof node.$ref === "string" &&
        node.$ref.startsWith("#/$defs/") &&
        "additionalProperties" in node &&
        !("type" in node)
    ) {
        const definition = schema.$defs[node.$ref.slice("#/$defs/".length)];
        if (definition?.type !== "object") {
            throw new Error("An object constraint references a non-object definition");
        }
        node.type = "object";
    }
    for (const child of Object.values(node)) repeatReferencedObjectTypes(child);
};
repeatReferencedObjectTypes(schema);
const output = resolve(root, "src/api/generated/validators.js");
const ajv = new Ajv2020({
    strict: true,
    allErrors: true,
    code: { source: true, esm: true },
});
ajv.addKeyword({ keyword: "freeze_revision", schemaType: "string", valid: true });
addFormats(ajv);
ajv.addSchema(schema);
const names = {
    validateAnswer: "Answer",
    validateFetchResult: "FetchResult",
    validateBootstrapResponse: "BootstrapResponse",
    validateFeedbackQueued: "FeedbackQueued",
};
const validators = Object.fromEntries(
    Object.entries(names).map(([exportName, definition]) => [
        exportName,
        `${schema.$id}#/$defs/${definition}`,
    ]),
);
const source = standaloneCode(ajv, validators)
    .replaceAll('require("ajv-formats/dist/formats").fullFormats', "fullFormats")
    .replaceAll('require("ajv/dist/runtime/ucs2length").default', "codePointLength")
    .replace(
        '"use strict";',
        '"use strict";\nimport { fullFormats } from "ajv-formats/dist/formats.js";\nconst codePointLength = (value) => Array.from(value).length;',
    );
const prettierConfig = await prettier.resolveConfig(output);
const generated = await prettier.format(`${source}\n`, {
    ...prettierConfig,
    filepath: output,
});
if (process.argv.includes("--check")) {
    let current = "";
    try {
        current = readFileSync(output, "utf8");
    } catch {
        // A missing generated file is reported by the stale check below.
    }
    if (current !== generated) {
        console.error("Generated API validators are stale. Run npm run validators:generate.");
        process.exitCode = 1;
    }
} else {
    mkdirSync(dirname(output), { recursive: true });
    writeFileSync(output, generated);
}
