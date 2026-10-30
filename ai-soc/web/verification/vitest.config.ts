import { defineConfig } from "vitest/config";

export default defineConfig({
    test: {
        environment: "node",
        include: ["verification/unit/**/*.check.ts"],
    },
});
