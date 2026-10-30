import type {
    BootstrapResponse,
    ErrorResponse,
    FeedbackQueued,
} from "../../../contracts/v1/generated/types.ts";
import { provenance, trace } from "./fixture-builders";

export const bootstrapFixture = {
    mode: "fixture",
    csrf_token: "synthetic-csrf-token",
    limits: {
        question_bytes: 16384,
        page_size: 20,
        window_days: 90,
        request_bytes: 65536,
        plan_bytes: 131072,
    },
    models: [
        {
            id: "synthetic-model",
            label: "Synthetic model",
            efforts: ["low", "medium", "high"],
            context_tokens: 8192,
            max_output_tokens: 2048,
        },
        {
            id: "synthetic-basic-model",
            label: "Synthetic basic model",
            efforts: [],
            context_tokens: 4096,
            max_output_tokens: 1024,
        },
    ],
    provenance,
    sites: [{ id: "synthetic", label: "Synthetic site" }],
    schema_version: "1",
} satisfies BootstrapResponse;
export const feedbackQueued = {
    feedback_id: "f00d1234-1234-4234-8234-123456789abc",
    status: "queued",
} satisfies FeedbackQueued;
export const errorResponse = {
    error: {
        code: "AUDIT_UNAVAILABLE",
        message: "Synthetic audit service is unavailable.",
        retryable: true,
        trace_id: trace,
    },
} satisfies ErrorResponse;
