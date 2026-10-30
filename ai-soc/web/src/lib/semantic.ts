import type { AnswerStatus, JudgmentState } from "../../../contracts/v1/generated/types.ts";

export type TagTone = "neutral" | "blue" | "green" | "amber" | "orange" | "red" | "purple" | "teal";

export type SemanticTag = Readonly<{
    tone: TagTone;
    dot: boolean;
}>;

export type WorkStatus = "new" | "acknowledged" | "in_progress" | "resolved" | "closed";
export type Disposition =
    | "true_positive"
    | "benign"
    | "benign_true_positive"
    | "false_positive"
    | "duplicate"
    | "undecided"
    | "undetermined";
export type EntityKind = "host" | "user" | "ip" | "file" | "rule";
export type Health = "operational" | "degraded" | "down" | "unknown";
export type Framework = "MITRE" | "PCI" | "GDPR" | "NIST";

const tag = (tone: TagTone, dot = false): SemanticTag => ({ tone, dot });

export function severityTag(level: number | "info"): SemanticTag {
    if (level === "info") return tag("neutral");
    if (level >= 15) return tag("red", true);
    if (level >= 12) return tag("orange", true);
    if (level >= 7) return tag("amber", true);
    return tag("neutral", true);
}

export const statusTags = {
    new: tag("blue"),
    acknowledged: tag("purple"),
    in_progress: tag("amber"),
    resolved: tag("green"),
    closed: tag("neutral"),
} satisfies Record<WorkStatus, SemanticTag>;

export const dispositionTags = {
    true_positive: tag("red"),
    benign: tag("green"),
    benign_true_positive: tag("green"),
    false_positive: tag("neutral"),
    duplicate: tag("neutral"),
    undecided: tag("neutral"),
    undetermined: tag("neutral"),
} satisfies Record<Disposition, SemanticTag>;

export const answerStatusTags = {
    answered: tag("green"),
    partial: tag("amber"),
    clarify: tag("blue"),
    refused: tag("neutral"),
} satisfies Record<AnswerStatus, SemanticTag>;

export const judgmentStateTags = {
    validated: tag("green"),
    ingestion_unconfirmed: tag("amber"),
    all_removed: tag("amber"),
    context_exceeded: tag("amber"),
    budget_exceeded: tag("amber"),
    deadline_exceeded: tag("amber"),
    capacity_limited: tag("amber"),
    guardrail_blocked: tag("red"),
    model_unavailable: tag("red"),
    invalid_output: tag("red"),
    no_findings: tag("neutral"),
    not_requested: tag("neutral"),
    denial: tag("neutral"),
    evidence_unavailable: tag("neutral"),
    token_count_unavailable: tag("neutral"),
} satisfies Record<JudgmentState, SemanticTag>;

export const entityTags = {
    host: tag("blue"),
    user: tag("teal"),
    ip: tag("purple"),
    file: tag("orange"),
    rule: tag("neutral"),
} satisfies Record<EntityKind, SemanticTag>;

export const healthTags = {
    operational: tag("green", true),
    degraded: tag("amber", true),
    down: tag("red", true),
    unknown: tag("neutral", true),
} satisfies Record<Health, SemanticTag>;

export const frameworkTags = {
    MITRE: tag("neutral"),
    PCI: tag("neutral"),
    GDPR: tag("neutral"),
    NIST: tag("neutral"),
} satisfies Record<Framework, SemanticTag>;
