export const cols = [
    {
        field: "timestamp" as const,
        kind: "date" as const,
        label: { en: "timestamp", es: "timestamp" },
    },
    {
        field: "agent.name" as const,
        kind: "text" as const,
        label: { en: "agent.name", es: "agent.name" },
    },
    { field: "rule.id" as const, kind: "text" as const, label: { en: "rule.id", es: "rule.id" } },
];
export const authCols = [
    {
        field: "timestamp" as const,
        kind: "date" as const,
        label: { en: "timestamp", es: "timestamp" },
    },
    {
        field: "agent.id" as const,
        kind: "text" as const,
        label: { en: "agent.id", es: "agent.id" },
    },
    {
        field: "agent.name" as const,
        kind: "text" as const,
        label: { en: "agent.name", es: "agent.name" },
    },
    {
        field: "rule.id" as const,
        kind: "text" as const,
        label: { en: "rule.id", es: "rule.id" },
    },
    {
        field: "rule.level" as const,
        kind: "integer" as const,
        label: { en: "rule.level", es: "rule.level" },
    },
    {
        field: "rule.groups" as const,
        kind: "text" as const,
        label: { en: "rule.groups", es: "rule.groups" },
    },
    {
        field: "data.srcip" as const,
        kind: "ip" as const,
        label: { en: "data.srcip", es: "data.srcip" },
    },
    {
        field: "data.dstip" as const,
        kind: "ip" as const,
        label: { en: "data.dstip", es: "data.dstip" },
    },
];
export const vulnCols = [
    {
        field: "agent.id" as const,
        kind: "text" as const,
        label: { en: "agent.id", es: "agent.id" },
    },
    {
        field: "agent.name" as const,
        kind: "text" as const,
        label: { en: "agent.name", es: "agent.name" },
    },
    {
        field: "vulnerability.id" as const,
        kind: "text" as const,
        label: { en: "vulnerability.id", es: "vulnerability.id" },
    },
    {
        field: "vulnerability.severity" as const,
        kind: "text" as const,
        label: { en: "vulnerability.severity", es: "vulnerability.severity" },
    },
    {
        field: "vulnerability.detected_at" as const,
        kind: "date" as const,
        label: { en: "vulnerability.detected_at", es: "vulnerability.detected_at" },
    },
    {
        field: "package.name" as const,
        kind: "text" as const,
        label: { en: "package.name", es: "package.name" },
    },
    {
        field: "package.version" as const,
        kind: "text" as const,
        label: { en: "package.version", es: "package.version" },
    },
];
