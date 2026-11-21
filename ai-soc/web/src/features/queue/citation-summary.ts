/** Analyst-facing label for one cited assessment fact. The raw evidence id stays secondary. */
export function citationSummary(fields: Record<string, unknown>): string {
    const text = (key: string) => {
        const value = fields[key];
        return typeof value === "string" || typeof value === "number" ? String(value) : "";
    };
    const rule = text("rule_id");
    return [rule ? `Rule ${rule}` : "", text("agent") || text("agent_name"), text("source") || text("src_ip")]
        .filter(Boolean)
        .join(" · ");
}

/** Shorten a contract evidence id for display. The full id stays available as the title. */
export function shortEvidenceId(id: string): string {
    return id.length <= 18 ? id : `${id.slice(0, 10)}…${id.slice(-4)}`;
}
