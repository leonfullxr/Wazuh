export { cn } from "../components/ui/cn";

type Primitive = string | number | boolean | null;

function isPrimitive(field: unknown): field is Primitive {
    return field === null || ["string", "number", "boolean"].includes(typeof field);
}

/**
 * True for a plain object whose fields are primitives or lists of primitives,
 * so it can render as label/value rows.
 */
export function isFlatRecord(value: unknown): value is Record<string, Primitive | Primitive[]> {
    return (
        typeof value === "object" &&
        value !== null &&
        !Array.isArray(value) &&
        Object.values(value).every(
            (field) => isPrimitive(field) || (Array.isArray(field) && field.every(isPrimitive)),
        )
    );
}

const ACRONYMS: Record<string, string> = {
    id: "ID",
    ids: "IDs",
    ip: "IP",
    ips: "IPs",
    url: "URL",
    sha: "SHA",
    sha256: "SHA-256",
};

/** API field keys as labels: "evidence_ids" reads "Evidence IDs", "count_30d" reads "Count 30d". */
export function humanizeKey(key: string): string {
    const words = key.split(/[_\s]+/).filter(Boolean);
    return words
        .map((word, index) => {
            const lower = word.toLowerCase();
            if (ACRONYMS[lower]) return ACRONYMS[lower];
            return index === 0 ? lower.charAt(0).toUpperCase() + lower.slice(1) : lower;
        })
        .join(" ");
}
