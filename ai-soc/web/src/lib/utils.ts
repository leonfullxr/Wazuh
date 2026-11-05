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
