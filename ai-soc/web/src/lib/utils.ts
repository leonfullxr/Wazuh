export { cn } from "../components/ui/cn";

/** True for a plain object whose fields are all primitives, so it can render as label/value rows. */
export function isFlatRecord(
    value: unknown,
): value is Record<string, string | number | boolean | null> {
    return (
        typeof value === "object" &&
        value !== null &&
        !Array.isArray(value) &&
        Object.values(value).every(
            (field) => field === null || ["string", "number", "boolean"].includes(typeof field),
        )
    );
}
