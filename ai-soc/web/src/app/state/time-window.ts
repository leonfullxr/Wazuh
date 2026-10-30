import { rangeBounds } from "../../api/workspace";

export function resolveWindow({
    range,
    anchor,
    from,
    to,
}: {
    range: "24h" | "7d" | "30d";
    anchor: number;
    from: string | null;
    to: string | null;
}): { from: string; to: string } {
    const defaults = rangeBounds(range, anchor);
    const toTime = to === null ? NaN : Date.parse(to);
    return {
        from:
            from ??
            (Number.isFinite(toTime) ? new Date(toTime - 86_400_000).toISOString() : defaults.from),
        to: to ?? defaults.to,
    };
}
