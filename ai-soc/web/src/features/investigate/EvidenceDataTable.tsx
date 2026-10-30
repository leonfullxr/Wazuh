import { useMemo, useState } from "react";
import {
    flexRender,
    getCoreRowModel,
    getSortedRowModel,
    useReactTable,
    type ColumnDef,
    type SortingState,
} from "@tanstack/react-table";
import {
    ArrowDown,
    ArrowUp,
    ArrowUpDown,
    CircleHelp,
    CircleCheck,
    CircleX,
    ShieldOff,
    Settings2,
} from "lucide-react";
import type {
    Answer,
    CheckOutcome,
    EvidenceItem,
    EvidenceRow,
    FetchResult,
} from "../../../../contracts/v1/generated/types.ts";
import type { Locale } from "../../i18n";
import { CopyValue } from "./CopyValue";
import { words, fmt, localeEnum, stateWord } from "../../i18n/answer-copy";
import { outcomes } from "../../i18n/answer-enums";
import { emptyProofQualified, formatVisibility, fieldValue } from "../../app/state/answer-format";
type KevContextRow = {
    kind: string;
    source: { role?: string; parent_evidence_id?: string };
    values: Record<string, unknown>;
};
export function kevLabel(value: unknown, locale: Locale) {
    const key =
        typeof value === "string"
            ? (
                  {
                      hit: "kevHit",
                      not_listed: "kevNotListed",
                      unavailable: "kevUnavailable",
                      invalid: "kevInvalid",
                      fresh: "kevFresh",
                      stale: "kevStale",
                      not_yet_valid: "kevNotYetValid",
                      unknown: "unknown",
                      complete: "kevComplete",
                      incomplete: "kevIncomplete",
                      not_configured: "kevNotConfigured",
                      limit: "kevLimit",
                      lookup_error: "kevLookupError",
                      not_yet_available: "kevNotYetAvailable",
                  } as Record<string, keyof typeof words.en>
              )[value]
            : undefined;
    return key ? fmt(locale, key) : String(value ?? "-");
}

export function KevFreshnessNote({
    answer,
    locale,
    t,
}: {
    answer: Answer | null;
    locale: Locale;
    t: (key: keyof typeof words.en) => string;
}) {
    const contexts = (answer?.blocks.flatMap((block) =>
        block.tables.flatMap((table) => table.items),
    ) ?? []) as unknown as KevContextRow[];
    const subjects = contexts.filter(
        (item) => item.kind === "context" && item.source.role === "subject",
    );
    if (!subjects.length) return null;
    const counts = subjects.reduce(
        (result, item) => {
            const key = String(item.values.kev_freshness ?? "unknown");
            result[key] = (result[key] ?? 0) + 1;
            return result;
        },
        {} as Record<string, number>,
    );
    return (
        <p className="kev-freshness">
            <strong>{t("kevFreshness")}:</strong>{" "}
            {Object.entries(counts)
                .map(([key, count]) => `${kevLabel(key, locale)} ${count}`)
                .join(" | ")}
        </p>
    );
}

export function EvidenceDataTable({
    fetch,
    locale,
    timezone,
    findItem,
    onEvidence,
    t,
}: {
    fetch: FetchResult;
    locale: Locale;
    timezone: string;
    findItem: (id: string) => EvidenceItem | undefined;
    onEvidence: (item: EvidenceItem, trigger: HTMLElement) => void;
    t: (key: keyof typeof words.en) => string;
}) {
    const [sorting, setSorting] = useState<SortingState>([]);
    const contextItems = (fetch.items as unknown as KevContextRow[]).filter(
        (item) => item.kind === "context",
    );
    const kevSubjects = new Map<string, KevContextRow[]>();
    for (const item of contextItems) {
        const parent = item.source.parent_evidence_id;
        if (item.source.role !== "subject" || !parent) continue;
        kevSubjects.set(parent, [...(kevSubjects.get(parent) ?? []), item]);
    }
    const kevPage = contextItems.find((item) => item.source.role === "page");
    const columns = useMemo<ColumnDef<EvidenceRow>[]>(() => {
        const base: ColumnDef<EvidenceRow>[] = fetch.columns.map((column) => ({
            id: column.field,
            accessorFn: (row) => row.values[column.field],
            header: ({ column: tableColumn }) => (
                <button
                    className="sort-button"
                    aria-label={`${fmt(locale, "sortBy")} ${column.label[locale]}`}
                    onClick={tableColumn.getToggleSortingHandler()}
                >
                    {column.label[locale]}
                    {tableColumn.getIsSorted() === "asc" ? (
                        <ArrowUp size={14} />
                    ) : tableColumn.getIsSorted() === "desc" ? (
                        <ArrowDown size={14} />
                    ) : (
                        <ArrowUpDown size={14} />
                    )}
                </button>
            ),
            cell: ({ row }) => (
                <span
                    className={
                        column.kind === "ip" ? "mono" : column.kind === "integer" ? "numeric" : ""
                    }
                >
                    {fieldValue(row.original.values[column.field], column.kind, timezone, locale)}
                </span>
            ),
        }));
        if (kevSubjects.size)
            base.push({
                id: "kev_context",
                accessorFn: (row) =>
                    kevSubjects
                        .get(row.evidence_id)
                        ?.map((item) => item.values.kev_lookup)
                        .join(" "),
                header: t("kev"),
                cell: ({ row }) => {
                    const subjects = kevSubjects.get(row.original.evidence_id);
                    if (!subjects?.length) return "-";
                    return (
                        <ul className="kev-row">
                            {subjects.map((subject) => (
                                <li key={String(subject.values.kev_cve)}>
                                    <span className="mono">
                                        {String(subject.values.kev_cve ?? "-")}
                                    </span>
                                    : {kevLabel(subject.values.kev_lookup, locale)} /{" "}
                                    {kevLabel(subject.values.kev_freshness, locale)}
                                    {subject.values.kev_added_on
                                        ? ` | ${t("kevAdded")}: ${subject.values.kev_added_on}`
                                        : ""}
                                </li>
                            ))}
                        </ul>
                    );
                },
            });
        return base;
    }, [fetch.columns, locale, timezone, kevSubjects, t]);
    const table = useReactTable({
        data: fetch.rows,
        columns,
        state: { sorting },
        onSortingChange: setSorting,
        getCoreRowModel: getCoreRowModel(),
        getSortedRowModel: getSortedRowModel(),
    });
    return (
        <div
            className="table-scroll"
            role="region"
            tabIndex={0}
            aria-label={`${t("tables")} ${fetch.fetch_id}`}
        >
            <table>
                <thead>
                    {table.getHeaderGroups().map((group) => (
                        <tr key={group.id}>
                            {group.headers.map((header) => (
                                <th
                                    key={header.id}
                                    scope="col"
                                    aria-sort={
                                        header.column.getIsSorted() === "asc"
                                            ? "ascending"
                                            : header.column.getIsSorted() === "desc"
                                              ? "descending"
                                              : "none"
                                    }
                                >
                                    {flexRender(
                                        header.column.columnDef.header,
                                        header.getContext(),
                                    )}
                                </th>
                            ))}
                        </tr>
                    ))}
                </thead>
                <tbody>
                    {table.getRowModel().rows.map((row) => (
                        <tr
                            id={`evidence-${CSS.escape(row.original.evidence_id)}`}
                            key={row.id}
                            tabIndex={0}
                            onClick={(event) => {
                                const item = findItem(row.original.evidence_id);
                                if (item) onEvidence(item, event.currentTarget);
                            }}
                            onKeyDown={(event) => {
                                if (event.key === "Enter" || event.key === " ") {
                                    const item = findItem(row.original.evidence_id);
                                    if (item) {
                                        event.preventDefault();
                                        onEvidence(item, event.currentTarget);
                                    }
                                }
                            }}
                        >
                            {row.getVisibleCells().map((cell) => (
                                <td key={cell.id}>
                                    {flexRender(cell.column.columnDef.cell, cell.getContext())}
                                </td>
                            ))}
                        </tr>
                    ))}
                </tbody>
            </table>
            {kevPage && (
                <div className="kev-coverage">
                    <strong>{t("kev")}</strong>
                    <span>
                        {t("kevCoverage")}: {kevLabel(kevPage.values.kev_coverage, locale)}
                    </span>
                    <span>
                        {t("kevReason")}: {kevLabel(kevPage.values.kev_reason, locale)}
                    </span>
                    <span>
                        {t("kevCounts")}: {String(kevPage.values.kev_hit_n ?? 0)} /{" "}
                        {String(kevPage.values.kev_not_listed_n ?? 0)} /{" "}
                        {String(kevPage.values.kev_unavailable_n ?? 0)}
                    </span>
                    <p>{t("kevDisclaimer")}</p>
                </div>
            )}
        </div>
    );
}

export function OutcomePill({ outcome, locale }: { outcome: CheckOutcome; locale: Locale }) {
    const Icon =
        outcome === "passed"
            ? CircleCheck
            : outcome === "failed"
              ? CircleX
              : outcome === "unknown"
                ? CircleHelp
                : outcome === "denied"
                  ? ShieldOff
                  : Settings2;
    const tone =
        outcome === "passed"
            ? "status-pill-positive"
            : outcome === "failed"
              ? "status-pill-negative"
              : outcome === "denied"
                ? "status-pill-warning"
                : "status-pill-neutral";
    return (
        <span className={`status-pill ${tone}`}>
            <Icon aria-hidden="true" size={13} />
            {localeEnum(outcomes, outcome, locale)}
        </span>
    );
}

export function EvidenceChip({
    id,
    mapped,
    onEvidence,
    t,
    isCheckRecord = false,
}: {
    id: string;
    isCheckRecord?: boolean;
    mapped: Map<string, EvidenceItem>;
    onEvidence: (i: EvidenceItem, e: HTMLElement) => void;
    t: (k: keyof typeof words.en) => string;
}) {
    const item = mapped.get(id);
    if (!item && isCheckRecord)
        return (
            <span className="citation check-reference" title={id}>
                <code>{id.slice(0, 14)}...</code>
                <CopyValue value={id} displayValue="" t={t} />
                <small>{t("checkNotIncluded")}</small>
            </span>
        );
    if (!item)
        return (
            <span className="citation check-reference">
                <code>{id}</code> <small>{t("notView")}</small>
            </span>
        );
    return (
        <button
            className="citation"
            aria-label={`${t("citation")}: ${id}`}
            onClick={(e) => onEvidence(item, e.currentTarget)}
        >
            {id.slice(0, 16)}
        </button>
    );
}
export function EmptyExplanation({
    fetch,
    t,
    locale,
}: {
    fetch: FetchResult;
    locale: Locale;
    t: (k: keyof typeof words.en) => string;
}) {
    const p = fetch.empty_proof;
    return (
        <div className="empty-proof">
            <strong>{emptyProofQualified(p) ? t("emptyConfirmed") : t("emptyUnconfirmed")}</strong>
            <span>
                {t("index")}: {stateWord(p?.index_exists ?? "unknown", locale)}
            </span>
            <span>
                {t("windowData")}: {stateWord(p?.window_has_data ?? "unknown", locale)}
            </span>
            <span>
                {t("visibility")}:{" "}
                {formatVisibility(p?.visibility ?? fetch.scope.visibility, locale)}
            </span>
            <span>
                {t("consistency")}: {stateWord(p?.consistency ?? "unconfirmed", locale)}
            </span>
        </div>
    );
}
