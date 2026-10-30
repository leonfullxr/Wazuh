import { flexRender, type Table as TableInstance } from "@tanstack/react-table";
export function DataTable<T>({ table }: { table: TableInstance<T> }) {
    return (
        <div className="overflow-x-auto rounded-panel border border-[var(--stroke-subtle)]">
            <table className="w-full border-collapse text-left text-sm">
                <thead className="bg-[var(--bg-secondary)]">
                    {table.getHeaderGroups().map((group) => (
                        <tr key={group.id}>
                            {group.headers.map((header) => (
                                <th
                                    key={header.id}
                                    scope="col"
                                    className="px-4 py-3 font-medium text-[var(--text-tertiary)]"
                                >
                                    {header.isPlaceholder
                                        ? null
                                        : flexRender(
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
                        <tr key={row.id} className="border-t border-[var(--stroke-subtle)]">
                            {row.getVisibleCells().map((cell) => (
                                <td key={cell.id} className="px-4 py-3">
                                    {flexRender(cell.column.columnDef.cell, cell.getContext())}
                                </td>
                            ))}
                        </tr>
                    ))}
                </tbody>
            </table>
        </div>
    );
}
