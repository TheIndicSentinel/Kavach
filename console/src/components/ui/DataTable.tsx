import { cn } from "../../lib/cn";

type Column<T> = {
  key: string;
  header: string;
  className?: string;
  render: (row: T) => React.ReactNode;
};

type DataTableProps<T> = {
  columns: Column<T>[];
  rows: T[];
  rowKey: (row: T) => string;
  emptyMessage?: string;
};

export function DataTable<T>({
  columns,
  rows,
  rowKey,
  emptyMessage = "No records found.",
}: DataTableProps<T>) {
  if (rows.length === 0) {
    return (
      <p className="rounded-lg border border-dashed border-border bg-stone-50/50 px-4 py-8 text-center text-sm text-muted">
        {emptyMessage}
      </p>
    );
  }

  return (
    <>
      <div className="space-y-3 md:hidden">
        {rows.map((row) => (
          <article
            key={rowKey(row)}
            className="rounded-xl border border-border bg-surface-raised p-4 shadow-sm"
          >
            <dl className="space-y-3">
              {columns.map((column) => (
                <div key={column.key} className="flex flex-col gap-1">
                  <dt className="text-[0.65rem] font-semibold uppercase tracking-wide text-muted">
                    {column.header}
                  </dt>
                  <dd className="text-sm text-ink break-words">{column.render(row)}</dd>
                </div>
              ))}
            </dl>
          </article>
        ))}
      </div>

      <div className="hidden overflow-x-auto rounded-xl border border-border md:block">
        <table className="min-w-full divide-y divide-border text-sm">
          <thead className="bg-stone-50/80">
            <tr>
              {columns.map((column) => (
                <th
                  key={column.key}
                  scope="col"
                  className={cn(
                    "px-4 py-3 text-left text-xs font-semibold uppercase tracking-wide text-muted",
                    column.className,
                  )}
                >
                  {column.header}
                </th>
              ))}
            </tr>
          </thead>
          <tbody className="divide-y divide-border bg-surface-raised">
            {rows.map((row) => (
              <tr key={rowKey(row)} className="hover:bg-stone-50/60">
                {columns.map((column) => (
                  <td
                    key={column.key}
                    className={cn("px-4 py-3 align-top text-ink", column.className)}
                  >
                    {column.render(row)}
                  </td>
                ))}
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </>
  );
}
