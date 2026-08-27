import { useEffect, useState } from "react";
import { Card, CardDescription, CardHeader, CardTitle } from "../components/ui/Card";
import { DataTable } from "../components/ui/DataTable";
import { PageHeader } from "../components/ui/PageHeader";
import { Skeleton } from "../components/ui/Skeleton";
import { fetchAuditLog, type AuditEntry } from "../lib/api";
import { formatDateTime } from "../lib/format";

export default function AuditPage() {
  const [entries, setEntries] = useState<AuditEntry[] | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;
    fetchAuditLog()
      .then((data) => {
        if (!cancelled) setEntries(data);
      })
      .catch((err: unknown) => {
        if (!cancelled) {
          setError(err instanceof Error ? err.message : "Failed to load audit log");
        }
      });
    return () => {
      cancelled = true;
    };
  }, []);

  return (
    <section>
      <PageHeader
        title="Admin audit"
        hindi="प्रशासनिक ऑडिट"
        subtitle="Dual-control governance mutations — pack activate, rollback, and model promotion."
      />

      <Card>
        <CardHeader>
          <CardTitle>Audit log</CardTitle>
          <CardDescription>
            Requires admin principal. Mutations need distinct actor and approver headers.
          </CardDescription>
        </CardHeader>

        {error && <p className="mb-4 text-sm text-decision-block">{error}</p>}
        {entries === null && !error && <Skeleton className="h-24 w-full" />}

        {entries && (
          <DataTable
            rows={entries}
            rowKey={(row) => String(row.id)}
            emptyMessage="No admin actions recorded yet."
            columns={[
              {
                key: "when",
                header: "When",
                render: (row) => formatDateTime(row.created_at),
              },
              { key: "action", header: "Action", render: (row) => row.action },
              {
                key: "resource",
                header: "Resource",
                render: (row) => `${row.resource_type}/${row.resource_id}`,
              },
              {
                key: "actor",
                header: "Actor",
                render: (row) => row.actor_principal,
              },
              {
                key: "approver",
                header: "Approver",
                render: (row) => row.approver_principal,
              },
            ]}
          />
        )}
      </Card>
    </section>
  );
}
