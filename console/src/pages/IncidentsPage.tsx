import { useEffect, useState } from "react";
import { Card, CardDescription, CardHeader, CardTitle } from "../components/ui/Card";
import { DataTable } from "../components/ui/DataTable";
import { PageHeader } from "../components/ui/PageHeader";
import { Skeleton } from "../components/ui/Skeleton";
import { fetchIncidents, type IncidentRecord } from "../lib/api";
import { formatDateTime } from "../lib/format";

export default function IncidentsPage() {
  const [incidents, setIncidents] = useState<IncidentRecord[] | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;
    fetchIncidents()
      .then((data) => {
        if (!cancelled) setIncidents(data);
      })
      .catch((err: unknown) => {
        if (!cancelled) {
          setError(err instanceof Error ? err.message : "Failed to load incidents");
        }
      });
    return () => {
      cancelled = true;
    };
  }, []);

  return (
    <section>
      <PageHeader
        title="Incidents"
        hindi="घटनाएँ"
        subtitle="Shadow-mode evidence failures and infrastructure exceptions — no fake evidence rows."
      />

      <Card>
        <CardHeader>
          <CardTitle>Evaluate incidents</CardTitle>
          <CardDescription>
            Recorded when sync shadow cannot append evidence. Query by correlation_id in LOS workflows.
          </CardDescription>
        </CardHeader>

        {error && <p className="mb-4 text-sm text-decision-block">{error}</p>}
        {incidents === null && !error && <Skeleton className="h-24 w-full" />}

        {incidents && (
          <DataTable
            rows={incidents}
            rowKey={(row) => String(row.id)}
            emptyMessage="No incidents recorded."
            columns={[
              {
                key: "when",
                header: "When",
                render: (row) => formatDateTime(row.recorded_at),
              },
              { key: "model", header: "Model", render: (row) => row.model_id },
              {
                key: "correlation",
                header: "Correlation",
                render: (row) => row.correlation_id,
              },
              { key: "reason", header: "Reason", render: (row) => row.reason },
            ]}
          />
        )}
      </Card>
    </section>
  );
}
