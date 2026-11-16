import { Card, CardDescription, CardHeader, CardTitle } from "../components/ui/Card";
import { DataTable } from "../components/ui/DataTable";
import { PageHeader } from "../components/ui/PageHeader";
import { ResourceState, listSummary } from "../components/ui/ResourceState";
import { Skeleton } from "../components/ui/Skeleton";
import { useResource, type Resource } from "../hooks/useResource";
import { fetchIncidents, type IncidentRecord } from "../lib/api";
import { formatDateTime } from "../lib/format";

type IncidentsPageProps = {
  /** For tests: the read of GET /v1/admin/incidents, in place of the API's answer. */
  resource?: Resource<IncidentRecord[]>;
};

export default function IncidentsPage({ resource: given }: IncidentsPageProps) {
  const { resource: read, retry } = useResource(fetchIncidents);
  const resource = given ?? read;

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

        <ResourceState
          resource={resource}
          loading="Loading incidents…"
          summary={(incidents) => listSummary(incidents.length, "incident", "incidents")}
          onRetry={retry}
          skeleton={<Skeleton className="h-24 w-full" />}
        >
          {(incidents) => (
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
        </ResourceState>
      </Card>
    </section>
  );
}
