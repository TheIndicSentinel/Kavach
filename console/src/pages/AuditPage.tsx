import { Card, CardDescription, CardHeader, CardTitle } from "../components/ui/Card";
import { DataTable } from "../components/ui/DataTable";
import { PageHeader } from "../components/ui/PageHeader";
import { ResourceState, listSummary } from "../components/ui/ResourceState";
import { Skeleton } from "../components/ui/Skeleton";
import { useResource, type Resource } from "../hooks/useResource";
import { fetchAuditLog, type AuditEntry } from "../lib/api";
import { formatDateTime } from "../lib/format";

type AuditPageProps = {
  /** For tests: the read of GET /v1/admin/audit, in place of the API's answer. */
  resource?: Resource<AuditEntry[]>;
};

export default function AuditPage({ resource: given }: AuditPageProps) {
  const { resource: read, retry } = useResource(fetchAuditLog);
  const resource = given ?? read;

  return (
    <section>
      <PageHeader
        title="Admin audit"
        hindi="प्रशासनिक ऑडिट"
        subtitle="Approved governance changes: who proposed each one and who approved it."
      />

      <Card>
        <CardHeader>
          <CardTitle>Audit log</CardTitle>
          <CardDescription>
            Requires admin principal. Governance changes record the proposer (actor) and the distinct approver.
          </CardDescription>
        </CardHeader>

        <ResourceState
          resource={resource}
          loading="Loading the audit log…"
          summary={(entries) => listSummary(entries.length, "entry", "entries")}
          onRetry={retry}
          skeleton={<Skeleton className="h-24 w-full" />}
        >
          {(entries) => (
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
        </ResourceState>
      </Card>
    </section>
  );
}
