import { Link } from "react-router-dom";
import { Card, CardDescription, CardHeader, CardTitle } from "../components/ui/Card";
import { DataTable } from "../components/ui/DataTable";
import { PageHeader } from "../components/ui/PageHeader";
import { ResourceState, listSummary } from "../components/ui/ResourceState";
import { Skeleton } from "../components/ui/Skeleton";
import { Badge } from "../components/ui/Badge";
import { useResource, type Resource } from "../hooks/useResource";
import { fetchBatchJobs, type BatchJob } from "../lib/api";
import { formatDateTime } from "../lib/format";

function statusVariant(status: string): "active" | "warning" | "default" | "muted" {
  switch (status) {
    case "completed":
      return "active";
    case "running":
      return "warning";
    case "failed":
      return "warning";
    default:
      return "muted";
  }
}

type BatchJobsPageProps = {
  /** For tests: the read of GET /v1/admin/batch-jobs, in place of the API's answer. */
  resource?: Resource<BatchJob[]>;
};

export default function BatchJobsPage({ resource: given }: BatchJobsPageProps) {
  const { resource: read, retry } = useResource(fetchBatchJobs);
  const resource = given ?? read;

  return (
    <section>
      <PageHeader
        title="Batch jobs"
        hindi="बैच कार्य"
        subtitle="NDJSON ingest runs from CronJob or workflow — read-only inventory from Postgres job lifecycle."
      />

      <Card>
        <CardHeader>
          <CardTitle>Job inventory</CardTitle>
          <CardDescription>
            Triggered via <code className="font-mono text-xs">kavach-batch run</code> in production.
            Result NDJSON remains on the filesystem path recorded at completion.
          </CardDescription>
        </CardHeader>

        <ResourceState
          resource={resource}
          loading="Loading batch jobs…"
          summary={(jobs) => listSummary(jobs.length, "job", "jobs")}
          onRetry={retry}
          skeleton={<Skeleton className="h-24 w-full" />}
        >
          {(jobs) => (
          <DataTable
            rows={jobs}
            rowKey={(row) => row.job_id}
            emptyMessage="No batch jobs recorded yet. Jobs appear after Postgres-backed runs."
            columns={[
              {
                key: "status",
                header: "Status",
                render: (row) => (
                  <Badge variant={statusVariant(row.status)}>{row.status}</Badge>
                ),
              },
              {
                key: "model",
                header: "Model",
                render: (row) => row.model_id,
              },
              {
                key: "mode",
                header: "Mode",
                render: (row) => row.governance_mode,
              },
              {
                key: "rows",
                header: "Rows",
                render: (row) =>
                  `${row.succeeded_rows}/${row.total_rows} ok · ${row.failed_rows} fail`,
              },
              {
                key: "when",
                header: "Created",
                render: (row) => formatDateTime(row.created_at),
              },
              {
                key: "link",
                header: "",
                className: "text-right",
                render: (row) => (
                  <Link
                    to={`/batch/${encodeURIComponent(row.job_id)}`}
                    className="text-sm font-semibold text-peacock-700 hover:underline"
                  >
                    View
                  </Link>
                ),
              },
            ]}
          />
          )}
        </ResourceState>
      </Card>
    </section>
  );
}
