import { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { Card, CardDescription, CardHeader, CardTitle } from "../components/ui/Card";
import { DataTable } from "../components/ui/DataTable";
import { PageHeader } from "../components/ui/PageHeader";
import { Skeleton } from "../components/ui/Skeleton";
import { Badge } from "../components/ui/Badge";
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

export default function BatchJobsPage() {
  const [jobs, setJobs] = useState<BatchJob[] | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;
    fetchBatchJobs()
      .then((data) => {
        if (!cancelled) setJobs(data);
      })
      .catch((err: unknown) => {
        if (!cancelled) {
          setError(err instanceof Error ? err.message : "Failed to load batch jobs");
        }
      });
    return () => {
      cancelled = true;
    };
  }, []);

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

        {error && <p className="mb-4 text-sm text-decision-block">{error}</p>}
        {jobs === null && !error && <Skeleton className="h-24 w-full" />}

        {jobs && (
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
      </Card>
    </section>
  );
}
