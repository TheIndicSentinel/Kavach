import { useCallback, type ReactNode } from "react";
import { Link, useParams } from "react-router-dom";
import { ArrowLeft } from "lucide-react";
import { Badge } from "../components/ui/Badge";
import { Card, CardDescription, CardHeader, CardTitle } from "../components/ui/Card";
import { PageHeader } from "../components/ui/PageHeader";
import { ResourceState } from "../components/ui/ResourceState";
import { Skeleton } from "../components/ui/Skeleton";
import { useResource, type Resource } from "../hooks/useResource";
import { fetchBatchJob, type BatchJob } from "../lib/api";
import { formatDateTime } from "../lib/format";

function DetailRow({ label, value }: { label: string; value: ReactNode }) {
  return (
    <div className="grid gap-1 border-b border-border py-3 sm:grid-cols-[10rem_1fr] sm:gap-4">
      <dt className="text-xs font-semibold uppercase tracking-wide text-muted">{label}</dt>
      <dd className="text-sm text-ink break-words">{value}</dd>
    </div>
  );
}

type BatchJobDetailPageProps = {
  /** For tests: the job's read, in place of the API's answer. */
  resource?: Resource<BatchJob>;
};

export default function BatchJobDetailPage({ resource: given }: BatchJobDetailPageProps = {}) {
  const { jobId = "" } = useParams<{ jobId: string }>();
  const load = useCallback(() => fetchBatchJob(jobId), [jobId]);
  const { resource: read, retry } = useResource(load);
  const resource = given ?? read;
  const job = resource.phase === "ok" ? resource.data : null;

  return (
    <section>
      <div className="mb-6">
        <Link
          to="/batch"
          className="inline-flex items-center gap-2 rounded-lg border border-border px-3 py-1.5 text-sm font-semibold text-kavach-900 hover:bg-kavach-900/5"
        >
          <ArrowLeft className="h-4 w-4" aria-hidden />
          All batch jobs
        </Link>
      </div>

      <PageHeader
        title={jobId}
        hindi="बैच विवरण"
        subtitle={job ? `${job.model_id} · ${job.governance_mode} mode` : "Batch job"}
        action={job && <Badge variant="active">{job.status}</Badge>}
      />

      <ResourceState
        resource={resource}
        loading="Loading batch job…"
        notFound={`No batch job ${jobId} on this server.`}
        onRetry={retry}
        skeleton={<Skeleton className="mb-6 h-32 w-full" />}
      >
        {() => null}
      </ResourceState>

      {job && (
        <>

          <div className="grid gap-4 lg:grid-cols-2">
            <Card>
              <CardHeader>
                <CardTitle>Run summary</CardTitle>
                <CardDescription>Row counts and timing from job lifecycle store.</CardDescription>
              </CardHeader>
              <dl>
                <DetailRow label="Total rows" value={job.total_rows} />
                <DetailRow label="Succeeded" value={job.succeeded_rows} />
                <DetailRow label="Failed" value={job.failed_rows} />
                <DetailRow label="Skipped" value={job.skipped_rows} />
                <DetailRow label="Created" value={formatDateTime(job.created_at)} />
                <DetailRow
                  label="Started"
                  value={job.started_at ? formatDateTime(job.started_at) : "—"}
                />
                <DetailRow
                  label="Completed"
                  value={job.completed_at ? formatDateTime(job.completed_at) : "—"}
                />
              </dl>
            </Card>

            <Card>
              <CardHeader>
                <CardTitle>Paths</CardTitle>
                <CardDescription>
                  Basenames only — full paths stay on the batch worker host.
                </CardDescription>
              </CardHeader>
              <dl>
                <DetailRow label="Input" value={<code className="font-mono text-xs">{job.input_path}</code>} />
                <DetailRow
                  label="Output"
                  value={
                    job.output_path ? (
                      <code className="font-mono text-xs">{job.output_path}</code>
                    ) : (
                      "—"
                    )
                  }
                />
                {job.error_summary && (
                  <DetailRow
                    label="Error"
                    value={<span className="text-decision-block">{job.error_summary}</span>}
                  />
                )}
              </dl>
            </Card>
          </div>
        </>
      )}
    </section>
  );
}
