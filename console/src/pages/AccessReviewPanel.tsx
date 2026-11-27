import { useState } from "react";
import { Button } from "../components/ui/Button";
import { Card, CardDescription, CardHeader, CardTitle } from "../components/ui/Card";
import { ProblemAlert } from "../components/ui/ProblemAlert";
import { ResourceState } from "../components/ui/ResourceState";
import { RoleHint } from "../components/ui/RoleHint";
import type { Resource } from "../hooks/useResource";
import { fetchAccessReview, fetchAccessReviewCsv, type AccessReview } from "../lib/api";

function staleLabel(value: boolean | null): string {
  if (value === null) return "Not assessed (group membership is in the identity provider)";
  return value ? "Stale" : "Current";
}

function dateLabel(value: string | null): string {
  if (value === null) return "Never seen";
  const date = new Date(value);
  return Number.isNaN(date.valueOf()) ? "Unknown" : date.toLocaleString();
}

function ReviewRows({ review }: { review: AccessReview }) {
  if (review.rows.length === 0) return <p className="py-5 text-sm text-muted">No active role bindings to review.</p>;
  return (
    <div className="overflow-x-auto">
      <table className="w-full min-w-[72rem] border-collapse text-left text-sm">
        <thead>
          <tr className="border-b border-border text-xs uppercase tracking-wide text-muted">
            <th scope="col" className="px-3 py-3 font-semibold">Role</th>
            <th scope="col" className="px-3 py-3 font-semibold">Subject</th>
            <th scope="col" className="px-3 py-3 font-semibold">Granted</th>
            <th scope="col" className="px-3 py-3 font-semibold">Change request</th>
            <th scope="col" className="px-3 py-3 font-semibold">Proposed by</th>
            <th scope="col" className="px-3 py-3 font-semibold">Approved by</th>
            <th scope="col" className="px-3 py-3 font-semibold">Last seen</th>
            <th scope="col" className="px-3 py-3 font-semibold">Freshness</th>
          </tr>
        </thead>
        <tbody>
          {review.rows.map((row) => (
            <tr key={row.binding_id} className="border-b border-border last:border-0">
              <th scope="row" className="px-3 py-3 font-medium text-ink">{row.role}</th>
              <td className="px-3 py-3 text-ink">
                <span className="block">{row.display_name || row.subject}</span>
                <code className="mt-1 block break-all text-xs text-muted">{row.subject}</code>
                <span className="mt-1 block text-xs text-muted">{row.subject_kind} · {row.issuer}</span>
              </td>
              <td className="px-3 py-3 text-muted">{dateLabel(row.granted_at)}</td>
              <td className="px-3 py-3 text-muted">{row.change_request_id ?? "Bootstrap"}</td>
              <td className="px-3 py-3 text-muted">{row.proposer}</td>
              <td className="px-3 py-3 text-muted">{row.approver || "Bootstrap"}</td>
              <td className="px-3 py-3 text-muted">{dateLabel(row.last_seen_at)}</td>
              <td className="px-3 py-3 text-muted">{staleLabel(row.stale)}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

/** Click-to-load and audited access review with the API-generated safe CSV export. */
export function AccessReviewPanel({ canRead = true, readHint }: { canRead?: boolean; readHint?: string | null }) {
  const [resource, setResource] = useState<Resource<AccessReview> | null>(null);
  const [loading, setLoading] = useState(false);
  const [downloading, setDownloading] = useState(false);
  const [csvError, setCsvError] = useState<unknown>(null);
  const [csvNotice, setCsvNotice] = useState("");

  async function loadReview() {
    if (loading) return;
    setLoading(true);
    setResource({ phase: "loading" });
    setCsvError(null);
    setCsvNotice("");
    try {
      setResource({ phase: "ok", data: await fetchAccessReview() });
    } catch (error) {
      setResource({ phase: "error", error });
    } finally {
      setLoading(false);
    }
  }

  async function downloadCsv() {
    if (downloading) return;
    setDownloading(true);
    setCsvError(null);
    setCsvNotice("");
    try {
      const csv = await fetchAccessReviewCsv();
      const url = URL.createObjectURL(new Blob([csv], { type: "text/csv;charset=utf-8" }));
      const link = document.createElement("a");
      link.href = url;
      link.download = "access-review.csv";
      document.body.append(link);
      link.click();
      link.remove();
      window.setTimeout(() => URL.revokeObjectURL(url), 0);
      setCsvNotice("The CSV was downloaded and recorded in the audit log.");
    } catch (error) {
      setCsvError(error);
    } finally {
      setDownloading(false);
    }
  }

  return (
    <Card className="mt-6">
      <CardHeader>
        <CardTitle>Access review</CardTitle>
        <CardDescription>
          Each review load and CSV export is recorded in the tenant audit log. Alias group memberships remain in the identity provider and are not expanded here.
        </CardDescription>
      </CardHeader>
      {canRead ? (
        <>
          <div className="mb-4 flex flex-wrap gap-2">
            <Button variant="secondary" aria-disabled={loading} onClick={() => { void loadReview(); }}>
              {resource?.phase === "ok" ? "Refresh access review" : resource?.phase === "error" ? "Try access review again" : loading ? "Loading review…" : "Load access review"}
            </Button>
            {resource?.phase === "ok" && (
              <Button variant="ghost" aria-disabled={downloading} onClick={() => { void downloadCsv(); }}>
                {downloading ? "Preparing CSV…" : "Download CSV"}
              </Button>
            )}
          </div>
          {resource && (
            <ResourceState
              resource={resource}
              loading="Loading and auditing the access review…"
              summary={(review) => `${review.rows.length} active ${review.rows.length === 1 ? "binding" : "bindings"}; stale after ${review.stale_after_days} days.`}
              onRetry={() => { void loadReview(); }}
            >
              {(review) => (
                <>
                  <p className="mb-3 text-sm text-muted">Generated {dateLabel(review.generated_at)} · Tenant {review.tenant_id}</p>
                  <p className="mb-4 text-sm text-muted">{review.note}</p>
                  <p className="mb-4 text-sm text-muted">Policy alias groups: {review.alias_groups.join(", ") || "none"}. Their membership is not included in this review.</p>
                  <ReviewRows review={review} />
                </>
              )}
            </ResourceState>
          )}
        </>
      ) : (
        <RoleHint>{readHint ?? "Your current access does not include reading the access review. The server decides; ask an admin if you need this."}</RoleHint>
      )}
      <ProblemAlert error={csvError} className="mt-3" />
      {csvNotice && <p role="status" className="mt-3 text-sm text-ink">{csvNotice}</p>}
    </Card>
  );
}
