import { useCallback, useEffect, useState } from "react";
import { Badge } from "../components/ui/Badge";
import { Button } from "../components/ui/Button";
import { Card, CardDescription, CardHeader, CardTitle } from "../components/ui/Card";
import { PageHeader } from "../components/ui/PageHeader";
import { Skeleton } from "../components/ui/Skeleton";
import {
  approveChange,
  cancelChange,
  fetchChangeRequests,
  rejectChange,
  type ChangeKind,
  type ChangeRequest,
  type ChangeStatus,
} from "../lib/api";
import { changeRequestAnchor } from "../lib/agentActions";
import { formatDateTime } from "../lib/format";

const KIND_LABELS: Record<ChangeKind, string> = {
  activate_pack: "Activate policy pack",
  rollback_pack: "Roll back policy pack",
  update_model: "Update model record",
  update_retention: "Change retention period",
  erase_evidence: "Erase evidence (DPDP)",
  apply_retention: "Run retention",
  activate_model: "Activate model version",
  reinstate_agent: "Reinstate agent",
};

function statusVariant(status: ChangeStatus): "active" | "warning" | "muted" | "default" {
  switch (status) {
    case "pending":
      return "warning";
    case "applied":
      return "active";
    case "failed":
    case "rejected":
      return "default";
    default:
      return "muted";
  }
}

/** A JSON value the spec leaves open (`params`, `binding`, `outcome`). */
function Details({ label, value }: { label: string; value: unknown }) {
  const entries =
    value !== null && typeof value === "object" && !Array.isArray(value)
      ? Object.entries(value)
      : value === null || value === undefined
        ? []
        : [["value", value] as const];
  if (entries.length === 0) return null;
  return (
    <div>
      <p className="mb-1 text-xs font-semibold uppercase tracking-wide text-muted">{label}</p>
      <dl className="grid grid-cols-[auto_1fr] gap-x-3 gap-y-1 text-sm">
        {entries.map(([key, item]) => (
          <div key={key} className="contents">
            <dt className="text-muted">{key}</dt>
            <dd className="break-all font-mono text-xs text-ink">
              {typeof item === "string" ? item : JSON.stringify(item)}
            </dd>
          </div>
        ))}
      </dl>
    </div>
  );
}

export default function ChangeRequestsPage() {
  const [filter, setFilter] = useState<ChangeStatus | undefined>("pending");
  const [requests, setRequests] = useState<ChangeRequest[] | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [message, setMessage] = useState<string | null>(null);
  const [busyId, setBusyId] = useState<string | null>(null);

  // State is set only when the request settles, never synchronously here.
  const reload = useCallback(() => {
    fetchChangeRequests(filter)
      .then((next) => {
        setError(null);
        setRequests(next);
      })
      .catch((err: unknown) => {
        setError(err instanceof Error ? err.message : "Failed to load change requests");
      });
  }, [filter]);

  useEffect(() => {
    reload();
  }, [reload]);

  const showFilter = (next: ChangeStatus | undefined) => {
    setRequests(null);
    setError(null);
    setFilter(next);
  };

  async function act(
    request: ChangeRequest,
    action: (request: ChangeRequest) => Promise<ChangeRequest>,
    done: string,
  ) {
    setBusyId(request.id);
    setError(null);
    setMessage(null);
    try {
      const updated = await action(request);
      setMessage(`${KIND_LABELS[updated.kind]}: ${done} (${updated.status}).`);
      reload();
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : "Action failed");
      reload();
    } finally {
      setBusyId(null);
    }
  }

  return (
    <section>
      <PageHeader
        title="Change requests"
        hindi="परिवर्तन अनुरोध"
        subtitle="Maker-checker: governance changes apply only when a different, authorised principal approves exactly what was proposed."
        action={
          <div className="flex gap-2">
            <Button
              size="sm"
              variant={filter === "pending" ? "secondary" : "ghost"}
              onClick={() => showFilter("pending")}
            >
              Pending
            </Button>
            <Button
              size="sm"
              variant={filter === undefined ? "secondary" : "ghost"}
              onClick={() => showFilter(undefined)}
            >
              All
            </Button>
          </div>
        }
      />

      <div role="alert" className="mb-4 text-sm text-decision-block empty:mb-0">
        {error}
      </div>
      <div role="status" aria-live="polite" className="mb-4 text-sm text-decision-pass empty:mb-0">
        {message}
      </div>

      {requests === null && !error && <Skeleton className="h-32 w-full" />}
      {requests !== null && requests.length === 0 && (
        <p className="text-sm text-muted">No change requests.</p>
      )}

      <div className="space-y-4">
        {(requests ?? []).map((request) => (
          <Card key={request.id} id={changeRequestAnchor(request.id)}>
            <CardHeader>
              <div className="flex flex-wrap items-center gap-3">
                <CardTitle>{KIND_LABELS[request.kind]}</CardTitle>
                <Badge variant={statusVariant(request.status)}>{request.status}</Badge>
              </div>
              <CardDescription>
                Proposed by <span className="font-medium text-ink">{request.proposer}</span> on{" "}
                {formatDateTime(request.created_at)}
                {request.status === "pending"
                  ? ` · expires ${formatDateTime(request.expires_at)}`
                  : request.decided_by
                    ? ` · ${request.status} by ${request.decided_by}`
                    : ""}
              </CardDescription>
            </CardHeader>
            <div className="space-y-4">
              {request.reason && <p className="text-sm text-ink">“{request.reason}”</p>}
              <div className="grid gap-4 md:grid-cols-2">
                <Details label="Change" value={request.params} />
                <Details label="Bound to (must still hold at approval)" value={request.binding} />
              </div>
              {request.outcome != null && request.status !== "applied" && (
                <Details label="Outcome" value={request.outcome} />
              )}
              <p className="break-all font-mono text-xs text-muted">
                digest {request.change_digest}
              </p>
              {request.status === "pending" && (
                <div className="flex flex-wrap gap-2">
                  <Button
                    disabled={busyId === request.id}
                    onClick={() => act(request, approveChange, "approved")}
                  >
                    Approve and apply
                  </Button>
                  <Button
                    variant="ghost"
                    disabled={busyId === request.id}
                    onClick={() => act(request, (r) => rejectChange(r.id), "rejected")}
                  >
                    Reject
                  </Button>
                  <Button
                    variant="ghost"
                    disabled={busyId === request.id}
                    onClick={() => act(request, (r) => cancelChange(r.id), "cancelled")}
                  >
                    Cancel (proposer)
                  </Button>
                </div>
              )}
            </div>
          </Card>
        ))}
      </div>
    </section>
  );
}
