import { useCallback, useEffect, useRef, useState } from "react";
import { Badge } from "../components/ui/Badge";
import { Button } from "../components/ui/Button";
import { Card, CardDescription, CardHeader, CardTitle } from "../components/ui/Card";
import { PageHeader } from "../components/ui/PageHeader";
import { ProblemAlert } from "../components/ui/ProblemAlert";
import { RoleHint } from "../components/ui/RoleHint";
import { Skeleton } from "../components/ui/Skeleton";
import type { Resource } from "../hooks/useResource";
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
import { changeRequestButtons, useViewer, type Viewer } from "../lib/changeRequests";
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

type RequestButtonsProps = {
  request: ChangeRequest;
  viewer: Viewer;
  busy: boolean;
  onAct: (action: (request: ChangeRequest) => Promise<ChangeRequest>, done: string) => void;
};

/**
 * Approve, reject and cancel, less the ones the API is known to refuse this
 * principal (the proposer rule) or its groups are known to lack (a hint line
 * takes their place; the server still decides).
 */
export function RequestButtons({ request, viewer, busy, onAct }: RequestButtonsProps) {
  const { actions, note, hint } = changeRequestButtons(request, viewer);
  if (actions.length === 0 && !note && !hint) return null;
  // aria-disabled, not disabled, while a request is in flight: a disabled
  // button would drop keyboard focus to the page body. `act` ignores a press.
  const press = (action: (request: ChangeRequest) => Promise<ChangeRequest>, done: string) => () => {
    if (!busy) onAct(action, done);
  };
  const busyClass = "aria-disabled:cursor-not-allowed aria-disabled:opacity-50";
  return (
    <div className="space-y-2">
      {note && <p className="text-sm text-muted">{note}</p>}
      {hint && <RoleHint>{hint}</RoleHint>}
      {actions.length > 0 && (
        <div className="flex flex-wrap gap-2">
          {actions.includes("approve") && (
            <Button aria-disabled={busy} className={busyClass} onClick={press(approveChange, "approved")}>
              Approve and apply
            </Button>
          )}
          {actions.includes("reject") && (
            <Button
              variant="ghost"
              aria-disabled={busy}
              className={busyClass}
              onClick={press((r) => rejectChange(r.id), "rejected")}
            >
              Reject
            </Button>
          )}
          {actions.includes("cancel") && (
            <Button
              variant="ghost"
              aria-disabled={busy}
              className={busyClass}
              onClick={press((r) => cancelChange(r.id), "cancelled")}
            >
              Cancel (proposer)
            </Button>
          )}
        </div>
      )}
    </div>
  );
}

type ChangeRequestsPageProps = {
  /** For tests: the list's read, in place of the API's answer. */
  resource?: Resource<ChangeRequest[]>;
};

export default function ChangeRequestsPage({ resource: given }: ChangeRequestsPageProps = {}) {
  const viewer = useViewer();
  const [filter, setFilter] = useState<ChangeStatus | undefined>("pending");
  const [requests, setRequests] = useState<ChangeRequest[] | null>(null);
  const [error, setError] = useState<unknown>(null);
  const [message, setMessage] = useState<string | null>(null);
  const [busyId, setBusyId] = useState<string | null>(null);
  // Focus lands on the result: the buttons that started it may be gone.
  const result = useRef<HTMLDivElement>(null);

  // State is set only when the request settles, never synchronously here.
  const reload = useCallback(() => {
    fetchChangeRequests(filter)
      .then((next) => {
        setError(null);
        setRequests(next);
      })
      .catch((err: unknown) => {
        setError(err);
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
    if (busyId !== null) return;
    setBusyId(request.id);
    setError(null);
    setMessage(null);
    try {
      const updated = await action(request);
      setMessage(`${KIND_LABELS[updated.kind]}: ${done} (${updated.status}).`);
      result.current?.focus();
      reload();
    } catch (err: unknown) {
      // The request stays pending, so its buttons, and focus, stay put.
      setError(err);
      reload();
    } finally {
      setBusyId(null);
    }
  }

  // The list is not refetched through useResource: after a refused action
  // the request stays on screen, with its buttons and focus.
  const listed = given ? (given.phase === "ok" ? given.data : null) : requests;
  const shownError = given?.phase === "error" ? given.error : error;
  const loading = listed === null && !shownError;

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

      <ProblemAlert error={shownError} className="mb-4 empty:mb-0" />
      <div
        ref={result}
        tabIndex={-1}
        role="status"
        aria-live="polite"
        className="mb-4 text-sm font-medium text-ink empty:mb-0"
      >
        {message ?? (loading ? "Loading change requests…" : "")}
      </div>

      {loading && <Skeleton className="h-32 w-full" />}
      {listed === null && shownError !== null && (
        <Button variant="ghost" size="sm" onClick={reload}>
          Try again
        </Button>
      )}
      {listed !== null && listed.length === 0 && (
        <p className="text-sm text-muted">
          {filter === "pending" ? "No pending change requests." : "No change requests."}
        </p>
      )}

      <div className="space-y-4">
        {(listed ?? []).map((request) => (
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
              <RequestButtons
                request={request}
                viewer={viewer}
                busy={busyId === request.id}
                onAct={(action, done) => act(request, action, done)}
              />
            </div>
          </Card>
        ))}
      </div>
    </section>
  );
}
