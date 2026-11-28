import { useRef, useState, type FormEvent, type RefObject } from "react";
import {
  DecisionRecordView,
  EvidenceNotice,
  RevocationRecordView,
} from "../components/agents/EvidenceViews";
import { LookupPanel } from "../components/evidence/LookupPanel";
import { Button } from "../components/ui/Button";
import { Card, CardDescription, CardHeader, CardTitle } from "../components/ui/Card";
import { PageHeader } from "../components/ui/PageHeader";
import { RoleHint } from "../components/ui/RoleHint";
import { ProblemAlert } from "../components/ui/ProblemAlert";
import { ResourceState } from "../components/ui/ResourceState";
import { TextField } from "../components/ui/TextField";
import { useLookup, type Lookup } from "../hooks/useLookup";
import { LOOKUP_MAX_LENGTH, idProblem, recordIdProblem } from "../lib/agents";
import {
  fetchAgentDecision,
  beginHumanReviewStepUp,
  decideHumanReview,
  fetchHumanReviewSnapshot,
  fetchRevocationRecord,
  fetchUnknownOutcomeReviews,
  type AgentDecisionLookup,
  type HumanReviewSnapshot,
  type HumanReviewDecisionResult,
  type RevocationLookup,
  type UnknownOutcomeReviewPage,
} from "../lib/api";
import type { Resource } from "../hooks/useResource";
import { useViewer } from "../lib/changeRequests";
import { roleHint, type Viewer } from "../lib/permissions";

/** Both lookups read signed evidence: `read_evidence`. */
function evidenceHint(viewer: Viewer): string | null {
  return roleHint(viewer, "read_evidence", "read evidence records");
}

/** Checks every field, focuses the first one refused, and says whether all passed. */
function checkFields(
  checks: { problem: string | null; set: (problem: string | null) => void; ref: RefObject<HTMLInputElement | null> }[],
): boolean {
  let first: RefObject<HTMLInputElement | null> | null = null;
  for (const check of checks) {
    check.set(check.problem);
    if (check.problem && !first) first = check.ref;
  }
  first?.current?.focus();
  return first === null;
}

function DecisionLookup({
  viewer,
  initial,
}: {
  viewer: Viewer;
  initial?: Lookup<AgentDecisionLookup>;
}) {
  const input = useRef<HTMLInputElement>(null);
  const [recordId, setRecordId] = useState("");
  const [problem, setProblem] = useState<string | null>(null);
  const { lookup, run } = useLookup<AgentDecisionLookup>(initial);
  const hint = evidenceHint(viewer);

  function submit(event: FormEvent) {
    event.preventDefault();
    if (lookup.phase === "loading") return;
    const id = recordId.trim();
    if (!checkFields([{ problem: recordIdProblem(id), set: setProblem, ref: input }])) return;
    run(`Looking up record ${id}`, () => fetchAgentDecision(id));
  }

  return (
    <Card>
      <CardHeader>
        <CardTitle>Agent decision record</CardTitle>
        <CardDescription>By record id, with its outcome if one is recorded.</CardDescription>
      </CardHeader>
      {hint ? (
        <RoleHint>{hint}</RoleHint>
      ) : (
        <>
          <form onSubmit={submit} noValidate className="flex flex-col gap-3 sm:flex-row sm:items-start">
            <TextField
              id="decision-record-id"
              label="Record id"
              value={recordId}
              onChange={setRecordId}
              hint="adr:<tenant>:<partition>:<sequence>"
              error={problem}
              maxLength={LOOKUP_MAX_LENGTH}
              ref={input}
              className="flex-1"
            />
            <Button
              type="submit"
              variant="secondary"
              className="sm:mt-7 aria-disabled:cursor-not-allowed aria-disabled:opacity-50"
              // aria-disabled, not disabled, so keyboard focus stays on the button.
              aria-disabled={lookup.phase === "loading"}
            >
              Look up record
            </Button>
          </form>
          <LookupPanel
            lookup={lookup}
            notFound="No agent decision record with that id on this server."
            done={(result) => `Found record ${result.record.record_id}.`}
            render={(result) => <DecisionRecordView result={result} />}
          />
        </>
      )}
    </Card>
  );
}

function HumanReviewLookup({
  viewer,
  initial,
}: {
  viewer: Viewer;
  initial?: Lookup<HumanReviewSnapshot>;
}) {
  const input = useRef<HTMLInputElement>(null);
  const [recordId, setRecordId] = useState("");
  const [problem, setProblem] = useState<string | null>(null);
  const [stepUpError, setStepUpError] = useState<unknown>(null);
  const [startingStepUp, setStartingStepUp] = useState(false);
  const [decisionError, setDecisionError] = useState<unknown>(null);
  const [savingDecision, setSavingDecision] = useState(false);
  const [decisionResult, setDecisionResult] = useState<HumanReviewDecisionResult | null>(null);
  const { lookup, run } = useLookup<HumanReviewSnapshot>(initial);
  const hint = roleHint(viewer, "approve_human_review", "review HUMAN_REVIEW actions");

  async function startStepUp(recordId: string) {
    if (startingStepUp) return;
    setStartingStepUp(true);
    setStepUpError(null);
    try {
      const started = await beginHumanReviewStepUp(recordId);
      window.location.assign(started.authorization_url);
    } catch (error) {
      setStepUpError(error);
      setStartingStepUp(false);
    }
  }

  async function decide(recordId: string, decision: "approve" | "reject") {
    if (savingDecision) return;
    setSavingDecision(true);
    setDecisionError(null);
    setDecisionResult(null);
    try {
      setDecisionResult(await decideHumanReview(recordId, decision));
    } catch (error) {
      setDecisionError(error);
    } finally {
      setSavingDecision(false);
    }
  }

  function submit(event: FormEvent) {
    event.preventDefault();
    if (lookup.phase === "loading") return;
    const id = recordId.trim();
    if (!checkFields([{ problem: recordIdProblem(id), set: setProblem, ref: input }])) return;
    run(`Loading human review ${id}`, () => fetchHumanReviewSnapshot(id));
  }

  return (
    <Card>
      <CardHeader>
        <CardTitle>Human review</CardTitle>
        <CardDescription>
          Review the exact action held for this signed decision. This view does not approve or release it.
        </CardDescription>
      </CardHeader>
      {hint ? <RoleHint>{hint}</RoleHint> : (
        <>
          <form onSubmit={submit} noValidate className="flex flex-col gap-3 sm:flex-row sm:items-start">
            <TextField
              id="human-review-record-id"
              label="Decision record id"
              value={recordId}
              onChange={setRecordId}
              hint="adr:<tenant>:<partition>:<sequence>"
              error={problem}
              maxLength={LOOKUP_MAX_LENGTH}
              ref={input}
              className="flex-1"
            />
            <Button
              type="submit"
              variant="secondary"
              className="sm:mt-7 aria-disabled:cursor-not-allowed aria-disabled:opacity-50"
              aria-disabled={lookup.phase === "loading"}
            >
              {lookup.phase === "loading" ? "Loading review…" : "Load human review"}
            </Button>
          </form>
          <LookupPanel
            lookup={lookup}
            notFound="No live human-review snapshot is available for that decision record."
            done={(result) => `Loaded the exact action for ${result.record_id}.`}
            render={(result) => (
              <div className="rounded-lg border border-border bg-surface p-4">
                <dl className="grid gap-3 text-sm sm:grid-cols-[max-content_1fr]">
                  <dt className="text-muted">Decision record</dt><dd className="break-all font-mono text-xs">{result.record_id}</dd>
                  <dt className="text-muted">Action digest</dt><dd className="break-all font-mono text-xs">{result.action_hash}</dd>
                  <dt className="text-muted">Agent</dt><dd>{result.agent_id}</dd>
                  <dt className="text-muted">Action</dt><dd>{result.action}</dd>
                  <dt className="text-muted">Subject reference</dt><dd className="break-all font-mono text-xs">{result.subject_ref}</dd>
                  {result.channel && <><dt className="text-muted">Channel</dt><dd>{result.channel}</dd></>}
                  {result.waiver_bps !== null && result.waiver_bps !== undefined && <><dt className="text-muted">Waiver</dt><dd>{result.waiver_bps} bps</dd></>}
                  <dt className="text-muted">Requested fields</dt>
                  <dd>{result.requested_fields.length ? result.requested_fields.join(", ") : "None"}</dd>
                  <dt className="text-muted">Parameters</dt>
                  <dd>
                    {Object.keys(result.parameters).length ? (
                      <dl className="grid grid-cols-[max-content_1fr] gap-x-3 gap-y-1">
                        {Object.entries(result.parameters).map(([name, value]) => (
                          <div key={name} className="contents"><dt className="text-muted">{name}</dt><dd className="break-all font-mono text-xs">{value}</dd></div>
                        ))}
                      </dl>
                    ) : "None"}
                  </dd>
                  <dt className="text-muted">Snapshot expires</dt><dd>{new Date(result.expires_at).toLocaleString()}</dd>
                </dl>
                <div className="mt-5 border-t border-border pt-4">
                  <p className="mb-3 text-sm text-muted">
                    Passkey verification is bound to this exact action. After verification, choose approve or reject. Approval records a short-lived execution handoff; it does not send the action.
                  </p>
                  <Button
                    variant="secondary"
                    aria-disabled={startingStepUp}
                    className="aria-disabled:cursor-not-allowed aria-disabled:opacity-50"
                    onClick={() => void startStepUp(result.record_id)}
                  >
                    {startingStepUp ? "Starting passkey verification…" : "Continue to passkey verification"}
                  </Button>
                  <p role="status" aria-live="polite" className="mt-2 text-sm text-muted">
                    {startingStepUp ? "Starting the identity-provider step-up flow…" : ""}
                  </p>
                  <ProblemAlert error={stepUpError} className="mt-3" />
                </div>
                <div className="mt-4 border-t border-border pt-4">
                  <div className="flex flex-wrap gap-2">
                    <Button
                      disabled={savingDecision}
                      onClick={() => void decide(result.record_id, "approve")}
                    >
                      {savingDecision ? "Recording decision…" : "Approve exact action"}
                    </Button>
                    <Button
                      variant="secondary"
                      disabled={savingDecision}
                      onClick={() => void decide(result.record_id, "reject")}
                    >
                      Reject exact action
                    </Button>
                  </div>
                  <ProblemAlert error={decisionError} className="mt-3" />
                  {decisionResult && (
                    <div role="status" aria-live="polite" className="mt-3 rounded-lg border border-border bg-surface p-3 text-sm">
                      <p>Decision recorded: <strong>{decisionResult.decision}</strong>. Expires {new Date(decisionResult.expires_at).toLocaleString()}.</p>
                      {decisionResult.decision === "approve" && decisionResult.execution_id && (
                        <dl className="mt-2 grid gap-2 sm:grid-cols-[max-content_1fr]">
                          <dt className="text-muted">Approval ID</dt><dd className="break-all font-mono text-xs">{decisionResult.approval_id}</dd>
                          <dt className="text-muted">Execution ID</dt><dd className="break-all font-mono text-xs">{decisionResult.execution_id}</dd>
                          <dt className="text-muted">Agent handoff</dt><dd>Send both IDs with the original request ID and unchanged action parameters.</dd>
                        </dl>
                      )}
                      {decisionResult.decision === "reject" && <p className="mt-1">The action was rejected and cannot be executed from this decision.</p>}
                    </div>
                  )}
                </div>
              </div>
            )}
          />
        </>
      )}
    </Card>
  );
}

function RevocationLookupCard({
  viewer,
  initial,
}: {
  viewer: Viewer;
  initial?: Lookup<RevocationLookup>;
}) {
  const systemInput = useRef<HTMLInputElement>(null);
  const eventInput = useRef<HTMLInputElement>(null);
  const [system, setSystem] = useState("");
  const [eventId, setEventId] = useState("");
  const [systemProblem, setSystemProblem] = useState<string | null>(null);
  const [eventProblem, setEventProblem] = useState<string | null>(null);
  const { lookup, run } = useLookup<RevocationLookup>(initial);
  const hint = evidenceHint(viewer);

  function submit(event: FormEvent) {
    event.preventDefault();
    if (lookup.phase === "loading") return;
    const sys = system.trim();
    const evt = eventId.trim();
    const ok = checkFields([
      { problem: idProblem("system", sys), set: setSystemProblem, ref: systemInput },
      { problem: idProblem("event id", evt), set: setEventProblem, ref: eventInput },
    ]);
    if (!ok) return;
    run(`Looking up the revocation for event ${evt} from ${sys}`, () =>
      fetchRevocationRecord(sys, evt),
    );
  }

  return (
    <Card>
      <CardHeader>
        <CardTitle>Revocation record</CardTitle>
        <CardDescription>
          The signed record a system-of-record event produced, if one was written. It names the
          loan only by a keyed pseudonym.
        </CardDescription>
      </CardHeader>
      {hint ? (
        <RoleHint>{hint}</RoleHint>
      ) : (
        <>
          <form onSubmit={submit} noValidate className="grid gap-3 sm:grid-cols-[1fr_1fr_auto] sm:items-start">
            <TextField
              id="revocation-system"
              label="System"
              value={system}
              onChange={setSystem}
              hint="The system of record that sent the event."
              error={systemProblem}
              maxLength={LOOKUP_MAX_LENGTH}
              ref={systemInput}
            />
            <TextField
              id="revocation-event-id"
              label="Event id"
              value={eventId}
              onChange={setEventId}
              error={eventProblem}
              maxLength={LOOKUP_MAX_LENGTH}
              ref={eventInput}
            />
            <Button
              type="submit"
              variant="secondary"
              className="sm:mt-7 aria-disabled:cursor-not-allowed aria-disabled:opacity-50"
              // aria-disabled, not disabled, so keyboard focus stays on the button.
              aria-disabled={lookup.phase === "loading"}
            >
              Look up revocation
            </Button>
          </form>
          <LookupPanel
            lookup={lookup}
            notFound="No revocation record for that system and event id on this server."
            done={(result) =>
              `Found the revocation for event ${result.record.event_id} from ${result.record.source_system}.`
            }
            render={(result) => <RevocationRecordView result={result} />}
          />
        </>
      )}
    </Card>
  );
}

function reviewState(state: string): string {
  switch (state) {
    case "confirmed_delivered": return "Confirmed delivered";
    case "confirmed_not_delivered": return "Confirmed not delivered";
    case "ambiguous": return "Ambiguous";
    case "conflicted": return "Conflicted";
    default: return "Unresolved";
  }
}

function reviewTime(value: string): string {
  const date = new Date(value);
  return Number.isNaN(date.valueOf()) ? "Unknown" : date.toLocaleString();
}

function UnknownOutcomeReview({ viewer, initial }: { viewer: Viewer; initial?: Resource<UnknownOutcomeReviewPage> }) {
  const [resource, setResource] = useState<Resource<UnknownOutcomeReviewPage> | null>(initial ?? null);
  const [loading, setLoading] = useState(false);
  const [loadingMore, setLoadingMore] = useState(false);
  const [pageError, setPageError] = useState<unknown>(null);
  const hint = evidenceHint(viewer);

  async function load(cursor?: string) {
    if (loading || loadingMore) return;
    if (cursor) setLoadingMore(true);
    else {
      setLoading(true);
      setResource({ phase: "loading" });
    }
    setPageError(null);
    try {
      const page = await fetchUnknownOutcomeReviews({ limit: 50, ...(cursor ? { cursor } : {}) });
      setResource((current) => ({
        phase: "ok",
        data: cursor && current?.phase === "ok"
          ? { items: [...current.data.items, ...page.items], next_cursor: page.next_cursor }
          : page,
      }));
    } catch (error) {
      if (cursor) setPageError(error);
      else setResource({ phase: "error", error });
    } finally {
      setLoading(false);
      setLoadingMore(false);
    }
  }

  return (
    <Card>
      <CardHeader>
        <CardTitle>Unknown outcome review</CardTitle>
        <CardDescription>
          Loads every unknown outcome and its signed resolution history, including ambiguous and conflicted cases. This read is audited; it does not resend a message or release a contact slot.
        </CardDescription>
      </CardHeader>
      {hint ? <RoleHint>{hint}</RoleHint> : (
        <>
          <Button variant="secondary" aria-disabled={loading || loadingMore} onClick={() => { void load(); }}>
            {resource?.phase === "ok" ? "Refresh review" : loading ? "Loading review…" : resource?.phase === "error" ? "Try review again" : "Load unknown outcomes"}
          </Button>
          {resource && (
            <div className="mt-4">
              <ResourceState
                resource={resource}
                loading="Loading and auditing unknown outcomes…"
                summary={(page) => `${page.items.length} unknown ${page.items.length === 1 ? "outcome" : "outcomes"} loaded${page.next_cursor ? "; more are available" : "."}`}
                onRetry={() => { void load(); }}
              >
                {(page) => page.items.length === 0 ? (
                  <p className="text-sm text-muted">No unknown outcomes are recorded for this tenant.</p>
                ) : (
                  <div className="overflow-x-auto">
                    <table className="w-full min-w-[52rem] border-collapse text-left text-sm">
                      <thead><tr className="border-b border-border text-xs uppercase tracking-wide text-muted">
                        <th scope="col" className="px-3 py-3 font-semibold">Credential</th>
                        <th scope="col" className="px-3 py-3 font-semibold">Action</th>
                        <th scope="col" className="px-3 py-3 font-semibold">Unknown since</th>
                        <th scope="col" className="px-3 py-3 font-semibold">Governing state</th>
                        <th scope="col" className="px-3 py-3 font-semibold">History</th>
                      </tr></thead>
                      <tbody>
                        {page.items.map((item) => (
                          <tr key={item.outcome.credential_id} className="border-b border-border align-top last:border-0">
                            <th scope="row" className="break-all px-3 py-3 font-mono text-xs font-medium text-ink">{item.outcome.credential_id}</th>
                            <td className="px-3 py-3 text-ink">{item.action}</td>
                            <td className="px-3 py-3 text-muted">{reviewTime(item.outcome.ts)}</td>
                            <td className="px-3 py-3 text-ink">
                              {reviewState(item.governing_state)}{item.governing_source ? ` · ${item.governing_source}` : ""}
                            </td>
                            <td className="px-3 py-3 text-muted">
                              {item.resolutions.length === 0 ? "No resolution" : (
                                <ul className="space-y-1">
                                  {item.resolutions.map((row) => (
                                    <li key={`${row.ts}-${row.source}-${row.state}`}>
                                      {reviewState(row.state)} · {row.source} · {row.reason} · {reviewTime(row.ts)}
                                    </li>
                                  ))}
                                </ul>
                              )}
                            </td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                )}
              </ResourceState>
              {resource?.phase === "ok" && resource.data.next_cursor && (
                <Button variant="ghost" className="mt-4" aria-disabled={loadingMore} onClick={() => { void load(resource.data.next_cursor ?? undefined); }}>
                  {loadingMore ? "Loading more…" : "Load more unknown outcomes"}
                </Button>
              )}
              <ProblemAlert error={pageError} className="mt-3" />
            </div>
          )}
        </>
      )}
    </Card>
  );
}

type AgentEvidencePageProps = {
  /** For tests; the app passes none and the page reads it. */
  viewer?: Viewer;
  /** For tests: each lookup's phase, as if it had been submitted. */
  decision?: Lookup<AgentDecisionLookup>;
  humanReview?: Lookup<HumanReviewSnapshot>;
  revocation?: Lookup<RevocationLookup>;
  /** For tests: the on-demand unknown-outcome review state. */
  review?: Resource<UnknownOutcomeReviewPage>;
};

export default function AgentEvidencePage({
  viewer: given,
  decision,
  humanReview,
  revocation,
  review,
}: AgentEvidencePageProps) {
  const current = useViewer();
  const viewer = given ?? current;
  return (
    <section>
      <PageHeader
        title="Agent evidence"
        hindi="साक्ष्य"
        subtitle="Look up one signed record at a time: an agent decision record by its id, or a revocation record by system and event id."
      />

      <Card className="mb-6">
        <CardHeader>
          <CardTitle>Before you look up a record</CardTitle>
        </CardHeader>
        <EvidenceNotice />
      </Card>

      <div className="space-y-6">
        <UnknownOutcomeReview viewer={viewer} initial={review} />
        <HumanReviewLookup viewer={viewer} initial={humanReview} />
        <DecisionLookup viewer={viewer} initial={decision} />
        <RevocationLookupCard viewer={viewer} initial={revocation} />
      </div>
    </section>
  );
}
