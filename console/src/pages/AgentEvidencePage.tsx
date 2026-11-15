import { useRef, useState, type FormEvent, type ReactNode, type RefObject } from "react";
import {
  DecisionRecordView,
  EvidenceNotice,
  RevocationRecordView,
} from "../components/agents/EvidenceViews";
import { Button } from "../components/ui/Button";
import { Card, CardDescription, CardHeader, CardTitle } from "../components/ui/Card";
import { PageHeader } from "../components/ui/PageHeader";
import { ProblemAlert } from "../components/ui/ProblemAlert";
import { RoleHint } from "../components/ui/RoleHint";
import { TextField } from "../components/ui/TextField";
import { LOOKUP_MAX_LENGTH, idProblem, recordIdProblem } from "../lib/agents";
import {
  fetchAgentDecision,
  fetchRevocationRecord,
  type AgentDecisionLookup,
  type RevocationLookup,
} from "../lib/api";
import { useViewer } from "../lib/changeRequests";
import { roleHint, type Viewer } from "../lib/permissions";

/** Both lookups read signed evidence: `read_evidence`. */
function evidenceHint(viewer: Viewer): string | null {
  return roleHint(viewer, "read_evidence", "read evidence records");
}

type Lookup<T> =
  | { phase: "idle" }
  | { phase: "loading"; what: string }
  | { phase: "done"; what: string; result: T }
  | { phase: "error"; what: string; error: unknown };

/**
 * One lookup at a time, started only by a submit: each call is audited and
 * rate limited, so nothing here fetches on its own or on every keystroke.
 */
function useLookup<T>() {
  const [lookup, setLookup] = useState<Lookup<T>>({ phase: "idle" });
  const latest = useRef(0);

  function run(what: string, call: () => Promise<T>) {
    const id = ++latest.current;
    setLookup({ phase: "loading", what });
    call().then(
      (result) => {
        if (latest.current === id) setLookup({ phase: "done", what, result });
      },
      (error: unknown) => {
        if (latest.current === id) setLookup({ phase: "error", what, error });
      },
    );
  }

  return { lookup, run };
}

function lookupStatus(lookup: Lookup<unknown>): string {
  switch (lookup.phase) {
    case "loading":
      return `Looking up ${lookup.what}…`;
    case "done":
      return `Found ${lookup.what}.`;
    default:
      return "";
  }
}

function LookupResult<T>({
  lookup,
  render,
}: {
  lookup: Lookup<T>;
  render: (result: T) => ReactNode;
}) {
  return (
    <div className="mt-6">
      <ProblemAlert error={lookup.phase === "error" ? lookup.error : null} className="mb-4 empty:mb-0" />
      <p role="status" aria-live="polite" className="mb-4 text-sm text-muted empty:mb-0">
        {lookupStatus(lookup)}
      </p>
      {lookup.phase === "done" && render(lookup.result)}
    </div>
  );
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

function DecisionLookup({ viewer }: { viewer: Viewer }) {
  const input = useRef<HTMLInputElement>(null);
  const [recordId, setRecordId] = useState("");
  const [problem, setProblem] = useState<string | null>(null);
  const { lookup, run } = useLookup<AgentDecisionLookup>();
  const hint = evidenceHint(viewer);

  function submit(event: FormEvent) {
    event.preventDefault();
    if (lookup.phase === "loading") return;
    const id = recordId.trim();
    if (!checkFields([{ problem: recordIdProblem(id), set: setProblem, ref: input }])) return;
    run(`record ${id}`, () => fetchAgentDecision(id));
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
          <LookupResult
            lookup={lookup}
            render={(result) => <DecisionRecordView result={result} />}
          />
        </>
      )}
    </Card>
  );
}

function RevocationLookupCard({ viewer }: { viewer: Viewer }) {
  const systemInput = useRef<HTMLInputElement>(null);
  const eventInput = useRef<HTMLInputElement>(null);
  const [system, setSystem] = useState("");
  const [eventId, setEventId] = useState("");
  const [systemProblem, setSystemProblem] = useState<string | null>(null);
  const [eventProblem, setEventProblem] = useState<string | null>(null);
  const { lookup, run } = useLookup<RevocationLookup>();
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
    run(`the revocation for event ${evt} from ${sys}`, () => fetchRevocationRecord(sys, evt));
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
          <LookupResult
            lookup={lookup}
            render={(result) => <RevocationRecordView result={result} />}
          />
        </>
      )}
    </Card>
  );
}

/** `viewer` is for tests; the app passes none and the page reads it. */
export default function AgentEvidencePage({ viewer: given }: { viewer?: Viewer }) {
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
        <DecisionLookup viewer={viewer} />
        <RevocationLookupCard viewer={viewer} />
      </div>
    </section>
  );
}
