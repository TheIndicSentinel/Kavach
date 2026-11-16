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
import { TextField } from "../components/ui/TextField";
import { useLookup, type Lookup } from "../hooks/useLookup";
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

type AgentEvidencePageProps = {
  /** For tests; the app passes none and the page reads it. */
  viewer?: Viewer;
  /** For tests: each lookup's phase, as if it had been submitted. */
  decision?: Lookup<AgentDecisionLookup>;
  revocation?: Lookup<RevocationLookup>;
};

export default function AgentEvidencePage({
  viewer: given,
  decision,
  revocation,
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
        <DecisionLookup viewer={viewer} initial={decision} />
        <RevocationLookupCard viewer={viewer} initial={revocation} />
      </div>
    </section>
  );
}
