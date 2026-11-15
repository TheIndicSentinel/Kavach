import { useRef, useState, type FormEvent } from "react";
import { DecisionEventNotice, DecisionEventView } from "../components/evidence/DecisionEventView";
import { LookupPanel } from "../components/evidence/LookupPanel";
import { Button } from "../components/ui/Button";
import { Card, CardDescription, CardHeader, CardTitle } from "../components/ui/Card";
import { PageHeader } from "../components/ui/PageHeader";
import { TextField } from "../components/ui/TextField";
import { useLookup } from "../hooks/useLookup";
import { fetchDecisionEvent, type DecisionEventLookup } from "../lib/api";
import { EVIDENCE_ID_LENGTH, evidenceIdProblem } from "../lib/evidence";

type Found = { evidenceId: string; lookup: DecisionEventLookup };

export default function DecisionEventsPage() {
  const input = useRef<HTMLInputElement>(null);
  const [evidenceId, setEvidenceId] = useState("");
  const [problem, setProblem] = useState<string | null>(null);
  const { lookup, run } = useLookup<Found>();

  function submit(event: FormEvent) {
    event.preventDefault();
    if (lookup.phase === "loading") return;
    const id = evidenceId.trim();
    const refused = evidenceIdProblem(id);
    setProblem(refused);
    if (refused) {
      input.current?.focus();
      return;
    }
    run(`Looking up decision event ${id}`, async () => ({
      evidenceId: id,
      lookup: await fetchDecisionEvent(id),
    }));
  }

  return (
    <section>
      <PageHeader
        title="Decision events"
        hindi="निर्णय साक्ष्य"
        subtitle="Look up one evaluate (credit) decision event by its evidence id, and get the commands that check it offline."
      />

      <Card className="mb-6">
        <CardHeader>
          <CardTitle>Before you look up an event</CardTitle>
        </CardHeader>
        <DecisionEventNotice />
      </Card>

      <Card>
        <CardHeader>
          <CardTitle>Decision event</CardTitle>
          <CardDescription>By evidence id, as /v1/evaluate returned it.</CardDescription>
        </CardHeader>
        <form onSubmit={submit} noValidate className="flex flex-col gap-3 sm:flex-row sm:items-start">
          <TextField
            id="decision-event-id"
            label="Evidence id"
            value={evidenceId}
            onChange={setEvidenceId}
            hint="A lowercase UUID, like 9771a6c1-edc5-4b2b-b38d-ffb397b7df55"
            error={problem}
            maxLength={EVIDENCE_ID_LENGTH + 8}
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
            Look up event
          </Button>
        </form>
        <LookupPanel
          lookup={lookup}
          done={(found) => `Found decision event ${found.evidenceId}.`}
          render={(found) => (
            <DecisionEventView result={found.lookup} evidenceId={found.evidenceId} />
          )}
        />
      </Card>
    </section>
  );
}
