import { useRef, useState, type ChangeEvent, type FormEvent } from "react";
import {
  ClosedRecordsCounts,
  ClosedRecordsFindings,
  ClosedRecordsNotice,
} from "../components/evidence/ClosedRecordsViews";
import { LookupPanel } from "../components/evidence/LookupPanel";
import { Button } from "../components/ui/Button";
import { Card, CardDescription, CardHeader, CardTitle } from "../components/ui/Card";
import { PageHeader } from "../components/ui/PageHeader";
import { RoleHint } from "../components/ui/RoleHint";
import { useLookup } from "../hooks/useLookup";
import { reconcileClosedRecords, type ClosedRecordsResult } from "../lib/api";
import { useViewer } from "../lib/changeRequests";
import { cn } from "../lib/cn";
import {
  CLOSED_RECORDS_LIMITS,
  parseClosedRecords,
  reconciliationSummary,
} from "../lib/evidence";
import { roleHint, type Viewer } from "../lib/permissions";

const EXAMPLE =
  '{"system": "lms", "records": [{"record_ref": "lms:loan/L-1", "state": "paid", "closed_at": "2026-10-01T06:00:00Z"}]}';

/** `viewer` is for tests; the app passes none and the page reads it. */
export default function ReconciliationPage({ viewer: given }: { viewer?: Viewer }) {
  const current = useViewer();
  const hint = roleHint(given ?? current, "reconcile_closed_records", "reconcile closed loans");
  const listInput = useRef<HTMLTextAreaElement>(null);
  const fileInput = useRef<HTMLInputElement>(null);
  const [list, setList] = useState("");
  const [problems, setProblems] = useState<string[]>([]);
  const { lookup, run, reset } = useLookup<ClosedRecordsResult>();

  function refuse(found: string[]) {
    setProblems(found);
    listInput.current?.focus();
  }

  async function load(event: ChangeEvent<HTMLInputElement>) {
    const file = event.target.files?.[0];
    if (!file) return;
    // Read here, in the browser; nothing is sent until Reconcile.
    if (file.size > CLOSED_RECORDS_LIMITS.textMaxBytes) {
      refuse(["The file is larger than 1 MiB."]);
      return;
    }
    try {
      setList(await file.text());
      setProblems([]);
    } catch {
      refuse(["The file could not be read."]);
    }
  }

  function submit(event: FormEvent) {
    event.preventDefault();
    if (lookup.phase === "loading") return;
    const parsed = parseClosedRecords(list);
    if (!parsed.ok) {
      refuse(parsed.problems);
      return;
    }
    setProblems([]);
    const loans = parsed.body.records.length;
    run(`Reconciling ${loans} ${loans === 1 ? "loan" : "loans"}`, () =>
      reconcileClosedRecords(parsed.body),
    );
  }

  function clear() {
    setList("");
    setProblems([]);
    if (fileInput.current) fileInput.current.value = "";
    reset();
  }

  const invalid = problems.length > 0;

  return (
    <section>
      <PageHeader
        title="Closed loans"
        hindi="बंद ऋण मिलान"
        subtitle="Check the loans the lender reports paid or disputed against the mandates Kavach still holds live for them."
      />

      <Card className="mb-6">
        <CardHeader>
          <CardTitle>Before you reconcile</CardTitle>
        </CardHeader>
        <ClosedRecordsNotice />
      </Card>

      <Card>
        <CardHeader>
          <CardTitle>The lender&apos;s list</CardTitle>
          <CardDescription>
            The same JSON as <code className="font-mono text-xs">kavach reconcile</code> reads.
          </CardDescription>
        </CardHeader>
        {hint ? (
          <RoleHint>{hint}</RoleHint>
        ) : (
          <>
            <form onSubmit={submit} noValidate className="space-y-4">
              <div>
                <label htmlFor="closed-records-file" className="mb-1.5 block text-sm font-medium text-ink">
                  Load from a file (optional)
                </label>
                <input
                  id="closed-records-file"
                  ref={fileInput}
                  type="file"
                  accept="application/json,.json"
                  onChange={load}
                  aria-describedby="closed-records-file-hint"
                  className="block text-sm text-ink file:mr-3 file:rounded-lg file:border file:border-border file:bg-white file:px-3 file:py-1.5 file:text-sm file:font-semibold"
                />
                <p id="closed-records-file-hint" className="mt-1 text-xs text-muted">
                  Read in this browser into the box below. Up to 1 MiB.
                </p>
              </div>
              <div>
                <label htmlFor="closed-records-list" className="mb-1.5 block text-sm font-medium text-ink">
                  Closed loans (JSON)
                </label>
                <textarea
                  id="closed-records-list"
                  ref={listInput}
                  value={list}
                  onChange={(event) => setList(event.target.value)}
                  rows={10}
                  spellCheck={false}
                  autoComplete="off"
                  aria-invalid={invalid || undefined}
                  aria-describedby={
                    invalid ? "closed-records-list-hint closed-records-list-error" : "closed-records-list-hint"
                  }
                  className={cn(
                    "w-full rounded-lg border bg-white px-3 py-2 font-mono text-xs text-ink focus:border-saffron-500 focus:ring-2 focus:ring-saffron-500/20",
                    invalid ? "border-decision-block" : "border-border",
                  )}
                />
                <p id="closed-records-list-hint" className="mt-1 text-xs text-muted">
                  For example: <code className="font-mono">{EXAMPLE}</code>. state is paid or disputed;
                  closed_at is when the lender says it was paid or disputed.
                </p>
                {invalid && (
                  <ul id="closed-records-list-error" className="mt-1 space-y-0.5 text-xs font-medium text-decision-block">
                    {problems.map((problem) => (
                      <li key={problem}>{problem}</li>
                    ))}
                  </ul>
                )}
              </div>
              <div className="flex flex-wrap gap-3">
                <Button
                  type="submit"
                  variant="secondary"
                  className="aria-disabled:cursor-not-allowed aria-disabled:opacity-50"
                  // aria-disabled, not disabled, so keyboard focus stays on the button.
                  aria-disabled={lookup.phase === "loading"}
                >
                  Reconcile
                </Button>
                <Button variant="ghost" onClick={clear}>
                  Clear the list and results
                </Button>
              </div>
            </form>
            <LookupPanel
              lookup={lookup}
              done={reconciliationSummary}
              render={(result) => (
                <div className="space-y-4">
                  <ClosedRecordsCounts result={result} />
                  <ClosedRecordsFindings result={result} />
                </div>
              )}
            />
          </>
        )}
      </Card>
    </section>
  );
}
