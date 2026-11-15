import { useMemo, useRef, useState } from "react";
import { Play, RotateCcw } from "lucide-react";
import { Button } from "../components/ui/Button";
import {
  Card,
  CardDescription,
  CardHeader,
  CardTitle,
} from "../components/ui/Card";
import { DecisionBadge } from "../components/ui/DecisionBadge";
import { PageHeader } from "../components/ui/PageHeader";
import { ProblemAlert } from "../components/ui/ProblemAlert";
import { RoleHint } from "../components/ui/RoleHint";
import { evaluateRequest, type EvaluateResponse } from "../lib/api";
import { useViewer } from "../lib/changeRequests";
import { cn } from "../lib/cn";
import { buildPartnerSampleRequest } from "../lib/constants";
import { formatInr } from "../lib/format";
import { roleHint, type Viewer } from "../lib/permissions";

function buildSampleRequest(): string {
  return buildPartnerSampleRequest();
}

/** What the status region says: loading, the decision, or nothing. */
function evaluateStatus(loading: boolean, result: EvaluateResponse | null): string {
  if (loading) return "Evaluating the request…";
  if (result) return `Evaluated: returned decision ${result.returned_decision}.`;
  return "";
}

/** `viewer` is for tests; the app passes none and the page reads it. */
export default function EvaluatePage({ viewer: given }: { viewer?: Viewer }) {
  const current = useViewer();
  const hint = roleHint(given ?? current, "evaluate", "run evaluate");
  const initialRequest = useMemo(() => buildSampleRequest(), []);
  const textarea = useRef<HTMLTextAreaElement>(null);
  const [input, setInput] = useState(initialRequest);
  const [result, setResult] = useState<EvaluateResponse | null>(null);
  // A JSON problem belongs to the field; an API refusal goes to role=alert.
  const [jsonProblem, setJsonProblem] = useState<string | null>(null);
  const [error, setError] = useState<unknown>(null);
  const [loading, setLoading] = useState(false);

  async function onSubmit(event: React.FormEvent) {
    event.preventDefault();
    if (loading) return;
    setError(null);
    setResult(null);
    let body: unknown;
    try {
      body = JSON.parse(input) as unknown;
    } catch {
      setJsonProblem("This is not valid JSON. Check the request formatting.");
      textarea.current?.focus();
      return;
    }
    setJsonProblem(null);
    setLoading(true);
    try {
      setResult(await evaluateRequest(body));
    } catch (err) {
      setError(err);
    } finally {
      setLoading(false);
    }
  }

  function resetSample() {
    setInput(buildSampleRequest());
    setResult(null);
    setError(null);
    setJsonProblem(null);
  }

  const parsedInput = useMemo(() => {
    try {
      return JSON.parse(input) as {
        input?: { loan_amount?: number; monthly_income_inr?: number };
      };
    } catch {
      return null;
    }
  }, [input]);

  return (
    <section>
      <PageHeader
        title="Evaluate"
        hindi="मूल्यांकन"
        subtitle="Submit a sync evaluate request against the active finance model. Uses partner-shaped payload fields with en-IN formatting."
        action={
          <Button variant="ghost" size="sm" onClick={resetSample}>
            <RotateCcw className="h-4 w-4" aria-hidden />
            Reset sample
          </Button>
        }
      />

      {parsedInput?.input?.loan_amount != null && (
        <p className="mb-4 text-sm text-muted">
          Loan amount in request:{" "}
          <span className="font-semibold text-ink">
            {formatInr(parsedInput.input.loan_amount)}
          </span>
          {parsedInput.input.monthly_income_inr != null && (
            <>
              {" "}
              · Monthly income:{" "}
              <span className="font-semibold text-ink">
                {formatInr(parsedInput.input.monthly_income_inr)}
              </span>
            </>
          )}
        </p>
      )}

      <form onSubmit={onSubmit} className="space-y-4">
        <Card>
          <CardHeader>
            <CardTitle>EvaluateRequest</CardTitle>
            <CardDescription>
              POST /v1/evaluate — governance mode is not caller-controlled.
            </CardDescription>
          </CardHeader>
          <label htmlFor="request-json" className="sr-only">
            EvaluateRequest JSON
          </label>
          <textarea
            id="request-json"
            ref={textarea}
            value={input}
            onChange={(event) => setInput(event.target.value)}
            rows={20}
            spellCheck={false}
            aria-invalid={jsonProblem ? true : undefined}
            aria-describedby={jsonProblem ? "request-json-error" : undefined}
            className={cn(
              "w-full rounded-lg border bg-stone-50/50 p-4 font-mono text-sm leading-relaxed text-ink focus:border-saffron-500 focus:ring-2 focus:ring-saffron-500/20",
              jsonProblem ? "border-decision-block" : "border-border",
            )}
          />
          {jsonProblem && (
            <p id="request-json-error" className="mt-1 text-xs font-medium text-decision-block">
              {jsonProblem}
            </p>
          )}
          <div className="mt-4 flex items-center gap-3">
            {hint ? (
              <RoleHint>{hint}</RoleHint>
            ) : (
              <Button
                type="submit"
                className="aria-disabled:cursor-not-allowed aria-disabled:opacity-50"
                // aria-disabled, not disabled, so keyboard focus stays on the button.
                aria-disabled={loading}
              >
                <Play className="h-4 w-4" aria-hidden />
                Run evaluate
              </Button>
            )}
          </div>
        </Card>
      </form>

      <ProblemAlert error={error} className="mt-4 empty:mt-0" />
      <p role="status" aria-live="polite" className="mt-4 text-sm text-muted empty:mt-0">
        {evaluateStatus(loading, result)}
      </p>

      {result && (
        <Card className="mt-4">
          <CardHeader>
            <CardTitle>Decision</CardTitle>
            <CardDescription>
              Policy vs returned decision per active governance mode.
            </CardDescription>
          </CardHeader>

          <div className="mb-6 grid gap-4 sm:grid-cols-2">
            <div className="rounded-lg border border-border bg-stone-50/80 p-4">
              <p className="text-xs font-semibold uppercase tracking-wide text-muted">
                Returned decision
              </p>
              <div className="mt-2">
                <DecisionBadge decision={result.returned_decision} />
              </div>
            </div>
            <div className="rounded-lg border border-border bg-stone-50/80 p-4">
              <p className="text-xs font-semibold uppercase tracking-wide text-muted">
                Policy decision
              </p>
              <div className="mt-2">
                <DecisionBadge decision={result.policy_decision} />
              </div>
            </div>
          </div>

          <dl className="mb-4 grid grid-cols-[auto_1fr] gap-x-4 gap-y-2 text-sm">
            <dt className="text-muted">Evidence ID</dt>
            <dd className="font-mono text-xs text-ink">
              {result.evidence_id ?? "—"}
            </dd>
            <dt className="text-muted">Reason codes</dt>
            <dd className="font-medium text-ink">
              {result.reason_codes.length > 0
                ? result.reason_codes.join(", ")
                : "—"}
            </dd>
          </dl>

          <details className="group">
            <summary className="cursor-pointer text-sm font-medium text-kavach-700 hover:text-kavach-900">
              Raw response JSON
            </summary>
            <pre className="mt-3 overflow-auto rounded-lg bg-kavach-950 p-4 text-xs text-stone-200">
              {JSON.stringify(result, null, 2)}
            </pre>
          </details>
        </Card>
      )}
    </section>
  );
}
