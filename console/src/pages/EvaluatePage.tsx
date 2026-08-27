import { useMemo, useState } from "react";
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
import { ApiError, evaluateRequest, type EvaluateResponse } from "../lib/api";
import { buildPartnerSampleRequest } from "../lib/constants";
import { formatInr } from "../lib/format";

function buildSampleRequest(): string {
  return buildPartnerSampleRequest();
}

export default function EvaluatePage() {
  const initialRequest = useMemo(() => buildSampleRequest(), []);
  const [input, setInput] = useState(initialRequest);
  const [result, setResult] = useState<EvaluateResponse | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);

  async function onSubmit(event: React.FormEvent) {
    event.preventDefault();
    setLoading(true);
    setError(null);
    setResult(null);
    try {
      const body = JSON.parse(input) as unknown;
      const response = await evaluateRequest(body);
      setResult(response);
    } catch (err) {
      if (err instanceof SyntaxError) {
        setError("Invalid JSON — check request formatting.");
      } else if (err instanceof ApiError) {
        setError(err.message);
      } else {
        setError(err instanceof Error ? err.message : "Evaluate failed");
      }
    } finally {
      setLoading(false);
    }
  }

  function resetSample() {
    setInput(buildSampleRequest());
    setResult(null);
    setError(null);
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
            value={input}
            onChange={(event) => setInput(event.target.value)}
            rows={20}
            spellCheck={false}
            className="w-full rounded-lg border border-border bg-stone-50/50 p-4 font-mono text-sm leading-relaxed text-ink focus:border-saffron-500 focus:ring-2 focus:ring-saffron-500/20"
          />
          <div className="mt-4 flex items-center gap-3">
            <Button type="submit" disabled={loading}>
              <Play className="h-4 w-4" aria-hidden />
              {loading ? "Evaluating…" : "Run evaluate"}
            </Button>
          </div>
        </Card>
      </form>

      {error && (
        <Card className="mt-4 border-decision-block/30 bg-decision-block-bg/30">
          <CardHeader>
            <CardTitle className="text-decision-block">Request failed</CardTitle>
            <CardDescription>{error}</CardDescription>
          </CardHeader>
        </Card>
      )}

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
