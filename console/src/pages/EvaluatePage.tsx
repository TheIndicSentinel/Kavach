import { useState } from "react";
import { evaluateRequest, type EvaluateResponse } from "../api";

const SAMPLE_REQUEST = `{
  "model_id": "credit-underwriting-v1",
  "model_version": "1.0.0",
  "purpose": "credit_decision",
  "consent": {
    "purpose_id": "credit_decision",
    "timestamp": "2026-08-27T12:00:00Z"
  },
  "input": {
    "credit_score": 740,
    "income": 85000,
    "debt_ratio": 0.32,
    "loan_amount": 300000,
    "employment_years": 6
  },
  "confidence": 0.89,
  "decision_time": "2026-08-27T12:00:01Z",
  "correlation_id": "console-demo-001"
}`;

export default function EvaluatePage() {
  const [input, setInput] = useState(SAMPLE_REQUEST);
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
      setError(err instanceof Error ? err.message : "evaluate failed");
    } finally {
      setLoading(false);
    }
  }

  return (
    <section>
      <header className="page-header">
        <h1>Evaluate</h1>
        <p>Send a sync evaluate request to `/v1/evaluate`.</p>
      </header>

      <form className="card evaluate-form" onSubmit={onSubmit}>
        <label htmlFor="request-json">EvaluateRequest JSON</label>
        <textarea
          id="request-json"
          value={input}
          onChange={(event) => setInput(event.target.value)}
          rows={18}
          spellCheck={false}
        />
        <div className="form-actions">
          <button type="submit" disabled={loading}>
            {loading ? "Evaluating…" : "Run evaluate"}
          </button>
        </div>
      </form>

      {error && (
        <article className="card error-card">
          <h2>Error</h2>
          <pre>{error}</pre>
        </article>
      )}

      {result && (
        <article className="card">
          <h2>Response</h2>
          <dl className="result-grid">
            <dt>Returned decision</dt>
            <dd>{result.returned_decision}</dd>
            <dt>Policy decision</dt>
            <dd>{result.policy_decision}</dd>
            <dt>Evidence ID</dt>
            <dd>{result.evidence_id ?? "—"}</dd>
          </dl>
          <pre>{JSON.stringify(result, null, 2)}</pre>
        </article>
      )}
    </section>
  );
}
