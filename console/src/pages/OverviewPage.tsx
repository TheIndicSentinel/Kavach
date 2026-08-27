import { useEffect, useState } from "react";
import { fetchHealth } from "../api";

type HealthState =
  | { kind: "loading" }
  | { kind: "ok"; status: string }
  | { kind: "error"; message: string };

export default function OverviewPage() {
  const [health, setHealth] = useState<HealthState>({ kind: "loading" });

  useEffect(() => {
    let cancelled = false;
    fetchHealth()
      .then((payload) => {
        if (!cancelled) {
          setHealth({ kind: "ok", status: payload.status });
        }
      })
      .catch((err: Error) => {
        if (!cancelled) {
          setHealth({ kind: "error", message: err.message });
        }
      });
    return () => {
      cancelled = true;
    };
  }, []);

  return (
    <section>
      <header className="page-header">
        <h1>Overview</h1>
        <p>Sync evaluate API health and deployment posture.</p>
      </header>

      <div className="card-grid">
        <article className="card">
          <h2>API health</h2>
          {health.kind === "loading" && <p className="muted">Checking…</p>}
          {health.kind === "ok" && (
            <p className="status-pill ok">{health.status}</p>
          )}
          {health.kind === "error" && (
            <p className="status-pill error">{health.message}</p>
          )}
        </article>

        <article className="card">
          <h2>Milestone B</h2>
          <ul className="feature-list">
            <li>Cedar RBAC on API routes</li>
            <li>Static console served from `kavach-api`</li>
            <li>Policy lifecycle UI (next)</li>
          </ul>
        </article>
      </div>
    </section>
  );
}
