import {
  Activity,
  Database,
  Scale,
  ShieldCheck,
} from "lucide-react";
import { Link } from "react-router-dom";
import { Card, CardDescription, CardHeader, CardTitle } from "../components/ui/Card";
import { PageHeader } from "../components/ui/PageHeader";
import { Skeleton } from "../components/ui/Skeleton";
import { StatusIndicator } from "../components/ui/StatusIndicator";
import { useHealth } from "../hooks/useHealth";
import { useRuntime } from "../hooks/useRuntime";
import type { RuntimeInfo } from "../lib/api";

const capabilities = [
  {
    icon: Scale,
    title: "Sync evaluate",
    description: "HTTP and gRPC paths with enforce and shadow semantics.",
  },
  {
    icon: Database,
    title: "Evidence chain",
    description: "Hash-linked audit trail with input digest only — no raw PII.",
  },
  {
    icon: ShieldCheck,
    title: "Operator access control",
    description: "Cedar policies decide each operator action; the caller is named by a bearer token.",
  },
  {
    icon: Activity,
    title: "Batch ingest",
    description: "NDJSON worker for partner LOS exports (primary install path).",
    href: "/batch",
  },
] as const;

export default function OverviewPage() {
  const health = useHealth();
  const runtime = useRuntime();

  return (
    <section>
      <PageHeader
        title="Overview"
        hindi="अवलोकन"
        subtitle="System health, active model posture, and governance capabilities for your on-prem deployment."
      />

      {runtime.kind === "ok" && runtime.data.model_pack_mismatch && (
        <div
          role="alert"
          className="mb-6 rounded-lg border border-saffron-400/40 bg-saffron-100/40 px-4 py-3 text-sm text-ink"
        >
          The active model record names a different policy pack than the one running (
          <span className="font-mono">{runtime.data.pack_id}</span>). Evidence records the pack
          actually used; activate a matching pack or model version to resolve this.
        </div>
      )}
      {runtime.kind === "ok" && runtime.data.pointer_drift && (
        <div
          role="alert"
          className="mb-6 rounded-lg border border-saffron-400/40 bg-saffron-100/40 px-4 py-3 text-sm text-ink"
        >
          Another replica applied a governance change this instance has not loaded. Restart it
          to converge.
        </div>
      )}

      <div className="grid gap-4 md:grid-cols-2 xl:grid-cols-3">
        <Card>
          <CardHeader>
            <CardTitle>API health</CardTitle>
            <CardDescription>Sync evaluate service liveness</CardDescription>
          </CardHeader>
          {health.kind === "loading" && <Skeleton className="h-8 w-32" />}
          {health.kind === "ok" && (
            <StatusIndicator status="ok" label={health.status.toUpperCase()} />
          )}
          {health.kind === "error" && (
            <div className="space-y-2">
              <StatusIndicator status="error" label="Unavailable" />
              <p className="text-sm text-muted">{health.message}</p>
              {health.status === 401 || health.status === 403 ? (
                <p className="text-sm text-muted">
                  Set an access token in Settings.
                </p>
              ) : null}
            </div>
          )}
        </Card>

        <Card>
          <CardHeader>
            <CardTitle>Active model</CardTitle>
            <CardDescription>Pinned model record; status and mode are governed</CardDescription>
          </CardHeader>
          {runtime.kind === "loading" && <Skeleton className="h-20 w-full" />}
          {runtime.kind === "error" && (
            <p className="text-sm text-muted">{runtime.message}</p>
          )}
          {runtime.kind === "ok" && (
            <dl className="grid grid-cols-[auto_1fr] gap-x-4 gap-y-2 text-sm">
              <dt className="text-muted">Model</dt>
              <dd>
                <Link
                  to={`/models/${runtime.data.model_id}`}
                  className="font-medium text-kavach-700 hover:text-saffron-600"
                >
                  {runtime.data.model_id}
                </Link>
              </dd>
              <dt className="text-muted">Version</dt>
              <dd className="font-medium text-ink">{runtime.data.model_version}</dd>
              <dt className="text-muted">Pack</dt>
              <dd>
                <Link
                  to={`/policies/${runtime.data.pack_id}`}
                  className="font-medium text-peacock-700 hover:underline"
                >
                  {runtime.data.pack_id}
                </Link>
              </dd>
              <dt className="text-muted">Mode</dt>
              <dd>
                <span className="rounded-md bg-peacock-600/10 px-2 py-0.5 text-xs font-semibold uppercase tracking-wide text-peacock-700">
                  {runtime.data.governance_mode}
                </span>
              </dd>
            </dl>
          )}
        </Card>

        <Card className="md:col-span-2 xl:col-span-1">
          <CardHeader>
            <CardTitle>Jurisdiction</CardTitle>
            <CardDescription>
              {runtime.kind === "ok"
                ? `${runtime.data.sector} sector · India`
                : "Finance sector · India"}
            </CardDescription>
          </CardHeader>
          <p className="text-sm leading-relaxed text-muted">
            Policy pack{" "}
            <code className="rounded bg-stone-100 px-1.5 py-0.5 text-xs text-ink">
              {runtime.kind === "ok" ? runtime.data.pack_id : "finance-v0"}
            </code>{" "}
            sets the rules for credit evaluations (consent presence, DTI thresholds,
            human-review gates). Each evidence record names the pack that decided it.
          </p>
        </Card>
      </div>

      {runtime.kind === "ok" && <PosturePanel runtime={runtime.data} />}

      <div className="mt-8">
        <h2 className="mb-4 text-sm font-semibold uppercase tracking-widest text-muted">
          Platform capabilities
        </h2>
        <div className="grid gap-4 sm:grid-cols-2">
          {capabilities.map((item) => (
            <Card key={item.title} className="flex gap-4">
              <div className="flex h-10 w-10 shrink-0 items-center justify-center rounded-lg bg-kavach-900/5 text-kavach-700">
                <item.icon className="h-5 w-5" aria-hidden />
              </div>
              <div>
                <CardTitle className="text-sm">
                  {"href" in item ? (
                    <Link to={item.href} className="hover:text-saffron-600">
                      {item.title}
                    </Link>
                  ) : (
                    item.title
                  )}
                </CardTitle>
                <CardDescription className="mt-1">{item.description}</CardDescription>
              </div>
            </Card>
          ))}
        </div>
      </div>
    </section>
  );
}

/** What this process runs with: every relaxed guarantee by name, keys, checkpoints, clock. */
function PosturePanel({ runtime }: { runtime: RuntimeInfo }) {
  const relaxed = runtime.relaxations.length > 0;
  const checkpointsKnown = runtime.checkpoint_stalled !== undefined;

  return (
    <Card className="mt-4">
      <CardHeader>
        <CardTitle>Runtime posture</CardTitle>
        <CardDescription>
          Guarantees this process runs with, as reported by <code>/v1/runtime</code>
        </CardDescription>
      </CardHeader>
      <dl className="grid grid-cols-[auto_1fr] gap-x-4 gap-y-3 text-sm">
        <dt className="text-muted">Relaxations</dt>
        <dd>
          {relaxed ? (
            <div className="space-y-1">
              <StatusIndicator
                status="error"
                label={`${runtime.relaxations.length} relaxed${runtime.insecure_dev ? " · --insecure-dev" : ""}`}
              />
              <ul className="flex flex-wrap gap-1.5">
                {runtime.relaxations.map((name) => (
                  <li
                    key={name}
                    className="rounded bg-stone-100 px-1.5 py-0.5 font-mono text-xs text-ink"
                  >
                    {name}
                  </li>
                ))}
              </ul>
            </div>
          ) : (
            <StatusIndicator status="ok" label="None" />
          )}
        </dd>

        <dt className="text-muted">Signing keys</dt>
        <dd>
          {runtime.hsm ? (
            <div className="space-y-1">
              <StatusIndicator
                status={runtime.hsm.healthy ? "ok" : "error"}
                label={`HSM ${runtime.hsm.healthy ? "healthy" : "unhealthy"} · ${runtime.hsm.roles.join(", ")}`}
              />
              {runtime.hsm.error && <p className="text-xs text-muted">{runtime.hsm.error}</p>}
            </div>
          ) : (
            <span className="text-ink">Key files (no HSM configured)</span>
          )}
        </dd>

        <dt className="text-muted">Checkpoints</dt>
        <dd>
          {checkpointsKnown ? (
            <div className="space-y-1">
              <StatusIndicator
                status={runtime.checkpoint_stalled ? "error" : "ok"}
                label={runtime.checkpoint_stalled ? "Stalled" : "Running"}
              />
              <p className="text-xs text-muted">
                Last sequence {runtime.checkpoint_last_seq ?? "none"}
                {runtime.checkpoint_lag_seconds !== undefined &&
                  ` · lag ${runtime.checkpoint_lag_seconds}s`}
                {runtime.checkpoint_uncovered_records !== undefined &&
                  ` · ${runtime.checkpoint_uncovered_records} records not yet covered`}
              </p>
            </div>
          ) : (
            <span className="text-muted">Not reported</span>
          )}
        </dd>

        {runtime.dev_clock && (
          <>
            <dt className="text-muted">Clock</dt>
            <dd>
              <StatusIndicator
                status="error"
                label={`Development clock (${runtime.dev_clock.kind === "fixed" ? "fixed" : "started"} at ${runtime.dev_clock.at})`}
              />
            </dd>
          </>
        )}
      </dl>
    </Card>
  );
}
