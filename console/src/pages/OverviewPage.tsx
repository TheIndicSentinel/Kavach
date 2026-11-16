import {
  Activity,
  Database,
  Scale,
  ShieldCheck,
} from "lucide-react";
import { Link } from "react-router-dom";
import { Card, CardDescription, CardHeader, CardTitle } from "../components/ui/Card";
import { PageHeader } from "../components/ui/PageHeader";
import { ResourceState } from "../components/ui/ResourceState";
import { Skeleton } from "../components/ui/Skeleton";
import { StatusIndicator } from "../components/ui/StatusIndicator";
import { useResource, type Resource } from "../hooks/useResource";
import { fetchHealth, fetchRuntime, type RuntimeInfo } from "../lib/api";

const capabilities = [
  {
    icon: Scale,
    title: "Sync evaluate",
    description: "HTTP and gRPC paths with enforce and shadow semantics.",
    creditTrack: true,
  },
  {
    icon: Database,
    title: "Agent evidence",
    description:
      "Agent decision and revocation records are signed and hash-chained; a verifier checks them offline against the keys you list.",
    creditTrack: false,
  },
  {
    icon: Database,
    title: "Decision events",
    description:
      "Each credit decision is a hash-chained event, not signed, that keeps a digest of the input rather than the input.",
    creditTrack: true,
  },
  {
    icon: ShieldCheck,
    title: "Operator access control",
    description: "Cedar policies decide each operator action for the principal the API authenticated.",
    creditTrack: false,
  },
  {
    icon: Activity,
    title: "Batch ingest",
    description: "NDJSON worker for partner LOS exports (primary install path).",
    href: "/batch",
    creditTrack: true,
  },
] as const;

type OverviewPageProps = {
  /** For tests: the reads of GET /health and GET /v1/runtime, in place of the API's answers. */
  health?: Resource<{ status: string }>;
  runtime?: Resource<RuntimeInfo>;
};

export default function OverviewPage({ health: givenHealth, runtime: givenRuntime }: OverviewPageProps) {
  const healthRead = useResource(fetchHealth);
  const runtimeRead = useResource(fetchRuntime);
  const health = givenHealth ?? healthRead.resource;
  const runtime = givenRuntime ?? runtimeRead.resource;
  const info = runtime.phase === "ok" ? runtime.data : undefined;
  // --agent-only: the credit track (models, packs, evaluate, batch) is not served.
  const agentOnly = info?.agent_only === true;

  return (
    <section>
      <PageHeader
        title="Overview"
        hindi="अवलोकन"
        subtitle={
          agentOnly
            ? "System health and the runtime posture of this agent-only server."
            : "System health, active model posture, and governance capabilities for your on-prem deployment."
        }
      />

      {info && !agentOnly && info.model_pack_mismatch && (
        <div
          role="alert"
          className="mb-6 rounded-lg border border-saffron-400/40 bg-saffron-100/40 px-4 py-3 text-sm text-ink"
        >
          The active model record names a different policy pack than the one running (
          <span className="font-mono">{info.pack_id}</span>). Evidence records the pack
          actually used; activate a matching pack or model version to resolve this.
        </div>
      )}
      {info?.pointer_drift && (
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
            <CardDescription>Liveness of this API server (GET /health)</CardDescription>
          </CardHeader>
          <ResourceState
            resource={health}
            loading="Checking API health…"
            onRetry={healthRead.retry}
            skeleton={<Skeleton className="h-8 w-32" />}
          >
            {(data) => <StatusIndicator status="ok" label={data.status.toUpperCase()} />}
          </ResourceState>
          {health.phase === "error" && (
            <StatusIndicator status="error" label="Unavailable" className="mt-2" />
          )}
        </Card>

        {!agentOnly && (
          <>
          <Card>
            <CardHeader>
              <CardTitle>Active model</CardTitle>
              <CardDescription>Pinned model record; status and mode are governed</CardDescription>
            </CardHeader>
            <ResourceState
              resource={runtime}
              loading="Loading the runtime…"
              onRetry={runtimeRead.retry}
              skeleton={<Skeleton className="h-20 w-full" />}
            >
              {(data) => (
              <dl className="grid grid-cols-[auto_1fr] gap-x-4 gap-y-2 text-sm">
                <dt className="text-muted">Model</dt>
                <dd>
                  <Link
                    to={`/models/${data.model_id}`}
                    className="font-medium text-kavach-700 hover:text-saffron-600"
                  >
                    {data.model_id}
                  </Link>
                </dd>
                <dt className="text-muted">Version</dt>
                <dd className="font-medium text-ink">{data.model_version}</dd>
                <dt className="text-muted">Pack</dt>
                <dd>
                  <Link
                    to={`/policies/${data.pack_id}`}
                    className="font-medium text-peacock-700 hover:underline"
                  >
                    {data.pack_id}
                  </Link>
                </dd>
                <dt className="text-muted">Mode</dt>
                <dd>
                  <span className="rounded-md bg-peacock-600/10 px-2 py-0.5 text-xs font-semibold uppercase tracking-wide text-peacock-700">
                    {data.governance_mode}
                  </span>
                </dd>
              </dl>
              )}
            </ResourceState>
          </Card>

          <Card className="md:col-span-2 xl:col-span-1">
            <CardHeader>
              <CardTitle>Policy pack</CardTitle>
              <CardDescription>
                {info ? `${info.sector} sector` : "The pack this server evaluates credit with"}
              </CardDescription>
            </CardHeader>
            {runtime.phase === "loading" && <Skeleton className="h-16 w-full" />}
            {runtime.phase === "error" && (
              <p className="text-sm text-muted">Not known until GET /v1/runtime answers.</p>
            )}
            {info && (
              <p className="text-sm leading-relaxed text-muted">
                Pack{" "}
                <Link
                  to={`/policies/${info.pack_id}`}
                  className="rounded bg-stone-100 px-1.5 py-0.5 font-mono text-xs text-ink hover:text-saffron-600"
                >
                  {info.pack_id}
                </Link>{" "}
                sets the rules for credit evaluations; its page lists them and its jurisdiction.
                Each decision event names the pack and version that decided it.
              </p>
            )}
          </Card>
          </>
        )}
      </div>

      {info && <PosturePanel runtime={info} />}

      <div className="mt-8">
        <h2 className="mb-4 text-sm font-semibold uppercase tracking-widest text-muted">
          Platform capabilities
        </h2>
        <div className="grid gap-4 sm:grid-cols-2">
          {capabilities.filter((item) => !(agentOnly && item.creditTrack)).map((item) => (
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
