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
    title: "Cedar RBAC",
    description: "Optional access control via X-Kavach-Principal header.",
  },
  {
    icon: Activity,
    title: "Batch ingest",
    description: "NDJSON worker for partner LOS exports (primary install path).",
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
                  Configure your principal in Settings when Cedar RBAC is enabled.
                </p>
              ) : null}
            </div>
          )}
        </Card>

        <Card>
          <CardHeader>
            <CardTitle>Active model</CardTitle>
            <CardDescription>Loaded at runtime from model record YAML</CardDescription>
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
            enforces consent presence, DTI thresholds, and human-review gates aligned
            to RBI digital lending and DPDP consent posture.
          </p>
        </Card>
      </div>

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
                <CardTitle className="text-sm">{item.title}</CardTitle>
                <CardDescription className="mt-1">{item.description}</CardDescription>
              </div>
            </Card>
          ))}
        </div>
      </div>
    </section>
  );
}
