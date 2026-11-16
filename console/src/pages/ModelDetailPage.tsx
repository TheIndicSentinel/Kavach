import { useCallback } from "react";
import { Link, useParams } from "react-router-dom";
import { ArrowLeft } from "lucide-react";
import { Badge } from "../components/ui/Badge";
import { Button } from "../components/ui/Button";
import { Card, CardDescription, CardHeader, CardTitle } from "../components/ui/Card";
import { PageHeader } from "../components/ui/PageHeader";
import { ProposalStatus } from "../components/ui/ProposalStatus";
import { ResourceState } from "../components/ui/ResourceState";
import { Skeleton } from "../components/ui/Skeleton";
import { useProposal } from "../hooks/useProposal";
import { useResource, type Resource } from "../hooks/useResource";
import { fetchModel, type ModelRecord } from "../lib/api";

type ModelDetailPageProps = {
  /** For tests: the model's read, in place of the API's answer. */
  resource?: Resource<ModelRecord>;
};

export default function ModelDetailPage({ resource: given }: ModelDetailPageProps = {}) {
  const { modelId = "" } = useParams<{ modelId: string }>();
  const load = useCallback(() => fetchModel(modelId), [modelId]);
  const { resource: read, retry } = useResource(load);
  const resource = given ?? read;
  const { proposal, propose } = useProposal();
  const model = resource.phase === "ok" ? resource.data : null;

  return (
    <section>
      <div className="mb-6">
        <Link
          to="/models"
          className="inline-flex items-center gap-2 rounded-lg border border-border px-3 py-1.5 text-sm font-semibold text-kavach-900 hover:bg-kavach-900/5"
        >
          <ArrowLeft className="h-4 w-4" aria-hidden />
          All models
        </Link>
      </div>

      <PageHeader
        title={modelId}
        hindi="मॉडल विवरण"
        subtitle={model ? `${model.purpose.replace(/_/g, " ")} · owned by ${model.owner}` : "Model record"}
        action={
          model && (
            <Badge variant={model.status === "production" ? "active" : "default"}>
              {model.status}
            </Badge>
          )
        }
      />

      <ResourceState
        resource={resource}
        loading="Loading model…"
        notFound={`No model ${modelId} on this server.`}
        onRetry={retry}
        skeleton={<Skeleton className="mb-6 h-24 w-full" />}
      >
        {() => null}
      </ResourceState>

      {model && (
        <div className="space-y-4">
          {model.origin === "vendor" && model.governance_mode === "enforce" && model.status !== "production" && (
            <Card className="border-decision-alert/30 bg-decision-alert-bg/30">
              <CardHeader>
                <CardTitle className="text-decision-alert">Supplier AI control</CardTitle>
                <CardDescription>
                  Vendor models cannot run in enforce mode until dual-control promotion to production.
                </CardDescription>
              </CardHeader>
            </Card>
          )}
          <Card>
            <CardHeader>
              <CardTitle>Governance</CardTitle>
            </CardHeader>
            <dl className="grid grid-cols-[auto_1fr] gap-x-4 gap-y-2 text-sm">
              <dt className="text-muted">Version</dt>
              <dd className="font-medium">{model.version}</dd>
              <dt className="text-muted">Mode</dt>
              <dd>
                <Badge variant="warning">{model.governance_mode}</Badge>
              </dd>
              <dt className="text-muted">Risk tier</dt>
              <dd className="font-medium">{model.risk_tier}</dd>
              <dt className="text-muted">Origin</dt>
              <dd className="font-medium">{model.origin}</dd>
              <dt className="text-muted">Pack</dt>
              <dd>
                <Link
                  to={`/policies/${model.pack_id}`}
                  className="font-medium text-peacock-700 hover:underline"
                >
                  {model.pack_id}
                </Link>
              </dd>
            </dl>
          </Card>

          {model.human_review_hold_policy && (
            <Card>
              <CardHeader>
                <CardTitle>Human review hold policy</CardTitle>
              </CardHeader>
              <p className="text-sm leading-relaxed text-muted">
                {model.human_review_hold_policy}
              </p>
            </Card>
          )}

          <Card>
            <CardHeader>
              <CardTitle>Input schema</CardTitle>
              <CardDescription>Validated before CEL policy evaluation.</CardDescription>
            </CardHeader>
            <pre className="overflow-auto rounded-lg bg-kavach-950 p-4 text-xs text-stone-200">
              {JSON.stringify(model.input_schema, null, 2)}
            </pre>
          </Card>

          <Card className="border-saffron-400/30 bg-saffron-100/20">
            <CardHeader>
              <CardTitle>Promotion workflow</CardTitle>
              <CardDescription>
                Dual-control status changes are audited. Governance mode remains authoritative on evaluate path.
              </CardDescription>
            </CardHeader>
            <Button
              variant="secondary"
              disabled={proposal.phase === "busy"}
              onClick={() => void propose("update_model", { model_id: modelId, status: "production" })}
            >
              Propose promotion to production
            </Button>
            <ProposalStatus proposal={proposal} />
          </Card>
        </div>
      )}
    </section>
  );
}
