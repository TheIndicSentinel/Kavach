import { useCallback } from "react";
import { Link, useParams } from "react-router-dom";
import { ArrowLeft } from "lucide-react";
import { Badge } from "../components/ui/Badge";
import { Button } from "../components/ui/Button";
import { Card, CardDescription, CardHeader, CardTitle } from "../components/ui/Card";
import { DataTable } from "../components/ui/DataTable";
import { DecisionBadge } from "../components/ui/DecisionBadge";
import { PageHeader } from "../components/ui/PageHeader";
import { ProposalStatus } from "../components/ui/ProposalStatus";
import { ResourceState } from "../components/ui/ResourceState";
import { Skeleton } from "../components/ui/Skeleton";
import { useProposal } from "../hooks/useProposal";
import { useResource, type Resource } from "../hooks/useResource";
import { fetchPack, type PolicyPack } from "../lib/api";
import { formatDateTime } from "../lib/format";

type PolicyDetailPageProps = {
  /** For tests: the pack's read, in place of the API's answer. */
  resource?: Resource<PolicyPack>;
};

export default function PolicyDetailPage({ resource: given }: PolicyDetailPageProps = {}) {
  const { packId = "" } = useParams<{ packId: string }>();
  const load = useCallback(() => fetchPack(packId), [packId]);
  const { resource: read, retry } = useResource(load);
  const resource = given ?? read;
  const { proposal, propose } = useProposal();
  const pack = resource.phase === "ok" ? resource.data : null;

  return (
    <section>
      <div className="mb-6">
        <Link
          to="/policies"
          className="inline-flex items-center gap-2 rounded-lg border border-border px-3 py-1.5 text-sm font-semibold text-kavach-900 hover:bg-kavach-900/5"
        >
          <ArrowLeft className="h-4 w-4" aria-hidden />
          All policies
        </Link>
      </div>

      <PageHeader
        title={packId}
        hindi="नीति विवरण"
        subtitle={pack?.description ?? "CEL policy pack for governed credit decisions."}
        action={pack && <Badge variant="active">v{pack.version}</Badge>}
      />

      <ResourceState
        resource={resource}
        loading="Loading policy pack…"
        notFound={`No policy pack ${packId} on this server.`}
        onRetry={retry}
        skeleton={<Skeleton className="mb-6 h-24 w-full" />}
      >
        {() => null}
      </ResourceState>

      {pack && (
        <div className="space-y-4">
          <Card>
            <CardHeader>
              <CardTitle>Metadata</CardTitle>
            </CardHeader>
            <dl className="grid grid-cols-[auto_1fr] gap-x-4 gap-y-2 text-sm">
              <dt className="text-muted">Sector</dt>
              <dd className="font-medium">{pack.sector}</dd>
              <dt className="text-muted">Jurisdiction</dt>
              <dd className="font-medium">{pack.jurisdiction}</dd>
              <dt className="text-muted">Effective from</dt>
              <dd className="font-medium">{formatDateTime(pack.effective_from)}</dd>
            </dl>
          </Card>

          <Card>
            <CardHeader>
              <CardTitle>Rules ({pack.rules.length})</CardTitle>
              <CardDescription>
                Per-record CEL expressions evaluated on the hot path.
              </CardDescription>
            </CardHeader>
            <DataTable
              rows={pack.rules}
              rowKey={(row) => row.id}
              columns={[
                { key: "id", header: "Rule ID", render: (row) => row.id },
                {
                  key: "decision",
                  header: "Decision",
                  render: (row) => <DecisionBadge decision={row.decision} />,
                },
                {
                  key: "reason",
                  header: "Reason",
                  render: (row) => (
                    <code className="text-xs">{row.reason_code}</code>
                  ),
                },
                {
                  key: "expression",
                  header: "CEL expression",
                  render: (row) => (
                    <code className="block max-w-md truncate text-xs text-muted">
                      {row.expression}
                    </code>
                  ),
                },
              ]}
            />
          </Card>

          <Card className="border-saffron-400/30 bg-saffron-100/20">
            <CardHeader>
              <CardTitle>Lifecycle actions</CardTitle>
              <CardDescription>
                Maker-checker: you propose, a different change approver approves on the Change requests page. Both are recorded in the admin audit log.
              </CardDescription>
            </CardHeader>
            <Button
              variant="secondary"
              disabled={proposal.phase === "busy"}
              onClick={() => void propose("activate_pack", { pack_id: packId })}
            >
              Propose activation
            </Button>
            <ProposalStatus proposal={proposal} />
          </Card>
        </div>
      )}
    </section>
  );
}
