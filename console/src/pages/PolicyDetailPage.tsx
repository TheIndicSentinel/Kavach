import { useEffect, useState } from "react";
import { Link, useParams } from "react-router-dom";
import { ArrowLeft } from "lucide-react";
import { Badge } from "../components/ui/Badge";
import { Button } from "../components/ui/Button";
import { Card, CardDescription, CardHeader, CardTitle } from "../components/ui/Card";
import { DataTable } from "../components/ui/DataTable";
import { DecisionBadge } from "../components/ui/DecisionBadge";
import { PageHeader } from "../components/ui/PageHeader";
import { Skeleton } from "../components/ui/Skeleton";
import { ApiError, activatePack, fetchPack, getApprover, getPrincipal, type PolicyPack } from "../lib/api";
import { formatDateTime } from "../lib/format";

export default function PolicyDetailPage() {
  const { packId } = useParams<{ packId: string }>();
  const [pack, setPack] = useState<PolicyPack | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [actionMessage, setActionMessage] = useState<string | null>(null);
  const [activating, setActivating] = useState(false);

  useEffect(() => {
    if (!packId) return;
    let cancelled = false;
    fetchPack(packId)
      .then((data) => {
        if (!cancelled) setPack(data);
      })
      .catch((err: unknown) => {
        if (!cancelled) {
          const message =
            err instanceof ApiError && err.status === 404
              ? `Policy pack "${packId}" not found.`
              : err instanceof Error
                ? err.message
                : "Failed to load pack";
          setError(message);
        }
      });
    return () => {
      cancelled = true;
    };
  }, [packId]);

  async function onActivate() {
    if (!packId) return;
    const actor = getPrincipal();
    const approver = getApprover();
    if (!actor || !approver) {
      setActionMessage("Set actor and approver principals in Settings.");
      return;
    }
    setActivating(true);
    setActionMessage(null);
    try {
      await activatePack(packId, actor, approver);
      setActionMessage("Pack activated. Runtime updated.");
    } catch (err) {
      setActionMessage(err instanceof Error ? err.message : "Activate failed");
    } finally {
      setActivating(false);
    }
  }

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

      {pack && (
        <PageHeader
          title={pack.id}
          hindi="नीति विवरण"
          subtitle={pack.description ?? "CEL policy pack for governed credit decisions."}
          action={<Badge variant="active">v{pack.version}</Badge>}
        />
      )}

      {error && (
        <Card className="border-decision-block/30 bg-decision-block-bg/30">
          <CardHeader>
            <CardTitle className="text-decision-block">Unable to load pack</CardTitle>
            <CardDescription>{error}</CardDescription>
          </CardHeader>
        </Card>
      )}

      {!pack && !error && <Skeleton className="mb-6 h-24 w-full" />}

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
                Dual control: distinct actor and approver admins required. Recorded in admin audit log.
              </CardDescription>
            </CardHeader>
            <Button
              variant="secondary"
              disabled={activating}
              onClick={onActivate}
            >
              {activating ? "Activating…" : "Activate pack"}
            </Button>
            {actionMessage && (
              <p className="mt-3 text-sm text-muted">{actionMessage}</p>
            )}
          </Card>
        </div>
      )}
    </section>
  );
}
