import { useState } from "react";
import { Button } from "../components/ui/Button";
import { Card, CardDescription, CardHeader, CardTitle } from "../components/ui/Card";
import { DataTable } from "../components/ui/DataTable";
import { PageHeader } from "../components/ui/PageHeader";
import { ProposalStatus } from "../components/ui/ProposalStatus";
import { ResourceState, listSummary } from "../components/ui/ResourceState";
import { Skeleton } from "../components/ui/Skeleton";
import { useProposal } from "../hooks/useProposal";
import { useResource, type Resource } from "../hooks/useResource";
import {
  fetchRetentionSettings,
  fetchTombstones,
  type RetentionSettings,
  type TombstoneRecord,
} from "../lib/api";
import { formatDateTime } from "../lib/format";

type RetentionPageProps = {
  /** For tests: the reads of GET /v1/admin/retention and /v1/admin/tombstones. */
  settings?: Resource<RetentionSettings>;
  tombstones?: Resource<TombstoneRecord[]>;
};

export default function RetentionPage({ settings: givenSettings, tombstones: givenTombstones }: RetentionPageProps = {}) {
  const settingsRead = useResource(fetchRetentionSettings);
  const tombstonesRead = useResource(fetchTombstones);
  const settings = givenSettings ?? settingsRead.resource;
  const tombstones = givenTombstones ?? tombstonesRead.resource;
  // What the operator typed; until then, the window the server holds.
  const [typedDays, setTypedDays] = useState<string | null>(null);
  const { proposal, propose } = useProposal();

  return (
    <section>
      <PageHeader
        title="Retention & erasure"
        hindi="प्रतिधारण और मिटाना"
        subtitle="Tenant retention policy and DPDP tombstones — chain integrity preserved."
      />

      <div className="grid gap-6 lg:grid-cols-2">
        <Card>
          <CardHeader>
            <CardTitle>Retention policy</CardTitle>
            <CardDescription>
              Evidence older than this window can be tombstoned via apply retention.
            </CardDescription>
          </CardHeader>
          <ResourceState
            resource={settings}
            loading="Loading the retention policy…"
            onRetry={settingsRead.retry}
            skeleton={<Skeleton className="h-20 w-full" />}
          >
            {(current) => {
              const days = typedDays ?? String(current.evidence_retention_days);
              return (
                <div className="space-y-4">
                  <label className="block text-sm">
                    <span className="mb-1 block font-medium text-stone-700">Retention days</span>
                    <input
                      type="number"
                      min={1}
                      className="w-full rounded-lg border border-stone-200 px-3 py-2"
                      value={days}
                      onChange={(event) => setTypedDays(event.target.value)}
                    />
                  </label>
                  <div className="flex flex-wrap gap-2">
                    <Button
                      disabled={proposal.phase === "busy"}
                      onClick={() =>
                        void propose("update_retention", { evidence_retention_days: Number(days) })
                      }
                    >
                      Propose policy change
                    </Button>
                    <Button
                      variant="secondary"
                      disabled={proposal.phase === "busy"}
                      onClick={() => void propose("apply_retention")}
                    >
                      Propose retention run
                    </Button>
                  </div>
                  <ProposalStatus proposal={proposal} />
                  <p className="text-xs text-stone-500">
                    Last updated {formatDateTime(current.updated_at)}
                    {current.updated_by ? ` by ${current.updated_by}` : ""}
                  </p>
                </div>
              );
            }}
          </ResourceState>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle>Tombstones</CardTitle>
            <CardDescription>
              Metadata redacted in export views; hash chain fields remain verifiable.
            </CardDescription>
          </CardHeader>
          <ResourceState
            resource={tombstones}
            loading="Loading tombstones…"
            summary={(rows) => listSummary(rows.length, "tombstone", "tombstones")}
            onRetry={tombstonesRead.retry}
            skeleton={<Skeleton className="h-24 w-full" />}
          >
            {(rows) => (
              <DataTable
                rows={rows}
                rowKey={(row) => row.evidence_id}
                emptyMessage="No tombstoned evidence yet."
                columns={[
                  {
                    key: "when",
                    header: "When",
                    render: (row) => formatDateTime(row.tombstoned_at),
                  },
                  {
                    key: "evidence",
                    header: "Evidence ID",
                    render: (row) => row.evidence_id,
                  },
                  { key: "reason", header: "Reason", render: (row) => row.reason },
                ]}
              />
            )}
          </ResourceState>
        </Card>
      </div>
    </section>
  );
}
