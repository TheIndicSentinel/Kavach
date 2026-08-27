import { useEffect, useState } from "react";
import { Button } from "../components/ui/Button";
import { Card, CardDescription, CardHeader, CardTitle } from "../components/ui/Card";
import { DataTable } from "../components/ui/DataTable";
import { PageHeader } from "../components/ui/PageHeader";
import { Skeleton } from "../components/ui/Skeleton";
import {
  applyRetention,
  fetchRetentionSettings,
  fetchTombstones,
  getApprover,
  getPrincipal,
  updateRetentionSettings,
  type RetentionSettings,
  type TombstoneRecord,
} from "../lib/api";
import { formatDateTime } from "../lib/format";

export default function RetentionPage() {
  const [settings, setSettings] = useState<RetentionSettings | null>(null);
  const [tombstones, setTombstones] = useState<TombstoneRecord[] | null>(null);
  const [retentionDays, setRetentionDays] = useState("365");
  const [error, setError] = useState<string | null>(null);
  const [message, setMessage] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const reload = () => {
    setError(null);
    Promise.all([fetchRetentionSettings(), fetchTombstones()])
      .then(([nextSettings, nextTombstones]) => {
        setSettings(nextSettings);
        setRetentionDays(String(nextSettings.evidence_retention_days));
        setTombstones(nextTombstones);
      })
      .catch((err: unknown) => {
        setError(err instanceof Error ? err.message : "Failed to load retention data");
      });
  };

  useEffect(() => {
    reload();
  }, []);

  const actor = getPrincipal();
  const approver = getApprover();

  async function saveSettings() {
    const days = Number(retentionDays);
    if (!actor || !approver || actor === approver) {
      setError("Set distinct actor and approver principals in Settings.");
      return;
    }
    setBusy(true);
    setError(null);
    setMessage(null);
    try {
      const updated = await updateRetentionSettings(days, actor, approver);
      setSettings(updated);
      setMessage("Retention settings updated.");
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : "Update failed");
    } finally {
      setBusy(false);
    }
  }

  async function runRetentionApply() {
    if (!actor || !approver || actor === approver) {
      setError("Set distinct actor and approver principals in Settings.");
      return;
    }
    setBusy(true);
    setError(null);
    setMessage(null);
    try {
      const report = await applyRetention(actor, approver);
      setMessage(`Retention applied — ${report.tombstoned_count} evidence row(s) tombstoned.`);
      reload();
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : "Retention apply failed");
    } finally {
      setBusy(false);
    }
  }

  return (
    <section>
      <PageHeader
        title="Retention & erasure"
        hindi="प्रतिधारण और मिटाना"
        subtitle="Tenant retention policy and DPDP tombstones — chain integrity preserved."
      />

      {error && <p className="mb-4 text-sm text-decision-block">{error}</p>}
      {message && <p className="mb-4 text-sm text-decision-pass">{message}</p>}

      <div className="grid gap-6 lg:grid-cols-2">
        <Card>
          <CardHeader>
            <CardTitle>Retention policy</CardTitle>
            <CardDescription>
              Evidence older than this window can be tombstoned via apply retention.
            </CardDescription>
          </CardHeader>
          {settings === null && !error ? (
            <Skeleton className="h-20 w-full" />
          ) : (
            <div className="space-y-4">
              <label className="block text-sm">
                <span className="mb-1 block font-medium text-stone-700">Retention days</span>
                <input
                  type="number"
                  min={1}
                  className="w-full rounded-lg border border-stone-200 px-3 py-2"
                  value={retentionDays}
                  onChange={(event) => setRetentionDays(event.target.value)}
                />
              </label>
              <div className="flex flex-wrap gap-2">
                <Button disabled={busy} onClick={saveSettings}>
                  Save policy
                </Button>
                <Button variant="secondary" disabled={busy} onClick={runRetentionApply}>
                  Apply retention
                </Button>
              </div>
              {settings && (
                <p className="text-xs text-stone-500">
                  Last updated {formatDateTime(settings.updated_at)}
                  {settings.updated_by ? ` by ${settings.updated_by}` : ""}
                </p>
              )}
            </div>
          )}
        </Card>

        <Card>
          <CardHeader>
            <CardTitle>Tombstones</CardTitle>
            <CardDescription>
              Metadata redacted in export views; hash chain fields remain verifiable.
            </CardDescription>
          </CardHeader>
          {tombstones === null && !error ? (
            <Skeleton className="h-24 w-full" />
          ) : (
            <DataTable
              rows={tombstones ?? []}
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
        </Card>
      </div>
    </section>
  );
}
