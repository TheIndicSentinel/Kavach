import { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { Badge } from "../components/ui/Badge";
import { Card, CardDescription, CardHeader, CardTitle } from "../components/ui/Card";
import { DataTable } from "../components/ui/DataTable";
import { PageHeader } from "../components/ui/PageHeader";
import { Skeleton } from "../components/ui/Skeleton";
import { fetchPacks, type PackSummary } from "../lib/api";
import { formatDateTime } from "../lib/format";

export default function PoliciesPage() {
  const [packs, setPacks] = useState<PackSummary[] | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;
    fetchPacks()
      .then((data) => {
        if (!cancelled) setPacks(data);
      })
      .catch((err: unknown) => {
        if (!cancelled) {
          setError(err instanceof Error ? err.message : "Failed to load packs");
        }
      });
    return () => {
      cancelled = true;
    };
  }, []);

  return (
    <section>
      <PageHeader
        title="Policies"
        hindi="नीतियाँ"
        subtitle="Policy pack inventory, effective dates, and CEL rule definitions. Activate and rollback workflows require ops approval in v1."
      />

      <Card>
        <CardHeader>
          <CardTitle>Policy packs</CardTitle>
          <CardDescription>
            File-backed registry scanned from the packs directory at runtime.
          </CardDescription>
        </CardHeader>

        {error && (
          <p className="mb-4 text-sm text-decision-block">
            {error}
            {error.includes("401") || error.includes("403") ? (
              <> — configure principal in Settings.</>
            ) : null}
          </p>
        )}

        {packs === null && !error && (
          <div className="space-y-2">
            <Skeleton className="h-10 w-full" />
            <Skeleton className="h-10 w-full" />
          </div>
        )}

        {packs && (
          <DataTable
            rows={packs}
            rowKey={(row) => `${row.id}-${row.version}`}
            columns={[
              {
                key: "id",
                header: "Pack",
                render: (row) => (
                  <Link
                    to={`/policies/${row.id}`}
                    className="font-semibold text-kavach-700 hover:text-saffron-600"
                  >
                    {row.id}
                  </Link>
                ),
              },
              {
                key: "version",
                header: "Version",
                render: (row) => row.version,
              },
              {
                key: "sector",
                header: "Sector",
                render: (row) => row.sector,
              },
              {
                key: "effective",
                header: "Effective from",
                render: (row) => formatDateTime(row.effective_from),
              },
              {
                key: "rules",
                header: "Rules",
                render: (row) => row.rule_count,
              },
              {
                key: "status",
                header: "Runtime",
                render: (row) =>
                  row.active ? (
                    <Badge variant="active">Active</Badge>
                  ) : (
                    <Badge variant="muted">Available</Badge>
                  ),
              },
            ]}
          />
        )}
      </Card>
    </section>
  );
}
