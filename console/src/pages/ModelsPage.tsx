import { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { Badge } from "../components/ui/Badge";
import { Card, CardDescription, CardHeader, CardTitle } from "../components/ui/Card";
import { DataTable } from "../components/ui/DataTable";
import { PageHeader } from "../components/ui/PageHeader";
import { Skeleton } from "../components/ui/Skeleton";
import { fetchModels, type ModelSummary } from "../lib/api";

export default function ModelsPage() {
  const [models, setModels] = useState<ModelSummary[] | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;
    fetchModels()
      .then((data) => {
        if (!cancelled) setModels(data);
      })
      .catch((err: unknown) => {
        if (!cancelled) {
          setError(err instanceof Error ? err.message : "Failed to load models");
        }
      });
    return () => {
      cancelled = true;
    };
  }, []);

  return (
    <section>
      <PageHeader
        title="Models"
        hindi="मॉडल"
        subtitle="Model inventory with governance mode, risk tier, and pack binding. Promotion workflow is read-only in v1."
      />

      <Card>
        <CardHeader>
          <CardTitle>Model records</CardTitle>
          <CardDescription>
            Authoritative governance configuration — callers cannot override mode.
          </CardDescription>
        </CardHeader>

        {error && <p className="mb-4 text-sm text-decision-block">{error}</p>}

        {models === null && !error && (
          <div className="space-y-2">
            <Skeleton className="h-10 w-full" />
            <Skeleton className="h-10 w-full" />
          </div>
        )}

        {models && (
          <DataTable
            rows={models}
            rowKey={(row) => `${row.model_id}-${row.version}`}
            columns={[
              {
                key: "model",
                header: "Model",
                render: (row) => (
                  <Link
                    to={`/models/${row.model_id}`}
                    className="font-semibold text-kavach-700 hover:text-saffron-600"
                  >
                    {row.model_id}
                  </Link>
                ),
              },
              {
                key: "version",
                header: "Version",
                render: (row) => row.version,
              },
              {
                key: "status",
                header: "Status",
                render: (row) => (
                  <Badge variant={row.status === "production" ? "active" : "default"}>
                    {row.status}
                  </Badge>
                ),
              },
              {
                key: "origin",
                header: "Origin",
                render: (row) => (
                  <Badge variant={row.origin === "vendor" ? "warning" : "default"}>
                    {row.origin}
                  </Badge>
                ),
              },
              {
                key: "mode",
                header: "Governance",
                render: (row) => row.governance_mode,
              },
              {
                key: "risk",
                header: "Risk",
                render: (row) => row.risk_tier,
              },
              {
                key: "pack",
                header: "Pack",
                render: (row) => (
                  <Link
                    to={`/policies/${row.pack_id}`}
                    className="text-peacock-700 hover:underline"
                  >
                    {row.pack_id}
                  </Link>
                ),
              },
              {
                key: "runtime",
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
