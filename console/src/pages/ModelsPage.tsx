import { Link } from "react-router-dom";
import { Badge } from "../components/ui/Badge";
import { Card, CardDescription, CardHeader, CardTitle } from "../components/ui/Card";
import { DataTable } from "../components/ui/DataTable";
import { PageHeader } from "../components/ui/PageHeader";
import { ResourceState } from "../components/ui/ResourceState";
import { useResource, type Resource } from "../hooks/useResource";
import { fetchModels, type ModelSummary } from "../lib/api";

type ModelsPageProps = {
  /** For tests: the read of GET /v1/models, in place of the API's answer. */
  resource?: Resource<ModelSummary[]>;
};

export default function ModelsPage({ resource: given }: ModelsPageProps) {
  const { resource: read, retry } = useResource(fetchModels);
  const resource = given ?? read;

  return (
    <section>
      <PageHeader
        title="Models"
        hindi="मॉडल"
        subtitle="Model inventory with governance mode, risk tier, and pack binding. Open a model to propose its promotion; a different change approver approves it."
      />

      <Card>
        <CardHeader>
          <CardTitle>Model records</CardTitle>
          <CardDescription>
            Authoritative governance configuration — callers cannot override mode.
          </CardDescription>
        </CardHeader>

        <ResourceState
          resource={resource}
          loading="Loading models…"
          summary={(models) => `${models.length} ${models.length === 1 ? "model" : "models"}.`}
          onRetry={retry}
        >
          {(models) => (
          <DataTable
            rows={models}
            rowKey={(row) => `${row.model_id}-${row.version}`}
            emptyMessage="No model records yet."
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
                render: (row) =>
                  row.governed ? (
                    <Badge variant={row.status === "production" ? "active" : "default"}>
                      {row.status}
                    </Badge>
                  ) : (
                    <Badge variant="muted">not governed</Badge>
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
        </ResourceState>
      </Card>
    </section>
  );
}
