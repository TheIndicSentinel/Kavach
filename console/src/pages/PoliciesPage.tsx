import { Link } from "react-router-dom";
import { Badge } from "../components/ui/Badge";
import { Card, CardDescription, CardHeader, CardTitle } from "../components/ui/Card";
import { DataTable } from "../components/ui/DataTable";
import { PageHeader } from "../components/ui/PageHeader";
import { ResourceState } from "../components/ui/ResourceState";
import { useResource, type Resource } from "../hooks/useResource";
import { fetchPacks, type PackSummary } from "../lib/api";
import { formatDateTime } from "../lib/format";

type PoliciesPageProps = {
  /** For tests: the read of GET /v1/packs, in place of the API's answer. */
  resource?: Resource<PackSummary[]>;
};

export default function PoliciesPage({ resource: given }: PoliciesPageProps) {
  const { resource: read, retry } = useResource(fetchPacks);
  const resource = given ?? read;

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

        <ResourceState
          resource={resource}
          loading="Loading policy packs…"
          summary={(packs) => `${packs.length} ${packs.length === 1 ? "pack" : "packs"}.`}
          onRetry={retry}
        >
          {(packs) => (
          <DataTable
            rows={packs}
            rowKey={(row) => `${row.id}-${row.version}`}
            emptyMessage="No policy packs in the packs directory yet."
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
        </ResourceState>
      </Card>
    </section>
  );
}
