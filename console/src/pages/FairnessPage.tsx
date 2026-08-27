import { useRef, useState } from "react";
import { FileUp, Scale } from "lucide-react";
import { Badge } from "../components/ui/Badge";
import { Button } from "../components/ui/Button";
import { Card, CardDescription, CardHeader, CardTitle } from "../components/ui/Card";
import { DataTable } from "../components/ui/DataTable";
import { PageHeader } from "../components/ui/PageHeader";
import { formatDateTime, formatPercent } from "../lib/format";
import {
  isDisparityReport,
  parseFairnessReport,
  type FairnessReport,
  type GroupMetric,
} from "../lib/fairness";

type SampleKind = "disparity" | "inclusion";

const samplePaths: Record<SampleKind, string> = {
  disparity: "/samples/disparity-sample.json",
  inclusion: "/samples/inclusion-sample.json",
};

function Stat({
  label,
  value,
  hint,
}: {
  label: string;
  value: string;
  hint?: string;
}) {
  return (
    <div className="rounded-lg border border-border bg-stone-50/60 px-4 py-3">
      <p className="text-xs font-semibold uppercase tracking-wide text-muted">{label}</p>
      <p className="mt-1 text-lg font-semibold text-ink">{value}</p>
      {hint && <p className="mt-1 text-xs text-muted">{hint}</p>}
    </div>
  );
}

function SampleSufficientBadge({ sufficient }: { sufficient: boolean }) {
  return (
    <Badge variant={sufficient ? "active" : "warning"}>
      {sufficient ? "Sample OK" : "Low sample"}
    </Badge>
  );
}

function DisparityReportView({ report }: { report: Extract<FairnessReport, { report_type: "disparity" }> }) {
  const hasFlags = report.flagged.length > 0;

  return (
    <div className="space-y-6">
      <div className="flex flex-wrap items-center gap-2">
        <Badge variant="default">Disparity</Badge>
        {hasFlags ? (
          <Badge variant="warning">Threshold exceeded</Badge>
        ) : (
          <Badge variant="active">Within threshold</Badge>
        )}
        <span className="text-xs text-muted">
          Generated {formatDateTime(report.generated_at)}
        </span>
      </div>

      <div className="grid gap-3 sm:grid-cols-2 xl:grid-cols-4">
        <Stat label="Attribute" value={report.attribute} />
        <Stat
          label="Evaluated"
          value={String(report.total_evaluated)}
          hint={`Min sample ${report.min_sample_size}`}
        />
        <Stat
          label="Overall approval"
          value={formatPercent(report.overall_approval_rate)}
        />
        <Stat
          label="Max gap"
          value={formatPercent(report.max_disparity_gap)}
          hint={`Threshold ${formatPercent(report.disparity_threshold)} · ref ${report.reference_group}`}
        />
      </div>

      <Card>
        <CardHeader>
          <CardTitle>Group metrics</CardTitle>
          <CardDescription>
            Approval rates by declared attribute value. Gaps are relative to the reference group.
          </CardDescription>
        </CardHeader>
        <DataTable
          rows={report.groups}
          rowKey={(row) => row.group_value}
          emptyMessage="No group metrics in report."
          columns={[
            { key: "group", header: "Group", render: (row: GroupMetric) => row.group_value },
            { key: "count", header: "Count", render: (row) => String(row.count) },
            {
              key: "rate",
              header: "Approval rate",
              render: (row) => formatPercent(row.approval_rate),
            },
            {
              key: "gap",
              header: "Gap from ref",
              render: (row) =>
                row.gap_from_reference == null ? "—" : formatPercent(row.gap_from_reference),
            },
            {
              key: "sample",
              header: "Sample",
              render: (row) => <SampleSufficientBadge sufficient={row.sample_sufficient} />,
            },
          ]}
        />
      </Card>

      {hasFlags && (
        <Card>
          <CardHeader>
            <CardTitle>Flagged groups</CardTitle>
            <CardDescription>
              Groups exceeding the disparity threshold versus {report.reference_group}.
            </CardDescription>
          </CardHeader>
          <DataTable
            rows={report.flagged}
            rowKey={(row) => row.group_value}
            emptyMessage="No flagged groups."
            columns={[
              { key: "group", header: "Group", render: (row) => row.group_value },
              {
                key: "gap",
                header: "Gap",
                render: (row) => formatPercent(row.gap_from_reference),
              },
              {
                key: "rate",
                header: "Approval rate",
                render: (row) => formatPercent(row.approval_rate),
              },
              {
                key: "ref",
                header: "Reference rate",
                render: (row) => formatPercent(row.reference_approval_rate),
              },
            ]}
          />
        </Card>
      )}
    </div>
  );
}

function InclusionReportView({
  report,
}: {
  report: Extract<FairnessReport, { report_type: "inclusion" }>;
}) {
  return (
    <div className="space-y-6">
      <div className="flex flex-wrap items-center gap-2">
        <Badge variant="default">Inclusion</Badge>
        {report.flagged ? (
          <Badge variant="warning">Approval gap flagged</Badge>
        ) : (
          <Badge variant="active">Within threshold</Badge>
        )}
        <span className="text-xs text-muted">
          Generated {formatDateTime(report.generated_at)}
        </span>
      </div>

      <div className="grid gap-3 sm:grid-cols-2 xl:grid-cols-4">
        <Stat label="Segment field" value={report.segment_field} />
        <Stat
          label="Evaluated"
          value={String(report.total_evaluated)}
          hint={`Min sample ${report.min_sample_size}`}
        />
        <Stat label="Approval gap" value={formatPercent(report.approval_gap)} />
        <Stat
          label="Inclusion cohort"
          value={`${report.inclusion_count} rows`}
          hint={`${formatPercent(report.inclusion_approval_rate)} approval`}
        />
      </div>

      <div className="grid gap-4 lg:grid-cols-2">
        <Card>
          <CardHeader>
            <CardTitle>Inclusion segment</CardTitle>
            <CardDescription>PSL / inclusion cohort approval posture.</CardDescription>
          </CardHeader>
          <div className="space-y-3">
            <div className="flex flex-wrap items-center justify-between gap-2">
              <p className="text-sm text-muted">Count</p>
              <p className="font-semibold text-ink">{report.inclusion_count}</p>
            </div>
            <div className="flex flex-wrap items-center justify-between gap-2">
              <p className="text-sm text-muted">Approval rate</p>
              <p className="font-semibold text-ink">
                {formatPercent(report.inclusion_approval_rate)}
              </p>
            </div>
            <SampleSufficientBadge sufficient={report.inclusion_sample_sufficient} />
          </div>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle>Non-inclusion segment</CardTitle>
            <CardDescription>Comparator cohort for inclusion monitoring.</CardDescription>
          </CardHeader>
          <div className="space-y-3">
            <div className="flex flex-wrap items-center justify-between gap-2">
              <p className="text-sm text-muted">Count</p>
              <p className="font-semibold text-ink">{report.non_inclusion_count}</p>
            </div>
            <div className="flex flex-wrap items-center justify-between gap-2">
              <p className="text-sm text-muted">Approval rate</p>
              <p className="font-semibold text-ink">
                {formatPercent(report.non_inclusion_approval_rate)}
              </p>
            </div>
            <SampleSufficientBadge sufficient={report.non_inclusion_sample_sufficient} />
          </div>
        </Card>
      </div>
    </div>
  );
}

export default function FairnessPage() {
  const fileInputRef = useRef<HTMLInputElement>(null);
  const [report, setReport] = useState<FairnessReport | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);

  function loadParsed(raw: unknown) {
    setReport(parseFairnessReport(raw));
    setError(null);
  }

  async function loadSample(kind: SampleKind) {
    setLoading(true);
    setError(null);
    try {
      const response = await fetch(samplePaths[kind]);
      if (!response.ok) {
        throw new Error(`Failed to load ${kind} sample`);
      }
      loadParsed(await response.json());
    } catch (err: unknown) {
      setReport(null);
      setError(err instanceof Error ? err.message : "Failed to load sample report");
    } finally {
      setLoading(false);
    }
  }

  function onFileSelected(event: React.ChangeEvent<HTMLInputElement>) {
    const file = event.target.files?.[0];
    event.target.value = "";
    if (!file) return;

    setLoading(true);
    setError(null);
    const reader = new FileReader();
    reader.onload = () => {
      try {
        const raw = JSON.parse(String(reader.result)) as unknown;
        loadParsed(raw);
      } catch (err: unknown) {
        setReport(null);
        if (err instanceof SyntaxError) {
          setError("Invalid JSON — upload a fairness report from kavach-batch fairness.");
        } else {
          setError(err instanceof Error ? err.message : "Failed to parse report");
        }
      } finally {
        setLoading(false);
      }
    };
    reader.onerror = () => {
      setLoading(false);
      setError("Could not read the selected file.");
    };
    reader.readAsText(file);
  }

  return (
    <section>
      <PageHeader
        title="Fairness reports"
        hindi="निष्पक्षता रिपोर्ट"
        subtitle="View disparity and inclusion batch reports produced by kavach-batch fairness. Upload JSON output — no server-side storage."
        action={
          <Button
            variant="ghost"
            size="sm"
            disabled={loading}
            onClick={() => fileInputRef.current?.click()}
          >
            <FileUp className="h-4 w-4" aria-hidden />
            Upload JSON
          </Button>
        }
      />

      <input
        ref={fileInputRef}
        type="file"
        accept="application/json,.json"
        className="sr-only"
        onChange={onFileSelected}
      />

      <Card className="mb-6">
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <Scale className="h-4 w-4 text-peacock-600" aria-hidden />
            Load a report
          </CardTitle>
          <CardDescription>
            Generate reports with{" "}
            <code className="rounded bg-stone-100 px-1 py-0.5 font-mono text-xs">
              kavach-batch fairness
            </code>{" "}
            or try the bundled golden samples.
          </CardDescription>
        </CardHeader>
        <div className="flex flex-wrap gap-2">
          <Button disabled={loading} onClick={() => loadSample("disparity")}>
            Disparity sample
          </Button>
          <Button variant="secondary" disabled={loading} onClick={() => loadSample("inclusion")}>
            Inclusion sample
          </Button>
        </div>
      </Card>

      {error && <p className="mb-4 text-sm text-decision-block">{error}</p>}

      {!report && !error && (
        <p className="rounded-lg border border-dashed border-border bg-stone-50/50 px-4 py-10 text-center text-sm text-muted">
          Upload a fairness report JSON or load a sample to inspect cohort metrics.
        </p>
      )}

      {report && isDisparityReport(report) && <DisparityReportView report={report} />}
      {report && !isDisparityReport(report) && <InclusionReportView report={report} />}
    </section>
  );
}
