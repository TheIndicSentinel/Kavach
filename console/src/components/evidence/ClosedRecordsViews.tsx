import { Badge } from "../ui/Badge";
import { DataTable } from "../ui/DataTable";
import { mono, timestamp } from "../agents/AgentViews";
import type { ClosedRecordsResult } from "../../lib/api";
import { CLOSED_RECORDS_LIMITS, FINDING_WORDING, sortFindings } from "../../lib/evidence";

/** What the page must say before anything is sent (ADR-012 addendum). */
export function ClosedRecordsNotice() {
  return (
    <div className="space-y-2 text-sm text-ink">
      <p>
        <strong>This call revokes nothing.</strong> It reports which loans the lender lists as
        paid or disputed still hold a live mandate in Kavach. A mismatch means a payment or dispute
        event most likely did not arrive: resend the signed event, which revokes through the normal
        path, or stop the agent.
      </p>
      <p>
        Each run is <strong>rate limited</strong> and <strong>audited</strong> by the API. The
        audit entry holds counts, never loan references.
      </p>
      <p>
        Name loans by the lender&apos;s reference only, never by a borrower&apos;s name, phone
        number or other personal details. The list stays in this page and is sent only when you
        choose Reconcile; the console stores none of it. Up to {CLOSED_RECORDS_LIMITS.recordsMax}{" "}
        loans per run.
      </p>
    </div>
  );
}

/** The counts the API returned and its remedy, in its own words. */
export function ClosedRecordsCounts({ result }: { result: ClosedRecordsResult }) {
  return (
    <div className="space-y-3">
      <dl className="grid grid-cols-3 gap-3 text-sm">
        {(
          [
            ["Loans checked", result.checked],
            ["Should have been revoked", result.mismatches],
            ["To confirm", result.information],
          ] as const
        ).map(([label, value]) => (
          <div key={label} className="rounded-lg border border-border px-3 py-2">
            <dt className="text-xs font-medium text-muted">{label}</dt>
            <dd className="text-lg font-semibold text-ink">{value}</dd>
          </div>
        ))}
      </dl>
      {result.mismatches > 0 && <p className="text-sm text-ink">{result.remedy}</p>}
    </div>
  );
}

/** Every finding, mismatches first, each with its kind in words. */
export function ClosedRecordsFindings({ result }: { result: ClosedRecordsResult }) {
  return (
    <DataTable
      rows={sortFindings(result.findings)}
      rowKey={(row) => `${row.kind} ${row.record_ref} ${row.mandate_id}`}
      emptyMessage="No loan in the list holds a live mandate."
      columns={[
        {
          key: "kind",
          header: "Finding",
          render: (row) => {
            const wording = FINDING_WORDING[row.kind];
            return (
              <div className="space-y-1">
                <Badge variant={row.kind === "should_have_been_revoked" ? "warning" : "muted"}>
                  {wording.label}
                </Badge>
                <p className="text-xs text-muted">{wording.meaning}</p>
              </div>
            );
          },
        },
        { key: "loan", header: "Loan reference", render: (row) => mono(row.record_ref) },
        { key: "state", header: "Lender says", render: (row) => row.state },
        { key: "mandate", header: "Mandate", render: (row) => mono(row.mandate_id) },
        { key: "holder", header: "Holder", render: (row) => mono(row.holder) },
        { key: "issued", header: "Issued", render: (row) => timestamp(row.issued_at) },
        { key: "expires", header: "Expires", render: (row) => timestamp(row.expires_at) },
      ]}
    />
  );
}
