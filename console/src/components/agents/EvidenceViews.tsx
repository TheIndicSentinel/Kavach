import type { ReactNode } from "react";
import { Link } from "react-router-dom";
import { DecisionBadge } from "../ui/DecisionBadge";
import type { AgentDecisionLookup, RevocationLookup } from "../../lib/api";
import { agentPath, FieldList, mono, timestamp } from "./AgentViews";

/** What the page may say about evidence, and nothing more (docs/CONSOLE_PLAN.md section 3). */
export function EvidenceNotice() {
  return (
    <div className="space-y-2 text-sm text-ink">
      <p>
        Each lookup is <strong>audited</strong> and <strong>rate limited</strong> by the API: it
        writes an audit entry before it returns anything, and refuses lookups past the limit. Look
        up a record only when you need it.
      </p>
      <p>
        An agent record is “signature verified against the listed keys” only once a verifier has
        checked it. This page shows the record as the API returned it and does not check signatures.
        One record proves nothing about the chain.
      </p>
    </div>
  );
}

/** A list of ids, or null when there are none (FieldList then shows "none"). */
function idList(items: string[]): ReactNode {
  if (items.length === 0) return null;
  return (
    <ul className="space-y-0.5">
      {items.map((item) => (
        <li key={item}>{mono(item)}</li>
      ))}
    </ul>
  );
}

function RawRecord({ value }: { value: unknown }) {
  return (
    <details className="mt-4">
      <summary className="cursor-pointer text-sm font-medium text-kavach-700">
        Full record as returned (JSON)
      </summary>
      <pre className="mt-2 max-h-96 overflow-auto rounded-lg bg-stone-50 p-3 font-mono text-xs text-ink">
        {JSON.stringify(value, null, 2)}
      </pre>
    </details>
  );
}

export function DecisionRecordView({ result }: { result: AgentDecisionLookup }) {
  const { record, outcome } = result;
  return (
    <div className="space-y-6">
      <section aria-labelledby="decision-record-heading">
        <h3 id="decision-record-heading" className="mb-3 text-sm font-semibold text-ink">
          Agent decision record
        </h3>
        <FieldList
          fields={[
            ["Record id", mono(record.record_id)],
            ["Kind", record.kind],
            ["Partition / sequence", `${record.partition_id} / ${record.seq}`],
            [
              "Agent",
              <Link
                to={agentPath(record.actor.agent_id)}
                className="font-mono text-xs font-semibold text-kavach-700 hover:text-saffron-600"
              >
                {record.actor.agent_id}
              </Link>,
            ],
            ["Delegation chain", idList(record.chain)],
            ["Mandate", mono(record.mandate_id)],
            ["Purpose", record.purpose],
            ["Action", record.action],
            ["Returned decision", <DecisionBadge decision={record.returned_decision} />],
            ["Policy decision", <DecisionBadge decision={record.policy_decision} />],
            ["Pre-commit decision", <DecisionBadge decision={record.pre_commit_decision} />],
            ["Obligations", idList(record.obligations)],
            ["Signals", idList(record.signals)],
            ["Subject pseudonym", mono(record.subject_pseudonym)],
            ["Recorded at", timestamp(record.ts)],
            ["Clock sync", record.time_sync.status],
            ["Key id", mono(record.key_id)],
            ["Hash", mono(`${record.hash_alg} ${record.hash}`)],
            ["Previous hash", mono(record.prev_hash)],
          ]}
        />
        <RawRecord value={record} />
      </section>

      <section aria-labelledby="decision-outcome-heading">
        <h3 id="decision-outcome-heading" className="mb-3 text-sm font-semibold text-ink">
          Outcome
        </h3>
        {outcome ? (
          <>
            <FieldList
              fields={[
                ["Outcome", outcome.outcome],
                ["Reason", outcome.reason],
                ["Recorded at", timestamp(outcome.ts)],
                ["Record hash", mono(outcome.record_hash)],
                ["Key id", mono(outcome.key_id)],
              ]}
            />
            <RawRecord value={outcome} />
          </>
        ) : (
          <p className="text-sm text-muted">No outcome is recorded for this record.</p>
        )}
      </section>
    </div>
  );
}

export function RevocationRecordView({ result }: { result: RevocationLookup }) {
  const { record } = result;
  return (
    <section aria-labelledby="revocation-record-heading">
      <h3 id="revocation-record-heading" className="mb-3 text-sm font-semibold text-ink">
        Revocation record
      </h3>
      <FieldList
        fields={[
          ["Record id", mono(record.record_id)],
          ["Kind", record.kind],
          ["Partition / sequence", `${record.partition_id} / ${record.seq}`],
          ["System", mono(record.source_system)],
          ["Event id", mono(record.event_id)],
          ["Event type", record.event_type],
          ["Event digest", mono(record.event_digest ?? record.event_sha256)],
          ["Record pseudonym", mono(record.record_pseudonym)],
          ["Mandates revoked", idList(record.revoked)],
          ["Event occurred at", timestamp(record.occurred_at)],
          ["Revoked at", timestamp(record.revoked_at)],
          ["Recorded at", timestamp(record.recorded_at)],
          ["Clock sync", record.time_sync.status],
          ["Key id", mono(record.key_id)],
          ["Hash", mono(`${record.hash_alg} ${record.hash}`)],
          ["Previous hash", mono(record.prev_hash)],
        ]}
      />
      <RawRecord value={record} />
    </section>
  );
}
