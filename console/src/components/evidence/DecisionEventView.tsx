import type { ReactNode } from "react";
import { DecisionBadge } from "../ui/DecisionBadge";
import { FieldList, mono, timestamp } from "../agents/AgentViews";
import { VerifyCommands } from "./VerifyCommands";
import type { DecisionEventLookup } from "../../lib/api";
import { decisionEventCommands } from "../../lib/evidence";

/** What the page may say about evaluate decision events, and nothing more. */
export function DecisionEventNotice() {
  return (
    <div className="space-y-2 text-sm text-ink">
      <p>
        Each lookup is <strong>audited</strong> and <strong>rate limited</strong> by the API: it
        writes an audit entry for every read, found or not, and refuses lookups past the limit.
        Look up an event only when you need it.
      </p>
      <p>
        Decision events are hash-chained but <strong>not signed</strong>. Someone with write access
        to the database could rewrite an event and rehash the chain, so a matching hash does not
        prove an event was not rewritten. This page shows the event as the API returned it and
        checks nothing. One event proves nothing about the chain.
      </p>
    </div>
  );
}

function codeList(items: string[]): ReactNode {
  if (items.length === 0) return null;
  return (
    <ul className="space-y-0.5">
      {items.map((item) => (
        <li key={item}>{mono(item)}</li>
      ))}
    </ul>
  );
}

/**
 * One decision event. `evidenceId` is the id the operator looked up: the
 * commands use it because a tombstoned event's own ids read `ERASED`.
 */
export function DecisionEventView({
  result,
  evidenceId,
}: {
  result: DecisionEventLookup;
  evidenceId: string;
}) {
  const { event, tombstoned } = result;
  const shadowHides =
    event.governance_mode === "shadow" && event.policy_decision !== event.returned_decision;
  return (
    <div className="space-y-6">
      <section aria-labelledby="decision-event-heading">
        <h3 id="decision-event-heading" className="mb-3 text-sm font-semibold text-ink">
          Decision event
        </h3>
        {tombstoned && (
          <p className="mb-3 rounded-lg border border-saffron-400/30 bg-saffron-100 px-3 py-2 text-sm text-ink">
            Tombstoned: this is the redacted form. Reasons, hits and PII tokens are emptied, the
            idempotency key is removed and ids read ERASED, so its hash cannot be re-checked from
            what is shown here.
          </p>
        )}
        {shadowHides && (
          <p className="mb-3 rounded-lg border border-saffron-400/30 bg-saffron-100 px-3 py-2 text-sm text-ink">
            Shadow mode: the {event.returned_decision} return hides a would-be{" "}
            {event.policy_decision}.
          </p>
        )}
        <FieldList
          fields={[
            ["Evidence id", mono(event.evidence_id)],
            ["Event id", mono(event.event_id)],
            ["Schema version", event.schema_version],
            ["Returned decision", <DecisionBadge decision={event.returned_decision} />],
            ["Policy decision", <DecisionBadge decision={event.policy_decision} />],
            ["Governance mode", event.governance_mode],
            ["Reason codes", codeList(event.reason_codes)],
            ["Policy hits", codeList(event.policy_hits)],
            ["Pack", mono(`${event.pack_id} ${event.pack_version}`)],
            ["Sector", event.sector],
            ["Model", mono(`${event.model_id} ${event.model_version} (${event.model_origin})`)],
            ["Input digest", mono(event.input_digest)],
            ["Decision time", timestamp(event.decision_time)],
            ["Evaluated at", timestamp(event.evaluated_at)],
            ["Service identity", mono(event.service_identity_id)],
            ["Correlation id", mono(event.correlation_id)],
            ["Hash", mono(event.hash)],
            ["Previous hash", mono(event.prev_hash)],
          ]}
        />
      </section>

      <section aria-labelledby="decision-event-outcome-heading">
        <h3 id="decision-event-outcome-heading" className="mb-3 text-sm font-semibold text-ink">
          Outcome
        </h3>
        <p className="text-sm text-muted">
          Not part of this response: the decision-event API returns the decision only, with no
          outcome field.
        </p>
      </section>

      <VerifyCommands commands={decisionEventCommands(evidenceId)}>
        <p className="text-sm text-ink">
          These check hashes and links only; decision events carry no signature to verify. You need
          an export of the decision event chain.
        </p>
      </VerifyCommands>
    </div>
  );
}
