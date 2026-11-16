// Evidence and reconciliation bodies typed from openapi.d.ts, so a spec change breaks the tests.
import type { ClosedRecordsResult, DecisionEventLookup } from "../lib/api";

export const EVIDENCE_ID = "9771a6c1-edc5-4b2b-b38d-ffb397b7df55";

export const decisionEvent: DecisionEventLookup = {
  event: {
    schema_version: "1.1.0",
    event_id: "evt-77",
    evidence_id: EVIDENCE_ID,
    prev_hash: "prevhash76",
    hash: "eventhash77",
    pack_id: "rbi-digital-lending",
    pack_version: "1.2.0",
    sector: "retail",
    model_id: "pd-model",
    model_version: "3.1",
    model_origin: "in_house",
    governance_mode: "enforce",
    policy_decision: "BLOCK",
    returned_decision: "BLOCK",
    reason_codes: ["DTI_ABOVE_LIMIT"],
    policy_hits: ["dti.max"],
    pii_tokens: ["tok-1"],
    input_digest: "sha256:inputdigest",
    latency_ms: 4,
    decision_time: "2026-11-14T09:00:00Z",
    evaluated_at: "2026-11-14T09:00:00.120Z",
    service_identity_id: "svc-los",
    correlation_id: "corr-1",
    idempotency_key: "idem-1",
  },
  tombstoned: false,
};

export const shadowEvent: DecisionEventLookup = {
  event: {
    ...decisionEvent.event,
    governance_mode: "shadow",
    policy_decision: "BLOCK",
    returned_decision: "PASS",
  },
  tombstoned: false,
};

export const tombstonedEvent: DecisionEventLookup = {
  event: {
    ...decisionEvent.event,
    event_id: "ERASED",
    evidence_id: "ERASED",
    reason_codes: [],
    policy_hits: [],
    pii_tokens: [],
    idempotency_key: undefined,
    correlation_id: "ERASED",
  },
  tombstoned: true,
};

export const reconciliation: ClosedRecordsResult = {
  checked: 3,
  mismatches: 1,
  information: 1,
  remedy:
    "a mismatch means a payment or dispute event did not arrive: resend the signed event (it revokes through the normal path) or stop the agent. This call changed nothing.",
  findings: [
    {
      kind: "issued_after_closure",
      record_ref: "lms:loan/L-2",
      state: "paid",
      mandate_id: "mandate-21",
      holder: "agent:collections-bot",
      issued_at: "2026-10-03T06:00:00Z",
      expires_at: "2026-12-03T06:00:00Z",
    },
    {
      kind: "should_have_been_revoked",
      record_ref: "lms:loan/L-1",
      state: "disputed",
      mandate_id: "mandate-11",
      holder: "agent:payments-bot",
      issued_at: "2026-09-01T06:00:00Z",
      expires_at: "2026-12-01T06:00:00Z",
    },
  ],
};

export const cleanReconciliation: ClosedRecordsResult = {
  checked: 2,
  mismatches: 0,
  information: 0,
  remedy: reconciliation.remedy,
  findings: [],
};
