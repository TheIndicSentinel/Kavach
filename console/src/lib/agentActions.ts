// The agent actions of ADR-013: which ones a state allows, what each one
// does, and the checks and request bodies for them. No I/O: the API calls
// are in api.ts, and the API stays the gate for every one of them.
import { AGENT_STATES } from "./agents";
import type {
  AgentReasonCode,
  AgentStateName,
  AgentStateView,
  AgentStopResult,
  ReinstateProposal,
  ReinstateTo,
  StopAction,
  StopAgentRequest,
} from "./api";

/** The state each stop moves an agent to. */
export const STOP_TARGET: Record<StopAction, AgentStateName> = {
  restrict: "restricted",
  quarantine: "quarantined",
  revoke: "revoked",
};

/** Every stop, mildest first. */
export const STOP_ACTIONS = ["restrict", "quarantine", "revoke"] as const satisfies readonly StopAction[];

/** How tight a state is: AGENT_STATES is the spec's order, active to revoked. */
function rank(state: AgentStateName): number {
  return AGENT_STATES.indexOf(state);
}

/**
 * The stops the API takes from `state`. A stop only ever tightens: a move to
 * a weaker state is refused (409) because it would loosen without approval,
 * and the same stop again changes nothing, so neither is offered. The one
 * repeat offered is a revoke of a revoked agent: the spec says a repeat
 * finishes a sweep that stopped half-way.
 */
export function stopActionsFor(state: AgentStateName): StopAction[] {
  if (state === "revoked") return ["revoke"];
  return STOP_ACTIONS.filter((action) => rank(STOP_TARGET[action]) > rank(state));
}

/** Every state a reinstatement may name, in the spec's order. */
const REINSTATE_TARGETS = ["active", "restricted"] as const satisfies readonly ReinstateTo[];

/**
 * What a `reinstate_agent` change request may bring an agent in `state` back
 * to: a weaker state only, and nothing at all from `revoked` (a new passport
 * with a new agent id is the way back).
 */
export function reinstateTargetsFor(state: AgentStateName): ReinstateTo[] {
  if (state === "revoked") return [];
  return REINSTATE_TARGETS.filter((to) => rank(to) < rank(state));
}

/** The reason codes, in the spec's order; the Record makes a new one a type error here. */
export const REASON_CODE_LABELS: Record<AgentReasonCode, string> = {
  rogue_behaviour: "Rogue behaviour",
  compromise_suspected: "Compromise suspected",
  policy_violation: "Policy violation",
  customer_complaint: "Customer complaint",
  operator_request: "Operator request",
  reviewed: "Reviewed",
  other: "Other",
};

export const REASON_CODES = Object.keys(REASON_CODE_LABELS) as AgentReasonCode[];

export function isReasonCode(value: string): value is AgentReasonCode {
  return (REASON_CODES as string[]).includes(value);
}

/** Why `value` cannot be sent as a reason code, or null when it can. */
export function reasonCodeProblem(value: string): string | null {
  if (!value) return "Choose a reason code.";
  return isReasonCode(value) ? null : "Choose one of the listed reason codes.";
}

/**
 * The longest note, in characters (the spec's `maxLength`). The store counts
 * Unicode characters after trimming and refuses control characters.
 */
export const NOTE_MAX_CHARS = 256;

/** The length of `note` in characters, as the API counts them (not UTF-16 units). */
export function noteLength(note: string): number {
  return [...note].length;
}

/** `note` cut to the limit, so the field never holds more than may be sent. */
export function clampNote(note: string): string {
  const chars = [...note];
  return chars.length > NOTE_MAX_CHARS ? chars.slice(0, NOTE_MAX_CHARS).join("") : note;
}

/** What the counter under the note says. */
export function noteCounter(note: string): string {
  return `${noteLength(note)} of ${NOTE_MAX_CHARS} characters. Optional. Kept in the store and the audit log, never in the evidence chain.`;
}

// Control characters: C0, DEL and C1, as Rust's char::is_control counts them.
// eslint-disable-next-line no-control-regex
const CONTROL = /[\u0000-\u001f\u007f-\u009f]/;

/** Why `note` cannot be sent, or null when it can. */
export function noteProblem(note: string): string | null {
  if (noteLength(note.trim()) > NOTE_MAX_CHARS) {
    return `A note is at most ${NOTE_MAX_CHARS} characters.`;
  }
  if (CONTROL.test(note)) return "A note cannot hold tabs, line breaks or other control characters.";
  return null;
}

/** What the operator filled in: a reason code and an optional note. */
export type ActionForm = { reasonCode: string; note: string };

export const emptyActionForm: ActionForm = { reasonCode: "", note: "" };

export type ActionFormErrors = { reasonCode: string | null; note: string | null };

export function actionFormErrors(form: ActionForm): ActionFormErrors {
  return { reasonCode: reasonCodeProblem(form.reasonCode), note: noteProblem(form.note) };
}

export function hasErrors(errors: ActionFormErrors): boolean {
  return errors.reasonCode !== null || errors.note !== null;
}

/** The trimmed note, or nothing when it is blank. */
function noteMember(note: string): { note?: string } {
  const trimmed = note.trim();
  return trimmed ? { note: trimmed } : {};
}

/** The body of a stop. Call only once `actionFormErrors` finds nothing. */
export function stopRequestBody(form: ActionForm): StopAgentRequest {
  if (!isReasonCode(form.reasonCode)) throw new Error("reason code not checked");
  return { reason_code: form.reasonCode, ...noteMember(form.note) };
}

/** The change request that proposes bringing `agentId` back to `to`. */
export function reinstateProposalBody(
  agentId: string,
  to: ReinstateTo,
  form: ActionForm,
): ReinstateProposal {
  if (!isReasonCode(form.reasonCode)) throw new Error("reason code not checked");
  return {
    kind: "reinstate_agent",
    params: { agent_id: agentId, to, reason_code: form.reasonCode, ...noteMember(form.note) },
  };
}

/** What the button that opens each stop says. */
export function stopButtonLabel(action: StopAction, state: AgentStateName): string {
  if (action === "revoke" && state === "revoked") return "Repeat revoke";
  return { restrict: "Restrict", quarantine: "Quarantine", revoke: "Revoke" }[action];
}

/** What the confirm button says while idle and while the request is in flight. */
export function confirmLabel(action: StopAction, busy: boolean): string {
  if (busy) return { restrict: "Restricting…", quarantine: "Quarantining…", revoke: "Revoking…" }[action];
  return {
    restrict: "Restrict agent",
    quarantine: "Quarantine agent",
    revoke: "Revoke agent permanently",
  }[action];
}

/** What a stop does, in the words of ADR-013 §2 and the spec. */
export function stopEffect(action: StopAction, state: AgentStateName): string {
  switch (action) {
    case "restrict":
      return "No external effects: the agent may read within its mandate and do nothing with an external effect (no contact, no call, no proposal). From its next call, on every replica.";
    case "quarantine":
      return "The agent does nothing, and the mandates it holds, and those delegated from them, are suspended, not revoked. From its next call, on every replica. Bringing it back needs a change request that a different principal approves.";
    case "revoke":
      return state === "revoked"
        ? "The agent is already revoked. Repeating the revoke finishes a sweep of its mandates that stopped half-way; nothing else changes."
        : "Permanent. The agent does nothing, and the mandates it holds are revoked, delegations included. A revoked agent cannot be reinstated: a new passport with a new agent id is the way back.";
  }
}

/** What the record field of a stop result means. */
export function recordText(record: AgentStopResult["record"]): string {
  switch (record) {
    case "written":
      return "written: the change's evidence record is in the chain";
    case "pending":
      return "pending: the reconciler writes the evidence record";
    case "unchanged":
      return "unchanged: nothing was changed, so no record";
  }
}

/** The agent's state as a stop returned it, in the shape the detail view shows. */
export function stopResultState(result: AgentStopResult): AgentStateView {
  const { agent_id, state, change_no, reason_code, note, changed_by, approved_by } = result;
  const { change_request_id, changed_at } = result;
  return { agent_id, state, change_no, reason_code, note, changed_by, approved_by, change_request_id, changed_at };
}

/** The first line of a stop result, for the status region. */
export function stopResultSummary(action: StopAction, result: AgentStopResult): string {
  if (!result.applied) {
    return action === "revoke" && result.state === "revoked"
      ? `Agent ${result.agent_id} is revoked. The revoke was repeated; its state did not change.`
      : `Agent ${result.agent_id} was already ${result.state}; nothing changed.`;
  }
  return `Agent ${result.agent_id} is now ${result.state} (change ${result.change_no}).`;
}

/**
 * Lets one request run at a time: a second press while the first is in
 * flight is ignored, before React has re-rendered the button.
 */
export function createFlightGuard() {
  let busy = false;
  return {
    get busy() {
      return busy;
    },
    /** Runs `task`, or returns null without running it while another is in flight. */
    run<T>(task: () => Promise<T>): Promise<T> | null {
      if (busy) return null;
      busy = true;
      return task().finally(() => {
        busy = false;
      });
    },
  };
}

/** Where the change requests page shows a request. */
export function changeRequestHref(id: string): string {
  return `/changes#${encodeURIComponent(changeRequestAnchor(id))}`;
}

/** The element id of a change request's card on the change requests page. */
export function changeRequestAnchor(id: string): string {
  return `change-${id}`;
}
