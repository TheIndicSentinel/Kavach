import { useRef, useState, type ReactNode, type RefObject } from "react";
import { Link } from "react-router-dom";
import { Button } from "../ui/Button";
import { Card, CardDescription, CardHeader, CardTitle } from "../ui/Card";
import { Dialog } from "../ui/Dialog";
import { ProblemAlert } from "../ui/ProblemAlert";
import { RoleHint } from "../ui/RoleHint";
import { TextField } from "../ui/TextField";
import { FieldList, mono } from "./AgentViews";
import {
  actionFormErrors,
  changeRequestHref,
  clampNote,
  confirmLabel,
  createFlightGuard,
  emptyActionForm,
  hasErrors,
  noteCounter,
  REASON_CODE_LABELS,
  REASON_CODES,
  recordText,
  reinstateProposalBody,
  reinstateTargetsFor,
  stopActionsFor,
  stopButtonLabel,
  stopEffect,
  stopRequestBody,
  stopResultSummary,
  STOP_TARGET,
  type ActionForm,
  type ActionFormErrors,
} from "../../lib/agentActions";
import {
  proposeReinstatement,
  stopAgent,
  type AgentStateName,
  type AgentStateView,
  type AgentStopResult,
  type ChangeRequest,
  type ReinstateTo,
  type StopAction,
} from "../../lib/api";
import { roleHint, type Viewer } from "../../lib/permissions";

const noErrors: ActionFormErrors = { reasonCode: null, note: null };

type ReasonAndNoteProps = {
  idPrefix: string;
  form: ActionForm;
  errors: ActionFormErrors;
  onChange: (form: ActionForm) => void;
};

/** The required reason code and the optional note, with its counter. */
function ReasonAndNote({ idPrefix, form, errors, onChange }: ReasonAndNoteProps) {
  const reasonId = `${idPrefix}-reason`;
  const reasonErrorId = `${reasonId}-error`;
  return (
    <div className="space-y-3">
      <div>
        <label htmlFor={reasonId} className="mb-1.5 block text-sm font-medium text-ink">
          Reason code (required)
        </label>
        <select
          id={reasonId}
          value={form.reasonCode}
          required
          aria-invalid={errors.reasonCode ? true : undefined}
          aria-describedby={errors.reasonCode ? reasonErrorId : undefined}
          onChange={(event) => onChange({ ...form, reasonCode: event.target.value })}
          className="w-full rounded-lg border border-border bg-white px-3 py-2 text-sm text-ink focus:border-saffron-500 focus:ring-2 focus:ring-saffron-500/20"
        >
          <option value="">Choose a reason code</option>
          {REASON_CODES.map((code) => (
            <option key={code} value={code}>
              {REASON_CODE_LABELS[code]} ({code})
            </option>
          ))}
        </select>
        {errors.reasonCode && (
          <p id={reasonErrorId} className="mt-1 text-xs font-medium text-decision-block">
            {errors.reasonCode}
          </p>
        )}
      </div>
      <TextField
        id={`${idPrefix}-note`}
        label="Note"
        value={form.note}
        onChange={(note) => onChange({ ...form, note: clampNote(note) })}
        hint={noteCounter(form.note)}
        error={errors.note}
      />
    </div>
  );
}

type StopDialogProps = {
  agentId: string;
  state: AgentStateName;
  action: StopAction;
  form: ActionForm;
  errors: ActionFormErrors;
  busy: boolean;
  /** The API's refusal of the last attempt, if any. */
  problem: unknown;
  onChange: (form: ActionForm) => void;
  onConfirm: () => void;
  onCancel: () => void;
  fallbackFocus?: RefObject<HTMLElement | null>;
};

/** The confirmation of a restrict, quarantine or revoke. */
export function StopDialog(props: StopDialogProps) {
  const { agentId, state, action, form, errors, busy, problem } = props;
  const permanent = action === "revoke" && state !== "revoked";
  return (
    <Dialog
      titleId="agent-action-title"
      descriptionId="agent-action-effect"
      title={
        <>
          {stopButtonLabel(action, state)} <span className="break-all font-mono">{agentId}</span>
          {permanent ? " (permanent)" : ""}?
        </>
      }
      onCancel={props.onCancel}
      busy={busy}
      fallbackFocus={props.fallbackFocus}
    >
      <p id="agent-action-effect" className="mb-4 text-sm text-ink">
        {action === "revoke" && state !== "revoked" ? (
          <strong className="font-semibold text-decision-block">{stopEffect(action, state)}</strong>
        ) : (
          stopEffect(action, state)
        )}{" "}
        The agent moves to <strong>{STOP_TARGET[action]}</strong>. The API decides whether you may
        do this.
      </p>
      <form
        noValidate
        onSubmit={(event) => {
          event.preventDefault();
          props.onConfirm();
        }}
      >
        <ReasonAndNote idPrefix="agent-action" form={form} errors={errors} onChange={props.onChange} />
        <ProblemAlert error={problem} className="mt-4 empty:mt-0" />
        <div className="mt-5 flex flex-wrap justify-end gap-2">
          <Button
            variant="ghost"
            aria-disabled={busy}
            onClick={() => {
              if (!busy) props.onCancel();
            }}
            className="aria-disabled:cursor-not-allowed aria-disabled:opacity-50"
          >
            Cancel
          </Button>
          {/* aria-disabled, not disabled: focus stays on the button while the
              request is in flight, and the handler refuses a second press. */}
          <Button
            type="submit"
            variant={action === "revoke" ? "secondary" : "primary"}
            aria-disabled={busy}
            className="aria-disabled:cursor-not-allowed aria-disabled:opacity-50"
          >
            {confirmLabel(action, busy)}
          </Button>
        </div>
      </form>
    </Dialog>
  );
}

type ReinstateDialogProps = {
  agentId: string;
  state: AgentStateName;
  to: ReinstateTo;
  form: ActionForm;
  errors: ActionFormErrors;
  busy: boolean;
  problem: unknown;
  onTo: (to: ReinstateTo) => void;
  onChange: (form: ActionForm) => void;
  onConfirm: () => void;
  onCancel: () => void;
  fallbackFocus?: RefObject<HTMLElement | null>;
};

/** The proposal of a `reinstate_agent` change request. */
export function ReinstateDialog(props: ReinstateDialogProps) {
  const { agentId, state, to, form, errors, busy, problem } = props;
  const targets = reinstateTargetsFor(state);
  return (
    <Dialog
      titleId="agent-reinstate-title"
      descriptionId="agent-reinstate-effect"
      title={
        <>
          Request reinstatement of <span className="break-all font-mono">{agentId}</span>?
        </>
      }
      onCancel={props.onCancel}
      busy={busy}
      fallbackFocus={props.fallbackFocus}
    >
      <p id="agent-reinstate-effect" className="mb-4 text-sm text-ink">
        This proposes a change request to bring the agent from <strong>{state}</strong> back to the
        state you choose. Nothing changes until a different principal approves it. The API decides
        whether you may propose it.
      </p>
      <form
        noValidate
        onSubmit={(event) => {
          event.preventDefault();
          props.onConfirm();
        }}
      >
        <div className="mb-3">
          <label htmlFor="agent-reinstate-to" className="mb-1.5 block text-sm font-medium text-ink">
            Bring back to
          </label>
          <select
            id="agent-reinstate-to"
            value={to}
            onChange={(event) => {
              const next = targets.find((target) => target === event.target.value);
              if (next) props.onTo(next);
            }}
            className="w-full rounded-lg border border-border bg-white px-3 py-2 text-sm text-ink focus:border-saffron-500 focus:ring-2 focus:ring-saffron-500/20"
          >
            {targets.map((target) => (
              <option key={target} value={target}>
                {target}
              </option>
            ))}
          </select>
        </div>
        <ReasonAndNote idPrefix="agent-reinstate" form={form} errors={errors} onChange={props.onChange} />
        <ProblemAlert error={problem} className="mt-4 empty:mt-0" />
        <div className="mt-5 flex flex-wrap justify-end gap-2">
          <Button
            variant="ghost"
            aria-disabled={busy}
            onClick={() => {
              if (!busy) props.onCancel();
            }}
            className="aria-disabled:cursor-not-allowed aria-disabled:opacity-50"
          >
            Cancel
          </Button>
          <Button
            type="submit"
            aria-disabled={busy}
            className="aria-disabled:cursor-not-allowed aria-disabled:opacity-50"
          >
            {busy ? "Proposing…" : "Propose reinstatement"}
          </Button>
        </div>
      </form>
    </Dialog>
  );
}

/** What a stop did: the state now, the evidence record, and for a revoke the mandates. */
export function StopResultView({ action, result }: { action: StopAction; result: AgentStopResult }) {
  const notRevoked = result.mandates_not_revoked ?? [];
  const fields: [string, ReactNode][] = [
    ["State now", result.state],
    ["Applied", result.applied ? "yes" : "no (it was already in that state)"],
    ["Evidence record", recordText(result.record)],
  ];
  if (action === "revoke") {
    fields.push(["Mandates revoked", listOrNone(result.mandates_revoked)]);
    fields.push(["Mandates not revoked", listOrNone(notRevoked)]);
  }
  return (
    <div className="space-y-3">
      <p className="font-medium text-ink">{stopResultSummary(action, result)}</p>
      <FieldList fields={fields} />
      {action === "revoke" && notRevoked.length > 0 && (
        <p className="font-medium text-decision-block">
          {notRevoked.length} mandate{notRevoked.length === 1 ? "" : "s"} could not be revoked:
          repeat the revoke to finish.
        </p>
      )}
    </div>
  );
}

function listOrNone(ids?: string[]): ReactNode {
  if (!ids || ids.length === 0) return null;
  return (
    <ul className="space-y-1">
      {ids.map((id) => (
        <li key={id}>{mono(id)}</li>
      ))}
    </ul>
  );
}

/** A proposed reinstatement, with the link to its change request. */
export function ReinstateResultView({ request }: { request: ChangeRequest }) {
  return (
    <div className="space-y-2">
      <p className="font-medium text-ink">
        Change request <code className="font-mono">{request.id}</code> proposed ({request.status}).
        Nothing has changed yet: a different principal must approve it.
      </p>
      <Link
        to={changeRequestHref(request.id)}
        className="font-medium text-kavach-700 underline hover:text-saffron-600"
      >
        Open change request {request.id}
      </Link>
    </div>
  );
}

/** What the last action that succeeded did. */
export type Outcome =
  | { kind: "stop"; action: StopAction; result: AgentStopResult }
  | { kind: "reinstate"; request: ChangeRequest };

/** The status region: always rendered, so what fills it is announced. */
export function ActionStatus({ outcome }: { outcome: Outcome | null }) {
  return (
    <div role="status" aria-live="polite" className="mb-4 text-sm empty:mb-0">
      {outcome?.kind === "stop" && <StopResultView action={outcome.action} result={outcome.result} />}
      {outcome?.kind === "reinstate" && <ReinstateResultView request={outcome.request} />}
    </div>
  );
}

type Open =
  | { kind: "stop"; action: StopAction }
  | { kind: "reinstate"; to: ReinstateTo };

type AgentActionsProps = {
  agent: AgentStateView;
  /** A stop succeeded: the page shows the state it returned. */
  onStopped: (result: AgentStopResult) => void;
  /** A refusal may mean the page is stale: read the agent again. */
  onStale: () => void;
  /** Where focus goes when a dialog closes and its opener is gone. */
  fallbackFocus: RefObject<HTMLElement | null>;
  /** Who the console acts as; with unknown groups every control the state allows shows. */
  viewer: Viewer;
};

/**
 * The stops the agent's state allows, and reinstatement by change request,
 * less any the viewer's groups are known to lack (a hint line takes their
 * place; the server still decides).
 */
export function AgentActions({ agent, onStopped, onStale, fallbackFocus, viewer }: AgentActionsProps) {
  const [open, setOpen] = useState<Open | null>(null);
  const [form, setForm] = useState<ActionForm>(emptyActionForm);
  const [errors, setErrors] = useState<ActionFormErrors>(noErrors);
  const [busy, setBusy] = useState(false);
  const [problem, setProblem] = useState<unknown>(null);
  const [outcome, setOutcome] = useState<Outcome | null>(null);
  const flight = useRef(createFlightGuard());

  const stateStops = stopActionsFor(agent.state);
  const stateTargets = reinstateTargetsFor(agent.state);
  const stopHint = stateStops.length > 0 ? roleHint(viewer, "stop_agent", "stop agents") : null;
  const reinstateHint =
    stateTargets.length > 0
      ? roleHint(viewer, "propose_reinstate_agent", "propose reinstating an agent")
      : null;
  const stops = stopHint ? [] : stateStops;
  const targets = reinstateHint ? [] : stateTargets;

  function start(next: Open) {
    setOpen(next);
    setForm(emptyActionForm);
    setErrors(noErrors);
    setProblem(null);
  }

  function cancel() {
    const refused = problem !== null;
    setOpen(null);
    setProblem(null);
    if (refused) onStale();
  }

  function confirm() {
    if (!open || flight.current.busy) return;
    const found = actionFormErrors(form);
    setErrors(found);
    if (hasErrors(found)) {
      // Take the operator to the first field to fix; its error is tied to it.
      const prefix = open.kind === "stop" ? "agent-action" : "agent-reinstate";
      document.getElementById(`${prefix}-${found.reasonCode ? "reason" : "note"}`)?.focus();
      return;
    }
    setProblem(null);
    const task =
      open.kind === "stop"
        ? () =>
            stopAgent(agent.agent_id, open.action, stopRequestBody(form)).then((result) => {
              setOutcome({ kind: "stop", action: open.action, result });
              setOpen(null);
              onStopped(result);
            })
        : () =>
            proposeReinstatement(reinstateProposalBody(agent.agent_id, open.to, form)).then(
              (request) => {
                setOutcome({ kind: "reinstate", request });
                setOpen(null);
              },
            );
    const running = flight.current.run(task);
    if (!running) return;
    setBusy(true);
    running
      .catch((error: unknown) => setProblem(error))
      .finally(() => setBusy(false));
  }

  return (
    <Card className="mt-6">
      <CardHeader>
        <CardTitle>Actions</CardTitle>
        <CardDescription>
          The API decides: the console offers every change the agent's state allows, less any
          your groups are known to lack, and a principal without permission gets the API's
          refusal. A stop takes one principal and
          takes effect from the agent's next call. Bringing an agent back takes a change request
          that a different principal approves.
        </CardDescription>
      </CardHeader>

      <ActionStatus outcome={outcome} />

      {(stopHint || reinstateHint) && (
        <div className="mb-3 space-y-1">
          {stopHint && <RoleHint>{stopHint}</RoleHint>}
          {reinstateHint && <RoleHint>{reinstateHint}</RoleHint>}
        </div>
      )}

      <div className="flex flex-wrap gap-2 empty:hidden">
        {stops.map((action) => (
          <Button
            key={action}
            variant={action === "revoke" ? "secondary" : "ghost"}
            onClick={() => start({ kind: "stop", action })}
          >
            {stopButtonLabel(action, agent.state)}
          </Button>
        ))}
        {targets.length > 0 && (
          <Button variant="ghost" onClick={() => start({ kind: "reinstate", to: targets[0] })}>
            Request reinstatement
          </Button>
        )}
      </div>
      {agent.state === "revoked" && (
        <p className="mt-3 text-sm text-muted">
          A revoked agent cannot be reinstated: a new passport with a new agent id is the way back.
        </p>
      )}

      {open?.kind === "stop" && (
        <StopDialog
          agentId={agent.agent_id}
          state={agent.state}
          action={open.action}
          form={form}
          errors={errors}
          busy={busy}
          problem={problem}
          onChange={setForm}
          onConfirm={confirm}
          onCancel={cancel}
          fallbackFocus={fallbackFocus}
        />
      )}
      {open?.kind === "reinstate" && (
        <ReinstateDialog
          agentId={agent.agent_id}
          state={agent.state}
          to={open.to}
          form={form}
          errors={errors}
          busy={busy}
          problem={problem}
          onTo={(to) => setOpen({ kind: "reinstate", to })}
          onChange={setForm}
          onConfirm={confirm}
          onCancel={cancel}
          fallbackFocus={fallbackFocus}
        />
      )}
    </Card>
  );
}
