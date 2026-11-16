// The agent actions rendered to static markup: the buttons each state offers,
// the confirm dialogs, the refusal alert and the result status. Static
// rendering runs no effects, so focus handling is not exercised here.
import { describe, expect, it } from "vitest";
import { ApiError } from "../../lib/api";
import { emptyActionForm } from "../../lib/agentActions";
import { UNKNOWN_VIEWER, type Viewer } from "../../lib/permissions";
import { byRole, render, text } from "../../test/markup";
import {
  neverChanged,
  quarantineApplied,
  quarantined,
  reinstateProposed,
  revokeHalfway,
} from "../../test/fixtures";
import {
  ActionStatus,
  AgentActions,
  ReinstateDialog,
  ReinstateResultView,
  StopDialog,
  StopResultView,
} from "./AgentActions";

const noErrors = { reasonCode: null, note: null };
const noop = () => {};

function actions(agent = neverChanged, viewer: Viewer = UNKNOWN_VIEWER) {
  return render(
    <AgentActions
      agent={agent}
      onStopped={noop}
      onStale={noop}
      fallbackFocus={{ current: null }}
      viewer={viewer}
    />,
  );
}

/** The labels of the buttons in some markup, in order. */
function buttonLabels(html: string): string[] {
  return [...html.matchAll(/<button[^>]*>([^<]*)<\/button>/g)].map((m) => m[1]);
}

function stopDialog(overrides: Partial<Parameters<typeof StopDialog>[0]> = {}) {
  return render(
    <StopDialog
      agentId="agent:payments-bot"
      state="active"
      action="revoke"
      form={emptyActionForm}
      errors={noErrors}
      busy={false}
      problem={null}
      onChange={noop}
      onConfirm={noop}
      onCancel={noop}
      {...overrides}
    />,
  );
}

/** The opening tag of the element with `role`. */
function openingTag(html: string, role: string): string {
  return html.match(new RegExp(`<[a-z]+[^>]*role="${role}"[^>]*>`))?.[0] ?? "";
}

describe("AgentActions", () => {
  it("offers every stop to an active agent and no reinstatement", () => {
    const shown = text(actions());
    expect(shown).toContain("Restrict");
    expect(shown).toContain("Quarantine");
    expect(shown).toContain("Revoke");
    expect(shown).not.toContain("Request reinstatement");
  });

  it("offers a quarantined agent only revoke, and reinstatement by change request", () => {
    const html = actions(quarantined);
    const buttons = [...html.matchAll(/<button[^>]*>([^<]*)<\/button>/g)].map((m) => m[1]);
    expect(buttons).toEqual(["Revoke", "Request reinstatement"]);
  });

  it("offers a revoked agent only a repeat revoke, and says it cannot be reinstated", () => {
    const html = actions({ ...quarantined, state: "revoked" });
    const shown = text(html);
    expect(shown).toContain("Repeat revoke");
    expect(shown).not.toContain("Request reinstatement");
    expect(shown).toContain("cannot be reinstated");
  });

  it("says the API decides, and starts with an empty status region and no dialog", () => {
    const html = actions();
    expect(text(html)).toContain("The API decides");
    expect(byRole(html, "status")).toEqual([""]);
    expect(html).not.toContain('role="alertdialog"');
  });
});

describe("AgentActions: role hints", () => {
  const admins: Viewer = { principal: null, groups: ["admins"] };
  const viewers: Viewer = { principal: "viewer-1", groups: ["viewers"] };
  const approvers: Viewer = { principal: null, groups: ["change-approvers"] };

  it("known allowed: admins get every stop and reinstatement, and no hint", () => {
    expect(buttonLabels(actions(neverChanged, admins))).toEqual(["Restrict", "Quarantine", "Revoke"]);
    expect(buttonLabels(actions(quarantined, admins))).toEqual(["Revoke", "Request reinstatement"]);
    expect(text(actions(quarantined, admins))).not.toContain("Your groups");
  });

  it("known denied: viewers get no stop or reinstate button, and one line for each", () => {
    const html = actions(quarantined, viewers);
    expect(buttonLabels(html)).toEqual([]);
    const shown = text(html);
    expect(shown).toContain(
      "Your groups (viewers) don't include one that may stop agents. The server decides; ask an admin if you need this.",
    );
    expect(shown).toContain(
      "Your groups (viewers) don't include one that may propose reinstating an agent.",
    );
  });

  it("known denied for a revoked agent: no repeat revoke, and no reinstatement line", () => {
    const shown = text(actions({ ...quarantined, state: "revoked" }, approvers));
    expect(shown).not.toContain("Repeat revoke");
    expect(shown).toContain("may stop agents");
    expect(shown).not.toContain("reinstating");
  });

  it("unknown groups: every action the state allows, and no hint", () => {
    expect(buttonLabels(actions(quarantined, UNKNOWN_VIEWER))).toEqual([
      "Revoke",
      "Request reinstatement",
    ]);
    expect(text(actions(quarantined, { principal: "admin-1", groups: null }))).not.toContain(
      "Your groups",
    );
  });
});

describe("StopDialog", () => {
  it("is a labelled, described modal alertdialog that names the agent", () => {
    const html = stopDialog();
    const tag = openingTag(html, "alertdialog");
    expect(tag).toContain('aria-modal="true"');
    expect(tag).toContain('aria-labelledby="agent-action-title"');
    expect(tag).toContain('aria-describedby="agent-action-effect"');
    expect(html).toMatch(/<h2 id="agent-action-title"[^>]*>.*agent:payments-bot/);
    expect(html).toContain('id="agent-action-effect"');
  });

  it("names revoke as permanent, with its effect", () => {
    const shown = text(stopDialog());
    expect(shown).toMatch(/^Revoke agent:payments-bot \(permanent\)\?/);
    expect(shown).toContain("Permanent.");
    expect(shown).toContain("Revoke agent permanently");
  });

  it("names quarantine and its effect", () => {
    const shown = text(stopDialog({ action: "quarantine" }));
    expect(shown).toMatch(/^Quarantine agent:payments-bot \?/);
    expect(shown).toContain("suspended, not revoked");
    expect(shown).not.toContain("permanent");
  });

  it("labels the reason code and note, and shows the note counter", () => {
    const html = stopDialog({ form: { reasonCode: "", note: "abc" } });
    expect(html).toContain('<label for="agent-action-reason"');
    expect(html).toContain('<label for="agent-action-note"');
    expect(text(html)).toContain("3 of 256 characters");
    expect(html).toMatch(/aria-describedby="agent-action-note-hint"/);
    for (const code of ["rogue_behaviour", "compromise_suspected", "other"]) {
      expect(html).toContain(`value="${code}"`);
    }
  });

  it("marks a missing reason code invalid and says why", () => {
    const html = stopDialog({ errors: { reasonCode: "Choose a reason code.", note: null } });
    expect(html).toMatch(/<select[^>]*aria-invalid="true"[^>]*aria-describedby="agent-action-reason-error"/);
    expect(text(html)).toContain("Choose a reason code.");
  });

  it("cannot be confirmed again while the request is in flight", () => {
    const html = stopDialog({ busy: true });
    expect(html).toMatch(/<button type="submit"[^>]*aria-disabled="true"[^>]*>Revoking…<\/button>/);
    expect(html).toMatch(/aria-disabled="true"[^>]*>Cancel</);
  });

  it.each([
    [403, "forbidden", "req-403"],
    [409, "this would loosen the agent's state", "req-409"],
  ])("shows a %i refusal in role=alert with its detail, status and request_id", (status, detail, id) => {
    const problem = new ApiError(`${detail} (request ${id})`, status, id, detail);
    const [alert] = byRole(stopDialog({ problem }), "alert");
    expect(alert).toContain(detail);
    expect(alert).toContain(`HTTP ${status}`);
    expect(alert).toContain(`request_id ${id}`);
  });
});

describe("ReinstateDialog", () => {
  const html = render(
    <ReinstateDialog
      agentId="agent:payments-bot"
      state="quarantined"
      to="active"
      form={emptyActionForm}
      errors={noErrors}
      busy={false}
      problem={null}
      onTo={noop}
      onChange={noop}
      onConfirm={noop}
      onCancel={noop}
    />,
  );

  it("is a labelled modal alertdialog that names the agent", () => {
    const tag = openingTag(html, "alertdialog");
    expect(tag).toContain('aria-modal="true"');
    expect(tag).toContain('aria-labelledby="agent-reinstate-title"');
    expect(text(html)).toMatch(/^Request reinstatement of agent:payments-bot \?/);
  });

  it("says it proposes a change request a different principal must approve", () => {
    const shown = text(html);
    expect(shown).toContain("proposes a change request");
    expect(shown).toContain("different principal approves");
  });

  it("offers only the states the agent may be brought back to", () => {
    expect(html).toContain('<label for="agent-reinstate-to"');
    expect(html).toContain('<option value="active" selected="">active</option>');
    expect(html).toContain('<option value="restricted">restricted</option>');
    expect(html).not.toContain('<option value="revoked"');
  });
});

describe("results", () => {
  it("shows the state after a stop in role=status", () => {
    const html = render(
      <ActionStatus outcome={{ kind: "stop", action: "quarantine", result: quarantineApplied }} />,
    );
    const [status] = byRole(html, "status");
    expect(status).toContain("is now quarantined");
    expect(byRole(html, "alert")).toEqual([]);
  });

  it("shows a proposed reinstatement in role=status", () => {
    const html = render(<ActionStatus outcome={{ kind: "reinstate", request: reinstateProposed }} />);
    expect(byRole(html, "status")[0]).toContain("Change request cr-0099 proposed");
  });

  it("shows the new state, the record and pending honestly", () => {
    const shown = text(render(<StopResultView action="quarantine" result={quarantineApplied} />));
    expect(shown).toContain("Agent agent:collections-bot is now quarantined (change 1).");
    expect(shown).toContain("State now quarantined");
    expect(shown).toContain("pending: the reconciler writes the evidence record");
    expect(shown).not.toContain("Mandates");
  });

  it("lists a revoke's mandates and asks for a repeat when some were not revoked", () => {
    const shown = text(render(<StopResultView action="revoke" result={revokeHalfway} />));
    expect(shown).toContain("Mandates revoked mandate-7");
    expect(shown).toContain("Mandates not revoked mandate-8");
    expect(shown).toContain("repeat the revoke to finish");
  });

  it("links to the proposed change request and says nothing changed yet", () => {
    const html = render(<ReinstateResultView request={reinstateProposed} />);
    expect(html).toContain('href="/changes#change-cr-0099"');
    expect(text(html)).toContain("Change request cr-0099 proposed (pending)");
    expect(text(html)).toContain("Nothing has changed yet");
  });
});
