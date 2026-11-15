// Which change-request buttons to offer. The API stays the gate: these rules
// only drop buttons the API is known (or, from the groups, expected) to
// refuse, never add a permission.
import { useState } from "react";
import { getAccessToken, getPrincipal, type ChangeRequest } from "./api";
import {
  UNKNOWN_VIEWER,
  approveAction,
  deniedLine,
  mayProbably,
  proposeAction,
  type Viewer,
} from "./permissions";

export type { Viewer } from "./permissions";

/**
 * Who the console acts as, when it can tell without asking the API.
 *
 * The principal is known in one case: no access token, and a principal ID
 * sent as `X-Kavach-Principal`, which the API (in --insecure-dev) takes as
 * the principal verbatim. With a token the console does not know who it is:
 * the token's claims are not read here.
 *
 * The groups are unknown in every mode today. The header carries none: the
 * API resolves a header principal with no groups and Cedar takes its
 * memberships from the server's entities file, which the console cannot
 * see. `groups` is a parameter so that a source that does know them (the
 * session endpoint, later) can pass them in.
 */
export function currentViewer(
  token?: string,
  principal?: string,
  groups: readonly string[] | null = null,
): Viewer {
  if ((token === undefined || principal === undefined) && typeof sessionStorage === "undefined") {
    // Static rendering in tests has no sessionStorage.
    return { ...UNKNOWN_VIEWER, groups };
  }
  const bearer = token ?? getAccessToken();
  const header = principal ?? getPrincipal();
  return { principal: !bearer && header ? header : null, groups };
}

/**
 * The viewer for a page, read once: Settings reloads the page when the
 * credentials change. `groups` is the hook argument for a caller that knows
 * them; without it they are unknown and every control shows.
 */
export function useViewer(groups: readonly string[] | null = null): Viewer {
  const [viewer] = useState(() => currentViewer(undefined, undefined, groups));
  return viewer;
}

export type ChangeRequestAction = "approve" | "reject" | "cancel";

export type ChangeRequestButtons = {
  actions: ChangeRequestAction[];
  /** Why the proposer's buttons are missing, shown next to the ones that are left. */
  note: string | null;
  /** Why buttons the viewer's groups lack are missing; the server still decides. */
  hint: string | null;
};

const ALL: ChangeRequestAction[] = ["approve", "reject", "cancel"];

function joinOr(words: string[]): string {
  if (words.length <= 1) return words.join("");
  return `${words.slice(0, -1).join(", ")} or ${words[words.length - 1]}`;
}

/**
 * The buttons a pending change request gets.
 *
 * - The proposer rule: the API refuses approval and rejection by the
 *   proposer and cancellation by anyone else, so when the console knows the
 *   principal it does not offer those.
 * - The group rule: approve and reject need the kind's `approve_*` action,
 *   cancel its `propose_*` action (as the API checks them); when the groups
 *   are known and lack one, the button gives way to a line that says so.
 *
 * When the console knows neither, it offers all three and the API decides.
 */
export function changeRequestButtons(
  request: Pick<ChangeRequest, "status" | "proposer" | "kind">,
  viewer: Viewer,
): ChangeRequestButtons {
  if (request.status !== "pending") return { actions: [], note: null, hint: null };
  let actions = ALL;
  let note: string | null = null;
  if (viewer.principal !== null) {
    if (viewer.principal === request.proposer) {
      actions = ["cancel"];
      note = "You proposed this change: a different principal approves or rejects it.";
    } else {
      actions = ["approve", "reject"];
    }
  }
  const allowed = (action: ChangeRequestAction) =>
    mayProbably(
      viewer,
      action === "cancel" ? proposeAction(request.kind) : approveAction(request.kind),
    );
  const denied = actions.filter((action) => !allowed(action));
  const hint = denied.length > 0 ? deniedLine(viewer, `${joinOr(denied)} this change`) : null;
  return { actions: actions.filter(allowed), note, hint };
}
