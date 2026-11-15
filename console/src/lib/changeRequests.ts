// Which change-request buttons to offer. The API stays the gate: these rules
// only drop buttons the API is known to refuse, never add a permission.
import { getAccessToken, getPrincipal, type ChangeRequest } from "./api";

/**
 * Who the console acts as, when it can tell without asking the API.
 *
 * Only one case is known: no access token, and a principal ID sent as
 * `X-Kavach-Principal`, which the API (in --insecure-dev) takes as the
 * principal verbatim. With a token the console does not know who it is: the
 * API has no endpoint that says so (noted on #218), and the token's claims
 * are not read here.
 */
export type Viewer = { kind: "principal"; id: string } | { kind: "unknown" };

export function currentViewer(
  token: string = getAccessToken(),
  principal: string = getPrincipal(),
): Viewer {
  if (token) return { kind: "unknown" };
  return principal ? { kind: "principal", id: principal } : { kind: "unknown" };
}

export type ChangeRequestAction = "approve" | "reject" | "cancel";

export type ChangeRequestButtons = {
  actions: ChangeRequestAction[];
  /** Why buttons are missing, shown next to the ones that are left. */
  note: string | null;
};

const ALL: ChangeRequestAction[] = ["approve", "reject", "cancel"];

/**
 * The buttons a pending change request gets. The API refuses approval and
 * rejection by the proposer and cancellation by anyone else, so when the
 * console knows who it is, it does not offer those. When it does not know,
 * it offers all three and the API decides.
 */
export function changeRequestButtons(
  request: Pick<ChangeRequest, "status" | "proposer">,
  viewer: Viewer,
): ChangeRequestButtons {
  if (request.status !== "pending") return { actions: [], note: null };
  if (viewer.kind === "unknown") return { actions: ALL, note: null };
  if (viewer.id === request.proposer) {
    return {
      actions: ["cancel"],
      note: "You proposed this change: a different principal approves or rejects it.",
    };
  }
  return { actions: ["approve", "reject"], note: null };
}
