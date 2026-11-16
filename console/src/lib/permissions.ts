// Role hints: which console actions a principal's groups probably allow,
// copied from crates/kavach-auth/policies/kavach.cedar. The server stays the
// gate for every call. A hint only hides a control the server is expected to
// refuse, and says so; it never grants anything. permissions.test.ts reads
// the Cedar file and fails when this table and the file disagree.
import type { ChangeKind } from "./api";

/** The Cedar groups the policy file names. */
export const CEDAR_GROUPS = [
  "viewers",
  "operators",
  "admins",
  "change-approvers",
] as const;

export type CedarGroup = (typeof CEDAR_GROUPS)[number];

/** Every change kind; the Record makes a new kind in the spec a type error here. */
const CHANGE_KINDS_RECORD: Record<ChangeKind, true> = {
  activate_pack: true,
  rollback_pack: true,
  update_model: true,
  update_retention: true,
  erase_evidence: true,
  apply_retention: true,
  activate_model: true,
  reinstate_agent: true,
  grant_role: true,
  revoke_role: true,
};

export const CHANGE_KINDS = Object.keys(CHANGE_KINDS_RECORD) as ChangeKind[];

/**
 * Role changes (ADR-019 §4). No group is permitted them; only the
 * superadmin and user_admin roles are, which this group table does not
 * model, so their controls always show and the server decides.
 */
const ROLE_CHANGE_KINDS: readonly ChangeKind[] = ["grant_role", "revoke_role"];

/** The change kinds the group table covers. */
const GROUP_CHANGE_KINDS = CHANGE_KINDS.filter(
  (kind) => !ROLE_CHANGE_KINDS.includes(kind),
);

/** The Cedar actions behind the console's action controls. */
export type CedarAction =
  | "evaluate"
  | "read_evidence"
  | "reconcile_closed_records"
  | "stop_agent"
  | `propose_${ChangeKind}`
  | `approve_${ChangeKind}`;

const propose = (kind: ChangeKind): CedarAction => `propose_${kind}`;
const approve = (kind: ChangeKind): CedarAction => `approve_${kind}`;

/**
 * Group to the Cedar actions it is permitted, for the actions the console
 * offers a control for. Reads that only fill a page (read_agent_state,
 * read_change_requests, read_governance and the like) are left out: a
 * refused read already shows the API's problem on the page.
 */
export const GROUP_ACTIONS: Record<CedarGroup, readonly CedarAction[]> = {
  viewers: [],
  operators: ["evaluate"],
  admins: [
    "evaluate",
    "read_evidence",
    "reconcile_closed_records",
    "stop_agent",
    ...GROUP_CHANGE_KINDS.map(propose),
  ],
  "change-approvers": GROUP_CHANGE_KINDS.map(approve),
};

/** Every Cedar action the table covers, whether or not a group holds it. */
export const COVERED_ACTIONS: readonly CedarAction[] = [
  "evaluate",
  "read_evidence",
  "reconcile_closed_records",
  "stop_agent",
  ...GROUP_CHANGE_KINDS.map(propose),
  ...GROUP_CHANGE_KINDS.map(approve),
];

/**
 * Who the console acts as. `groups: null` means the console does not know
 * the groups, and then every control shows and the API decides. In login
 * mode (ADR-018) the groups are the ones `GET /auth/session` returns. In
 * the development fallback they are unknown: a pasted token's claims are
 * not read, and the `X-Kavach-Principal` header (--insecure-dev) carries no
 * groups (the API takes them from its entities file, which the console
 * cannot see).
 */
export type Viewer = {
  /** The principal id, when the console knows it; null otherwise. */
  principal: string | null;
  /** The principal's groups, when the console knows them; null otherwise. */
  groups: readonly string[] | null;
};

export const UNKNOWN_VIEWER: Viewer = { principal: null, groups: null };

function isGroup(name: string): name is CedarGroup {
  return (CEDAR_GROUPS as readonly string[]).includes(name);
}

/**
 * Whether the viewer's groups probably allow `action`: true when the groups
 * are unknown or the table does not cover the action (role changes). Probably, because the API also adds the memberships its
 * entities file gives the principal, which the console cannot see.
 */
export function mayProbably(viewer: Viewer, action: CedarAction): boolean {
  if (viewer.groups === null || !COVERED_ACTIONS.includes(action)) return true;
  return viewer.groups.some(
    (group) => isGroup(group) && GROUP_ACTIONS[group].includes(action),
  );
}

/**
 * The line shown in place of a control the viewer's groups are known to
 * lack, or null when the control shows. `what` finishes "may …", e.g.
 * "stop agents".
 */
export function roleHint(
  viewer: Viewer,
  action: CedarAction,
  what: string,
): string | null {
  if (mayProbably(viewer, action)) return null;
  return deniedLine(viewer, what);
}

/** The hint wording, for a caller that has already decided the control is hidden. */
export function deniedLine(viewer: Viewer, what: string): string {
  const groups =
    viewer.groups && viewer.groups.length > 0
      ? viewer.groups.join(", ")
      : "none";
  return `Your groups (${groups}) don't include one that may ${what}. The server decides; ask an admin if you need this.`;
}

/** The Cedar action that proposes (and cancels) a change of `kind`. */
export function proposeAction(kind: ChangeKind): CedarAction {
  return propose(kind);
}

/** The Cedar action that approves (and rejects) a change of `kind`. */
export function approveAction(kind: ChangeKind): CedarAction {
  return approve(kind);
}
