// Role hints: which console pages and actions a principal's groups and
// roles probably allow, copied from crates/kavach-auth/policies/kavach.cedar.
// The server stays the gate for every call. A hint only hides a control the server is expected to
// refuse, and says so; it never grants anything. permissions.test.ts reads
// the Cedar file and fails when this table and the file disagree.
import type { ChangeKind, RoleName } from "./api";

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
 * Role changes (ADR-019 §4). No alias group is permitted them; `superadmin`
 * and `user_admin` are (`user_admin` never for `superadmin`, a condition the
 * table leaves to the server).
 */
const ROLE_CHANGE_KINDS: readonly ChangeKind[] = ["grant_role", "revoke_role"];

/** The governance change kinds: every kind but the role changes. */
const GOVERNANCE_KINDS = CHANGE_KINDS.filter(
  (kind) => !ROLE_CHANGE_KINDS.includes(kind),
);

/** The reads behind the console's pages (one per page; ROLE_PAGES in Sidebar). */
export const READ_ACTIONS = [
  "read_health",
  "read_governance",
  "read_metrics",
  "read_incidents",
  "read_batch_jobs",
  "read_agent_state",
  "read_retention",
  "read_tombstones",
  "read_change_requests",
  "read_audit",
  "read_evidence",
  "read_principals",
  "read_access_review",
] as const;

export type ReadAction = (typeof READ_ACTIONS)[number];

/** The Cedar actions behind the console's pages and action controls. */
export type CedarAction =
  | ReadAction
  | "evaluate"
  | "reconcile_closed_records"
  | "stop_agent"
  | `propose_${ChangeKind}`
  | `approve_${ChangeKind}`;

const propose = (kind: ChangeKind): CedarAction => `propose_${kind}`;
const approve = (kind: ChangeKind): CedarAction => `approve_${kind}`;

/**
 * Group to the Cedar actions it is permitted (the alias groups, ADR-019 §1).
 * permissions.test.ts checks this table against kavach.cedar both ways.
 */
export const GROUP_ACTIONS: Record<CedarGroup, readonly CedarAction[]> = {
  viewers: ["read_health", "read_governance"],
  operators: ["evaluate", "read_governance"],
  admins: [
    "read_health",
    "read_governance",
    "read_metrics",
    "read_audit",
    "read_evidence",
    "read_retention",
    "read_tombstones",
    "read_incidents",
    "read_batch_jobs",
    "read_change_requests",
    "read_agent_state",
    "evaluate",
    "reconcile_closed_records",
    "stop_agent",
    ...GOVERNANCE_KINDS.map(propose),
  ],
  "change-approvers": [
    "read_governance",
    "read_change_requests",
    ...GOVERNANCE_KINDS.map(approve),
  ],
};

/** Every Cedar action the tables cover, whether or not anyone holds it. */
export const COVERED_ACTIONS: readonly CedarAction[] = [
  ...READ_ACTIONS,
  "evaluate",
  "reconcile_closed_records",
  "stop_agent",
  ...CHANGE_KINDS.map(propose),
  ...CHANGE_KINDS.map(approve),
];

/** The seven ADR-019 roles; the Record makes a role added to the spec a type error here. */
const ROLES_RECORD: Record<RoleName, true> = {
  superadmin: true,
  user_admin: true,
  policy_admin: true,
  approver: true,
  operator: true,
  auditor: true,
  viewer: true,
};

export const ROLES = Object.keys(ROLES_RECORD) as RoleName[];

/**
 * Role to the Cedar actions it is permitted: the matrix of ADR-019 §2, as
 * kavach.cedar writes it. `superadmin` holds every action.
 * permissions.test.ts checks this table against the file both ways.
 */
export const ROLE_ACTIONS: Record<RoleName, readonly CedarAction[]> = {
  superadmin: COVERED_ACTIONS,
  user_admin: [
    "read_health",
    "read_change_requests",
    "read_principals",
    "read_access_review",
    ...ROLE_CHANGE_KINDS.map(propose),
    ...ROLE_CHANGE_KINDS.map(approve),
  ],
  policy_admin: [
    "read_health",
    "read_governance",
    "read_incidents",
    "read_batch_jobs",
    "read_agent_state",
    "read_retention",
    "read_tombstones",
    "read_change_requests",
    ...GOVERNANCE_KINDS.map(propose),
  ],
  approver: [
    "read_health",
    "read_governance",
    "read_retention",
    "read_tombstones",
    "read_change_requests",
    ...GOVERNANCE_KINDS.map(approve),
  ],
  operator: [
    "read_health",
    "read_governance",
    "read_metrics",
    "evaluate",
    "read_incidents",
    "read_batch_jobs",
    "read_agent_state",
    "stop_agent",
    "reconcile_closed_records",
  ],
  auditor: [
    "read_health",
    "read_governance",
    "read_metrics",
    "read_incidents",
    "read_batch_jobs",
    "read_agent_state",
    "read_retention",
    "read_tombstones",
    "read_change_requests",
    "read_audit",
    "read_evidence",
    "read_principals",
    "read_access_review",
  ],
  viewer: ["read_health", "read_governance"],
};

/** Actions only a role grants (no alias group holds them). */
const ROLE_ONLY_ACTIONS: readonly CedarAction[] = COVERED_ACTIONS.filter(
  (action) =>
    !CEDAR_GROUPS.some((group) => GROUP_ACTIONS[group].includes(action)) &&
    ROLES.some((role) => role !== "superadmin" && ROLE_ACTIONS[role].includes(action)),
);

/**
 * Who the console acts as. `groups: null` means the console does not know
 * the groups, and then every control shows and the API decides. In login
 * mode (ADR-018) the groups are the ones `GET /auth/session` returns. In
 * the development fallback they are unknown: a pasted token's claims are
 * not read, and the `X-Kavach-Principal` header (--insecure-dev) carries no
 * groups (the API takes them from its entities file, which the console
 * cannot see).
 *
 * `roles` are the ones `GET /v1/me` returns (ADR-019). Absent or null: not
 * known, and then an action only a role grants shows.
 */
export type Viewer = {
  /** The principal id, when the console knows it; null otherwise. */
  principal: string | null;
  /** The principal's groups, when the console knows them; null otherwise. */
  groups: readonly string[] | null;
  /** The roles bound to the principal now, when the console knows them. */
  roles?: readonly RoleName[] | null;
  /** True while `GET /v1/me` has not answered yet; a page whose every read is role-only may wait. */
  rolesPending?: boolean;
};

export const UNKNOWN_VIEWER: Viewer = { principal: null, groups: null };

function isGroup(name: string): name is CedarGroup {
  return (CEDAR_GROUPS as readonly string[]).includes(name);
}

function isRole(name: string): name is RoleName {
  return Object.hasOwn(ROLES_RECORD, name);
}

/**
 * Whether the viewer's groups and roles probably allow `action`. True when
 * the groups are unknown, or the table does not cover the action; true for
 * an action only a role grants while the roles are unknown. Probably,
 * because the API also adds the memberships its entities file gives the
 * principal, which the console cannot see.
 */
export function mayProbably(viewer: Viewer, action: CedarAction): boolean {
  if (viewer.groups === null || !COVERED_ACTIONS.includes(action)) return true;
  const roles = viewer.roles ?? null;
  if (roles === null && ROLE_ONLY_ACTIONS.includes(action)) return true;
  const byGroup = viewer.groups.some(
    (group) => isGroup(group) && GROUP_ACTIONS[group].includes(action),
  );
  const byRole = (roles ?? []).some(
    (role) => isRole(role) && ROLE_ACTIONS[role].includes(action),
  );
  return byGroup || byRole;
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

const listed = (names: readonly string[] | null | undefined) =>
  names && names.length > 0 ? names.join(", ") : "none";

/** The hint wording, for a caller that has already decided the control is hidden. */
export function deniedLine(viewer: Viewer, what: string): string {
  const holders =
    viewer.roles === undefined || viewer.roles === null
      ? `Your groups (${listed(viewer.groups)}) don't include one`
      : `Your roles (${listed(viewer.roles)}) and groups (${listed(viewer.groups)}) don't include one`;
  return `${holders} that may ${what}. The server decides; ask an admin if you need this.`;
}

/** The Cedar action that proposes (and cancels) a change of `kind`. */
export function proposeAction(kind: ChangeKind): CedarAction {
  return propose(kind);
}

/** The Cedar action that approves (and rejects) a change of `kind`. */
export function approveAction(kind: ChangeKind): CedarAction {
  return approve(kind);
}
