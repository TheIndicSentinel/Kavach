// The role-hint tables against the Cedar policy file they copy. If someone
// edits kavach.cedar (or a table) so that they disagree about which group or
// role may do which action, this fails, and the hints cannot drift from the
// policy.
import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import {
  CEDAR_GROUPS,
  COVERED_ACTIONS,
  GROUP_ACTIONS,
  ROLES,
  ROLE_ACTIONS,
  UNKNOWN_VIEWER,
  approveAction,
  deniedLine,
  mayProbably,
  proposeAction,
  roleHint,
  type CedarAction,
} from "./permissions";

const CEDAR = new URL(
  "../../../crates/kavach-auth/policies/kavach.cedar",
  import.meta.url,
);

type Permit = { id: string; holder: string; actions: string[] | "all" };

/** The one condition a role permit may carry: user_admin never touches superadmin. */
const NOT_SUPERADMIN = /^when\s*\{\s*context\.role\s*!=\s*"superadmin"\s*\}$/;

function statementsOf(source: string): string[] {
  return source
    .replace(/\/\/[^\n]*/g, "")
    .split(";")
    .map((statement) => statement.trim())
    .filter(Boolean);
}

/**
 * Every policy in the file, read as `permit (principal in Group or Role,
 * action == A | action in [A, …] | action, resource == System::"api")`, with
 * at most the one condition above on a role permit. Anything else the
 * tables cannot model (a forbid, another condition, another principal)
 * fails here rather than being skipped.
 */
function readPolicies(source: string): { groups: Permit[]; roles: Permit[] } {
  const groups: Permit[] = [];
  const roles: Permit[] = [];
  for (const statement of statementsOf(source)) {
    const match = statement.match(
      /^@id\("([^"]+)"\)\s*permit\s*\(\s*principal\s+in\s+Kavach::(Group|Role)::"([^"]+)"\s*,\s*action(?:\s*==\s*Kavach::Action::"([^"]+)"|\s+in\s*\[([^\]]*)\])?\s*,\s*resource\s*==\s*Kavach::System::"api"\s*\)\s*(.*)$/s,
    );
    const fail = () => new Error(`the role-hint tables cannot model this policy:\n${statement}`);
    if (!match) throw fail();
    const [, id, kind, holder, single, list, condition] = match;
    const actions =
      single !== undefined
        ? [single]
        : list !== undefined
          ? list.split(",").map((item) => {
              const action = item.trim().match(/^Kavach::Action::"([^"]+)"$/);
              if (!action) throw fail();
              return action[1];
            })
          : ("all" as const);
    if (kind === "Group") {
      if (condition !== "" || actions === "all") throw fail();
      groups.push({ id, holder, actions });
    } else {
      if (condition !== "" && !NOT_SUPERADMIN.test(condition)) throw fail();
      if (!(ROLES as string[]).includes(holder)) throw fail();
      roles.push({ id, holder, actions });
    }
  }
  return { groups, roles };
}

const policies = readPolicies(readFileSync(CEDAR, "utf8"));
const pair = (holder: string, action: string) => `${holder} may ${action}`;
const covered = new Set<string>(COVERED_ACTIONS);

/** The covered actions the file permits each holder, as "holder may action". */
function pairsInFile(permits: Permit[]): string[] {
  return [
    ...new Set(
      permits.flatMap((permit) =>
        (permit.actions === "all" ? [...COVERED_ACTIONS] : permit.actions)
          .filter((action) => covered.has(action))
          .map((action) => pair(permit.holder, action)),
      ),
    ),
  ].sort();
}

describe("the role-hint tables match kavach.cedar", () => {
  it("reads a policy file with policies in it", () => {
    expect(policies.groups.length).toBeGreaterThan(20);
    expect(policies.roles.length).toBeGreaterThan(7);
  });

  it("names only the groups and roles the tables know", () => {
    expect([...new Set(policies.groups.map((p) => p.holder))].sort()).toEqual([...CEDAR_GROUPS].sort());
    expect([...new Set(policies.roles.map((p) => p.holder))].sort()).toEqual([...ROLES].sort());
  });

  it("gives each group exactly the covered actions the file permits it", () => {
    const inTable = CEDAR_GROUPS.flatMap((group) => GROUP_ACTIONS[group].map((action) => pair(group, action)));
    expect([...new Set(inTable)].sort()).toEqual(pairsInFile(policies.groups));
  });

  it("gives each role exactly the covered actions the file permits it", () => {
    const inTable = ROLES.flatMap((role) => ROLE_ACTIONS[role].map((action) => pair(role, action)));
    expect([...new Set(inTable)].sort()).toEqual(pairsInFile(policies.roles));
  });

  it("gives superadmin every action, with one permit and no condition", () => {
    const superadmin = policies.roles.filter((p) => p.holder === "superadmin");
    expect(superadmin.map((p) => p.actions)).toEqual(["all"]);
  });

  it("covers every propose_, approve_ and read_ action in the file (a new one needs a row)", () => {
    const named = [...policies.groups, ...policies.roles].flatMap((p) => (p.actions === "all" ? [] : p.actions));
    expect(named.filter((action) => /^(propose|approve|read)_/.test(action) && !covered.has(action))).toEqual([]);
  });

  it("covers only actions the file names (a renamed action fails)", () => {
    const named = new Set(
      [...policies.groups, ...policies.roles].flatMap((p) => (p.actions === "all" ? [] : p.actions)),
    );
    expect(COVERED_ACTIONS.filter((action) => !named.has(action))).toEqual([]);
  });

  it("refuses a policy it cannot model", () => {
    for (const policy of [
      '@id("x") permit (principal in Kavach::Group::"admins", action == Kavach::Action::"stop_agent", resource == Kavach::System::"api") when { false };',
      '@id("x") forbid (principal in Kavach::Role::"viewer", action, resource == Kavach::System::"api");',
      '@id("x") permit (principal in Kavach::Role::"admins", action, resource == Kavach::System::"api");',
      '@id("x") permit (principal in Kavach::Group::"admins", action, resource == Kavach::System::"api");',
      '@id("x") permit (principal in Kavach::Role::"user_admin", action in [Kavach::Action::"read_audit"], resource == Kavach::System::"api") when { true };',
    ]) {
      expect(() => readPolicies(policy)).toThrow(/cannot model/);
    }
  });
});

describe("mayProbably and roleHint", () => {
  const viewer = (groups: string[] | null) => ({ principal: "p-1", groups });

  it("allows everything when the groups are unknown", () => {
    for (const action of COVERED_ACTIONS)
      expect(mayProbably(UNKNOWN_VIEWER, action)).toBe(true);
    expect(roleHint(viewer(null), "stop_agent", "stop agents")).toBeNull();
  });

  it.each<[string[], CedarAction, boolean]>([
    [["admins"], "stop_agent", true],
    [["viewers"], "stop_agent", false],
    [["operators"], "evaluate", true],
    [["operators"], "read_evidence", false],
    [["change-approvers"], approveAction("reinstate_agent"), true],
    [["change-approvers"], proposeAction("reinstate_agent"), false],
    [["admins"], approveAction("reinstate_agent"), false],
    [["admins", "change-approvers"], approveAction("reinstate_agent"), true],
    [[], "evaluate", false],
    [["no-such-group"], "evaluate", false],
    // Role changes are not in the group table: the control shows, the server decides.
    [["viewers"], proposeAction("grant_role"), true],
    [[], approveAction("revoke_role"), true],
  ])("groups %j: %s is %s", (groups, action, allowed) => {
    expect(mayProbably(viewer(groups), action)).toBe(allowed);
  });

  it("names the groups, the action, and that the server decides", () => {
    expect(roleHint(viewer(["viewers"]), "stop_agent", "stop agents")).toBe(
      "Your groups (viewers) don't include one that may stop agents. The server decides; ask an admin if you need this.",
    );
    expect(roleHint(viewer([]), "evaluate", "run evaluate")).toMatch(
      /^Your groups \(none\)/,
    );
  });
});

describe("roles from GET /v1/me", () => {
  const viewer = (groups: string[] | null, roles: Parameters<typeof deniedLine>[0]["roles"]) => ({
    principal: "p-1",
    groups,
    roles,
  });

  it.each<[string[], string[], CedarAction, boolean]>([
    // A role adds to the groups; neither takes anything away.
    [["viewers"], ["operator"], "stop_agent", true],
    [["viewers"], [], "stop_agent", false],
    [["admins"], ["viewer"], "stop_agent", true],
    [[], ["superadmin"], proposeAction("grant_role"), true],
    [[], ["superadmin"], "read_audit", true],
    [[], ["user_admin"], approveAction("revoke_role"), true],
    [[], ["user_admin"], "read_principals", true],
    [[], ["user_admin"], "read_governance", false],
    [[], ["auditor"], "read_access_review", true],
    [[], ["auditor"], proposeAction("grant_role"), false],
    [["admins"], [], "read_principals", false],
    [["admins"], [], proposeAction("grant_role"), false],
    [[], ["policy_admin"], proposeAction("activate_pack"), true],
    [[], ["policy_admin"], approveAction("activate_pack"), false],
    [[], ["operator"], "attest_outcome_delivered", true],
    [[], ["auditor"], "attest_outcome_delivered", false],
    [[], ["approver"], approveAction("reinstate_agent"), true],
    [[], ["viewer"], "read_change_requests", false],
    // A role name the console does not know grants nothing.
    [[], ["root"], "read_audit", false],
  ])("groups %j, roles %j: %s is %s", (groups, roles, action, allowed) => {
    expect(mayProbably(viewer(groups, roles as never), action)).toBe(allowed);
  });

  it("shows a role-only action while the roles are unknown", () => {
    expect(mayProbably(viewer(["admins"], null), "read_principals")).toBe(true);
    expect(mayProbably(viewer(["admins"], undefined), proposeAction("grant_role"))).toBe(true);
    // A group-covered action is still decided by the groups.
    expect(mayProbably(viewer(["viewers"], null), "stop_agent")).toBe(false);
  });

  it("names the roles next to the groups once they are known", () => {
    expect(roleHint(viewer(["viewers"], []), "stop_agent", "stop agents")).toBe(
      "Your roles (none) and groups (viewers) don't include one that may stop agents. The server decides; ask an admin if you need this.",
    );
    expect(roleHint(viewer([], ["viewer", "auditor"]), "evaluate", "run evaluate")).toMatch(
      /^Your roles \(viewer, auditor\) and groups \(none\)/,
    );
  });
});
