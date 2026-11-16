// The role-hint table against the Cedar policy file it copies. If someone
// edits kavach.cedar (or the table) so that they disagree about which group
// may do which action, this fails, and the hint cannot drift from the policy.
import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import {
  CEDAR_GROUPS,
  COVERED_ACTIONS,
  GROUP_ACTIONS,
  UNKNOWN_VIEWER,
  approveAction,
  mayProbably,
  proposeAction,
  roleHint,
  type CedarAction,
} from "./permissions";

const CEDAR = new URL(
  "../../../crates/kavach-auth/policies/kavach.cedar",
  import.meta.url,
);

type Permit = { id: string; group: string; action: string };

/** The seven ADR-019 roles; their permits are not group hints. */
const ROLES = [
  "superadmin",
  "user_admin",
  "policy_admin",
  "approver",
  "operator",
  "auditor",
  "viewer",
] as const;

/** A `permit` whose principal is one of the seven roles (ADR-019 §2). */
const ROLE_PERMIT = new RegExp(
  `^@id\\("([^"]+)"\\)\\s*permit\\s*\\(\\s*principal\\s+in\\s+Kavach::Role::"(${ROLES.join("|")})"\\s*,`,
);

function statementsOf(source: string): string[] {
  return source
    .replace(/\/\/[^\n]*/g, "")
    .split(";")
    .map((statement) => statement.trim())
    .filter(Boolean);
}

/**
 * Every group policy in the file, read as `permit (principal in Group,
 * action == Action, resource == System::"api")`. Role permits (ADR-019) are
 * left to the role-based gating; anything else the table cannot model (a
 * forbid, a condition, a principal that is neither a group nor a role, a
 * set of actions) fails here rather than being skipped.
 */
function readPolicies(source: string): Permit[] {
  const statements = statementsOf(source).filter(
    (statement) => !ROLE_PERMIT.test(statement),
  );
  return statements.map((statement) => {
    const match = statement.match(
      /^@id\("([^"]+)"\)\s*permit\s*\(\s*principal\s+in\s+Kavach::Group::"([^"]+)"\s*,\s*action\s*==\s*Kavach::Action::"([^"]+)"\s*,\s*resource\s*==\s*Kavach::System::"api"\s*\)$/,
    );
    if (!match)
      throw new Error(
        `the role-hint table cannot model this policy:\n${statement}`,
      );
    return { id: match[1], group: match[2], action: match[3] };
  });
}

const policies = readPolicies(readFileSync(CEDAR, "utf8"));
const pair = (group: string, action: string) => `${group} may ${action}`;

describe("the role-hint table matches kavach.cedar", () => {
  it("reads a policy file with policies in it", () => {
    expect(policies.length).toBeGreaterThan(20);
  });

  it("names only the groups the table knows", () => {
    const groups = new Set(policies.map((policy) => policy.group));
    expect([...groups].sort()).toEqual([...CEDAR_GROUPS].sort());
  });

  it("gives each group exactly the covered actions the file permits it", () => {
    const covered = new Set<string>(COVERED_ACTIONS);
    const inFile = policies
      .filter((policy) => covered.has(policy.action))
      .map((policy) => pair(policy.group, policy.action));
    const inTable = CEDAR_GROUPS.flatMap((group) =>
      GROUP_ACTIONS[group].map((action) => pair(group, action)),
    );
    expect([...new Set(inTable)].sort()).toEqual([...new Set(inFile)].sort());
  });

  it("covers every propose_ and approve_ action in the file (a new change kind needs a row)", () => {
    const covered = new Set<string>(COVERED_ACTIONS);
    const changeActions = policies
      .map((policy) => policy.action)
      .filter((action) => /^(propose|approve)_/.test(action));
    expect(changeActions.filter((action) => !covered.has(action))).toEqual([]);
  });

  it("covers only actions the file names (a renamed action fails)", () => {
    const named = new Set(policies.map((policy) => policy.action));
    expect(COVERED_ACTIONS.filter((action) => !named.has(action))).toEqual([]);
  });

  it("leaves out only permits for the seven roles, and every role has one", () => {
    const rolePermits = statementsOf(readFileSync(CEDAR, "utf8"))
      .map((statement) => statement.match(ROLE_PERMIT))
      .filter((match): match is RegExpMatchArray => match !== null);
    expect(new Set(rolePermits.map((match) => match[2]))).toEqual(
      new Set(ROLES),
    );
    expect(() =>
      readPolicies(
        '@id("x") forbid (principal in Kavach::Role::"viewer", action, resource == Kavach::System::"api");',
      ),
    ).toThrow(/cannot model/);
    expect(() =>
      readPolicies(
        '@id("x") permit (principal in Kavach::Role::"admins", action, resource == Kavach::System::"api");',
      ),
    ).toThrow(/cannot model/);
  });

  it("refuses a policy it cannot model", () => {
    expect(() =>
      readPolicies(
        '@id("x") permit (principal in Kavach::Group::"admins", action == Kavach::Action::"stop_agent", resource == Kavach::System::"api") when { false };',
      ),
    ).toThrow(/cannot model/);
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
