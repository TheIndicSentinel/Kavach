// The Users & roles page's form rules (ADR-019 §4). The server checks every
// rule again (no self-grant, superadmin only by superadmin, no duplicate,
// never the last superadmin or user admin); these only catch an empty or
// malformed field before a round trip.
import type { BindingSubject, RoleName } from "./api";
import { ROLES } from "./permissions";

/** What each role is for (ADR-019 §1), shown next to the role in the form. */
export const ROLE_PURPOSES: Record<RoleName, string> = {
  superadmin: "Break-glass and setup: every action, each one flagged in the audit.",
  user_admin: "Proposes and approves role grants and revokes (never superadmin's); reads users and the access review.",
  policy_admin: "Proposes governance changes: packs, models, retention, erasure, reinstating an agent.",
  approver: "Approves or rejects governance change requests.",
  operator: "Runs the system: evaluates, reads operational state, stops an agent, reconciles closed loans.",
  auditor: "Reads everything, changes nothing.",
  viewer: "Reads governance and health.",
};

/** The longest issuer, subject or group name the form sends (the server has its own limits). */
export const MAX_FIELD = 512;

export type GrantForm = {
  role: RoleName | "";
  kind: BindingSubject["kind"];
  issuer: string;
  value: string;
};

export const EMPTY_GRANT: GrantForm = { role: "", kind: "principal", issuer: "", value: "" };

export type GrantErrors = Partial<Record<"role" | "issuer" | "value", string>>;

// eslint-disable-next-line no-control-regex
const CONTROL = /[\u0000-\u001f\u007f]/;

function fieldError(value: string, name: string): string | undefined {
  const trimmed = value.trim();
  if (!trimmed) return `Enter the ${name}.`;
  if (trimmed.length > MAX_FIELD) return `The ${name} is longer than ${MAX_FIELD} characters.`;
  if (CONTROL.test(trimmed)) return `The ${name} has a control character.`;
  return undefined;
}

/** What is wrong with the form, field by field; empty when it can be proposed. */
export function grantErrors(form: GrantForm): GrantErrors {
  const errors: GrantErrors = {};
  if (!(ROLES as string[]).includes(form.role)) errors.role = "Choose a role.";
  const issuer = fieldError(form.issuer, "issuer");
  if (issuer) errors.issuer = issuer;
  const value = fieldError(form.value, form.kind === "group" ? "group name" : "subject");
  if (value) errors.value = value;
  return errors;
}

/** The `grant_role` params for a valid form (`{role, subject: {kind, issuer, value}}`). */
export function grantParams(form: GrantForm): { role: RoleName; subject: BindingSubject } {
  return {
    role: form.role as RoleName,
    subject: { kind: form.kind, issuer: form.issuer.trim(), value: form.value.trim() },
  };
}

/** The line once a role change is proposed. */
export function roleChangeProposed(id: string): string {
  return `Change request ${id} proposed. A second person with superadmin or user_admin must approve it on the Change requests page; nothing changes until then.`;
}

/** "Yes", "No", or "—" for a group (its members are in the IdP). */
export function staleLabel(stale: boolean | null): string {
  return stale === null ? "—" : stale ? "Yes" : "No";
}
