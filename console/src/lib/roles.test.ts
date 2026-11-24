import { describe, expect, it } from "vitest";
import { EMPTY_GRANT, MAX_FIELD, grantErrors, grantParams, roleChangeProposed, staleLabel } from "./roles";

describe("the grant form", () => {
  it("asks for every field when empty", () => {
    expect(grantErrors(EMPTY_GRANT)).toEqual({
      role: "Choose a role.",
      issuer: "Enter the issuer.",
      value: "Enter the subject.",
    });
    expect(grantErrors({ ...EMPTY_GRANT, kind: "group" }).value).toBe("Enter the group name.");
  });

  it("refuses an unknown role, a control character, and an over-long field", () => {
    const base = { role: "auditor", kind: "principal", issuer: "https://idp", value: "alice" } as const;
    expect(grantErrors(base)).toEqual({});
    expect(grantErrors({ ...base, role: "root" as never }).role).toBe("Choose a role.");
    expect(grantErrors({ ...base, value: "ali\nce" }).value).toMatch(/control character/);
    expect(grantErrors({ ...base, issuer: "x".repeat(MAX_FIELD + 1) }).issuer).toMatch(/longer than/);
  });

  it("sends the trimmed subject in the grant_role shape", () => {
    expect(grantParams({ role: "viewer", kind: "group", issuer: " https://idp ", value: " readers " })).toEqual({
      role: "viewer",
      subject: { kind: "group", issuer: "https://idp", value: "readers" },
    });
  });

  it("says a second person must approve, and nothing changes until then", () => {
    expect(roleChangeProposed("cr-9")).toMatch(/^Change request cr-9 proposed\. A second person .* nothing changes until then\.$/);
  });

  it("shows a group's staleness as unknown", () => {
    expect([staleLabel(true), staleLabel(false), staleLabel(null)]).toEqual(["Yes", "No", "—"]);
  });
});
