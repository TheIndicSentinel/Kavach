// A refusal shows its detail and request_id inside role="alert".
import { describe, expect, it } from "vitest";
import { ApiError } from "../../lib/api";
import { byRole, render } from "../../test/markup";
import { ProblemAlert } from "./ProblemAlert";

describe("ProblemAlert", () => {
  it("shows the problem detail, the status and the request_id in role=alert", () => {
    const error = new ApiError(
      "agent not found (request req-404)",
      404,
      "req-404",
      "agent not found",
    );
    const [alert] = byRole(render(<ProblemAlert error={error} />), "alert");
    expect(alert).toContain("agent not found");
    expect(alert).toContain("HTTP 404");
    expect(alert).toContain("request_id req-404");
  });

  it("says when no request_id came back, and shows the status of a non-problem body", () => {
    const error = new ApiError("GET /v1/agents failed (502 Bad Gateway)", 502);
    const [alert] = byRole(render(<ProblemAlert error={error} />), "alert");
    expect(alert).toContain("502 Bad Gateway");
    expect(alert).toContain("no request_id was returned");
  });

  it("omits the status of an unreachable API", () => {
    const [alert] = byRole(
      render(<ProblemAlert error={new ApiError("The API could not be reached", 0)} />),
      "alert",
    );
    expect(alert).toContain("The API could not be reached");
    expect(alert).not.toContain("HTTP 0");
  });

  it("keeps an empty alert region when there is no error", () => {
    expect(byRole(render(<ProblemAlert error={null} />), "alert")).toEqual([""]);
  });
});
