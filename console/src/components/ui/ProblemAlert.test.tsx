// A refusal shows its detail and request_id inside role="alert".
import { describe, expect, it } from "vitest";
import { ApiError } from "../../lib/api";
import { byRole, render } from "../../test/markup";
import { ProblemAlert, unreachableMessage } from "./ProblemAlert";

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

  it("a 5xx with no request_id says the API is not reachable, and keeps the status", () => {
    // The Vite dev proxy answers 500 or 502 when nothing listens on :8080.
    for (const status of [500, 502, 503, 504]) {
      const error = new ApiError(`GET /auth/config failed (${status})`, status);
      const [alert] = byRole(render(<ProblemAlert error={error} />), "alert");
      expect(alert).toBe(`${unreachableMessage(true)} HTTP ${status} · no request_id was returned`);
      expect(alert).toContain("Start it with scripts/demo.sh");
      expect(alert).not.toContain("failed (");
    }
  });

  it("a request that never completed says the API is not reachable, with no status", () => {
    const [alert] = byRole(
      render(<ProblemAlert error={new ApiError("The API could not be reached", 0)} />),
      "alert",
    );
    expect(alert).toBe(`${unreachableMessage(true)} no request_id was returned`);
    expect(alert).not.toContain("HTTP 0");
  });

  it("a 5xx that carries a request_id came from kavach-api and shows its detail", () => {
    const error = new ApiError("x", 503, "req-503", "storage unavailable");
    const [alert] = byRole(render(<ProblemAlert error={error} />), "alert");
    expect(alert).toBe("storage unavailable HTTP 503 · request_id req-503");
  });

  it("a 4xx with no request_id keeps its own text: something answered", () => {
    const error = new ApiError("GET /v1/agents failed (404 Not Found)", 404);
    const [alert] = byRole(render(<ProblemAlert error={error} />), "alert");
    expect(alert).toContain("404 Not Found");
    expect(alert).not.toContain("not reachable");
    expect(alert).toContain("no request_id was returned");
  });

  it("names scripts/demo.sh only in a development build", () => {
    expect(unreachableMessage(true)).toBe(
      "The Kavach API is not reachable. Start it with scripts/demo.sh (or check that kavach-api runs on :8080).",
    );
    expect(unreachableMessage(false)).toContain("The Kavach API is not reachable.");
    expect(unreachableMessage(false)).not.toContain("demo.sh");
  });

  it("a 401 says to sign in again or set a token, with a link to Settings", () => {
    const html = render(
      <ProblemAlert error={new ApiError("missing bearer token", 401, "req-401")} />,
    );
    const [alert] = byRole(html, "alert");
    expect(alert).toContain("missing bearer token");
    expect(alert).toContain("Sign in again, or set an access token in Settings");
    expect(alert).toContain("HTTP 401 · request_id req-401");
    expect(html).toContain('href="/settings"');
  });

  it("a 403 says the server refused this principal, and that the server decides", () => {
    const [alert] = byRole(
      render(<ProblemAlert error={new ApiError("forbidden by policy", 403, "req-403")} />),
      "alert",
    );
    expect(alert).toContain("forbidden by policy");
    expect(alert).toContain("Not permitted: the server refused this for the principal");
    expect(alert).toContain("The server decides");
    expect(alert).toContain("HTTP 403 · request_id req-403");
  });

  it("a 404 with notFound leads with it and keeps the server detail", () => {
    const error = new ApiError("x", 404, "req-404", "agent surfaces are not configured");
    const [alert] = byRole(render(<ProblemAlert error={error} notFound="No such agent." />), "alert");
    expect(alert).toBe(
      "No such agent. agent surfaces are not configured · HTTP 404 · request_id req-404",
    );
  });

  it("notFound is ignored for other statuses", () => {
    const error = new ApiError("x", 500, "req-500", "storage unavailable");
    const [alert] = byRole(render(<ProblemAlert error={error} notFound="No such agent." />), "alert");
    expect(alert).not.toContain("No such agent.");
    expect(alert).toContain("storage unavailable");
  });

  it("keeps an empty alert region when there is no error", () => {
    expect(byRole(render(<ProblemAlert error={null} />), "alert")).toEqual([""]);
  });
});
