// Overview reads GET /health and GET /v1/runtime. Each card shows its own
// loading skeleton and refusal; nothing is filled in before the runtime
// answers, and the capability copy says only what the verifiers check.
import { describe, expect, it } from "vitest";
import { runtime } from "../test/governanceFixtures";
import { byRole, render, text } from "../test/markup";
import {
  badGateway,
  failed,
  forbidden,
  loading,
  ok,
  serverError,
  unauthorized,
} from "../test/states";
import OverviewPage from "./OverviewPage";

const SKELETON = 'class="animate-pulse';
const healthy = ok({ status: "ok" });

describe("OverviewPage states", () => {
  it("loading: skeletons, both reads in role=status, and no made-up pack or sector", () => {
    const html = render(<OverviewPage health={loading} runtime={loading} />);
    expect(html).toMatch(/<h1[^>]*>Overview<\/h1>/);
    expect(html).toContain(SKELETON);
    expect(byRole(html, "status")).toEqual(["Checking API health…", "Loading the runtime…"]);
    expect(byRole(html, "alert")).toEqual(["", ""]);
    const shown = text(html);
    expect(shown).not.toContain("finance-v0");
    expect(shown).not.toContain("India");
    expect(shown).not.toContain("Runtime posture");
  });

  it("loaded: health, the active model and pack, and the posture", () => {
    const shown = text(render(<OverviewPage health={healthy} runtime={ok(runtime)} />));
    expect(shown).toContain("OK");
    expect(shown).toContain("credit-risk");
    expect(shown).toContain("finance sector");
    expect(shown).toContain("Pack finance-core sets the rules for credit evaluations");
    expect(shown).toContain("Runtime posture");
  });

  it("agent-only: no model, pack or credit capability", () => {
    const shown = text(
      render(<OverviewPage health={healthy} runtime={ok({ ...runtime, agent_only: true })} />),
    );
    expect(shown).not.toContain("Active model");
    expect(shown).not.toContain("Policy pack");
    expect(shown).not.toContain("Decision events");
    expect(shown).toContain("Agent evidence");
  });

  it("runtime error: detail, status and request_id, Try again, and the pack not guessed", () => {
    const html = render(<OverviewPage health={healthy} runtime={failed(serverError)} />);
    expect(byRole(html, "alert")).toEqual(["", "storage unavailable HTTP 500 · request_id req-500"]);
    const shown = text(html);
    expect(shown).toContain("Try again");
    expect(shown).toContain("Not known until GET /v1/runtime answers.");
    expect(shown).not.toContain("finance-v0");
  });

  it("health error, a non-JSON 502: Unavailable, the status, and no request_id", () => {
    const html = render(<OverviewPage health={failed(badGateway("/health"))} runtime={ok(runtime)} />);
    const [alert] = byRole(html, "alert");
    expect(alert).toContain("502 Bad Gateway");
    expect(alert).toContain("no request_id was returned");
    expect(text(html)).toContain("Unavailable");
  });

  it("401: sign in again or set a token; 403: not permitted, the server decides", () => {
    const signedOut = byRole(render(<OverviewPage health={healthy} runtime={failed(unauthorized)} />), "alert");
    expect(signedOut[1]).toContain("Sign in again, or set an access token in Settings");
    const refused = byRole(render(<OverviewPage health={healthy} runtime={failed(forbidden)} />), "alert");
    expect(refused[1]).toContain("Not permitted");
    expect(refused[1]).toContain("The server decides");
  });

  // Empty and 404: not states of this page. /health and /v1/runtime always
  // answer with a body, and the page takes no id.
});

describe("OverviewPage copy", () => {
  const shown = text(render(<OverviewPage health={healthy} runtime={ok(runtime)} />));

  it("words evidence as the verifiers do, and claims no PII-free trail", () => {
    expect(shown).not.toMatch(/no raw PII/i);
    expect(shown).toContain("signed and hash-chained; a verifier checks them offline against the keys you list");
    expect(shown).toContain("hash-chained event, not signed");
  });

  it("names the principal the API authenticated, not only a bearer token", () => {
    expect(shown).toContain("for the principal the API authenticated");
    expect(shown).not.toContain("named by a bearer token");
  });
});
