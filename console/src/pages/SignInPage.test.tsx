// The sign-in screen and the session gate in each state, as static markup:
// a plain link to /auth/login (never a form), messages in the right live
// regions, the raw ?error= value never rendered, and the token field only in
// the development fallback.
import { renderToStaticMarkup } from "react-dom/server";
import { MemoryRouter, Route, Routes } from "react-router-dom";
import { afterEach, describe, expect, it } from "vitest";
import { SessionGate } from "../components/layout/SessionGate";
import { setSessionStateForTest, type SessionState } from "../lib/session";
import { byRole, text } from "../test/markup";
import SignInPage from "./SignInPage";

function signIn(state: SessionState, url = "/signin"): string {
  setSessionStateForTest(state);
  return renderToStaticMarkup(
    <MemoryRouter initialEntries={[url]}>
      <SignInPage />
    </MemoryRouter>,
  );
}

const signedOut: SessionState = { status: "signed_out", ended: false };

afterEach(() => setSessionStateForTest({ status: "checking" }));

describe("signed out (login mode)", () => {
  const html = signIn(signedOut);

  it("offers sign-in as a plain link to /auth/login, with no form and no field", () => {
    expect(html).toMatch(/<a [^>]*href="\/auth\/login"[^>]*>.*Sign in<\/a>/);
    expect(html).not.toContain("<form");
    expect(html).not.toContain("<input");
  });

  it("says tokens stay on the server and the browser holds only an HttpOnly cookie", () => {
    const shown = text(html);
    expect(shown).toContain("Tokens stay on the Kavach server");
    expect(shown).toContain("HttpOnly");
  });

  it("starts with empty status and alert regions", () => {
    expect(byRole(html, "status")).toEqual([""]);
    expect(byRole(html, "alert")).toEqual([""]);
  });
});

describe("the session-ended message", () => {
  it("is announced in role=status", () => {
    const html = signIn({ status: "signed_out", ended: true });
    expect(byRole(html, "status")).toEqual(["Your session ended. Sign in again."]);
    expect(byRole(html, "alert")).toEqual([""]);
  });
});

describe("/signin?error=", () => {
  it("shows the plain message for a known code, in role=alert", () => {
    const html = signIn(signedOut, "/signin?error=sessions_full");
    expect(byRole(html, "alert")[0]).toMatch(/limit of open sessions/);
    expect(html).not.toContain("sessions_full");
  });

  it("never renders the raw value of an unknown code", () => {
    const raw = "Your account is locked, call +91 0000 000000";
    const html = signIn(signedOut, `/signin?error=${encodeURIComponent(raw)}`);
    expect(byRole(html, "alert")).toEqual(["Sign-in did not complete. Try again."]);
    expect(text(html)).not.toContain("locked");
  });

  it("never renders markup from the query", () => {
    const html = signIn(signedOut, `/signin?error=${encodeURIComponent("<b>x</b>")}`);
    expect(html).not.toContain("<b>");
    expect(html).not.toContain("&lt;b&gt;");
  });
});

describe("development fallback", () => {
  const html = signIn({ status: "dev_token" });

  it("labels the pasted-token field as a development fallback", () => {
    expect(text(html)).toContain("Development fallback.");
    expect(text(html)).toContain("--insecure-dev");
    expect(html).toContain('<label for="token"');
    expect(html).toContain('<label for="principal"');
  });

  it("offers no sign-in link", () => {
    expect(html).not.toContain('href="/auth/login"');
  });
});

describe("login not configured", () => {
  const html = signIn({ status: "not_configured" });

  it("says so, points to docs/INSTALL.md, and offers no token field or link", () => {
    expect(text(html)).toContain("Console login is not configured on this server");
    expect(text(html)).toContain("docs/INSTALL.md");
    expect(html).not.toContain("<input");
    expect(html).not.toContain('href="/auth/login"');
  });
});

describe("settings unreadable", () => {
  it("shows the failure in role=alert and offers only a retry", () => {
    const html = signIn({ status: "unavailable", error: new Error("The API could not be reached") });
    expect(byRole(html, "alert")).toEqual(["The API could not be reached"]);
    expect(html).not.toContain("<input");
    expect(html).not.toContain('href="/auth/login"');
    expect(text(html)).toContain("Try again");
  });
});

describe("the session gate", () => {
  function gate(state: SessionState): string {
    setSessionStateForTest(state);
    return renderToStaticMarkup(
      <MemoryRouter initialEntries={["/agents"]}>
        <Routes>
          <Route element={<SessionGate />}>
            <Route path="agents" element={<p>signed-in page data</p>} />
          </Route>
        </Routes>
      </MemoryRouter>,
    );
  }

  it("shows the page only with a live session or in the development fallback", () => {
    expect(gate({ status: "signed_in", session: { principal: "p", groups: [], expires_at: "", idle_expires_at: "" } }))
      .toContain("signed-in page data");
    expect(gate({ status: "dev_token" })).toContain("signed-in page data");
  });

  it.each<SessionState>([
    { status: "checking" },
    { status: "signed_out", ended: true },
    { status: "signed_out", ended: false },
    { status: "not_configured" },
    { status: "unavailable", error: null },
  ])("never shows the page's data when the state is %o", (state) => {
    expect(gate(state)).not.toContain("signed-in page data");
  });

  it("says it is checking, in role=status, while the mode is read", () => {
    expect(byRole(gate({ status: "checking" }), "status")).toEqual(["Checking your session…"]);
  });
});
