// Console sign-in (ADR-018 option C): which mode the server is in, the
// signed-in session as `GET /auth/session` describes it, and sign-out.
//
// Tokens stay on the server. The browser holds only the HttpOnly session
// cookie, which no script here can read. What this module keeps (the
// principal, groups and expiry) is in memory only and is never written to
// sessionStorage, localStorage or IndexedDB.
import { useSyncExternalStore } from "react";
import { ApiError, request, setAuthMode, setUnauthorizedHandler } from "./api";

// TODO(openapi): replace with generated types once /auth/* is in openapi.yaml
/** `GET /auth/config` (public). */
export type AuthConfig = {
  login_configured: boolean;
  /** True only when login is not configured and the server runs with --insecure-dev. */
  pasted_token_allowed: boolean;
};

// TODO(openapi): replace with generated types once /auth/* is in openapi.yaml
/** `GET /auth/session` (session cookie). Never carries a token. */
export type AuthSession = {
  principal: string;
  groups: string[];
  /** The absolute limit: the session ends then, whatever the activity. */
  expires_at: string;
  /** When the session ends if nothing uses it before then. */
  idle_expires_at: string;
};

// TODO(openapi): replace with generated types once /auth/* is in openapi.yaml
/** `POST /auth/logout`. Null unless the server is set to end the IdP session too. */
export type LogoutResponse = {
  end_session_url: string | null;
};

// TODO(openapi): replace with generated types once /auth/* is in openapi.yaml
/** The fixed set of `/signin?error=` codes the server sends. */
export type SignInErrorCode = "login_failed" | "login_expired" | "sessions_full" | "login_unavailable";

/**
 * How the console authenticates, decided by `GET /auth/config`:
 * - `login`: console login is configured; the session cookie is the only credential.
 * - `dev_token`: no login, and the server runs with --insecure-dev, so the
 *   pasted token or principal ID field is offered as a development fallback.
 * - `not_configured`: neither; the console offers no way to sign in.
 */
export type AuthMode = "login" | "dev_token" | "not_configured";

export function authModeOf(config: AuthConfig): AuthMode {
  if (config.login_configured) return "login";
  if (config.pasted_token_allowed) return "dev_token";
  return "not_configured";
}

/** The path the sign-in link points at: a top-level navigation, never a fetch or a form. */
export const LOGIN_PATH = "/auth/login";

export const SIGNIN_PATH = "/signin";

export const SESSION_ENDED_MESSAGE = "Your session ended. Sign in again.";

const SIGNIN_ERRORS: Record<SignInErrorCode, string> = {
  login_failed: "Sign-in did not complete: the answer from the identity provider was refused. Try again.",
  login_expired: "That sign-in attempt expired or was already used. Try again.",
  sessions_full:
    "The server has reached its limit of open sessions, so no new sign-in is accepted now. Try again later, or ask an administrator.",
  login_unavailable:
    "Sign-in is not available: the server could not reach the identity provider, or console login is not configured.",
};

const UNKNOWN_SIGNIN_ERROR = "Sign-in did not complete. Try again.";

/**
 * The message for a `/signin?error=` value. The value itself is never shown:
 * a code outside the fixed set gets a generic message.
 */
export function signInErrorMessage(code: string | null): string | null {
  if (code === null || code === "") return null;
  return Object.hasOwn(SIGNIN_ERRORS, code)
    ? SIGNIN_ERRORS[code as SignInErrorCode]
    : UNKNOWN_SIGNIN_ERROR;
}

function isLoopback(hostname: string): boolean {
  return hostname === "localhost" || hostname === "127.0.0.1" || hostname === "[::1]";
}

/**
 * Where sign-out goes next. The IdP's end-session URL is followed only when it
 * is `https:`, or when it is on the console's own origin and that origin is a
 * plain-HTTP loopback address (a development stack). Anything else (no URL, a
 * relative or unparsable one, `javascript:`, `data:`, plain HTTP to another
 * origin) goes to the sign-in screen.
 */
export function signOutTarget(endSessionUrl: string | null, pageOrigin: string): string {
  if (!endSessionUrl) return SIGNIN_PATH;
  let url: URL;
  let page: URL;
  try {
    url = new URL(endSessionUrl);
    page = new URL(pageOrigin);
  } catch {
    return SIGNIN_PATH;
  }
  if (url.username || url.password) return SIGNIN_PATH;
  if (url.protocol === "https:") return url.href;
  const devOrigin = page.protocol === "http:" && isLoopback(page.hostname);
  if (url.protocol === "http:" && devOrigin && url.origin === page.origin) return url.href;
  return SIGNIN_PATH;
}

// --- the session state, in memory only ------------------------------------

export type SessionState =
  | { status: "checking" }
  /** `/auth/config` could not be read: nothing is offered until it can be. */
  | { status: "unavailable"; error: unknown }
  | { status: "not_configured" }
  | { status: "dev_token" }
  /** Login mode, no live session. `ended` when a call was refused with 401 after sign-in. */
  | { status: "signed_out"; ended: boolean }
  | { status: "signed_in"; session: AuthSession };

let state: SessionState = { status: "checking" };
const listeners = new Set<() => void>();

function setState(next: SessionState): void {
  state = next;
  for (const listener of listeners) listener();
}

export function getSessionState(): SessionState {
  return state;
}

function subscribe(listener: () => void): () => void {
  listeners.add(listener);
  return () => listeners.delete(listener);
}

/** The session state, re-rendering when it changes. */
export function useSessionState(): SessionState {
  return useSyncExternalStore(subscribe, getSessionState, getSessionState);
}

/**
 * A 401 from any call after sign-in: the session ended. The in-memory session
 * is dropped; the gate then sends the operator to the sign-in screen with
 * {@link SESSION_ENDED_MESSAGE}, and the views fetch again after the next sign-in.
 */
export function sessionEnded(): void {
  if (state.status === "signed_in") setState({ status: "signed_out", ended: true });
}

export function fetchAuthConfig(): Promise<AuthConfig> {
  return request("/auth/config");
}

export function fetchSession(): Promise<AuthSession> {
  return request("/auth/session");
}

/** `POST /auth/logout` (fetch, never a form: ADR-018 §7). */
export function postLogout(): Promise<LogoutResponse> {
  return request("/auth/logout", { method: "POST" });
}

let booting: Promise<void> | null = null;

async function boot(): Promise<void> {
  let mode: AuthMode;
  try {
    mode = authModeOf(await fetchAuthConfig());
  } catch (error) {
    setState({ status: "unavailable", error });
    return;
  }
  setAuthMode(mode);
  if (mode === "dev_token") return setState({ status: "dev_token" });
  if (mode === "not_configured") return setState({ status: "not_configured" });
  // A page restored from the back-forward cache (Back after signing out at
  // the IdP) would show what it showed before: load it again, which checks
  // the session before any view renders.
  window.addEventListener("pageshow", (event) => {
    if (event.persisted) window.location.reload();
  });
  try {
    setState({ status: "signed_in", session: await fetchSession() });
  } catch (error) {
    if (error instanceof ApiError && error.status === 401) {
      setState({ status: "signed_out", ended: false });
    } else {
      setState({ status: "unavailable", error });
    }
  }
}

/** Reads the mode and the session once per page load; later calls share the first. */
export function startSession(): Promise<void> {
  setUnauthorizedHandler(sessionEnded);
  booting ??= boot();
  return booting;
}

/** Reads the mode and the session again (the "Try again" after a failure). */
export function retrySession(): Promise<void> {
  booting = null;
  setState({ status: "checking" });
  return startSession();
}

/**
 * Signs out: `POST /auth/logout`, then the IdP's end-session URL when the
 * server returns one that {@link signOutTarget} accepts (a script navigation,
 * since the IdP is another origin), otherwise the sign-in screen. Returns the
 * target; `navigate` handles the in-app path.
 */
export async function signOut(navigate: (path: string) => void): Promise<string> {
  let endSessionUrl: string | null = null;
  try {
    endSessionUrl = (await postLogout()).end_session_url;
  } catch (error) {
    // A 401 means the session had already ended; anything else did not sign out.
    if (!(error instanceof ApiError && error.status === 401)) throw error;
  }
  setState({ status: "signed_out", ended: false });
  const target = signOutTarget(endSessionUrl, window.location.origin);
  if (target === SIGNIN_PATH) navigate(SIGNIN_PATH);
  else window.location.assign(target);
  return target;
}

/** Who the session says the operator is, for role hints. Null outside login mode. */
export type SessionViewer = { principal: string | null; groups: string[] | null };

function viewerOf(current: SessionState): SessionViewer {
  return current.status === "signed_in"
    ? { principal: current.session.principal, groups: current.session.groups }
    : { principal: null, groups: null };
}

/** The principal and groups from `GET /auth/session`. Hints only: the API decides. */
export function sessionViewer(): SessionViewer {
  return viewerOf(state);
}

/** {@link sessionViewer}, re-rendering when the session changes. */
export function useSessionViewer(): SessionViewer {
  const current = useSessionState();
  return viewerOf(current);
}

/** Test only: put the store in a given state. */
export function setSessionStateForTest(next: SessionState): void {
  booting = null;
  setState(next);
}
