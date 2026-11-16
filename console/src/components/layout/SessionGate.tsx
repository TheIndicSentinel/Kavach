import { Navigate, Outlet } from "react-router-dom";
import { SIGNIN_PATH, useSessionState } from "../../lib/session";

/** The whole-screen message while the sign-in mode and the session are read. */
export function SessionChecking() {
  return (
    <main id="main" className="flex min-h-screen items-center justify-center bg-surface p-6">
      <p role="status" className="text-sm text-muted">
        Checking your session…
      </p>
    </main>
  );
}

/**
 * The console's pages render only with a live session (login mode) or in the
 * development fallback. Everything else goes to the sign-in screen, which
 * says why. Nothing a page showed survives: its data lives in the page, and
 * the page unmounts.
 */
export function SessionGate() {
  const session = useSessionState();
  switch (session.status) {
    case "checking":
      return <SessionChecking />;
    case "signed_in":
    case "dev_token":
      return <Outlet />;
    default:
      return <Navigate to={SIGNIN_PATH} replace />;
  }
}
