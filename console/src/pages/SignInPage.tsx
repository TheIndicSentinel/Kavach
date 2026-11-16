import type { ReactNode } from "react";
import { Navigate, useSearchParams } from "react-router-dom";
import { LogIn } from "lucide-react";
import { KavachLogo } from "../components/brand/KavachLogo";
import { DevTokenForm } from "../components/auth/DevTokenForm";
import { SessionChecking } from "../components/layout/SessionGate";
import { Button } from "../components/ui/Button";
import { ProblemAlert } from "../components/ui/ProblemAlert";
import {
  LOGIN_PATH,
  SESSION_ENDED_MESSAGE,
  retrySession,
  signInErrorMessage,
  useSessionState,
} from "../lib/session";

function Screen({ title, children }: { title: string; children: ReactNode }) {
  return (
    <main id="main" className="flex min-h-screen items-start justify-center bg-surface p-4 sm:items-center sm:p-6">
      <div className="w-full max-w-md rounded-xl border border-border bg-surface-raised p-6 shadow-(--shadow-card)">
        <div className="mb-6 flex items-center gap-3">
          <KavachLogo showWordmark={false} />
          <div>
            <p className="text-base font-bold leading-none text-kavach-900">Kavach</p>
            <p className="mt-1 text-xs font-medium text-muted">Governance Console</p>
          </div>
        </div>
        <h1 className="text-xl font-bold tracking-tight text-kavach-900">{title}</h1>
        <div className="mt-4 space-y-4 text-sm text-muted">{children}</div>
      </div>
    </main>
  );
}

/**
 * `/signin`: the only page outside the session gate. What it offers depends
 * on the server (`GET /auth/config`): a link to `/auth/login`, the
 * development pasted-token fallback, or a note that login is not configured.
 */
export default function SignInPage() {
  const session = useSessionState();
  const [params] = useSearchParams();

  switch (session.status) {
    case "checking":
      return <SessionChecking />;

    case "signed_in":
      return <Navigate to="/" replace />;

    case "unavailable":
      return (
        <Screen title="Sign in to Kavach">
          <p>The console could not read this server's sign-in settings, so it offers no way to sign in yet.</p>
          <ProblemAlert error={session.error} />
          <Button variant="secondary" onClick={() => void retrySession()}>
            Try again
          </Button>
        </Screen>
      );

    case "not_configured":
      return (
        <Screen title="Console login is not configured on this server">
          <p>
            This server has no console login set up and does not accept a pasted token, so the console
            cannot sign you in. An administrator sets up console login as described in{" "}
            <code className="rounded bg-stone-100 px-1 text-ink">docs/INSTALL.md</code>.
          </p>
        </Screen>
      );

    case "dev_token":
      return (
        <Screen title="Development sign-in">
          <DevTokenForm afterSave={() => window.location.assign("/overview")} />
        </Screen>
      );

    case "signed_out": {
      const error = signInErrorMessage(params.get("error"));
      return (
        <Screen title="Sign in to Kavach">
          <p role="status" className={session.ended ? "font-medium text-ink" : undefined}>
            {session.ended ? SESSION_ENDED_MESSAGE : ""}
          </p>
          <div role="alert">
            {error && (
              <p className="rounded-lg border border-decision-block/30 bg-decision-block-bg px-4 py-3 font-medium text-decision-block">
                {error}
              </p>
            )}
          </div>
          <p>
            You sign in at your organisation's identity provider. Tokens stay on the Kavach server: this
            browser holds only a session cookie that scripts on the page cannot read (HttpOnly).
          </p>
          {/* A link, never a form or a fetch: login is a top-level navigation (ADR-018 §7). */}
          <a
            href={LOGIN_PATH}
            className="inline-flex items-center justify-center gap-2 rounded-lg bg-saffron-500 px-4 py-2 text-sm font-semibold text-kavach-950 shadow-sm hover:bg-saffron-600"
          >
            <LogIn className="h-4 w-4" aria-hidden />
            Sign in
          </a>
        </Screen>
      );
    }
  }
}
