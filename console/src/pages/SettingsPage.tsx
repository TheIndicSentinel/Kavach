import { KeyRound, ShieldCheck } from "lucide-react";
import { DevTokenForm } from "../components/auth/DevTokenForm";
import {
  Card,
  CardDescription,
  CardHeader,
  CardTitle,
} from "../components/ui/Card";
import { PageHeader } from "../components/ui/PageHeader";
import { formatDateTime } from "../lib/format";
import { useSessionState, type AuthSession } from "../lib/session";

const code = "rounded bg-stone-100 px-1 text-xs text-ink";

function SessionCard({ session }: { session: AuthSession }) {
  return (
    <Card>
      <CardHeader>
        <div className="mb-2 flex h-10 w-10 items-center justify-center rounded-lg bg-saffron-100 text-saffron-600">
          <ShieldCheck className="h-5 w-5" aria-hidden />
        </div>
        <CardTitle>Your session</CardTitle>
        <CardDescription>As the server reported it when this page loaded.</CardDescription>
      </CardHeader>
      <dl className="space-y-3 text-sm">
        <div>
          <dt className="text-muted">Principal</dt>
          <dd className="font-semibold text-ink">{session.principal}</dd>
        </div>
        <div>
          <dt className="text-muted">Groups</dt>
          <dd className="text-ink">
            {session.groups === null
              ? "not known to the console; the server decides each request"
              : session.groups.length
                ? session.groups.join(", ")
                : "none"}
          </dd>
        </div>
        <div>
          <dt className="text-muted">Session ends by</dt>
          <dd className="text-ink">{formatDateTime(session.expires_at)}</dd>
        </div>
        <div>
          <dt className="text-muted">Ends sooner if unused until</dt>
          <dd className="text-ink">{formatDateTime(session.idle_expires_at)}</dd>
        </div>
      </dl>
    </Card>
  );
}

function HowSignInWorks() {
  return (
    <Card>
      <CardHeader>
        <CardTitle>How console sign-in works</CardTitle>
      </CardHeader>
      <ul className="list-disc space-y-3 pl-5 text-sm text-muted">
        <li>
          You sign in at your organisation's identity provider. The Kavach server receives the tokens and
          keeps them in its memory; they are never sent to this browser.
        </li>
        <li>
          This browser holds only a session cookie marked HttpOnly, so scripts on the page cannot read it.
          The console keeps your principal, groups and session times in memory, not in browser storage.
        </li>
        <li>
          Every call still goes through the API's token verification and its Cedar policy. The groups
          shown here only shape what the console offers; the API decides.
        </li>
        <li>
          <span className="font-medium text-ink">Sign out</span> (top right) ends your Kavach session. You
          stay signed in at the identity provider unless this server is set to end that session too.
        </li>
        <li>
          A server restart ends every session. Setup: <code className={code}>docs/INSTALL.md</code>.
        </li>
      </ul>
    </Card>
  );
}

function DevFallbackCards() {
  return (
    <>
      <Card>
        <CardHeader>
          <div className="mb-2 flex h-10 w-10 items-center justify-center rounded-lg bg-saffron-100 text-saffron-600">
            <KeyRound className="h-5 w-5" aria-hidden />
          </div>
          <CardTitle>Development credentials</CardTitle>
          <CardDescription>
            A pasted token or principal ID, offered only because console login is not configured and the
            API runs with --insecure-dev.
          </CardDescription>
        </CardHeader>
        <DevTokenForm />
      </Card>

      <Card>
        <CardHeader>
          <CardTitle>Outside development</CardTitle>
        </CardHeader>
        <ul className="list-disc space-y-3 pl-5 text-sm text-muted">
          <li>
            Configure console login (OIDC authorization code with PKCE, ADR-018). Operators then sign in at
            the identity provider, and no token is pasted or kept in the browser.
          </li>
          <li>
            A server started with <code className={code}>--require-hardening</code> refuses this pasted-token
            fallback.
          </li>
          <li>
            Setup: <code className={code}>docs/INSTALL.md</code>.
          </li>
        </ul>
      </Card>
    </>
  );
}

export default function SettingsPage() {
  const session = useSessionState();

  return (
    <section>
      <PageHeader
        title="Settings"
        hindi="सेटिंग्स"
        subtitle={
          session.status === "signed_in"
            ? "Your console session and how sign-in works on this server."
            : "Development credentials for a server without console login."
        }
      />

      <div className="grid gap-4 lg:grid-cols-2">
        {session.status === "signed_in" ? (
          <>
            <SessionCard session={session.session} />
            <HowSignInWorks />
          </>
        ) : (
          <DevFallbackCards />
        )}
      </div>
    </section>
  );
}
