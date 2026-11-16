import { useState } from "react";
import { useNavigate } from "react-router-dom";
import { LogOut, Menu, UserCircle2 } from "lucide-react";
import { getPrincipal } from "../../lib/api";
import { formatDateTime } from "../../lib/format";
import { signOut, useSessionState } from "../../lib/session";
import { ProblemAlert } from "../ui/ProblemAlert";

type TopBarProps = {
  onOpenNav: () => void;
};

export function TopBar({ onOpenNav }: TopBarProps) {
  const session = useSessionState();
  const navigate = useNavigate();
  const [busy, setBusy] = useState(false);
  const [failure, setFailure] = useState<unknown>(null);
  const signedIn = session.status === "signed_in" ? session.session : null;
  const devPrincipal = session.status === "dev_token" ? getPrincipal() : "";

  async function onSignOut() {
    setBusy(true);
    setFailure(null);
    try {
      await signOut((path) => navigate(path, { replace: true }));
    } catch (error) {
      // The server did not confirm the sign-out: say so, and stay signed in.
      setFailure(error);
      setBusy(false);
    }
  }

  return (
    <>
      <header className="sticky top-0 z-30 flex h-14 items-center justify-between gap-3 border-b border-border bg-surface-raised/90 px-4 backdrop-blur-sm sm:px-6">
        <div className="flex min-w-0 items-center gap-3">
          <button
            type="button"
            className="inline-flex h-9 w-9 items-center justify-center rounded-lg border border-border text-kavach-900 hover:bg-kavach-900/5 lg:hidden"
            aria-label="Open navigation"
            onClick={onOpenNav}
          >
            <Menu className="h-5 w-5" aria-hidden />
          </button>
          <div className="min-w-0 text-sm text-muted">
            <span className="hidden sm:inline">Environment </span>
            <span className="rounded-md bg-peacock-600/10 px-2 py-0.5 text-xs font-semibold uppercase tracking-wide text-peacock-700">
              On-prem
            </span>
          </div>
        </div>

        {signedIn ? (
          <div className="flex min-w-0 items-center gap-3 text-sm text-muted">
            <UserCircle2 className="h-4 w-4 shrink-0" aria-hidden />
            <span className="min-w-0 truncate">
              <span className="hidden sm:inline">Signed in as </span>
              <span className="font-semibold text-ink">{signedIn.principal}</span>
              <span className="hidden xl:inline"> · session ends by {formatDateTime(signedIn.expires_at)}</span>
            </span>
            <button
              type="button"
              onClick={() => void onSignOut()}
              disabled={busy}
              className="inline-flex shrink-0 items-center gap-1.5 rounded-lg border border-border px-3 py-1.5 text-sm font-semibold text-kavach-900 hover:bg-kavach-900/5 disabled:cursor-not-allowed disabled:opacity-60"
            >
              <LogOut className="h-4 w-4" aria-hidden />
              {busy ? "Signing out…" : "Sign out"}
            </button>
          </div>
        ) : (
          <div className="flex min-w-0 items-center gap-2 text-sm text-muted">
            <UserCircle2 className="h-4 w-4 shrink-0" aria-hidden />
            {devPrincipal ? (
              <span className="truncate">
                <span className="hidden sm:inline">Principal </span>
                <span className="font-semibold text-ink">{devPrincipal}</span>
              </span>
            ) : (
              <span className="truncate">No principal</span>
            )}
          </div>
        )}
      </header>
      {/* Rendered only on a failure, so pages keep a single alert region otherwise. */}
      {failure !== null && <ProblemAlert error={failure} className="px-4 pt-4 sm:px-6" />}
    </>
  );
}
