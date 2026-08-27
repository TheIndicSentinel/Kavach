import { UserCircle2 } from "lucide-react";
import { getPrincipal } from "../../lib/api";

export function TopBar() {
  const principal = getPrincipal();

  return (
    <header className="sticky top-0 z-10 flex h-14 items-center justify-between border-b border-border bg-surface-raised/90 px-6 backdrop-blur-sm">
      <div className="text-sm text-muted">
        <span className="hidden sm:inline">Environment </span>
        <span className="rounded-md bg-peacock-600/10 px-2 py-0.5 text-xs font-semibold uppercase tracking-wide text-peacock-700">
          On-prem
        </span>
      </div>

      <div className="flex items-center gap-2 text-sm text-muted">
        <UserCircle2 className="h-4 w-4" aria-hidden />
        {principal ? (
          <span>
            Principal{" "}
            <span className="font-semibold text-ink">{principal}</span>
          </span>
        ) : (
          <span>No principal configured</span>
        )}
      </div>
    </header>
  );
}
