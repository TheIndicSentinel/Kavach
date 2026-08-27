import { Menu, UserCircle2 } from "lucide-react";
import { getPrincipal } from "../../lib/api";

type TopBarProps = {
  onOpenNav: () => void;
};

export function TopBar({ onOpenNav }: TopBarProps) {
  const principal = getPrincipal();

  return (
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

      <div className="flex min-w-0 items-center gap-2 text-sm text-muted">
        <UserCircle2 className="h-4 w-4 shrink-0" aria-hidden />
        {principal ? (
          <span className="truncate">
            <span className="hidden sm:inline">Principal </span>
            <span className="font-semibold text-ink">{principal}</span>
          </span>
        ) : (
          <span className="truncate">No principal</span>
        )}
      </div>
    </header>
  );
}
