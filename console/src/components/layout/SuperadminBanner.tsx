import { ShieldAlert } from "lucide-react";
import type { RoleName } from "../../lib/api";

/** Persistent notice for the ADR-019 break-glass role. */
export function SuperadminBanner({ roles }: { roles: readonly RoleName[] | null }) {
  if (!roles?.includes("superadmin")) return null;
  return (
    <aside
      aria-label="Acting as superadmin"
      className="flex items-start gap-3 border-b border-saffron-400 bg-saffron-100 px-4 py-3 text-sm text-kavach-900 sm:px-6"
    >
      <ShieldAlert className="mt-0.5 h-4 w-4 shrink-0 text-decision-alert" aria-hidden />
      <p>
        <strong className="font-semibold">Acting as superadmin.</strong> You may take any action. An audited action
        that only superadmin allows is flagged in the admin audit, and a second person still approves every change
        request. Use a narrower role for routine work.
      </p>
    </aside>
  );
}
