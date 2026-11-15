import { Info } from "lucide-react";

/**
 * The line shown in place of a control the viewer's groups are known to
 * lack (src/lib/permissions.ts). It is a hint, not the control: the text
 * says the server decides. Render it only when there is a hint.
 */
export function RoleHint({ children }: { children: string }) {
  return (
    <p className="flex items-start gap-2 text-sm text-muted">
      <Info className="mt-0.5 h-4 w-4 shrink-0" aria-hidden />
      <span>{children}</span>
    </p>
  );
}
