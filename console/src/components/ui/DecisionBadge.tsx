import { cn } from "../../lib/cn";
import { decisionMeta, normalizeDecision } from "../../lib/decisions";

type DecisionBadgeProps = {
  decision: string;
  className?: string;
};

export function DecisionBadge({ decision, className }: DecisionBadgeProps) {
  const normalized = normalizeDecision(decision);
  if (!normalized) {
    return (
      <span
        className={cn(
          "inline-flex items-center rounded-full border px-2.5 py-0.5 text-xs font-semibold uppercase tracking-wide",
          "bg-stone-100 text-stone-700 border-stone-200",
          className,
        )}
      >
        {decision}
      </span>
    );
  }

  const meta = decisionMeta[normalized];
  return (
    <span
      className={cn(
        "inline-flex items-center rounded-full border px-2.5 py-0.5 text-xs font-semibold uppercase tracking-wide",
        meta.className,
        className,
      )}
      title={meta.description}
    >
      {normalized.replace("_", " ")}
    </span>
  );
}
