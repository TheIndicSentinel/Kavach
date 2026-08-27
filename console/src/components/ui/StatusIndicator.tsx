import { cn } from "../../lib/cn";

type StatusIndicatorProps = {
  status: "ok" | "error" | "loading" | "idle";
  label: string;
  className?: string;
};

const statusStyles = {
  ok: "bg-decision-pass-bg text-decision-pass",
  error: "bg-decision-block-bg text-decision-block",
  loading: "bg-stone-100 text-muted animate-pulse",
  idle: "bg-stone-100 text-muted",
};

export function StatusIndicator({
  status,
  label,
  className,
}: StatusIndicatorProps) {
  return (
    <span
      className={cn(
        "inline-flex items-center gap-2 rounded-full px-3 py-1 text-sm font-semibold",
        statusStyles[status],
        className,
      )}
    >
      <span
        className={cn(
          "h-2 w-2 rounded-full",
          status === "ok" && "bg-decision-pass",
          status === "error" && "bg-decision-block",
          status === "loading" && "bg-muted",
          status === "idle" && "bg-stone-400",
        )}
        aria-hidden
      />
      {label}
    </span>
  );
}
