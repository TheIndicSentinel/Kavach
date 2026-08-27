import { cn } from "../../lib/cn";

type BadgeVariant = "default" | "active" | "muted" | "warning";

type BadgeProps = {
  children: React.ReactNode;
  variant?: BadgeVariant;
  className?: string;
};

const variants: Record<BadgeVariant, string> = {
  default: "bg-stone-100 text-stone-700 border-stone-200",
  active: "bg-peacock-600/10 text-peacock-700 border-peacock-600/20",
  muted: "bg-stone-100 text-muted border-stone-200",
  warning: "bg-saffron-100 text-saffron-600 border-saffron-400/30",
};

export function Badge({
  children,
  variant = "default",
  className,
}: BadgeProps) {
  return (
    <span
      className={cn(
        "inline-flex items-center rounded-full border px-2.5 py-0.5 text-xs font-semibold uppercase tracking-wide",
        variants[variant],
        className,
      )}
    >
      {children}
    </span>
  );
}
