import { cn } from "../../lib/cn";

type KavachLogoProps = {
  className?: string;
  showWordmark?: boolean;
  size?: "sm" | "md";
};

export function KavachLogo({
  className,
  showWordmark = true,
  size = "md",
}: KavachLogoProps) {
  const iconSize = size === "sm" ? "h-8 w-8" : "h-10 w-10";

  return (
    <div className={cn("flex items-center gap-3", className)}>
      <div
        className={cn(
          "flex shrink-0 items-center justify-center rounded-xl bg-gradient-to-br from-saffron-500 to-saffron-600 text-white shadow-sm",
          iconSize,
        )}
        aria-hidden
      >
        <svg viewBox="0 0 24 24" className="h-5 w-5" fill="currentColor">
          <path d="M12 2L4 6v6c0 5.25 3.4 10.15 8 12 4.6-1.85 8-6.75 8-12V6l-8-4zm0 2.18l6 3v5.82c0 4.28-2.73 8.32-6 9.98-3.27-1.66-6-5.7-6-9.98V7.18l6-3z" />
          <path d="M12 8.5a3.5 3.5 0 100 7 3.5 3.5 0 000-7zm0 2a1.5 1.5 0 110 3 1.5 1.5 0 010-3z" />
        </svg>
      </div>
      {showWordmark && (
        <div>
          <p className="text-base font-bold leading-none text-white">Kavach</p>
          <p className="mt-1 text-xs font-medium text-stone-400">
            Governance Console
          </p>
        </div>
      )}
    </div>
  );
}
