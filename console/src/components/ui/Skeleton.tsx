import { cn } from "../../lib/cn";

type SkeletonProps = {
  className?: string;
};

export function Skeleton({ className }: SkeletonProps) {
  return (
    <div
      className={cn("animate-pulse rounded-md bg-stone-200/80", className)}
      aria-hidden
    />
  );
}
