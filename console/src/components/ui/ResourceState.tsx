import type { ReactNode } from "react";
import type { Resource } from "../../hooks/useResource";
import { ApiError } from "../../lib/api";
import { Button } from "./Button";
import { ProblemAlert } from "./ProblemAlert";
import { Skeleton } from "./Skeleton";

type ResourceStateProps<T> = {
  resource: Resource<T>;
  /** Said in `role=status` while the read is in flight, e.g. "Loading agents…". */
  loading: string;
  /** Said in `role=status` once the data is in, e.g. "3 agents." Nothing by default. */
  summary?: (data: T) => string;
  /** The headline for a 404 (see `ProblemAlert`); a 404 then offers no Try again. */
  notFound?: string;
  /** Reads again; shown as "Try again" after a failure. */
  onRetry?: () => void;
  /** Stands in for the data while loading; two table rows by default. */
  skeleton?: ReactNode;
  children: (data: T) => ReactNode;
};

/**
 * The states of one read, laid out the same on every page: the always-rendered
 * `ProblemAlert` and `role=status` region, a skeleton (not text) while
 * loading, Try again after a failure, then the data.
 */
export function ResourceState<T>({
  resource,
  loading,
  summary,
  notFound,
  onRetry,
  skeleton,
  children,
}: ResourceStateProps<T>) {
  const error =
    resource.phase === "error" ? (resource.error ?? new Error("Something went wrong.")) : null;
  const missing = notFound !== undefined && error instanceof ApiError && error.status === 404;
  const status =
    resource.phase === "loading"
      ? loading
      : resource.phase === "ok" && summary
        ? summary(resource.data)
        : "";

  return (
    <>
      <ProblemAlert error={error} notFound={notFound} className="mb-4 empty:mb-0" />
      <p role="status" aria-live="polite" className="mb-4 text-sm text-muted empty:mb-0">
        {status}
      </p>
      {resource.phase === "loading" &&
        (skeleton ?? (
          <div className="space-y-2">
            <Skeleton className="h-10 w-full" />
            <Skeleton className="h-10 w-full" />
          </div>
        ))}
      {error !== null && onRetry && !missing && (
        <Button variant="ghost" size="sm" onClick={onRetry}>
          Try again
        </Button>
      )}
      {resource.phase === "ok" && children(resource.data)}
    </>
  );
}

/** The pages that read the API's newest 50 say so when the list is full. */
export const LIST_LIMIT = 50;

/** "3 jobs.", or "50 jobs, the most this page reads." when the list may be cut off. */
export function listSummary(count: number, one: string, many: string): string {
  const noun = count === 1 ? one : many;
  return count >= LIST_LIMIT ? `${count} ${noun}, the most this page reads.` : `${count} ${noun}.`;
}
