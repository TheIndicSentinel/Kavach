import type { ReactNode } from "react";
import { ProblemAlert } from "../ui/ProblemAlert";
import type { Lookup } from "../../hooks/useLookup";

/** What the status region says: loading, or the summary of a result. */
export function lookupStatus<T>(lookup: Lookup<T>, done: (result: T, what: string) => string): string {
  switch (lookup.phase) {
    case "loading":
      return `${lookup.what}…`;
    case "done":
      return done(lookup.result, lookup.what);
    default:
      return "";
  }
}

type LookupPanelProps<T> = {
  lookup: Lookup<T>;
  /** The status line once a result is in. */
  done: (result: T, what: string) => string;
  render: (result: T) => ReactNode;
};

/**
 * A call's progress and result: a refusal in role=alert (detail, status and
 * request_id), loading and the summary in role=status, then the result. Both
 * regions are always rendered so what fills them is announced.
 */
export function LookupPanel<T>({ lookup, done, render }: LookupPanelProps<T>) {
  return (
    <div className="mt-6">
      <ProblemAlert error={lookup.phase === "error" ? lookup.error : null} className="mb-4 empty:mb-0" />
      <p role="status" aria-live="polite" className="mb-4 text-sm text-muted empty:mb-0">
        {lookupStatus(lookup, done)}
      </p>
      {lookup.phase === "done" && render(lookup.result)}
    </div>
  );
}
