import { useEffect, useState } from "react";

/** Where a page's read of the API is. */
export type Resource<T> =
  | { phase: "loading" }
  | { phase: "ok"; data: T }
  | { phase: "error"; error: unknown };

export const LOADING: Resource<never> = { phase: "loading" };

type Settled<T> = { load: () => Promise<T>; attempt: number; resource: Resource<T> };

/**
 * One GET when the page mounts, again when `load` changes (wrap it in
 * `useCallback` with the ids it reads), and again on `retry`. Until the read
 * for the current `load` settles the page is loading: an older answer is
 * never shown for a newer request. The error is kept whole (an `ApiError`
 * carries the status and the `request_id`).
 */
export function useResource<T>(load: () => Promise<T>): {
  resource: Resource<T>;
  retry: () => void;
} {
  const [attempt, setAttempt] = useState(0);
  const [settled, setSettled] = useState<Settled<T> | null>(null);

  // State is set only when the request settles, never synchronously here.
  useEffect(() => {
    let cancelled = false;
    load().then(
      (data) => {
        if (!cancelled) setSettled({ load, attempt, resource: { phase: "ok", data } });
      },
      (error: unknown) => {
        if (!cancelled) setSettled({ load, attempt, resource: { phase: "error", error } });
      },
    );
    return () => {
      cancelled = true;
    };
  }, [load, attempt]);

  const current = settled?.load === load && settled.attempt === attempt;
  return {
    resource: current ? settled.resource : LOADING,
    retry: () => setAttempt((n) => n + 1),
  };
}
