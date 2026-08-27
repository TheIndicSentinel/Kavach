import { useEffect, useState } from "react";
import { ApiError, fetchHealth } from "../lib/api";

type HealthState =
  | { kind: "loading" }
  | { kind: "ok"; status: string }
  | { kind: "error"; message: string; status?: number };

export function useHealth(): HealthState {
  const [health, setHealth] = useState<HealthState>({ kind: "loading" });

  useEffect(() => {
    let cancelled = false;

    fetchHealth()
      .then((payload) => {
        if (!cancelled) {
          setHealth({ kind: "ok", status: payload.status });
        }
      })
      .catch((err: unknown) => {
        if (!cancelled) {
          const message =
            err instanceof Error ? err.message : "Health check failed";
          const status = err instanceof ApiError ? err.status : undefined;
          setHealth({ kind: "error", message, status });
        }
      });

    return () => {
      cancelled = true;
    };
  }, []);

  return health;
}
