import { useEffect, useState } from "react";
import { ApiError, fetchRuntime, type RuntimeInfo } from "../lib/api";

type RuntimeState =
  | { kind: "loading" }
  | { kind: "ok"; data: RuntimeInfo }
  | { kind: "error"; message: string; status?: number };

export function useRuntime(): RuntimeState {
  const [state, setState] = useState<RuntimeState>({ kind: "loading" });

  useEffect(() => {
    let cancelled = false;
    fetchRuntime()
      .then((data) => {
        if (!cancelled) setState({ kind: "ok", data });
      })
      .catch((err: unknown) => {
        if (!cancelled) {
          setState({
            kind: "error",
            message: err instanceof Error ? err.message : "Failed to load runtime",
            status: err instanceof ApiError ? err.status : undefined,
          });
        }
      });
    return () => {
      cancelled = true;
    };
  }, []);

  return state;
}
