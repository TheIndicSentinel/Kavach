import { useEffect, useState } from "react";
import { fetchRuntime } from "../lib/api";

// One GET /v1/runtime per page load for the shell, kept if the shell mounts
// again. A failed request is forgotten, so the next mount asks again; the
// credentials only change with a reload (Settings, sign-in).
let pending: Promise<boolean> | null = null;

export type AgentOnly = {
  /** The request has answered or failed. */
  settled: boolean;
  /**
   * `GET /v1/runtime`'s `agent_only` once it answered; `null` before, or when
   * it failed. Only `true` hides anything: while it is unknown every page
   * shows, and the API answers a route it does not serve with 404.
   */
  agentOnly: boolean | null;
};

/** Whether the server runs --agent-only (it then serves no credit-track route). */
export function useAgentOnly(): AgentOnly {
  const [state, setState] = useState<AgentOnly>({ settled: false, agentOnly: null });

  useEffect(() => {
    let cancelled = false;
    pending ??= fetchRuntime().then((runtime) => runtime.agent_only === true);
    pending.then(
      (agentOnly) => {
        if (!cancelled) setState({ settled: true, agentOnly });
      },
      () => {
        pending = null;
        if (!cancelled) setState({ settled: true, agentOnly: null });
      },
    );
    return () => {
      cancelled = true;
    };
  }, []);

  return state;
}
