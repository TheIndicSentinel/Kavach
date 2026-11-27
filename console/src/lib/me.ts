// The console uses GET /v1/me only for role-aware presentation. The server
// continues to authorize every request. Keep the result in memory only.
import { useEffect, useState } from "react";
import { fetchMe, type Me } from "./api";
import { useSessionState, type SessionState } from "./session";

let cached: { key: string; promise: Promise<Me> } | null = null;

function keyOf(state: SessionState): string | null {
  if (state.status === "signed_in") return `login:${state.session.principal}`;
  if (state.status === "dev_token") return "dev";
  return null;
}

/** The current caller's roles; null until available or when the lookup fails. */
export function useMe(): Me | null {
  const key = keyOf(useSessionState());
  const [answer, setAnswer] = useState<{ key: string; me: Me | null } | null>(null);

  useEffect(() => {
    if (key === null) return;
    if (cached?.key !== key) cached = { key, promise: fetchMe() };
    const current = cached;
    let cancelled = false;
    current.promise.then(
      (me) => {
        if (!cancelled) setAnswer({ key, me });
      },
      () => {
        if (cached === current) cached = null;
        if (!cancelled) setAnswer({ key, me: null });
      },
    );
    return () => {
      cancelled = true;
    };
  }, [key]);

  return answer?.key === key ? answer.me : null;
}
