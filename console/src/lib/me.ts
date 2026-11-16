// `GET /v1/me` (ADR-019 §8): the roles bound to the signed-in caller now.
// The console uses them only to choose which pages and controls to show and
// to show the superadmin banner; the server decides every request.
//
// One read per caller per page load, kept in memory only (never in storage).
// A failed read is forgotten, so the next mount asks again; until it answers
// the roles are unknown, and an action only a role grants stays shown.
import { useEffect, useState } from "react";
import { fetchMe, type Me } from "./api";
import { useSessionState, type SessionState } from "./session";

let cached: { key: string; promise: Promise<Me> } | null = null;

/** Who is asking, for the cache: the signed-in principal, or the development fallback. */
function keyOf(state: SessionState): string | null {
  if (state.status === "signed_in") return `login:${state.session.principal}`;
  if (state.status === "dev_token") return "dev";
  return null;
}

export type MeState = {
  /** `GET /v1/me`'s answer; null until it answers, when it failed, or with no session. */
  me: Me | null;
  /** True while the read for the current caller has not answered or failed yet. */
  pending: boolean;
};

/** `GET /v1/me` for the current caller. */
export function useMe(): MeState {
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

  const settled = answer !== null && answer.key === key;
  return { me: settled ? answer.me : null, pending: key !== null && !settled };
}

/** Test only: forget the cached read. */
export function resetMeForTest(): void {
  cached = null;
}
