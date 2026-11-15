import { useRef, useState } from "react";

/** Where one operator-started call is. */
export type Lookup<T> =
  | { phase: "idle" }
  | { phase: "loading"; what: string }
  | { phase: "done"; what: string; result: T }
  | { phase: "error"; what: string; error: unknown };

/**
 * One call at a time, started only by a submit: the evidence calls are
 * audited and rate limited, so nothing fetches on its own or per keystroke.
 * A newer call replaces an older one's result.
 */
export function useLookup<T>() {
  const [lookup, setLookup] = useState<Lookup<T>>({ phase: "idle" });
  const latest = useRef(0);

  function run(what: string, call: () => Promise<T>) {
    const id = ++latest.current;
    setLookup({ phase: "loading", what });
    call().then(
      (result) => {
        if (latest.current === id) setLookup({ phase: "done", what, result });
      },
      (error: unknown) => {
        if (latest.current === id) setLookup({ phase: "error", what, error });
      },
    );
  }

  function reset() {
    latest.current += 1;
    setLookup({ phase: "idle" });
  }

  return { lookup, run, reset };
}
