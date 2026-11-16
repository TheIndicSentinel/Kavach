import { Link } from "react-router-dom";
import { ApiError } from "../../lib/api";

type ProblemAlertProps = {
  /** The failure to show, or null when there is none. */
  error: unknown;
  /**
   * The headline for a 404, such as "No agent agent:x in this configuration."
   * The server's own detail stays on the line below it, because one 404 can
   * mean more than one thing (an unknown id, or a surface that is not on).
   */
  notFound?: string;
  className?: string;
};

/**
 * What to say when kavach-api did not answer ({@link ApiError.unreachable}).
 * A development build (the Vite dev server) names the demo script. A built
 * console is served by kavach-api itself, so a proxy in front of it is the
 * likelier cause there.
 */
export function unreachableMessage(dev: boolean): string {
  return dev
    ? "The Kavach API is not reachable. Start it with scripts/demo.sh (or check that kavach-api runs on :8080)."
    : "The Kavach API is not reachable. Check that kavach-api is running and that any proxy in front of it can reach it.";
}

/**
 * A refusal or failure: the problem `detail` (or the HTTP status when the body
 * was not a problem) and the `request_id` to quote when reporting it. A 401
 * says how to sign in again, a 403 that the server refused this principal.
 * When kavach-api did not answer at all, it says that instead of a status.
 * The region is always rendered so assistive technology announces what fills it.
 */
export function ProblemAlert({ error, notFound, className }: ProblemAlertProps) {
  const api = error instanceof ApiError ? error : null;
  const missing = api?.status === 404 && notFound ? notFound : null;
  const text = missing
    ? missing
    : api?.unreachable
      ? unreachableMessage(import.meta.env.DEV)
      : api
        ? api.detail
        : error instanceof Error
          ? error.message
          : error
            ? "Something went wrong."
            : null;

  return (
    <div role="alert" className={className}>
      {text && (
        <div className="rounded-lg border border-decision-block/30 bg-decision-block-bg px-4 py-3 text-sm text-ink">
          <p className="font-medium break-words text-decision-block">{text}</p>
          {api && <Guidance status={api.status} />}
          {api && (
            <p className="mt-1 text-xs break-words text-stone-700">
              {missing && <>{api.detail} · </>}
              {api.status > 0 && <>HTTP {api.status} · </>}
              {api.requestId ? (
                <>
                  request_id <code className="font-mono break-all text-ink">{api.requestId}</code>
                </>
              ) : (
                "no request_id was returned"
              )}
            </p>
          )}
        </div>
      )}
    </div>
  );
}

/** What a reader can do about a 401 or a 403; nothing for other statuses. */
function Guidance({ status }: { status: number }) {
  if (status === 401) {
    return (
      <p className="mt-1 text-ink">
        You are not signed in, or your session or access token has ended. Sign in again, or set an
        access token in{" "}
        <Link
          to="/settings"
          className="font-medium text-kavach-700 underline hover:text-saffron-600"
        >
          Settings
        </Link>
        .
      </p>
    );
  }
  if (status === 403) {
    return (
      <p className="mt-1 text-ink">
        Not permitted: the server refused this for the principal you are signed in as. The server
        decides; ask an admin if you need this.
      </p>
    );
  }
  return null;
}
