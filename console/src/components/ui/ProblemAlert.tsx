import { ApiError } from "../../lib/api";

type ProblemAlertProps = {
  /** The failure to show, or null when there is none. */
  error: unknown;
  className?: string;
};

/**
 * A refusal or failure: the problem `detail` (or the HTTP status when the body
 * was not a problem) and the `request_id` to quote when reporting it. The
 * region is always rendered so assistive technology announces what fills it.
 */
export function ProblemAlert({ error, className }: ProblemAlertProps) {
  const api = error instanceof ApiError ? error : null;
  const text = api
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
          <p className="font-medium text-decision-block">{text}</p>
          {api && (
            <p className="mt-1 text-xs text-muted">
              {api.status > 0 && <>HTTP {api.status} · </>}
              {api.requestId ? (
                <>
                  request_id <code className="font-mono text-ink">{api.requestId}</code>
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
