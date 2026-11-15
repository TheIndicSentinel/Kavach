// The credit track's pages. A server started with --agent-only does not serve
// their API routes (GET /v1/runtime then reports `agent_only: true`), so the
// console leaves them out of its navigation and says so on their paths.
// Change requests and the audit log belong to both tracks and stay.

/** Console paths whose API routes exist only when the credit track is served. */
export const CREDIT_TRACK_PATHS = [
  "/evaluate",
  "/policies",
  "/models",
  "/batch",
  "/incidents",
  "/retention",
  "/decision-events",
] as const;

/** Whether `pathname` is a credit-track page or one of its detail pages. */
export function isCreditTrackPath(pathname: string): boolean {
  return CREDIT_TRACK_PATHS.some((path) => pathname === path || pathname.startsWith(`${path}/`));
}
