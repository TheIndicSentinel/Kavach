// Which Cedar action each console page needs, so the navigation can leave
// out the pages the viewer's groups and roles probably may not open
// (ADR-019 §8). Leaving a link out is a hint, not a gate: a page opened by
// its address still loads, and the server answers its reads.
import { mayProbably, type CedarAction, type Viewer } from "./permissions";

/** A page's path to the action its main read (or its control) needs. Pages not listed always show. */
export const PAGE_ACTIONS: Readonly<Record<string, CedarAction>> = {
  "/evaluate": "evaluate",
  "/agents": "read_agent_state",
  "/agent-evidence": "read_evidence",
  "/reconciliation": "reconcile_closed_records",
  "/decision-events": "read_evidence",
  "/policies": "read_governance",
  "/models": "read_governance",
  "/batch": "read_batch_jobs",
  "/changes": "read_change_requests",
  "/audit": "read_audit",
  "/incidents": "read_incidents",
  "/retention": "read_retention",
  "/users": "read_principals",
};

/** Whether the navigation shows the link to `path` for `viewer`. */
export function showsPage(viewer: Viewer, path: string): boolean {
  const action = PAGE_ACTIONS[path];
  return action === undefined || mayProbably(viewer, action);
}
