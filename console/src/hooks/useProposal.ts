import { useState } from "react";
import { proposeChange, type ChangeKind } from "../lib/api";

/** Where a page's change proposal is. */
export type Proposal =
  | { phase: "idle" }
  | { phase: "busy" }
  | { phase: "done"; id: string }
  | { phase: "error"; error: unknown };

export const PROPOSED =
  "Change request proposed. A change approver must approve it on the Change requests page.";

/**
 * Proposes a change request (POST /v1/change-requests). The error is kept
 * whole, so the page shows its status and `request_id` (ProposalStatus).
 */
export function useProposal(): {
  proposal: Proposal;
  propose: (kind: ChangeKind, params?: Record<string, unknown>) => Promise<void>;
} {
  const [proposal, setProposal] = useState<Proposal>({ phase: "idle" });

  async function propose(kind: ChangeKind, params: Record<string, unknown> = {}) {
    setProposal({ phase: "busy" });
    try {
      const created = await proposeChange(kind, params);
      setProposal({ phase: "done", id: created.id });
    } catch (error) {
      setProposal({ phase: "error", error });
    }
  }

  return { proposal, propose };
}
