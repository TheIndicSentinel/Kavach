import { PROPOSED, type Proposal } from "../../hooks/useProposal";
import { ProblemAlert } from "./ProblemAlert";

/**
 * A proposal's outcome under its button: the refusal with its status and
 * `request_id`, or that it is proposed, in regions that are always rendered
 * so assistive technology announces what fills them.
 */
export function ProposalStatus({ proposal }: { proposal: Proposal }) {
  return (
    <>
      <ProblemAlert
        error={proposal.phase === "error" ? proposal.error : null}
        className="mt-3 empty:mt-0"
      />
      <p role="status" aria-live="polite" className="mt-3 text-sm text-muted empty:mt-0">
        {proposal.phase === "busy" ? "Proposing…" : proposal.phase === "done" ? PROPOSED : ""}
      </p>
    </>
  );
}
