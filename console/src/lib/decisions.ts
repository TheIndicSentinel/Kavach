export type Decision = "PASS" | "ALERT" | "BLOCK" | "HUMAN_REVIEW";

export function normalizeDecision(value: string): Decision | null {
  const upper = value.toUpperCase();
  if (
    upper === "PASS" ||
    upper === "ALERT" ||
    upper === "BLOCK" ||
    upper === "HUMAN_REVIEW"
  ) {
    return upper;
  }
  return null;
}

export const decisionMeta: Record<
  Decision,
  { label: string; description: string; className: string }
> = {
  PASS: {
    label: "Pass",
    description: "Policy checks satisfied",
    className: "bg-decision-pass-bg text-decision-pass border-decision-pass/20",
  },
  ALERT: {
    label: "Alert",
    description: "Threshold exceeded — review recommended",
    className: "bg-decision-alert-bg text-decision-alert border-decision-alert/20",
  },
  BLOCK: {
    label: "Block",
    description: "Policy violation — action denied",
    className: "bg-decision-block-bg text-decision-block border-decision-block/20",
  },
  HUMAN_REVIEW: {
    label: "Human review",
    description: "Requires underwriter decision",
    className:
      "bg-decision-review-bg text-decision-review border-decision-review/20",
  },
};
