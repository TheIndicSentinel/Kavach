// What the evidence pages need beyond the API calls: input checks, the
// commands that verify a record offline, and the words for outcomes and
// reconciliation findings. Pure functions, so the tests can pin them.
import type {
  ClosedRecordFinding,
  ClosedRecordsRequest,
  ClosedRecordsResult,
  Outcome,
} from "./api";

// ---------------------------------------------------------------------------
// Decision event lookup
// ---------------------------------------------------------------------------

/**
 * A canonical lowercase UUID. The spec says `format: uuid`; the API (and
 * `kavach why`) accept the lowercase form only, so the console asks for that
 * rather than spend an audited, rate-limited read on a refusal.
 */
const EVIDENCE_ID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
export const EVIDENCE_ID_LENGTH = 36;

/** Why `value` cannot be an evidence id, or null when it can. */
export function evidenceIdProblem(value: string): string | null {
  if (!value) return "Enter an evidence id.";
  if (EVIDENCE_ID.test(value)) return null;
  if (EVIDENCE_ID.test(value.toLowerCase())) {
    return "Use lowercase letters: the API accepts evidence ids in lowercase only.";
  }
  return "An evidence id is a UUID, like 9771a6c1-edc5-4b2b-b38d-ffb397b7df55.";
}

// ---------------------------------------------------------------------------
// Verify commands
// ---------------------------------------------------------------------------

/** One command an operator can run to check a record away from the console. */
export type VerifyCommand = {
  /** Short name of what the command does. */
  label: string;
  /** The command line, ready to paste. Paths are examples to replace. */
  command: string;
  /** What it checks and what it does not. */
  note: string;
};

/** Example paths in the commands; the page says to replace them. */
export const EXAMPLE_PATHS = {
  bundle: "./bundle",
  keys: "./trusted-keys.json",
  keptCheckpoints: "./kept-checkpoints.jsonl",
  decisionEvents: "./decision-events.ndjson",
} as const;

/**
 * `value` as one shell word: unchanged when it holds only characters no
 * shell treats specially, otherwise in single quotes. Ids come from the API,
 * so they are quoted rather than trusted.
 */
export function shellWord(value: string): string {
  if (/^[A-Za-z0-9._:/-]+$/.test(value)) return value;
  return `'${value.replace(/'/g, `'\\''`)}'`;
}

const { bundle, keys, keptCheckpoints, decisionEvents } = EXAMPLE_PATHS;

/** `kavach-evidence verify-bundle`, the offline bundle verifier (docs/EVIDENCE_BUNDLE.md). */
function verifyBundleCommand(): VerifyCommand {
  return {
    label: "Verify the bundle that holds this record",
    command: `kavach-evidence verify-bundle ${bundle} --keys ${keys} --expect-checkpoint ${keptCheckpoints}`,
    note:
      "Checks every record's hash and signature, the chain links, the outcomes and the checkpoints " +
      "against keys you supply, never the bundle's. Exit 0 verified, 2 verified but not fully " +
      "protected, 1 failed.",
  };
}

/** The independent verifier in conformance/, written from the specification alone. */
function conformanceBundleCommand(): VerifyCommand {
  return {
    label: "Check it again with the independent verifier",
    command: `python3 conformance/kavach_verify.py bundle ${bundle} --keys ${keys} --expect-checkpoint ${keptCheckpoints}`,
    note:
      "A second implementation, in Python, from the Kavach repository. Same exit statuses; " +
      "if it and kavach-evidence disagree, one of them or the specification is wrong.",
  };
}

/** Commands for an agent decision record (`adr:…`). */
export function agentDecisionCommands(recordId: string): VerifyCommand[] {
  return [
    verifyBundleCommand(),
    {
      label: "Explain this record from the bundle",
      command: `kavach why ${shellWord(recordId)} --bundle ${bundle} --keys ${keys}`,
      note: "Verifies the whole bundle first, then shows this record and its signature check.",
    },
    conformanceBundleCommand(),
  ];
}

/** Commands for a revocation record. `kavach why` explains decisions only. */
export function revocationCommands(): VerifyCommand[] {
  return [verifyBundleCommand(), conformanceBundleCommand()];
}

/**
 * Commands for an evaluate decision event. These events are hash-chained but
 * not signed, so no command here checks a signature.
 */
export function decisionEventCommands(evidenceId: string): VerifyCommand[] {
  return [
    {
      label: "Check the decision event chain",
      command: `kavach-evidence verify --file ${decisionEvents}`,
      note:
        "Checks every hash and link of an exported decision event chain (NDJSON or a JSON array). " +
        "Exit 0 verified, 2 verified except pre-1.1.0 events that cannot be re-checked, 1 failed.",
    },
    {
      label: "Explain this event from the export",
      command: `kavach why ${shellWord(evidenceId)} --export ${decisionEvents}`,
      note: "Checks the whole export's chain first and reports a break before showing the event.",
    },
  ];
}

/** What the copy button says in its status region. */
export const COPIED = "Copied";
export const COPY_FAILED = "Copy failed: select the text";

/** Copies `text` and returns what to announce. Call it only from a user's click. */
export async function copyCommand(
  text: string,
  clipboard: Pick<Clipboard, "writeText"> | undefined = globalThis.navigator?.clipboard,
): Promise<string> {
  if (!clipboard) return COPY_FAILED;
  try {
    await clipboard.writeText(text);
    return COPIED;
  } catch {
    return COPY_FAILED;
  }
}

// ---------------------------------------------------------------------------
// Outcomes of agent calls
// ---------------------------------------------------------------------------

/** Every outcome in the spec, in words (kavach-ports `Outcome`, ADR-005 §12). */
export const OUTCOME_WORDING: Record<Outcome, { label: string; meaning: string }> = {
  delivered: {
    label: "Delivered",
    meaning: "The provider accepted the call.",
  },
  refused: {
    label: "Refused",
    meaning: "The provider refused the call, so it was not delivered.",
  },
  failed: {
    label: "Failed",
    meaning: "The connection failed before any request went out, so nothing was sent.",
  },
  not_executed: {
    label: "Not executed",
    meaning:
      "The call was allowed but nothing was sent: a resolver or broker failure, or its send-by time passed first.",
  },
  unknown: {
    label: "Unknown",
    meaning:
      "The call was sent and its result is not known. The gateway never retries it. " +
      "The console cannot show a later resolution (ADR-017): the API has no endpoint to read one yet.",
  },
};

/** The outcome line for a record: its words, or plainly that none is recorded. */
export function outcomeText(outcome: Outcome | null | undefined): string {
  if (!outcome) return "No outcome is recorded for this record.";
  const { label, meaning } = OUTCOME_WORDING[outcome];
  return `${label}: ${meaning}`;
}

// ---------------------------------------------------------------------------
// Closed-records reconciliation
// ---------------------------------------------------------------------------

/** Limits from docs/openapi.yaml, as the API applies them (lengths in bytes). */
export const CLOSED_RECORDS_LIMITS = {
  systemMax: 64,
  recordRefMax: 256,
  recordsMax: 1000,
  /** A pasted or loaded list larger than this is refused before parsing. */
  textMaxBytes: 1024 * 1024,
} as const;

const CLOSED_STATES = ["paid", "disputed"] as const;
const RFC3339 = /^\d{4}-\d{2}-\d{2}[Tt]\d{2}:\d{2}:\d{2}(\.\d+)?([Zz]|[+-]\d{2}:\d{2})$/;
const PROBLEMS_SHOWN = 5;

function byteLength(value: string): number {
  return new TextEncoder().encode(value).length;
}

// Matches the API's own check: 1 to `max` bytes, no control characters.
function plain(value: unknown, max: number): value is string {
  if (typeof value !== "string") return false;
  const bytes = byteLength(value);
  // eslint-disable-next-line no-control-regex
  return bytes >= 1 && bytes <= max && !/[\u0000-\u001f\u007f-\u009f]/.test(value);
}

function isObject(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function unexpectedKeys(value: Record<string, unknown>, allowed: readonly string[]): string[] {
  return Object.keys(value).filter((key) => !allowed.includes(key));
}

export type ClosedRecordsParse =
  | { ok: true; body: ClosedRecordsRequest }
  | { ok: false; problems: string[] };

/**
 * Checks the lender's list before it is sent, against the request schema.
 * Problems name records by position, never by reference, so nothing the
 * operator pasted is echoed back.
 */
export function parseClosedRecords(text: string): ClosedRecordsParse {
  const { systemMax, recordRefMax, recordsMax, textMaxBytes } = CLOSED_RECORDS_LIMITS;
  if (!text.trim()) return { ok: false, problems: ["Paste or load the list of closed loans."] };
  if (byteLength(text) > textMaxBytes) {
    return { ok: false, problems: ["The list is larger than 1 MiB."] };
  }
  let value: unknown;
  try {
    value = JSON.parse(text);
  } catch {
    return { ok: false, problems: ["The list is not valid JSON."] };
  }
  if (!isObject(value)) {
    return { ok: false, problems: ['The list must be one JSON object: {"system": …, "records": […]}.'] };
  }

  const problems: string[] = [];
  const extra = unexpectedKeys(value, ["system", "records"]);
  if (extra.length) problems.push(`Unexpected member: ${extra.join(", ")}. Only system and records are allowed.`);
  if (!plain(value.system, systemMax)) {
    problems.push(`system must be 1-${systemMax} characters, with no control characters.`);
  }
  const records = value.records;
  if (!Array.isArray(records) || records.length < 1 || records.length > recordsMax) {
    problems.push(`records must be a list of 1-${recordsMax} loans.`);
    return { ok: false, problems };
  }

  records.forEach((record: unknown, index) => {
    const at = `Record ${index + 1}`;
    if (!isObject(record)) {
      problems.push(`${at}: must be an object with record_ref, state and closed_at.`);
      return;
    }
    const extraKeys = unexpectedKeys(record, ["record_ref", "state", "closed_at"]);
    if (extraKeys.length) problems.push(`${at}: unexpected member ${extraKeys.join(", ")}.`);
    if (!plain(record.record_ref, recordRefMax)) {
      problems.push(`${at}: record_ref must be 1-${recordRefMax} characters, with no control characters.`);
    }
    if (!CLOSED_STATES.includes(record.state as (typeof CLOSED_STATES)[number])) {
      problems.push(`${at}: state must be paid or disputed.`);
    }
    const closedAt = record.closed_at;
    if (typeof closedAt !== "string" || !RFC3339.test(closedAt) || Number.isNaN(Date.parse(closedAt))) {
      problems.push(`${at}: closed_at must be an RFC 3339 time, like 2026-10-01T06:00:00Z.`);
    }
  });

  if (problems.length) {
    const more = problems.length - PROBLEMS_SHOWN;
    const shown = problems.slice(0, PROBLEMS_SHOWN);
    if (more > 0) shown.push(`…and ${more} more.`);
    return { ok: false, problems: shown };
  }
  return { ok: true, body: value as ClosedRecordsRequest };
}

type FindingKind = ClosedRecordFinding["kind"];

/** Each finding kind in words. A mismatch is a defect; the other is for the lender to confirm. */
export const FINDING_WORDING: Record<FindingKind, { label: string; meaning: string }> = {
  should_have_been_revoked: {
    label: "Should have been revoked",
    meaning:
      "This mandate is still live although the loan was closed: the payment or dispute event most " +
      "likely did not arrive. Resend the signed event (it revokes through the normal path) or stop the agent.",
  },
  issued_after_closure: {
    label: "To confirm",
    meaning:
      "This mandate was issued after the loan was paid. Usually a new default; confirm it with the " +
      "lender. Information, not a defect.",
  },
};

/** Mismatches first; otherwise the order the API returned. */
export function sortFindings(findings: ClosedRecordFinding[]): ClosedRecordFinding[] {
  const rank = (f: ClosedRecordFinding) => (f.kind === "should_have_been_revoked" ? 0 : 1);
  return findings
    .map((finding, index) => ({ finding, index }))
    .sort((a, b) => rank(a.finding) - rank(b.finding) || a.index - b.index)
    .map(({ finding }) => finding);
}

function count(n: number, one: string, many: string): string {
  return `${n} ${n === 1 ? one : many}`;
}

/** What the status region says once a reconciliation returns. */
export function reconciliationSummary(result: ClosedRecordsResult): string {
  const checked = `Checked ${count(result.checked, "loan", "loans")}`;
  if (result.findings.length === 0) return `${checked}: none holds a live mandate. Nothing was revoked.`;
  return (
    `${checked}: ${count(result.mismatches, "mandate", "mandates")} should have been revoked, ` +
    `${result.information} to confirm. Nothing was revoked.`
  );
}
