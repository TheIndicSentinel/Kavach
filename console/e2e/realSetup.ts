// Seeds the real stack (playwright.real.config.ts) before any spec runs,
// as the system of record and the agents would: on each kavach-api, it
// issues a mandate, makes agent calls under it, then revokes it.
// Each step goes through the instance's own SoR or agent listener, so
// the console shows what those listeners recorded, not a fixture.
//
// The call under a live mandate may be allowed or blocked: the bundle's
// contact window is 08:00–19:00 IST, and kavach-api runs on the wall clock.
// The specs accept either outcome; the other calls are blocked at any hour.
import { execFileSync } from "node:child_process";
import { readFileSync, writeFileSync } from "node:fs";
import { AGENT, AGENT_ONLY, BUNDLE, FULL, type Instance, OTHER_AGENT, STACK, SUBJECT } from "./realStack";

declare const process: { env: Record<string, string | undefined> };

const BIN = `${process.env.CARGO_TARGET_DIR || "../target"}/debug`;

/** Request ids of the seeded calls, the same on both instances. */
export const SEEDED = {
  live: "e2e-live",
  forged: "e2e-forged-mandate",
  otherAgent: "e2e-other-agent",
  afterRevocation: "e2e-after-revocation",
} as const;

/** Where the seed writes the record ids the gateway returned, per instance. */
export const seededFile = (instance: Instance) => `${STACK}/seeded-${instance.name}.json`;

/** The record ids the seed saved for `instance`, by request id. */
export function seededRecords(instance: Instance): Record<string, string> {
  return JSON.parse(readFileSync(seededFile(instance), "utf8")) as Record<string, string>;
}

/** The revoking event's id (system `lms`), as the revocation lookup asks for it. */
export const REVOKING_EVENT = "evt-e2e-paid";

/** Signs a system-of-record event with the bundle's SoR key and posts it; returns the reply. */
function sorEvent(instance: Instance, eventId: string, extra: string[] = []): Record<string, unknown> {
  const out = execFileSync(
    `${BIN}/kavach-dev`,
    [
      "sor-event",
      "--bundle",
      BUNDLE,
      "--url",
      `http://127.0.0.1:${instance.sor}/v1/sor/events`,
      "--event-id",
      eventId,
      "--subject-ref",
      SUBJECT,
      ...extra,
    ],
    { encoding: "utf8" },
  );
  return JSON.parse(out) as Record<string, unknown>;
}

const token = (agent: string) => readFileSync(`${BUNDLE}/agents/${agent}.jwt`, "utf8").trim();

/**
 * One agent call through the gateway. A refusal is an answer; a server error
 * or no answer fails the run. Returns the decision record's id, if any.
 */
async function call(instance: Instance, agent: string, mandateId: string, requestId: string): Promise<string | null> {
  const response = await fetch(`http://127.0.0.1:${instance.agent}/v1/tools/send_reminder`, {
    method: "POST",
    headers: { authorization: `Bearer ${token(agent)}`, "content-type": "application/json" },
    body: JSON.stringify({
      mandate_id: mandateId,
      request_id: requestId,
      params: { subject_ref: SUBJECT, channel: "whatsapp", template_id: "emi_reminder_v1" },
    }),
  });
  if (response.status >= 500 || response.status === 401) {
    throw new Error(`${instance.name}: agent call ${requestId} answered ${response.status}`);
  }
  const reply = (await response.json().catch(() => ({}))) as { record_id?: unknown };
  return typeof reply.record_id === "string" ? reply.record_id : null;
}

async function seed(instance: Instance): Promise<void> {
  const issued = sorEvent(instance, "evt-e2e-assign");
  const mandateId = issued.mandate_id;
  if (typeof mandateId !== "string") throw new Error(`${instance.name}: the SoR event issued no mandate`);

  const records: Record<string, string> = {};
  const keep = (requestId: string, recordId: string | null) => {
    if (recordId) records[requestId] = recordId;
  };
  keep(SEEDED.live, await call(instance, AGENT, mandateId, SEEDED.live));
  keep(SEEDED.forged, await call(instance, AGENT, "mandate-that-was-never-issued", SEEDED.forged));
  keep(SEEDED.otherAgent, await call(instance, OTHER_AGENT, mandateId, SEEDED.otherAgent));

  sorEvent(instance, REVOKING_EVENT, ["--revoke", "loan.paid"]);
  keep(SEEDED.afterRevocation, await call(instance, AGENT, mandateId, SEEDED.afterRevocation));
  writeFileSync(seededFile(instance), JSON.stringify(records));
}

export default async function globalSetup(): Promise<void> {
  for (const instance of [FULL, AGENT_ONLY]) await seed(instance);
}
