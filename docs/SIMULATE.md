# Simulation (`kavach simulate`, pre-alpha)

`kavach simulate` runs synthetic agents over simulated days against a real development stack, and judges every decision with a small oracle that shares nothing with the agents. It shows that these synthetic scenarios behave as expected on this machine. **It is not a security assessment**, and it proves nothing about real providers, networks or data. Every report lists what it does not cover first.

**Validation record (2026-11-20):** `mixed-week --seed 42` passed after the simulator aligned its generated consent and preference fixtures to the fixed scenario calendar. The run reported 200 synthetic calls; its ledger, evidence and mock-provider inbox reconciled consistently, with 0 violations, 0 mismatches and 0 leaks. This is synthetic local validation, not a security assessment.

```bash
kavach simulate list                                   # the built-in scenarios; nothing runs
kavach simulate run                                    # normal-day
kavach simulate run --builtin two-agents-one-borrower
kavach simulate run my-scenario.yaml --seed 42 --report report.json --keep
```

## What a run does

1. **A throwaway project** in a temporary directory, made the way `kavach init` makes one but holding the scenario's world:
   - **borrowers:** opaque `ref:borrower:S-0001` references, synthetic `+910…` destinations, and one consent each;
   - **agents:** each with its own token and passport, all eligible under the mandate template.
   - Consent and contact-preference validity dates are aligned to the simulator's fixed calendar, so runs remain valid regardless of the host's current date.

   It is deleted afterwards, also on Ctrl-C, unless `--keep`. A run never attaches to a running stack.
2. **Its own stack:** `kavach dev up --clock <first slot> --export-on-exit <dir>`, on distinct free loopback ports, with a fixed development clock.
3. **One mandate per (agent, borrower) pair**, through signed system-of-record events.
4. **Each slot, day by day:**
   - the clock moves forward;
   - each agent decides its calls from its behaviour settings;
   - each call goes to `POST /v1/tools/send_reminder` with a `sim-` request id;
   - every reply goes into the ledger.
5. **The provider's inbox is read**: what actually arrived, the one record Kavach does not write.
6. **The stack stops (SIGTERM)** and writes its evidence as a development bundle. The bundle is verified against the auditor's dev keys.
7. **The oracle** judges every call in the ledger. The report counts violations, mismatches and leaks, and checks the scenario's `expect`.
8. **The three records are reconciled.** The ledger, the evidence and the inbox are checked against each other:
   - every call that produced a record is in the evidence, with the same request, decision and outcome;
   - every record came from a call;
   - an allowed, deliverable call arrived **exactly once**: the provider's proof that nothing was sent twice;
   - a blocked call, or one the provider refused or failed, never arrived;
   - each message went to that borrower's own destination, with the credential the evidence names;
   - **payments and disputes:** Kavach's reply revoked exactly the borrower's mandates issued before the event (the simulator's own record), the evidence holds exactly one signed revocation record per event naming the same mandates, and no record for an event the run never sent;
   - **the inbox against the revocations:** nothing arrived under a revoked mandate from its event on. The inbox's own mandate id and the evidence's signed decision time decide this, not the simulator's ledger.

   Any finding fails the run. Findings name borrowers and record ids, never destinations.

## Scenario file (format version 1)

```yaml
version: 1
name: my-scenario
seed: 7                   # same seed, same run
days: 2                   # 1–7 (one mandate's life)
borrowers: 20             # 1–200
schedule: ["09:00", "12:00", "18:55", "19:05"]   # IST, ascending; the clock only moves forward
agents:
  - type: compliant       # keeps the hours and its own daily limit, WhatsApp only
    count: 2
  - type: eager           # late, too often, wrong channel, by its rates
    behaviour: { contacts_per_day: 3, late_rate: 0.5, extra_contact_rate: 0.5, wrong_channel_rate: 0.2,
                 retry_rate: 1.0 }   # send the same request again after an unknown outcome
  - type: adversarial     # the attack catalog's tool-call attacks, on a borrower kept for it
    behaviour: { attack_rate: 0.5, attacks: [raw-phone-number, another-borrower] }   # default: all of them
assignment: shared        # split (default): one agent per borrower; shared: every agent serves every borrower
provider_failures: { refuse: 1, error: 1, lose: 1 }   # the first borrowers' destinations: 422, 500, lost response
events:                   # system-of-record events (ADR-012), for the first N borrowers whose messages are delivered
  - { day: 1, at: "12:00", type: loan.paid, borrowers: 2 }     # or loan.disputed: revokes their mandates
  - { day: 1, at: "12:00", type: agent.quarantine, agent: sim-eager-1 }   # or agent.restrict | agent.revoke | agent.reinstate
  - { day: 2, at: "09:00", type: loan.dpd30, borrowers: 1 }    # a new default: assigned again, new mandates
  - { day: 1, at: "12:00", type: loan.paid, borrowers: 1, lag_seconds: 9000 }   # happened at 09:30, arrives at 12:00
expect:                   # required: what passing means
  violations: 0
  mismatches: 0
  leaks: 0
  allowed_at_least: 10
  blocked_at_least: { contact-daily-cap: 1 }
```

Unknown keys are refused. An event at a slot's time comes before that slot's calls. An event reaches Kavach on the stack's clock, and may have **happened earlier**: `lag_seconds: N` signs it with a time N seconds before its arrival (a late payment, a default processed late). A new default may be at most 240 s late (an older issuing event is stale), a payment or dispute at most a day; operator changes to an agent cannot be late. `dropped: true` on a payment or dispute means the system of record never sends it (a lost event): Kavach does not learn of it and contact goes on. A `lender.snapshot` event sends Kavach every payment and dispute so far, sent or lost (snapshot reconciliation, ADR-012 addendum). An `outcomes.settle` event makes the run wait (up to 90 s) for Kavach's reconciler to resolve the unknown outcomes so far: put it a few minutes after the sends. Events never go to borrowers kept for attacks or set up to fail. `--seed`, `--days` and `--borrowers` override the file. A scenario may name the SECURITY_PROPERTIES.md rows it exercises in `covers:`. Every built-in does, and a test fails if one of those rows is renamed or removed.

## The oracle

It models the product's rules, written independently of Kavach's policies, and judges each call only by what was sent:
- **the tool registry:** `send_reminder` only, with exactly `subject_ref`, `channel` (WhatsApp or SMS) and `template_id` (`emi_reminder_v1`);
- **a plain reference:** at most eight digits and nothing PAN-shaped (ADR-004 §7);
- **the mandate:** it was issued, and for that subject;
- **contact hours:** only from 08:00 to 19:00 IST (19:00 itself is out);
- **the daily cap:** at most three contacts per borrower per IST day, **across all agents**. Only contacts Kavach allowed count, and a retry is not a new contact;
- **channels:** only those the mandate grants (WhatsApp, voice);
- **forward-once:** a retry (same request id) is never sent again. Once the first call's outcome is recorded, `unknown` included, it gets the stored reply (`replayed`). Only while the first call is still running is it 409 `in_flight`, and a run never retries into that;
- **provider outcomes** follow the agreed status contract (ADR-007): 2xx delivered, 4xx refused, and a 5xx or a lost response unknown (a 5xx does not prove the message was not sent);
- **an operator's stop or reinstatement of an agent** (ADR-013): a restricted agent may not contact (the registry's one tool contacts), a quarantined or revoked one may do nothing; a stop only ever holds an agent back further, a reinstatement frees a restricted or quarantined agent **with its same mandates** and never a revoked one; a change at a call's time comes first, and another agent is untouched. The oracle's model of this shares no code with Kavach's, and the changes come from the scenario, never from Kavach's replies. The run also checks each reply's state against the simulator's own record, a revoke's mandates against the ones the run held, and the evidence: one signed `agent_state` record per change, in order, a loosening with an approver.
- **payments and disputes** (ADR-012, with the B2 amendment): a payment or dispute stops contact **from the moment it reaches Kavach**, for every mandate whose default happened at or before it (give or take a 30 s margin, the simulator's own copy of the number). A default that happened after it by more than the margin is a new default and is not touched, however late the payment arrives. The other direction is checked too: Kavach must **refuse a new default** that happened before (or within the margin of) a payment that reached it first, and refuse any default after a **dispute**, which holds the loan (there is no release yet); a default it takes against this, or refuses against the model, is a mismatch. The oracle takes the events, their times and their arrival order from the scenario, never from Kavach's replies, and the time of each mandate's default from the simulator's own record. A **lost** event stops nothing; a snapshot must then find exactly the live mandates the run's own record says it should (a payment's event would have revoked them, or, as information, a default that happened after it; for a dispute, every live mandate), and a different answer is a mismatch. **Unknown outcomes** (ADR-017): the provider's own behaviour is the ground truth (a lost response was delivered, a provider error was not), and a confirmed resolution must be that, from the provider's status answer; a scenario that waits (`outcomes.settle`) requires one for every unknown outcome, and the provider's inbox must still show nothing sent twice. Not modelled: a payment dated ahead of the clock (the 300 s clamp).

The adversarial agent's attacks are the attack catalog's own payloads (`kavach-attacks`). Each call's attack label is for the report only; the oracle never reads it, and a test checks that.

Agents never see it, and two tests are mandatory:
- **independence:** the agents and the oracle share no code;
- **a deliberately weakened oracle** (a cap of 4) must show up as a mismatch.

| Finding | Meaning |
|---|---|
| Violation | Kavach allowed a call the oracle says the rules forbid |
| Mismatch | Kavach refused a call the oracle says the rules allow, or the call failed. One of them is wrong: investigate |
| Leak | A reply held a destination, a token or a raw number |

## Exit codes

- **0** as expected: every `expect` met, the evidence verifies, and the three records reconcile.
- **1** not as expected: a violation, mismatch or leak; an unmet expectation; evidence that does not verify; or a reconciliation finding.
- **2** inconclusive: no evidence to judge by, for example the stack was killed or crashed. Never a pass.
- **64** the scenario or the command is not valid. Nothing is started.

The same seed gives the same digest over the ledger (who did what, when, and what was decided). IDs and signatures are random by design and are not part of it.

## Built-in scenarios

| Name | Shows | Security property |
|---|---|---|
| `normal-day` | Compliant agents contact each borrower once, in hours: all allowed and delivered | Agent authorization core (contact window) |
| `after-hours` | 18:55 allowed, 19:05 blocked by the contact-hours floor | Agent authorization core (08:00–19:00 IST floor) |
| `fourth-contact` | The daily cap (3 per borrower per IST day) blocks the fourth contact | Agent authorization core (daily cap per borrower) |
| `two-agents-one-borrower` | Two agents, each with its own mandate for one borrower: the cap holds across them | Agent authorization core (daily cap per borrower) |
| `prompt-injection-raw-number` | Raw phone, PAN and Aadhaar numbers in place of a reference are refused | Agent authorization core (no raw identifiers) |
| `wrong-borrower` | A borrower outside the mandate is refused (`subject-binding`) | Agent authorization core (the mandate's subject) |
| `forged-mandate` | A mandate id that was never issued is refused | Agent authorization core (a mandate whose chain verifies) |
| `provider-failures` | 422 is recorded as refused, and a 500 or a lost response as unknown | Credential broker / gateway (outcomes) |
| `payment-stops-contact` | A payment at 12:00 revokes two borrowers' mandates: their later calls are refused, one revocation record each, nothing delivered after it. A new default on day 2 assigns one again, and contact resumes for it only | Revocation by system-of-record event (ADR-012) |
| `dispute-stops-contact` | Two agents share each borrower: one dispute revokes both agents' mandates, and neither reaches that borrower again | Revocation by system-of-record event (ADR-012) |
| `late-payment` | A payment that happened at 09:30 reaches Kavach at 12:00, after a new default at 10:30: it ends the mandate from before it and leaves the new default's mandate alone, so contact goes on | Revocation by system-of-record event (ADR-012) |
| `default-after-payment-refused` | Out of order: a default that happened a minute before a payment reaches Kavach three minutes after it. The loan is closed to it: refused, nothing issued, contact stays stopped | Revocation by system-of-record event (ADR-012) |
| `payment-after-default-processed` | Out of order: a default that happened just before a payment is processed after the payment happened but before it arrived. Contact goes on under it until the payment arrives, which ends it too | Revocation by system-of-record event (ADR-012) |
| `default-after-dispute-refused` | A dispute at 12:00 on day 1; the system of record says the loan defaulted again on day 2. Refused: a dispute holds the loan, and the borrower stays uncontacted while the other borrower is contacted as usual | Revocation by system-of-record event (ADR-012) |
| `dropped-payment-found-by-snapshot` | A payment event is lost: contact goes on, which nothing could prevent. The lender's snapshot at 15:00 finds the mandate that still holds authority; resending the event revokes it, a second snapshot finds nothing, and contact stops | A lost payment or dispute event is found when the lender sends its closed loans (ADR-012 addendum) |
| `unknown-outcome-resolved` | One message is delivered but its response is lost, another meets a provider error; both are unknown. Kavach's reconciler asks the mock provider what became of each, and resolves them as the provider did (delivered, not delivered). Nothing is sent again | Gateway (outcomes); credential-accepting backends |
| `retry-after-unknown` | A retry after an unknown outcome gets it back, replayed, and is never sent again | Gateway (forward-once) |
| `rogue-agent-quarantined` | An operator quarantines the eager agent at 12:00 and restricts the compliant one at 15:00; at 09:00 and 12:00 on day 2 a second principal reinstates them. Nothing is allowed while an agent is stopped, the other agent is untouched, and the same mandates work again after | A stopped agent does nothing, from its next call, on every replica (ADR-013, K1-1): |
| `mixed-week` | All of the above, with a payment on day 2, over three days | All of the above |

## Not covered yet

- **Delegation to sub-agents:** needs an agent delegation API. So a delegated mandate's suspension through a stopped parent holder is **not** exercised here (the data-plane tests cover it).
- **Consent withdrawn mid-run:** needs runtime consent changes.
- **Quarantining a rogue agent:** needs the kill switch.
- **Trusted time lost:** the acceptance suite covers it.
- **Network isolation:** CI's isolation job.
- **Performance:** `kavach-bench`.
