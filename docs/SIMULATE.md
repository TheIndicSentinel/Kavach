# Simulation (`kavach simulate`, pre-alpha)

`kavach simulate` runs synthetic agents over simulated days against a real development stack, and judges every decision with a small oracle that shares nothing with the agents. It shows that these synthetic scenarios behave as expected on this machine. **It is not a security assessment**, and it proves nothing about real providers, networks or data. Every report lists what it does not cover first.

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

   It is deleted afterwards, also on Ctrl-C, unless `--keep`. A run never attaches to a running stack.
2. **Its own stack:** `kavach dev up --clock <first slot> --export-on-exit <dir>`, on distinct free loopback ports, with a fixed development clock.
3. **One mandate per (agent, borrower) pair**, through signed system-of-record events.
4. **Each slot, day by day:**
   - the clock moves forward;
   - each agent decides its calls from its behaviour settings;
   - each call goes to `POST /v1/tools/send_reminder` with a `sim-` request id;
   - every reply goes into the ledger.
5. **The stack stops (SIGTERM)** and writes its evidence as a development bundle. The bundle is verified against the auditor's dev keys.
6. **The oracle** judges every call in the ledger. The report counts violations, mismatches and leaks, and checks the scenario's `expect`.

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
expect:                   # required: what passing means
  violations: 0
  mismatches: 0
  leaks: 0
  allowed_at_least: 10
  blocked_at_least: { contact-daily-cap: 1 }
```

Unknown keys are refused. `--seed`, `--days` and `--borrowers` override the file.

## The oracle

It models the product's rules, written independently of Kavach's policies, and judges each call only by what was sent:
- **the tool registry:** `send_reminder` only, with exactly `subject_ref`, `channel` (WhatsApp or SMS) and `template_id` (`emi_reminder_v1`);
- **a plain reference:** at most eight digits and nothing PAN-shaped (ADR-004 §7);
- **the mandate:** it was issued, and for that subject;
- **contact hours:** only from 08:00 to 19:00 IST (19:00 itself is out);
- **the daily cap:** at most three contacts per borrower per IST day, **across all agents**. Only contacts Kavach allowed count, and a retry is not a new contact;
- **channels:** only those the mandate grants (WhatsApp, voice);
- **forward-once:** a retry (same request id) is never sent again. After a final outcome it gets the stored reply (`replayed`); after an unknown one, 409 `in_flight`;
- **provider outcomes** follow the agreed status contract (ADR-007): 2xx delivered, 4xx refused, and a 5xx or a lost response unknown (a 5xx does not prove the message was not sent).

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

- **0** as expected: every `expect` met, and the evidence verifies.
- **1** not as expected: a violation, mismatch or leak; an unmet expectation; or evidence that does not verify.
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
| `retry-after-unknown` | A retry after an unknown outcome gets 409 `in_flight` and is never sent again | Gateway (forward-once) |
| `mixed-week` | All of the above, over three days | All of the above |

## Not covered yet

- **Revocation by payment or dispute:** needs R1.
- **Delegation to sub-agents:** needs an agent delegation API.
- **Consent withdrawn mid-run:** needs runtime consent changes.
- **Quarantining a rogue agent:** needs the kill switch.
- **Trusted time lost:** the acceptance suite covers it.
- **The provider's inbox reconciled against the evidence** (proof from the provider's side that nothing was sent twice): planned for S3. Until then, "never sent twice" rests on Kavach's replies and its evidence.
- **Network isolation:** CI's isolation job.
- **Performance:** `kavach-bench`.
