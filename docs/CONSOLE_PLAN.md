# Console plan: matching the UI to the backend

Status: accepted direction, 2026-11-14. Owner priority: this track goes before the rest of the hardening roadmap (Phase 1 resumes from 1.2 when the owner says so).

This document records what the console does today, what the backend offers that the console does not show, and the order in which the gap is closed. Each step is one pull request. The console's visual rules stay in [console/DESIGN.md](../console/DESIGN.md); this file is about scope and order.

## 1. Where the console stands (read on 2026-11-14 at 17d0232)

Facts, from the code:

- **Stack.** React 19, TypeScript (strict), Vite 7, React Router 7, Tailwind CSS 4, Lucide icons. 37 source files, about 3,100 lines. Fonts are self-hosted. No component library.
- **It is wired, for the credit track.** `console/src/lib/api.ts` calls 17 endpoints: health, runtime, evaluate, packs, models, audit, incidents, batch jobs, retention, tombstones and the change-request lifecycle (propose, list, approve with the reviewed digest, reject, cancel). There are 14 routes.
- **Nothing for the agent track.** No page calls `/v1/agents/*`, `/v1/agent-decisions/*`, `/v1/agent-revocations/*`, `/v1/reconciliation/closed-records` or `/v1/decision-events/*`.
- **Type drift.** The console's `ChangeKind` lacks `reinstate_agent`, which the backend and `docs/openapi.yaml` have. A `reinstate_agent` request in the list renders with an undefined label. `RuntimeInfo` ignores `checkpoints`, `hsm`, `dev_clock`, `insecure_dev` and `relaxations`, which `/v1/runtime` returns.
- **Error handling.** `governanceFetch` and `evaluateRequest` call `response.json()` before checking `response.ok`, so a non-JSON error (a proxy's 502 or 504) surfaces as a parse error instead of the status.
- **Not served in agent-only mode.** `crates/kavach-api/src/http.rs` falls back to a 404 instead of the console when the data plane is agent-only, the mode product direction makes the default for hosted builds.
- **Why a local build can look empty.** `crates/kavach-api/build.rs` embeds `console/dist` whenever `dist/index.html` exists. A stub `index.html` left in `dist/` embeds a blank page. `scripts/build-console.sh` and `deploy/Dockerfile` build the real console; a plain `cargo build` does not.
- **No console tests, lint or accessibility checks.** `package.json` has `dev`, `build` and `preview` only. CI builds the console and checks production licences (`ci.yml`, "Build console", "Console licence check").
- **Authentication.** Settings takes a pasted OIDC access token into `sessionStorage` (owner decision: stays, under a strict CSP, until the session work). There is no login flow.
- **Security headers.** None are set by `kavach-api` (roadmap items 1.3 and 1.4).
- **Wording.** The sidebar footer says "DPDP-aware · RBI-aligned posture" and the Overview page describes Cedar RBAC "via X-Kavach-Principal header", which is development-only. Both conflict with the project's rule against unproven claims.

Not read for this plan: the Evaluate, Retention, Models and Batch detail pages in full, and the CSS.

## 2. Backend surface and where it belongs in the console

The operator API (`docs/openapi.yaml`). The Cedar action is what the principal needs (`crates/kavach-auth/policies/kavach.cedar`).

| Endpoint | Action | Console today | Step |
|---|---|---|---|
| `GET /health` | `read_health` | Overview | done |
| `GET /v1/runtime` | `read_governance` | Overview (partial) | UI-0: show posture (relaxations, insecure dev, HSM, checkpoints, dev clock) |
| `GET/POST /v1/change-requests`, `GET …/{id}`, `POST …/{id}/approve \| reject \| cancel` | `read_change_requests`, `propose_*`, `approve_*` | Change requests | UI-0: add `reinstate_agent`; UI-2: propose it |
| `GET /v1/admin/audit` | `read_audit` | Audit | done; UI-0 wording |
| `GET /v1/agents?state=&limit=&cursor=` | `read_agent_state` | none | UI-1 (list) |
| `GET /v1/agents/{agent_id}` | `read_agent_state` | none | UI-1 |
| `POST /v1/agents/{agent_id}/restrict \| quarantine \| revoke` | `stop_agent` | none | UI-2 |
| `GET /v1/agent-decisions/{record_id}` | `read_evidence` (rate limited, audited) | none | UI-1 |
| `GET /v1/agent-revocations/{system}/{event_id}` | `read_evidence` (rate limited, audited) | none | UI-1 |
| `POST /v1/reconciliation/closed-records` | `reconcile_closed_records` (rate limited, audited; revokes nothing) | none | UI-3 |
| `GET /v1/decision-events/{evidence_id}` | `read_evidence` | none | UI-3 |
| Credit track: evaluate, packs, models, retention, tombstones, incidents, batch jobs | various | pages exist | frozen: keep working, no new features |
| `GET /metrics` | `read_metrics` | none | not planned: Prometheus and Grafana own it |
| `POST /v1/dev/clock` | `set_dev_clock`, dev stacks only | none | not planned |

The agent listener (`/v1/authorize`, `/v1/tools/{tool}`) and `/v1/sor/events` are for agents and systems of record, not operators. The console does not call them.

### Backend gaps the console needs

- **No list or search for agents, mandates or decision records.** Every agent read is by exact id. The console can look things up but cannot browse. A browsable view needs an additive, read-only, paginated endpoint (proposed in UI-1, owner approval required, OpenAPI and Cedar updated in the same PR).
- **Console in agent-only mode.** Serving the console when the credit track is off needs a change in `http.rs` and a credit-free navigation. Owner decision.

## 3. Standards the console is held to

- **Accessibility:** WCAG 2.2 level AA. Keyboard reachable, visible focus, a skip link, labelled controls, status messages announced (`role="status"`/`aria-live`), no colour-only meaning (decision and state badges carry text).
- **Web security:** OWASP ASVS 5.0 level 2 for the browser side. A strict Content-Security-Policy with no inline script, `frame-ancestors 'none'`, `nosniff`, `Referrer-Policy: no-referrer` (roadmap 1.3 and 1.4). No `dangerouslySetInnerHTML`. The token is never logged or put in a URL.
- **Errors:** RFC 9457 problem details. The console shows `detail` and the `request_id`, and the HTTP status when the body is not a problem.
- **Privacy:** no telemetry, no third-party requests, self-hosted fonts. The console never asks for, shows or stores raw personal data. Loans appear only as the references and pseudonyms the API returns.
- **Wording:** the project's claim rules apply to UI text. No "compliant", "production-grade" or latency claims. Evidence wording follows the verifiers: an agent record is "signature verified against the listed keys", and one record proves nothing about the chain. The console shows hashes and the verify command; it does not verify bundles itself.
- **Safety in the UI:** stopping an agent asks for a reason code and confirmation, and says what happens (restrict: no external effects; quarantine: mandates suspended; revoke: permanent, mandates revoked). The result shows `record: pending` honestly when the reconciler still has to write the evidence record. Reinstating is a change request that a different principal approves; the UI says so and does not offer an approve button to the proposer.
- **Contracts:** request and response types come from `docs/openapi.yaml`, not hand-written copies.

## 4. Steps

Each step is one PR from `main`, with the repo's five-question checklist. New npm dependencies, including dev-only tools, need the owner's approval first.

### UI-0: foundations (no new dependencies)

- One fetch helper: checks `ok` before parsing, turns problem details into a typed error with status and `request_id`, and handles non-JSON bodies.
- Types match `docs/openapi.yaml` by hand for now (`reinstate_agent`, the full runtime view). Generated types follow when the generator is approved.
- Overview shows the runtime posture: relaxations by name, insecure dev, HSM status, checkpoints, dev clock.
- Remove the unproven claims and the stale header wording.
- Accessibility basics: skip link, `aria-live` for action results, the drawer closes on Escape.
- Done when: `npm run build` passes, the console shows real data against a dev stack, and no page hand-writes a type that the spec defines differently.

### UI-1: agent track, read-only

- Agent page: look up an agent by id, show its state and history fields (state, change number, reason code, note, who changed it, approver, change request, time).
- Evidence lookups: an agent decision record by record id (with its outcome, if any), a revocation record by system and event id. Each lookup is audited and rate limited by the API; the page says so.
- Backend: propose the list endpoint (section 2) as its own PR.

### UI-2: agent actions

- Restrict, quarantine and revoke from the agent page, with reason code, optional note (256 characters, never in the evidence chain), and a confirmation that names the effect.
- Show the result: `applied`, `record` (`written`, `pending`, `unchanged`), and for revoke the mandates revoked and not revoked, with "repeat the revoke to finish" when the second list is not empty.
- Reinstate: propose a `reinstate_agent` change request (`to: active | restricted`), never from `revoked`.

### UI-3: evidence and reconciliation

- Closed-records reconciliation: upload or paste the lender's list, show findings, state plainly that the call revokes nothing.
- Decision events (credit) by evidence id, and the `kavach evidence verify` command for offline verification.
- Unknown outcomes and resolutions (ADR-017) once the read endpoints exist.

### UI-4: hardening and polish

- Role-aware views: hide or disable actions the principal cannot perform (the API stays the gate).
- Console tests and lint in CI, an automated accessibility check, end-to-end tests against a dev stack.
- OIDC authorization code with PKCE in place of the pasted token, with the token storage ADR: [ADR-018](ADR-018-console-login-and-token-storage.md) (proposed; also roadmap 1.4).

## 5. Open decisions

1. Serve the console in agent-only mode (section 2).
2. The list and search endpoint for agents, mandates and decision records.
3. Approval for dev tools: ESLint, Vitest and openapi-typescript (UI-0/UI-1), Playwright (UI-4).
