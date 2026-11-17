# Console plan: matching the UI to the backend

Status: accepted direction, 2026-11-14. Revised 2026-11-15: steps UI-0 to UI-4 are built, every operator API operation is called by the console or listed with a reason, and the open decisions are closed. Revised 2026-11-16: the console runs on a real, seeded stack in CI (#253), and every page has the same loading, empty, error and 404 states (#254). Owner priority: this track goes before the rest of the hardening roadmap (Phase 1 resumes from 1.2 when the owner says so).

This document records what the console does, which backend operations it uses, and what is still missing. The console's visual rules and components are in [console/DESIGN.md](../console/DESIGN.md); this file is about scope and order.

## 1. Where the console stands (read on 2026-11-16)

Facts, from the code at `4fefaf8` plus the ADR-018 sign-in (#248 backend, #250 console), the real-stack suite (#253) and the page states (#254):

- **Stack.** React 19, TypeScript (strict), Vite 7, React Router 7, Tailwind CSS 4, Lucide icons. At `4fefaf8`: 65 source files, about 6,900 lines, without tests and the generated `openapi.d.ts`. Fonts are self-hosted. No component library.
- **It is wired for both tracks.** Every API call is in `console/src/lib/api.ts` (and, with sign-in, the `/auth/*` calls in `console/src/lib/session.ts`). Section 2 lists each operation and the page that calls it. There are 18 routes in the app shell, plus `/signin` outside it.
- **Types come from the spec.** `npm run gen:api` (openapi-typescript) generates `src/lib/openapi.d.ts` from `docs/openapi.yaml`; `npm run check:api` fails when the committed file differs (#222). `api.ts` hand-types only `ReinstateAgentParams`, because `ChangeProposal.params` is untyped in the spec (issue #218).
- **Error handling.** `request()` checks the status before parsing. A problem body becomes an `ApiError` with status, `detail` and `request_id`; a non-JSON error (a proxy's 502) shows its status (#220).
- **Page states.** Every page that reads the API lays its read out the same way (`useResource`, `ResourceState`): a skeleton and a `role=status` line while loading, the empty message, a `ProblemAlert` with the HTTP status, `request_id` and 401/403 guidance, Try again, and on detail pages a 404 headline that names the record. An unknown path shows a 404 page. Vitest renders every governance page in each state; `e2e/narrow.e2e.ts` opens every page at 375px (#254). The rules are in [console/DESIGN.md](../console/DESIGN.md), "Page states".
- **Served in agent-only mode.** `kavach-api --agent-only` serves the console (#224). `GET /v1/runtime` reports `agent_only`, and the console then leaves the credit-track pages out of the navigation and shows "Not served on this server" on their paths (#244).
- **Only a real build is embedded.** `crates/kavach-api/build.rs` embeds `console/dist` only when its `index.html` loads a script from `/assets/` and every asset it names exists; otherwise `/` answers "console not built" (404) (#224).
- **Tests, lint and accessibility in CI.** The "Format, Clippy, Test" job builds the console and runs typecheck, ESLint (with `jsx-a11y` and `react-hooks`), Vitest (16 test files at `4fefaf8`), `check:api`, the Playwright suite against a stubbed API in Chromium with axe (WCAG 2.2 AA tags) on every page and state, keyboard flows and a CSP check (#222, #239, #241), the production licence check, and the API path check in section 2. With sign-in (#248, #250) it adds stubbed sign-in specs and a real round trip against `kavach-api` and an OIDC test double. With #253 it runs every page and action against a real, seeded stack: a `kavach-dev` bundle, the OIDC double, the mock provider, and `kavach-api` full and `--agent-only`, with memory stores (`npm run test:real`).
- **Authentication (ADR-018 option C).** `kavach-api` is a backend-for-frontend: `GET /auth/login` starts an authorization code flow with PKCE, the IdP tokens stay in server memory, and the browser holds only an HttpOnly `__Host-kavach_session` cookie. `GET /auth/config` picks one of three modes on load. With login configured, `/signin` offers a plain link to `/auth/login`, and pages render only with a live `GET /auth/session`; every request sends `X-Kavach-Console: 1` with same-origin credentials and never `Authorization` or `X-Kavach-Principal`. Without login, and only when the server runs with `--insecure-dev`, the pasted-token field stays as a labelled development fallback (`sessionStorage`); otherwise the console says login is not configured and offers no field.
- **Role-aware views.** `src/lib/permissions.ts` copies the Cedar policy's group-to-action map, and a test fails when it and `kavach.cedar` disagree. With the session's groups known, a control the groups lack is replaced by a `RoleHint`; with groups unknown every control shows. The API stays the gate (#239, #241).
- **Security headers.** Every console response carries a strict Content-Security-Policy (`default-src 'self'`, no inline script or style, `frame-ancestors 'none'`, `base-uri 'none'`, `form-action 'self'`), `nosniff` and `Referrer-Policy: no-referrer` (#224). API responses get their own headers in #237 (roadmap 1.3), which the sign-in work builds on.
- **Wording.** The sidebar's "DPDP-aware · RBI-aligned posture" and the Overview's "via X-Kavach-Principal header" are gone (#220).

## 2. Backend surface and where it is in the console

The operations in `docs/openapi.yaml`. The Cedar action is what the principal needs (`crates/kavach-auth/policies/kavach.cedar`; for change requests, `crates/kavach-api/src/change_requests.rs`). "Exempt" means listed with its reason in [`console/api-coverage-exempt.txt`](../console/api-coverage-exempt.txt).

CI keeps this table honest: `scripts/console_path_coverage.py` (step "Console API path coverage") fails when an operation is neither called from `console/src` nor exempt, and when an exemption is stale.

| Operation | Cedar action | Console | Status |
|---|---|---|---|
| `GET /health` | `read_health` | Overview | done |
| `GET /metrics` | `read_metrics` | none | exempt: Prometheus text format for Prometheus and Grafana (`deploy/monitoring/`) |
| `POST /v1/evaluate` | `evaluate` | Evaluate | done (credit track, frozen) |
| `GET /v1/runtime` | `read_governance` | Overview (posture); the shell reads `agent_only` | done (UI-0 #220, #244) |
| `GET /v1/packs` | `read_governance` | Policies | done (credit track) |
| `GET /v1/packs/{pack_id}` | `read_governance` | Policy detail | done (credit track) |
| `GET /v1/models` | `read_governance` | Models | done (credit track) |
| `GET /v1/models/{model_id}` | `read_governance` | Model detail | done (credit track) |
| `GET /v1/change-requests` | `read_change_requests` | Change requests | done |
| `POST /v1/change-requests` | `propose_<kind>` | Policy detail (`activate_pack`), Model detail (`update_model`), Retention (`update_retention`, `apply_retention`), Agent detail (`reinstate_agent`, UI-2 #233) | done; `rollback_pack`, `erase_evidence` and `activate_model` are not proposed from the console |
| `GET /v1/change-requests/{id}` | `read_change_requests` | none | exempt: the list returns the same `ChangeRequest` items, and the console has no single-request view |
| `POST /v1/change-requests/{id}/approve` | `approve_<kind>` | Change requests | done (role-aware #239) |
| `POST /v1/change-requests/{id}/reject` | `approve_<kind>` | Change requests | done (role-aware #239) |
| `POST /v1/change-requests/{id}/cancel` | `propose_<kind>` | Change requests | done (role-aware #239) |
| `GET /v1/admin/audit` | `read_audit` | Audit | done |
| `POST /v1/dev/clock` | `set_dev_clock` | none | exempt: development stacks only, driven by the `kavach` CLI |
| `GET /v1/agents?state=&limit=&cursor=` | `read_agent_state` | Agents | done (endpoint #227, UI-1 #232) |
| `GET /v1/agents/{agent_id}` | `read_agent_state` | Agent detail | done (UI-1 #232) |
| `POST /v1/agents/{agent_id}/restrict` | `stop_agent` | Agent detail | done (UI-2 #233) |
| `POST /v1/agents/{agent_id}/quarantine` | `stop_agent` | Agent detail | done (UI-2 #233) |
| `POST /v1/agents/{agent_id}/revoke` | `stop_agent` | Agent detail | done (UI-2 #233) |
| `GET /v1/agent-decisions/{record_id}` | `read_evidence` (rate limited, audited) | Agent evidence: signed decision/outcome and ADR-017 resolution history | done (UI-1 #232; ADR-017 first UI-3 slice) |
| `GET /v1/unknown-outcomes?limit=&cursor=` | `read_evidence` (rate limited, audited) | Agent evidence: on-demand unknown-outcome review by governing state | done (ADR-017 third UI-3 slice; console fourth slice) |
| `GET /v1/agent-revocations/{system}/{event_id}` | `read_evidence` (rate limited, audited) | Agent evidence | done (UI-1 #232) |
| `POST /v1/reconciliation/closed-records` | `reconcile_closed_records` (rate limited, audited; revokes nothing) | Closed loans (`/reconciliation`) | done (UI-3 #234) |
| `GET /v1/decision-events/{evidence_id}` | `read_evidence` | Decision events | done (UI-3 #234) |
| `GET /v1/admin/retention` | `read_retention` | Retention | done (credit track) |
| `GET /v1/admin/tombstones` | `read_tombstones` | Retention | done (credit track) |
| `GET /v1/admin/incidents` | `read_incidents` | Incidents | done (credit track) |
| `GET /v1/admin/batch-jobs` | `read_batch_jobs` | Batch jobs | done (credit track) |
| `GET /v1/admin/batch-jobs/{job_id}` | `read_batch_jobs` | Batch job detail | done (credit track) |
| `GET /v1/me` | caller's session | App shell: role-aware page hints and superadmin banner | done (ADR-019 step 3, `/v1/me` is presentation only) |
| `GET /v1/principals?q=&limit=&cursor=` | `read_principals` | Users & roles: searchable people directory | done (ADR-019 step 3, read-only slice) |
| `GET /v1/role-bindings` | `read_principals` | Users & roles: active role bindings | done (ADR-019 step 3, read-only slice) |
| `GET /v1/access-review?format=json\|csv` | `read_access_review` | Users & roles: on-demand review and CSV download | done (ADR-019 step 3) |
| `POST /v1/authorize` | agent token | none | exempt: agent listener |
| `POST /v1/tools/{tool}` | agent token | none | exempt: agent listener |
| `POST /v1/sor/events` | issuer signature | none | exempt: system-of-record listener |
| `GET /auth/config` | none (public) | every page load (`startSession` in `App.tsx`) | done (ADR-018 sign-in) |
| `GET /auth/login` | none (public) | Sign-in: the link on `/signin` | done (ADR-018 sign-in) |
| `GET /auth/callback` | none (public) | none | exempt: the IdP redirects the browser there; the console never requests or links it |
| `GET /auth/session` | session cookie | `SessionGate`, header, Settings | done (ADR-018 sign-in) |
| `GET /auth/human-review/{record_id}` | `approve_human_review` | Agent Evidence: manually load the exact-action reviewer projection by decision record id | done (D17 read-only display slice; no list/search or approval action) |
| `POST /auth/step-up/{record_id}` | `approve_human_review` | Agent Evidence: explicitly start exact-action IdP passkey verification from the loaded review | done (D17 step-up initiation UI; callback keeps proof server-side; no approval action) |
| `POST /auth/logout` | session cookie | header: Sign out | done (ADR-018 sign-in) |

The credit-track pages keep working and get no new features. On an `--agent-only` server they are left out (#244).

### Backend gaps the console still has

- **ADR-017 unknown outcomes and resolutions:** the agent-decision lookup returns and displays full resolution history (first UI-3 slice). Memory and Postgres stores expose all unknown outcomes and history (second slice), the API provides a paged audited read with governing state (third slice), and the Agent Evidence page now provides the on-demand list (fourth slice). The backend has delivered and not-delivered attestation plus two-person conflict-closure change requests; the console remains read-only for outcomes. Remaining mock simulator/demo work and validation before real-provider work are tracked in ADR-017.
- **Reinstatement parameters are untyped** in the spec (`ChangeProposal.params`), so `ReinstateAgentParams` is the one hand-written request type.
- **One change request by id.** `GET /v1/change-requests/{id}` exists but the console does not use it: after proposing a reinstatement it links to the list. A detail view would use it and drop the exemption.
- **Three change kinds** (`rollback_pack`, `erase_evidence`, `activate_model`) are listed, approved, rejected and cancelled in the console, but proposed only through the API.
- Done since 2026-11-14: the agent list endpoint (#227) and the console on agent-only servers (#224, #244).

Other known gaps, from issue #218 and the sign-in work:

- Console sessions live in one `kavach-api` process: a restart signs everyone out, and replicas do not share them.
- The browser suites run in Chromium only. Firefox and WebKit are not covered, the sign-in round trip included.
- The real-stack suite uses memory stores and the OIDC test double, not Postgres or a real IdP.
## 3. Standards the console is held to

- **Accessibility:** WCAG 2.2 level AA. Keyboard reachable, visible focus, a skip link, labelled controls, status messages announced (`role="status"`/`aria-live`), no colour-only meaning (decision and state badges carry text). axe runs on every page and state in CI.
- **Web security:** OWASP ASVS 5.0 level 2 for the browser side. A strict Content-Security-Policy with no inline script, `frame-ancestors 'none'`, `nosniff`, `Referrer-Policy: no-referrer`. No `dangerouslySetInnerHTML`. No token is ever logged or put in a URL; with sign-in, the browser holds no token at all.
- **Errors:** RFC 9457 problem details. The console shows `detail` and the `request_id`, and the HTTP status when the body is not a problem.
- **Privacy:** no telemetry, no third-party requests, self-hosted fonts. The console never asks for, shows or stores raw personal data. Loans appear only as the references and pseudonyms the API returns.
- **Wording:** the project's claim rules apply to UI text. No "compliant", "production-grade" or latency claims. Evidence wording follows the verifiers: an agent record is "signature verified against the listed keys", and one record proves nothing about the chain. The console shows hashes and the verify commands; it does not verify bundles itself.
- **Safety in the UI:** stopping an agent asks for a reason code and confirmation, and says what happens (restrict: no external effects; quarantine: mandates suspended; revoke: permanent, mandates revoked). The result shows `record: pending` honestly when the reconciler still has to write the evidence record. Reinstating is a change request that a different principal approves; the UI says so and does not offer an approve button to the proposer.
- **Contracts:** request and response types come from `docs/openapi.yaml`, not hand-written copies, and every operator operation is called or exempt with a reason (section 2).

## 4. Steps

Each step was one or more PRs from `main`, with the repo's five-question checklist.

### UI-0: foundations — done (#220, #222, #224)

- One fetch helper: checks the status before parsing, turns problem details into a typed error with status and `request_id`, and handles non-JSON bodies.
- Types generated from `docs/openapi.yaml` (#222), including `reinstate_agent` and the full runtime view.
- Overview shows the runtime posture: relaxations by name, insecure dev, HSM status, checkpoints, dev clock.
- The unproven claims and the stale header wording are gone.
- Accessibility basics: skip link, `aria-live` for action results, the drawer closes on Escape.
- The console is served in agent-only mode with security headers (#224).

### UI-1: agent track, read-only — done (#227, #232)

- Agents list (`GET /v1/agents`, #227) and agent page: state and history fields (state, change number, reason code, note, who changed it, approver, change request, time).
- Evidence lookups: an agent decision record by record id (with its outcome, if any), a revocation record by system and event id. Each lookup is audited and rate limited by the API; the page says so.

### UI-2: agent actions — done (#233)

- Restrict, quarantine and revoke from the agent page, with reason code, optional note (256 characters, never in the evidence chain), and a confirmation that names the effect.
- The result: `applied`, `record` (`written`, `pending`, `unchanged`), and for revoke the mandates revoked and not revoked, with "repeat the revoke to finish" when the second list is not empty.
- Reinstate: propose a `reinstate_agent` change request (`to: active | restricted`), never from `revoked`.

### UI-3: evidence and reconciliation — done (#234; ADR-017 read-only console slices)

- Closed-records reconciliation (Closed loans): upload or paste the lender's list, show findings, state plainly that the call revokes nothing.
- Decision events (credit) by evidence id, with `kavach-evidence verify --file` for the exported chain and `kavach why --export` for one event. Agent records get `kavach-evidence verify-bundle`, `kavach why --bundle` (decisions only) and the independent Python verifier. The console runs none of these; it shows them to copy.
- **Done (first ADR-017 slice):** an agent-decision evidence lookup returns all signed resolutions for an unknown outcome, oldest first, through the existing audited and rate-limited `read_evidence` path. The page renders the append-only history.
- **Done (second slice):** both evidence stores expose a tenant-scoped, cursor-paged read of every unknown outcome and its complete resolution history. It includes unresolved, ambiguous, conflicted and confirmed histories; the reconciler's narrower queue remains unchanged.
- **Done (third slice):** `GET /v1/unknown-outcomes` returns the paged store read with the governing state and source. It uses `read_evidence`, the evidence-read rate limit and an audit record; it does not resend or release a contact slot.
- **Done (fourth slice):** Agent Evidence has a click-to-load, cursor-paged list showing each unknown outcome's governing state and complete resolution history, with loading, empty, error, retry and role-hint states. The read does not enable a write action.
- **Separate backend work:** ADR-017 R3b attestation and conflict-closure change requests are backend capabilities. They are not part of the approved read-only UI-3 scope; no outcome write controls are shown in the console.

### UI-4: hardening and polish — done (#239, #241, #244, ADR-018 sign-in, #253, #254)

- Role-aware views: a control the viewer's known groups lack is replaced by a role hint (the API stays the gate).
- Console tests and lint in CI, axe on every page, keyboard and CSP checks; the sign-in round trip against `kavach-api` and an OIDC test double; every page and action on a real, seeded stack (#253).
- The same loading, empty, error, 401/403 and 404 states on every page, a 404 page, and every page checked at 375px (#254).
- OIDC authorization code with PKCE in place of the pasted token, per [ADR-018](ADR-018-console-login-and-token-storage.md) option C.
- The API path check (section 2).

### D17 browser reviewer surface — in progress

- **Done (first UI slice):** Agent Evidence provides a Cedar-role-aware manual lookup by signed decision record id and renders only the projection returned by the audited `GET /auth/human-review/{record_id}` endpoint. It is display-only; no approval or release control is present. No decision-record listing/search endpoint is introduced.
- **Done (second UI slice):** An explicit button starts `POST /auth/step-up/{record_id}` for the displayed action and redirects to the server-provided IdP URL. The UI states passkey verification is not approval; the callback retains proof server-side and returns to the console root.
- **Backend done (D17 approval creation and release record):** `POST /auth/human-review/{record_id}/approval` requires an explicit decision, Cedar permission, a live console session, and a one-use exact-action step-up proof; it audits before storing a short-lived approval and returns the opaque `approval_id`. Approved records also receive a separate execution ID. The store consumes an approval once and writes immutable release evidence while preserving the reviewed request ID and action hash. Tool request handoff/evidence idempotency and console decision controls remain pending.
- **Pending:** wire approval consumption to agent authorization, then add the console decision controls and handoff only after that path is complete and tested.

### ADR-019 step 3: operator role management — done

- **Done:** `/v1/me` is read once for the current caller and held in memory; known groups and roles inform sidebar visibility, and superadmins see the persistent banner.
- **Done:** `/users` shows the searchable, cursor-paged people directory. Its read is covered by loading, empty, error, and accessibility tests.
- **Done:** `/users` lists active role bindings separately from the people directory, with its own loading, empty and error states.
- **Done:** `/users` lets an authorized operator propose a role grant for a directory principal. It submits a maker-checker request; the UI states that the pending request grants no access. The API remains authoritative.
- **Done:** `/users` lets an authorized operator propose revocation of an active role binding by binding id. The UI states that the binding remains active until a different authorized person approves. The API remains authoritative.
- **Done:** `/users` loads the access review only on request and displays active binding, grant, approver, last-seen and stale information. JSON loads and CSV downloads use the API's audited export route; the API provides the spreadsheet-safe CSV.

## 5. Decisions (closed)

1. **Serve the console in agent-only mode:** done. Served in #224; credit-free navigation from `agent_only` in `GET /v1/runtime` in #244.
2. **The list endpoint:** agents only, built in #227 (`GET /v1/agents`, keyset paging, admins only). No list or search for mandates or decision records was built, and the console does not need one for the current pages.
3. **Dev tools:** approved and in the tree: ESLint, Vitest and openapi-typescript (#222), Playwright and axe (#239, #241).
4. **Console login and token storage:** ADR-018 option C, accepted in #228, built in the sign-in PRs.
