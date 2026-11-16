# Kavach Console — Design System

The design system of the governance console, as built. A new page extends these patterns; it does not introduce a parallel design.

Which API operation each page calls, what the console still lacks against the backend, and the order of work: [docs/CONSOLE_PLAN.md](../docs/CONSOLE_PLAN.md).

## Principles

1. **Enterprise trust first** — navy palette, clear hierarchy, accessible contrast (WCAG AA target).
2. **Minimal Indian touch** — Devanagari subtitles, `en-IN` formatting, saffron accent used sparingly. No decorative tricolor or cultural clipart.
3. **Domain-native** — four decision states (`PASS`, `ALERT`, `BLOCK`, `HUMAN_REVIEW`) are first-class visual tokens.
4. **Shield motif** — Kavach (कवच) means protection; logo and sidebar reinforce governance, not generic SaaS.

## Tech stack

| Layer | Choice |
|---|---|
| Framework | React 19 + TypeScript |
| Build | Vite 7 |
| Routing | React Router 7 |
| Styling | Tailwind CSS 4 (`@tailwindcss/vite`) |
| Icons | Lucide React |
| Utilities | `clsx` + `tailwind-merge` (`cn()`) |
| API types | Generated from `docs/openapi.yaml` by openapi-typescript (`npm run gen:api` → `src/lib/openapi.d.ts`; `npm run check:api` fails on drift) |
| Lint | ESLint 9 with `typescript-eslint`, `react-hooks` and `jsx-a11y` (`npm run lint`) |
| Unit tests | Vitest (`npm test`); pages and components render to static markup (`src/test/markup.ts`) |
| Browser tests | Playwright in Chromium, with axe (`@axe-core/playwright`): against a stubbed API (`npm run test:e2e`), the sign-in round trip (`test:roundtrip`) and a real, seeded stack (`test:real`) |

The last four rows are development tools, none of them in the built bundle; each needed the owner's approval. No heavy component library — primitives in `src/components/ui/` follow shadcn-style patterns without the dependency overhead.

## Brand tokens

Defined in `src/index.css` via `@theme`:

| Token | Value | Usage |
|---|---|---|
| `kavach-950` … `kavach-500` | Navy scale | Sidebar, headings, trust surfaces |
| `saffron-500` | `#E8870D` | Primary CTA (navy `kavach-950` text: white on saffron is under 4.5:1), logo accent |
| `peacock-600` | `#0D7377` | Secondary accent, environment badges |
| `surface` | Warm stone `#FAFAF9` | Page background |
| `decision-*` | Semantic | PASS / ALERT / BLOCK / HUMAN_REVIEW badges |

## Typography

- **UI:** Plus Jakarta Sans (bundled via `@fontsource`)
- **Devanagari:** Noto Sans Devanagari — page subtitles only (`hindi` prop on `PageHeader`)
- **Monospace:** JetBrains Mono — JSON editors and evidence IDs

Fonts are self-hosted (no external CDN) for on-prem bank VPCs.

## Components

Paths are under `src/components/`.

| Component | Path | Purpose |
|---|---|---|
| `Button` | `ui/Button.tsx` | Primary (saffron), secondary (navy), ghost |
| `Card` | `ui/Card.tsx` | Content panels |
| `Badge` | `ui/Badge.tsx` | Small labelled tag (default, active, muted, warning) |
| `DecisionBadge` | `ui/DecisionBadge.tsx` | Domain decision display |
| `StatusIndicator` | `ui/StatusIndicator.tsx` | Health / liveness |
| `PageHeader` | `ui/PageHeader.tsx` | Page title + optional Hindi subtitle |
| `DataTable` | `ui/DataTable.tsx` | Table from `md` up, stacked cards below |
| `Dialog` | `ui/Dialog.tsx` | Modal confirmation (`role=alertdialog`): focus moves in, Tab stays inside, Escape cancels, focus returns to the opener |
| `TextField` | `ui/TextField.tsx` | Labelled input whose hint and error are announced with it |
| `Skeleton` | `ui/Skeleton.tsx` | Loading placeholder for async data |
| `ResourceState` | `ui/ResourceState.tsx` | One read's states, laid out the same on every page (see Page states) |
| `ProposalStatus` | `ui/ProposalStatus.tsx` | A change proposal's outcome under its button: the refusal in a `ProblemAlert`, or "proposed" in `role=status` |
| `RoleHint` | `ui/RoleHint.tsx` | The line shown in place of a control the viewer's groups are known to lack |
| `ProblemAlert` | `ui/ProblemAlert.tsx` | A refusal in `role=alert`: problem detail, HTTP status, `request_id` |
| `AppShell` | `layout/AppShell.tsx` | Skip link, sidebar, top bar and main; asks `GET /v1/runtime` for `agent_only` |
| `Sidebar` | `layout/Sidebar.tsx` | Navigation in three groups (main, Agents, Governance); credit-track pages left out on an agent-only server |
| `TopBar` | `layout/TopBar.tsx` | Menu button below `lg`, environment, principal; with sign-in, the session end and Sign out |
| `NotServed` | `layout/NotServed.tsx` | In place of a credit-track page on an agent-only server |
| `SessionGate` | `layout/SessionGate.tsx` | Renders no page until the sign-in mode and session are known (ADR-018) |
| `DevTokenForm` | `auth/DevTokenForm.tsx` | The pasted token / principal form, development fallback only |
| `ErrorBoundary` | `ErrorBoundary.tsx` | A render error shows a card instead of a blank page |
| `KavachLogo` | `brand/KavachLogo.tsx` | Shield mark + wordmark |
| Agent views | `agents/AgentViews.tsx`, `agents/EvidenceViews.tsx` | Agent state badge and field lists; agent decision and revocation records, with what the page may say about evidence |
| Agent actions | `agents/AgentActions.tsx` | Restrict, quarantine and revoke dialogs with reason code and note; the reinstatement proposal; the result |
| Evidence views | `evidence/LookupPanel.tsx`, `evidence/VerifyCommands.tsx`, `evidence/DecisionEventView.tsx`, `evidence/ClosedRecordsViews.tsx` | A lookup's status, refusal and result; copyable verify commands (the console runs none); a decision event; closed-records counts and findings |

### Role hints (the server decides)

`src/lib/permissions.ts` copies which Cedar group may do which console action
from `crates/kavach-auth/policies/kavach.cedar`; `permissions.test.ts` reads
that file and fails when the two disagree; it also copies which ADR-019
role may do which action, and the test checks that table against the role
policies in the same file. A page takes a viewer,
`{ principal, groups, roles }`. The roles are `GET /v1/me`'s, read once per
sign-in and kept in memory (`src/lib/me.ts`); until it answers they are
unknown, and an action that only a role grants stays shown.

- **Groups unknown** (`null`: the development fallback, the moment before
  `GET /auth/session` answers, and a server with no Cedar policy loaded):
  every control shows and the API decides. In login mode the viewer is the
  session's principal and the groups `GET /auth/session` returns: the groups
  the server's Cedar policy evaluates the principal in, which are the token's
  groups merged with the principal's memberships in the entities file
  (`useViewer` in `src/lib/changeRequests.ts`).
- **Groups known and allowed:** the control shows, with no hint.
- **Groups known and lacking the action:** the control is not rendered. One
  `RoleHint` line takes its place, in muted text with an `Info` icon:
  "Your roles (…) and groups (…) don't include one that may <action>. The
  server decides; ask an admin if you need this." (While the roles are
  unknown: "Your groups (…) don't include one …".) Never word it as if the
  console were the control.
- **The sidebar** leaves out a page whose read the viewer's known roles and
  groups lack (`src/lib/pageAccess.ts`). A hint, not a gate: the page still
  opens by its address and shows the server's 403.
- **Superadmin banner.** While `GET /v1/me` names `superadmin`, every page
  shows "Acting as superadmin" under the top bar.

The change-request proposer rule still applies on top (the proposer gets
cancel only; anyone else approve and reject).

### Actions, status and focus

- Submit and action buttons use `aria-disabled` (with a guard in the
  handler), never `disabled`, while a request is in flight: a disabled button
  drops keyboard focus to the page body.
- Every result goes in an always-rendered `role=status` region; every refusal
  in an always-rendered `ProblemAlert`. A field error is tied to its field
  with `aria-invalid` and `aria-describedby`, and focus moves to that field.
- When the control that started an action is gone afterwards, focus moves to
  the result (change requests) or the page's heading (agent detail).
- Change-request results are plain `text-ink`, not green: the status says
  what happened (approved, rejected, cancelled), and colour is not the signal.

### Page states

Every page that reads the API reads through `useResource` (`src/hooks/useResource.ts`: `loading | ok | error`, and `retry`) and lays the read out with `ResourceState`:

| State | What the page shows |
|---|---|
| Loading | A skeleton (not placeholder text), and what is loading in `role=status`, e.g. "Loading agents…" |
| Loaded | The data; lists say how many in `role=status` ("3 jobs.", or "50 jobs, the most this page reads.") |
| Empty | The table's empty message, e.g. "No batch jobs recorded yet." |
| Error | `ProblemAlert`: the problem `detail`, `HTTP <status> · request_id <id>`, and Try again. A non-JSON error (a proxy's 502) shows its status and says no `request_id` was returned |
| 401 | The alert adds: sign in again, or set an access token in Settings (development fallback). In login mode a 401 also ends the session and goes to `/signin` |
| 403 | The alert adds that the server refused this for the principal, and that the server decides |
| 404 (detail pages) | A headline that names the record ("No batch job job-1 on this server."), the server's detail and `request_id`, and no Try again |

The `ProblemAlert` and `role=status` regions are always rendered, empty when there is nothing to say, so assistive technology announces what fills them. A detail page keeps its heading (the record id) in every state, and offers no action until the record is read.

Proposals (Policy detail, Model detail, Retention) go through `useProposal` and `ProposalStatus`, so a refused proposal shows the same alert. Change requests keeps its own reload, so after a refused approve or reject the request, its buttons and focus stay where they were.

Evaluate and the evidence lookups are actions, not reads on load: they start idle and report through the same `ProblemAlert` and `role=status`. Settings makes no API read.

An unknown path renders `NotFoundPage`: "Page not found", the path, and a link to Overview.

Each page takes its read as an optional `resource` prop, so the Vitest specs render every state to static markup with the helpers in `src/test/states.ts` (`loading`, `ok`, `failed`, and problems for 401, 403, 404, 500 and a non-JSON 502).

## Layout

```
Mobile (< lg): off-canvas sidebar + hamburger in top bar
Desktop (≥ lg): fixed 256px sidebar

┌──────────────┬────────────────────────────────────┐
│   Sidebar    │  TopBar (env + principal)          │
│   (navy)     ├────────────────────────────────────┤
│              │  Page content (cards, forms)       │
│   Governance │                                    │
└──────────────┴────────────────────────────────────┘
```

### Agent-only servers

A server started with `--agent-only` serves no credit-track route, and
`GET /v1/runtime` says so (`agent_only: true`). The shell asks once per page
load (`useAgentOnly`) and then:

- the sidebar leaves out Evaluate, Policies, Models, Batch jobs, Incidents,
  Retention and Decision events (`src/lib/creditTrack.ts`); the agent pages,
  Change requests and Audit stay;
- a credit-track path shows "Not served on this server" with a link to Agents,
  and calls none of its routes (a credit-track page waits for the answer);
- Overview drops the active model, jurisdiction and credit capability cards.

Until the server answers, or if it cannot be asked, every page shows and the
API answers a route it does not serve with 404.

### Sign-in screen and header (ADR-018)

`GET /auth/config` decides what the console offers, once per page load (`src/lib/session.ts`). No page renders until it is known (`SessionGate`, a "Checking your session…" `role=status`).

| Mode | When | `/signin` shows | Pages |
|---|---|---|---|
| Login | `login_configured` | "Sign in to Kavach": a plain link to `/auth/login` (never a form or a fetch: CSP `form-action`), and a line saying tokens stay on the server and the browser holds only an HttpOnly session cookie | only with a live `GET /auth/session`; otherwise sent to `/signin` |
| Development fallback | no login, `pasted_token_allowed` (server in `--insecure-dev`) | "Development sign-in": the pasted token / principal ID form, with a "Development fallback." note | as before login existed |
| Not configured | neither | "Console login is not configured on this server", pointing to `docs/INSTALL.md`; no field, no link | none |
| Settings unreadable | `/auth/config` failed | the failure in `role=alert` and "Try again" | none |

`/signin` (`src/pages/SignInPage.tsx`) is outside the app shell: a single card with the logo, an `h1`, a `role=status` region ("Your session ended. Sign in again." after a 401) and a `role=alert` region (the `?error=` message). Only the four codes of the contract map to text; any other value gets "Sign-in did not complete. Try again.", and the raw value is never rendered.

Header (`TopBar`), login mode: "Signed in as `<principal>`", the absolute session end on wide screens, and a **Sign out** button, reachable by keyboard. Sign-out is a `POST /auth/logout`; it then goes to `/signin` inside the app, or, when the server returns an end-session URL that is `https:` (or on the console's own loopback origin in development), navigates there by script. A sign-out the server does not confirm shows a `ProblemAlert` under the header and leaves the operator signed in. In the development fallback the header shows the pasted principal, as before, and no sign-out.

Settings, login mode: the session card (principal, groups, session end, idle end) and what sign-in does: tokens stay on the server, the browser holds only the HttpOnly cookie, and signing out ends the Kavach session, not the IdP session unless the server is set to. In the development fallback it keeps the pasted-token form, labelled as a development fallback.

Tests. The stubbed browser suite (`npm run test:e2e`, `e2e/login.e2e.ts`) covers each `/auth/config` mode, a stubbed sign-in and sign-out, a 401 that ends the session, sign-in errors, the keyboard, axe on every state, and the role hints a viewers-only session gets. The real round trip (`npm run test:roundtrip`, `playwright.roundtrip.config.ts`, `e2e/signin.roundtrip.ts`) needs `npm run build` and then `cargo build -p kavach-api --bin kavach-api --example oidc_double`. It starts the OIDC test double and kavach-api (this console embedded, `--insecure-dev`, memory stores) on 127.0.0.1, stubs nothing and injects no header. It covers every Playwright item of ADR-018:
- the sign-in round trip through the double; a reload keeps the session; after sign-out, Back shows no signed-in page;
- no token in `localStorage`, `sessionStorage`, IndexedDB or `document.cookie`, and the only cookie is `__Host-kavach_session` with Secure, HttpOnly, SameSite=Strict, Path=/, no Domain and no expiry;
- every page under the server's real CSP, with no `securitypolicyviolation` event and no request to another origin (the top-level redirect to the IdP is the one exception);
- an ended session, sent to `/signin` with "Your session ended. Sign in again.";
- keyboard-only sign-in and sign-out, with axe on the signed-out and signed-in pages.

The stack guard (`e2e/stack.ts`) checks the CSP and other-origin rules on every round-trip test.

The ended session is a stand-in. The session clock is the server's wall clock, and the shortest idle limit is 5 minutes, so the spec ends the session on the server by signing out in a second tab and then puts the old cookie back.

A request the CSP blocks never reaches Playwright's request log. So the other-origin check catches only what the CSP lets through, and the CSP listener catches the rest.

Chrome stores the `__Host-` Secure cookie on `http://127.0.0.1`, because it treats loopback as a secure context, so the round trip runs on plain HTTP with the production cookie. The console's origin must be exactly the redirect URI's origin (`127.0.0.1`, not `localhost`).

### Responsive breakpoints

| Breakpoint | Behavior |
|---|---|
| `< md` (default) | Data tables render as stacked cards; page padding `p-4` |
| `md+` | Full data tables with horizontal scroll fallback |
| `< lg` | Sidebar hidden; drawer opens from hamburger |
| `lg+` | Persistent sidebar; top bar without menu button |

Test at **375px**, **768px**, and **1280px** before shipping UI changes. `e2e/narrow.e2e.ts` opens every page at 375×800 in CI and fails on sideways scroll or an axe violation.

### The console on a real stack

`npm run test:real` (`playwright.real.config.ts`, `e2e/full.real.ts`, `e2e/agent-only.real.ts`) runs every page and action against a real, seeded stack, with nothing stubbed and no header injected. It starts:

- a `kavach-dev` bundle whose issuer is the OIDC test double;
- the double;
- the mock provider;
- `kavach-api` (memory stores, Cedar, console login) on a full server and an `--agent-only` one.

`e2e/realSetup.ts` then issues mandates and makes agent calls, so the pages have records to show. The specs sign in as an admin, an approver and a viewer, and cover:

- the page walk;
- evaluate and the decision-event lookup;
- agent evidence;
- restrict, quarantine and revoke;
- reinstatement: cancelled, then rejected and approved by the approver;
- reconciliation;
- model and retention proposals;
- the viewer's role hints;
- the agent-only navigation.

Build first: `npm run build`, then `cargo build -p kavach-api --bin kavach-api --example oidc_double -p kavach-devkit --bin kavach-dev -p kavach-mock-provider --bin kavach-mock-provider`. CI runs it in "Format, Clippy, Test". Its limits: memory stores only, and the double stands in for a real IdP.

## Pages

The routes in `src/App.tsx`. "Credit" pages are left out on an agent-only server (`src/lib/creditTrack.ts`). The API operation behind each call is in [docs/CONSOLE_PLAN.md](../docs/CONSOLE_PLAN.md) section 2.

| Route | Page | Nav group | Calls (`src/lib/api.ts`) | Credit |
|---|---|---|---|---|
| `/overview` (`/` redirects here) | `OverviewPage` | main | `fetchHealth`, `fetchRuntime` | no |
| `/evaluate` | `EvaluatePage` | main | `evaluateRequest` | yes |
| `/settings` | `SettingsPage` | main | none (session or development token) | no |
| `/agents` | `AgentsPage` | Agents | `fetchAgents` | no |
| `/agents/:agentId` | `AgentDetailPage` | Agents | `fetchAgent`, `stopAgent`, `proposeReinstatement` | no |
| `/agent-evidence` | `AgentEvidencePage` | Agents ("Agent evidence") | `fetchAgentDecision`, `fetchRevocationRecord` | no |
| `/reconciliation` | `ReconciliationPage` | Agents ("Closed loans") | `reconcileClosedRecords` | no |
| `/policies`, `/policies/:packId` | `PoliciesPage`, `PolicyDetailPage` | Governance | `fetchPacks`, `fetchPack`, `proposeChange` | yes |
| `/models`, `/models/:modelId` | `ModelsPage`, `ModelDetailPage` | Governance | `fetchModels`, `fetchModel`, `proposeChange` | yes |
| `/batch`, `/batch/:jobId` | `BatchJobsPage`, `BatchJobDetailPage` | Governance ("Batch jobs") | `fetchBatchJobs`, `fetchBatchJob` | yes |
| `/changes` | `ChangeRequestsPage` | Governance ("Change requests") | `fetchChangeRequests`, `approveChange`, `rejectChange`, `cancelChange` | no |
| `/audit` | `AuditPage` | Governance | `fetchAuditLog` | no |
| `/incidents` | `IncidentsPage` | Governance | `fetchIncidents` | yes |
| `/retention` | `RetentionPage` | Governance | `fetchRetentionSettings`, `fetchTombstones`, `proposeChange` | yes |
| `/decision-events` | `DecisionEventsPage` | Governance | `fetchDecisionEvent` | yes |
| `/users` | `UsersPage` | Access ("Users & roles") | `fetchPrincipals`, `fetchRoleBindings`, `fetchAccessReview`, `fetchAccessReviewCsv` (on a click only: every export is audited), `proposeChange` | no |
| `/signin` | `SignInPage` | outside the shell | none directly (`startSession` in `App.tsx` reads `GET /auth/config` on load); links to `/auth/login` | no |

Any other path shows `NotFoundPage` (404). `/signin` and the `/auth/*` calls (`src/lib/session.ts`) are the ADR-018 sign-in (#248, #250).

### Adding a page

- Reuse `PageHeader`, `Card`, `DataTable`, `Badge`/`DecisionBadge`, `Button`, `Dialog`, `TextField`, `ProblemAlert` and `RoleHint`.
- Call the API only through `src/lib/api.ts` with the generated types. A new operation is called by a page or listed with its reason in `console/api-coverage-exempt.txt`; CI checks both ways.
- Add the route to `src/App.tsx` and the sidebar group it belongs to; a credit-track page also goes in `CREDIT_TRACK_PATHS`.
- Read through `useResource` and lay the read out with `ResourceState` (Page states); take the read as an optional `resource` prop and test every state in Vitest. Format dates with `formatDateTime()` from `lib/format.ts`.
- Add the page to `PAGES` in `e2e/a11y.e2e.ts` (axe) and `e2e/narrow.e2e.ts` (375px), its actions to the keyboard specs in `e2e/`, and, if it reads seeded records, to `e2e/full.real.ts`.

## Local development

```bash
cd console
npm run dev          # Vite on :5173, proxies API to :8080
npm run build        # → dist/ (embedded by kavach-api)
npm run typecheck && npm run lint && npm test
npm run gen:api      # regenerate src/lib/openapi.d.ts; check:api compares it with the git index
npm run test:e2e     # Playwright + axe against a stubbed API (Chromium)
npm run test:roundtrip  # sign-in round trip against kavach-api and the OIDC double (build first)
npm run test:real    # every page and action on a real, seeded stack (build first)
python3 ../scripts/console_path_coverage.py --list   # which page calls which operation
```

Run `kavach-api` on port 8080 for live API integration during dev.
