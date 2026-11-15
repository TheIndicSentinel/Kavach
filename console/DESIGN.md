# Kavach Console — Design System

Production UI foundation for the governance console. Milestone B.4 (policy lifecycle) should extend these patterns — not introduce a parallel design.

What the console covers, what it still lacks against the backend, and the order of work: [docs/CONSOLE_PLAN.md](../docs/CONSOLE_PLAN.md).

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

No heavy component library — primitives in `src/components/ui/` follow shadcn-style patterns without the dependency overhead.

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

| Component | Path | Purpose |
|---|---|---|
| `Button` | `ui/Button.tsx` | Primary (saffron), secondary (navy), ghost |
| `Card` | `ui/Card.tsx` | Content panels |
| `DecisionBadge` | `ui/DecisionBadge.tsx` | Domain decision display |
| `StatusIndicator` | `ui/StatusIndicator.tsx` | Health / liveness |
| `PageHeader` | `ui/PageHeader.tsx` | Page title + optional Hindi subtitle |
| `AppShell` | `layout/AppShell.tsx` | Sidebar + top bar + main |
| `KavachLogo` | `brand/KavachLogo.tsx` | Shield mark + wordmark |
| `RoleHint` | `ui/RoleHint.tsx` | The line shown in place of a control the viewer's groups are known to lack |
| `ProblemAlert` | `ui/ProblemAlert.tsx` | A refusal in `role=alert`: problem detail, HTTP status, `request_id` |

### Role hints (the server decides)

`src/lib/permissions.ts` copies which Cedar group may do which console action
from `crates/kavach-auth/policies/kavach.cedar`; `permissions.test.ts` reads
that file and fails when the two disagree. A page takes a viewer,
`{ principal, groups }`:

- **Groups unknown** (`null`, every mode today): every control shows and the
  API decides.
- **Groups known and allowed:** the control shows, with no hint.
- **Groups known and lacking the action:** the control is not rendered. One
  `RoleHint` line takes its place, in muted text with an `Info` icon:
  "Your groups (…) don't include one that may <action>. The server decides;
  ask an admin if you need this." Never word it as if the console were the
  control.

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

### Responsive breakpoints

| Breakpoint | Behavior |
|---|---|
| `< md` (default) | Data tables render as stacked cards; page padding `p-4` |
| `md+` | Full data tables with horizontal scroll fallback |
| `< lg` | Sidebar hidden; drawer opens from hamburger |
| `lg+` | Persistent sidebar; top bar without menu button |

Test at **375px**, **768px**, and **1280px** before shipping UI changes.

## B.4 guidance

Policy lifecycle UI is implemented (read-only v1):

- `/policies` — pack inventory and rule detail
- `/models` — model inventory and promotion metadata
- `GET /v1/runtime`, `/v1/packs`, `/v1/models` — governance APIs

- `/retention` — retention policy and tombstones
- `/batch` — batch job inventory (Postgres lifecycle)

When adding mutations (activate, rollback, promote):

- Reuse `Card`, `PageHeader`, `DecisionBadge`, `Button`
- Add data tables with the same border/radius tokens
- Place new routes under the **Governance** nav section (replace "Soon" stubs)
- Use skeleton loaders, not placeholder text, for async data
- Format dates with `formatDateTime()` from `lib/format.ts`

## Local development

```bash
cd console
npm run dev          # Vite on :5173, proxies API to :8080
npm run build        # → dist/ (embedded by kavach-api)
```

Run `kavach-api` on port 8080 for live API integration during dev.
