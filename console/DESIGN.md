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
