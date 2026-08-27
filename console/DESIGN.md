# Kavach Console — Design System

Production UI foundation for the governance console. Milestone B.4 (policy lifecycle) should extend these patterns — not introduce a parallel design.

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
| `saffron-500` | `#E8870D` | Primary CTA, logo accent |
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

## Layout

```
┌──────────────┬────────────────────────────────────┐
│   Sidebar    │  TopBar (env + principal)          │
│   (navy)     ├────────────────────────────────────┤
│              │  Page content (cards, forms)       │
│   Governance │                                    │
│   [Soon]     │                                    │
└──────────────┴────────────────────────────────────┘
```

## B.4 guidance

When building policy lifecycle UI:

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
