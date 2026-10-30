# V2 console audit and plan

The V2 target is `web/`, the React console served on port 5217. The separate
`ui/` application is not the target. Preserve existing routes, permissions,
site scoping, audit behavior, API calls, translations, and test IDs.

## Screen map

| Existing route | Current source | V2 direction | Data source |
| --- | --- | --- | --- |
| `#overview` | `features/overview/OverviewPage.tsx` | Threat activity overview | Workspace overview and ingestion health |
| `#alerts` | `features/alerts/AlertsPage.tsx` | Alerts explorer | Workspace alert list and detail |
| `#queue` | `features/queue/QueuePage.tsx` | Queue and group detail | Workspace queue, group, assignment, status, disposition, and bulk APIs |
| `#chains` | `features/incidents/M3WorkspacePage.tsx` | Chain candidates | Workspace chains, detail, dismiss, and promote APIs |
| `#incidents` | `features/incidents/M3WorkspacePage.tsx` | Incident detail and timeline | Workspace incidents, events, narrative, context, and action APIs |
| `#metrics` | `features/metrics/MetricsPage.tsx` | Service health and available operations metrics | Workspace operations and quality metrics |
| `#investigate` | `features/investigate/` | Composer, answer, citations, and evidence | Bootstrap, questions, fetch paging, and feedback APIs |
| `#history` | `features/history/HistoryScreen.tsx` | Retain question history | Existing answer session |
| `#topics` | `features/topics/TopicsScreen.tsx` | Retain question topics | Bootstrap topics and existing navigation |
| `#status` | `features/investigate/StatusScreen.tsx` | Retain service status | Bootstrap service information |

Routes are defined in `app/Navigation.tsx`. Workspace endpoints and runtime
validation are in `api/workspace.ts` and `api/workspace-m3.ts`; question hooks
and endpoints are in `api/hooks.ts` and `api/client.ts`. Global styling and
tokens live in `styles/global.css` and `styles/tokens.css`, with shared UI
components in `components/ui/`. Preserve the existing `data-testid` in
`features/investigate/AnswerView.tsx` and check again before changing markup.

## Data gaps to resolve during design

Do not fabricate values or infer causality from unrelated events. Use an empty
state when the existing contract cannot supply a requested widget.

- The incident event contract supplies time, rule, fields, and stages but no
  typed entity graph edges or relationship semantics. A trustworthy graph with
  labelled hostile edges needs an API representation of entities, links, and
  their supporting events. The current incident screen has an event timeline.
- The quality metrics response contains disposition and precision measures,
  not answer outcomes by day, judgment states, stage latency, validator
  removals, or per-topic answer quality. These widgets need corresponding
  measured aggregates.
- The operations response has backlog, volume, and timing statistics. Backlog
  flow, analyst load, and a tuning recommendation need supported historical
  aggregates or explicit recommendations. Verify individual fields before use.
- Overview exposes hourly counts, totals, and top lists. Previous-period rule
  changes, day-by-hour heatmaps, per-agent severity histories, and first-seen
  entities require suitable scoped data or aggregation endpoints. Confirm each
  widget against the schema before displaying it.
- Explorer field cardinalities, top-value distributions, and arbitrary query
  syntax need explicit API support. Do not imply that client-side filtering of a
  page covers the full result set.

## Baseline (2026-10-30)

- `npm run typecheck` in both `ui/` and `web/`: passed.
- The checked-in `web/package.json` has no unit or end-to-end test scripts.
  Existing test files and browser configurations are ignored local artifacts.
- Direct `vitest run --mode production-test` failed: the default configuration
  collected Playwright files and ran DOM tests without a DOM environment. This
  is not a valid passing baseline; restore a supported test configuration.
- Direct `playwright test` failed before tests: its local configuration invokes
  the missing `dev:mock` script. Do not point it at the running lab service.

## Sequence

1. Restore a reproducible, isolated test harness and record a valid baseline.
2. Add tokens, theme selection, typography, semantic tags, and accessible shell.
3. Refine each existing route while preserving behavior and showing honest empty
   states for data gaps. Keep chain and incident revision boundaries intact.
4. Add behavior tests, keyboard and responsive coverage, and axe checks. Run
   typecheck, unit tests, end-to-end tests, and build before declaring completion.
