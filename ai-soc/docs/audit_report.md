# AI SOC state audit (2026-11-23)

This report records the state of the public `ai-soc` project at `origin/main`
`8e011ee`. It covers code, open issues and pull requests, CI, and the
uncommitted work in the canonical checkout. Private acceptance evidence lives
in ignored paths and is summarized here only at the level of "what blocks
what".

## 1. Repository inventory

| Item | State |
| --- | --- |
| `main` | `8e011ee`, merge of #94. The local checkout was 46 commits behind and was fast-forwarded. |
| Recent merges | #92 and #94 (console redesign shell and workspace views, umbrella #91), #93 (OAuth pages), #97 (heatmap hint), #86, #63, #60, #59, #56 (UI fixes), #87 to #89 (MCP server). |
| Open PRs | #96 (analyst views, mergeable, waiting on visual review under #91). #98 (#76), #81 (#73), #80 (#71), #82 (#72): CI passed when opened, but all four now conflict with `main`. |
| Open issues | #91 redesign umbrella, #77 focus trap coverage, #76 overflow, #73 title size, #72 empty dashboards, #71 tag fills. |
| Uncommitted product code | `workspace/model/worker.py` (explicit legacy slot alias for the host authority manifest, non-creating slot lock), `workspace/jobs.py` and `workspace/worker.py` (`target_job_id` single-job claim), `model/guardian.py` and `model/narrate.py` (`retry_transient_errors` switch), and two new tests in `verification/python/test_model_profile.py`. That file passes 16/16. |
| Other local changes | `../.gitignore` in the parent repository (not ai-soc scope, left alone), untracked `web/dist-demo/` build output. |
| TODO/FIXME markers | None in `src/` or `web/src/`. |

## 2. Issue and PR gap analysis

| Issue | Covered by | Gap |
| --- | --- | --- |
| #72 empty dashboards | #94 (merged) replaced the card grid with one index and added `dashboard-empty.check.ts` on `main`. | #82 is superseded. Close #82 and #72 after a check against `main`. |
| #73 title size | #81 (conflicting). | `main` now sets `.page-head h1` to 32px Source Serif after #92. #73 asks about 28px. #91 asks for 24px titles. Rebase #81 and land 24 to 28px. |
| #71 tag fills | #80 (conflicting). | #80 fills red, amber, orange and green tags, and neutralizes them inside `.rail`, which #92 restyled onto the panel surface. #91 later says status is "an outlined pill or a dot plus text" and colour is reserved for severity and status. Rebase and reconcile: severity gets the tinted fill, status keeps the outlined pill with tone text and border. |
| #76 overflow | #98 (conflicting). | Rebase onto the #92/#94 layout and re-verify at 390px and 1280px. |
| #77 focus trap | none | Custom range popover handles only Escape. No browser test walks Tab and Shift+Tab through every dialog. Needs a fix and a check. |
| #91 umbrella | #92, #94 merged; #96 open | Visual acceptance belongs to the owner. #73 is the remaining type-scale item. |

## 3. Uncommitted backend work

The slot alias lets the model worker read the original host authority
manifest when the slot directory was recorded under a legacy spelling of the
same physical directory. It never creates the slot lock through the alias,
and it rechecks the alias target and the authority file identity before and
after reading. `target_job_id` restricts `claim_job` and its expiry sweep to
one job at one configured site with a batch of one. `retry_transient_errors`
lets a caller settle a transient provider error as final rather than
rescheduling it.

Gaps:

- `target_job_id` and `retry_transient_errors` have no public regression
  test. Their only callers are private lab tools.
- The private PostgreSQL suite (`tests/`, ignored) is not in public CI by
  design. Its job and worker regressions must be run locally.
- The work is not on a branch. Any release or acceptance packet that pins
  source bytes needs it committed first.

## 4. CI and test harness

- `.github/workflows/ai-soc-ci.yml` runs `make ci-check` on every PR that
  touches `ai-soc/**`: ruff, ruff format, pyright, the production tree check,
  pytest over `verification/python` (4 files), web typecheck, three generated
  contract checks, vitest, the Playwright browser and CSP suites, and the
  production build.
- `web/verification/browser.config.ts` registers every browser check in one
  `testMatch` list. Every UI PR appends to the end of that list, so
  concurrent UI PRs conflict there. This is the conflict in #80, #81, #82
  and #98.
- The private suites (C05 PostgreSQL, synthetic, ledger) run only locally.

## 5. Acceptance programme (summary)

M3 is unaccepted. Its remaining steps each need their own owner approval
and are tracked privately. Code changes in this round cannot advance them,
and this round does not touch them.

## 6. Priorities for this round

1. Put the backend work on a branch with regression tests (P1, it blocks any
   future source pin).
2. #77 focus trap fix and coverage (P2, no PR exists).
3. Rebase and reconcile #80 (#71), #81 (#73) and #98 (#76) onto `main`
   (P2, CI-green work that no longer merges).
4. Close the superseded #82 and #72 (housekeeping).

## 7. Outcome of this round

The console redesign (f2c5a8b) landed on `main` during the round. The UI
PRs were rebased onto it.

| Work | PR | Result |
| --- | --- | --- |
| Slot admission, targeted claim, transient settlement | #100 | Merged. |
| #77 dialog focus trap | #99 | Merged. The redesign replaced the Queue sheet with an inline panel, so five dialogs remain. |
| #71 severity fills | #80 | Closed. The redesign gives every tag tone a tinted fill. |
| #73 compact titles and dashboard coverage | #81 | Merged as dashboard coverage only. The redesign sets the page title style. |
| #76 overflow under stress data | #98 | Ported to the redesigned screens. |
| Queue and Metrics row swap before site selection (flaky row-target checks) | #101 | Merged, with a fix for a hidden table label that widened the Metrics page on a phone. |
| Duplicate Metrics landmark after the redesign | #103 | Merged. |
| #72 and superseded #82 | closed, fixed by #94 | |

The specification and its review disposition are in
[implementation_spec.md](implementation_spec.md).
