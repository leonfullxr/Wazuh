# Implementation spec for 2026-11-23

Status: FINAL r2, gatekeeper approved

## 0. Scope

Five implementer workstreams, one PR each against main. WS-A starts at
`05a47de`. The UI baseline is `8e011ee` (merge of #94). The
[audit](audit_report.md) describes the earlier inventory. #82 and #72 are
already closed. WS-D adds coverage for the shipped dashboard.

Approval covers this spec. M3 acceptance, runtime qualification, live
queries, annotation, frozen evidence, the joint gate and the acceptance
calendar stay outside this round. #96 and visual acceptance under #91
remain with the owner. No schema, infrastructure or CI workflow change.

## 1. System context

PostgreSQL workers claim jobs inside an authorized site transaction. An
expiry sweep can change state even when the following claim returns no row.
The model scheduler admits a guardian before the guardian recovers, claims
or authorizes work. A scheduler or guardian can exit before its children.
The host manifest binds the host, runtime, path spelling and physical slot
directory. A site binding identifies that directory in each participating
database. The authority path is relative to the effective account's home
in the OS user database. Host-wide serialization assumes one cooperating
service account, one trusted authority and a local filesystem supporting
Linux flock across all participating checkouts and databases.

The console uses Radix sheets, a native command dialog and custom components.
StatusPill wraps Tag. Queue also uses Tag directly for status and disposition.
Alerts spreads severityTag into Tag. PageHeading renders an h1. Overview's
summary and the dashboard descriptions belong to their route components.
The verification build uses synthetic responses and an explicit Playwright
file list. The separate CSP suite has its own configuration.

## 2. Workstreams

Owned paths below are relative to ai-soc. Braces enumerate files. Each
verification block runs from that directory and includes the common gate
in section 5. Baseline failures below are required evidence to obtain at
implementation time.

### WS-A. Slot admission, targeted claims and transient settlement

Branch `feat/workspace-slot-alias-targeted-claim`. One backend PR.

Owned files: `src/ai_soc/workspace/{jobs.py,worker.py}`,
`src/ai_soc/workspace/model/{worker.py,guardian.py,narrate.py}`,
`docs/operations/workspace.md`,
`verification/python/{test_model_profile.py,test_targeted_claim.py}`.
Local test ownership: ignored `tests/workspace/db/test_ws_a_contract.py`.
Reuse the existing fixtures and narrative harness.

#### Contract and required tests

1. Admission and descriptor lifetime. On both canonical and alias paths,
   open the canonical private directory with O_RDONLY, O_DIRECTORY,
   O_NOFOLLOW and O_CLOEXEC. Validate its type, owner, mode and identity.
   Take an exclusive nonblocking flock on that fd first. Then open the
   legacy slot-0.lock relative to the directory fd and take its exclusive
   nonblocking flock. Preserve the legacy busy result on contention. On
   either acquisition failure close all acquired fds. Release by close,
   including on spawn errors, so inherited copies keep their locks.
   Only the ordinary creating path may use O_CREAT. After locking, use a
   fresh fstat on the lock file and compare with a no-follow entry stat.
   Require a private, owned regular file, link count one and matching device
   and inode. Check the directory fd against the current protected path
   and against the directory identity in the manifest and binding before
   admitting work. A fresh pathname lookup alone cannot prove which
   directory is locked.
2. Keep the stable directory fd as the physical slot handle used by
   direct guardian and recovery callers (`slot_fd=slot.fd`). The slot
   object also owns the legacy file fd. Transfer both open descriptions
   to the spawned guardian via explicit fd arguments and pass_fds. Check
   their types, identities and locks before recovery or claim. Recovery
   validates the held directory against the registered device/inode.
   Keep both in the guardian. Forward only the directory fd as the one
   slot_fds element to the existing provider, Bubblewrap supervisor and
   broker transport lifetime paths. The sandboxed payload must receive
   neither descriptor. The pinned Bubblewrap accepts only one effective
   sync fd. [Bubblewrap 0.8.0 option handling](https://github.com/containers/bubblewrap/blob/v0.8.0/bubblewrap.c#L1924-L1942)
3. Document the rollout precondition in workspace operations. Stop old
   schedulers and drain all old guardians and cost-bearing descendants
   sharing this authority before enabling the new fleet. Apply the same
   drain before rollback. During transition the legacy lock contends with
   a holder of the intact old entry. An old process cannot enforce the
   directory lock, and a surviving new sandbox holds the directory only.
   Mixed active versions are unsupported. The trusted service account and
   administrator control the manifest and its parents. No manifest rewrite
   or machine-wide path migration is part of this change.
4. Exercise canonical and alias admission in separate processes on the
   same temporary directory. Assert a second updated admission stays busy
   across replacement of the legacy entry while the directory fd is held,
   and succeeds after the final holder exits. Cover an intact legacy-only
   holder, close on busy/error, and an independently opened directory fd.
   Exercise the real scheduler-to-guardian argv and pass_fds handoff.
   Use local, non-networking stand-ins to verify capacity after scheduler
   exit, then after guardian exit with the CLI or transport still alive,
   and release after the last descendant. Verify the generated sandbox
   command has exactly one sync fd and the transport retains that same
   directory identity. Exercise hard links, symlinks, mismatched post-lock
   identity and link count changes between open and flock with controlled
   filesystem fixtures. No sleeps as synchronization.
5. Legacy alias and enrollment. In configuration, authority_slot_directory
   is optional. If present, require a NUL-free normalized absolute spelling
   without dot segments or redundant/trailing separators and lexically
   distinct from the canonical slot_directory. Its resolved target must
   equal the canonical directory and match its device/inode. The manifest
   keeps the original alias spelling and exact bytes. Use the resolved target as the alias identity. A same-target symlink
   replacement between observations is valid. Compare alias target, canonical path and held
   directory before and after reading the manifest.
6. Alias provisioning is filesystem read-only. Under both locks, validate
   the existing directory, entry and manifest before the first binding
   insert. A busy slot refuses enrollment with `slot_busy` and makes no DB
   change. A privileged provisioner may enroll missing sites, including
   in another participating database. Store the canonical path, host,
   runtime, directory device/inode and slot count one. Verify an existing
   identical row idempotently. Retrying after a partial multi-site enrollment
   must converge without rewriting previously verified rows. Refuse a conflicting row with
   `runtime_binding_not_provisioned_or_changed`. Ordinary execution only
   verifies bindings. In local PostgreSQL, verify row contents, repeat
   provisioning, refuse a missing prerequisite without creating a row or
   file, preserve manifest bytes and show two enrolled databases contend
   for the same physical slot.
7. Verification errors have an observation boundary. Initially absent
   directory, alias target, required lock or manifest raises
   FileNotFoundError. An initially wrong alias target, or a previously
   observed alias/target that disappears or resolves elsewhere, raises
   PermissionError(`authority_slot_directory_changed`). Pin the manifest
   locator and its lstat identity before open. Compare with fstat at open
   and after read, and recheck the locator and lstat after read. A changed
   or vanished manifest after first observation, including replacement
   before open, raises PermissionError(`host_authority_changed`). Stable
   wrong manifest bytes, owner, mode or type raise
   PermissionError(`host_runtime_already_bound`). A stable symlink at the
   final manifest component is an invalid type. Preserve a stable symlink
   in an ancestor if all checks pass. Retain the existing private path and
   type checks for the slot. Report post-open link/entry mismatch as
   PermissionError(`slot_file_changed`). Write deterministic tests at
   observation boundaries for these results, including a same-target alias
   swap, parent retarget and same-bytes manifest replacement. Test config
   rejection and refusal before SQL as well as successful enrollment.
8. Targeted work. A supplied target is an exact Python int in
   1 through 9223372036854775807 inclusive. Reject True, strings, zero, negatives and overflow with
   ValueError before issuing claim or expiry SQL. Test both valid bounds.
   run_once requires exactly one site and batch_size=1 for a target.
   Keep authorization, row-level security, fencing, attempt limits and
   untargeted scheduling. For targeted expiry and claim use the same
   site, ID and intersection of kind and job_kinds when supplied. Bind
   values as SQL parameters. A missing, locked or ineligible target
   never selects a neighbor. run_once returning 0 means no job claimed
   on this pass, including a pass that terminally expires the target.
9. Test validation without a DB. Prove effects in real PostgreSQL using
   non-owner app connections in site transactions. Insert an earlier
   eligible neighbor and a later eligible target. A valid run passes only
   the latter ID to the handler. Compare neighbor state, attempts, owner,
   lease token and deadline before/after in memory. With two exhausted
   running jobs only the requested one becomes dead and clears its lease.
   Below the limit reclaim an expired target with a new lease and one
   additional attempt. Exercise missing ID, wrong singular kind, excluded
   job_kinds, incompatible filters, and foreign-site queued and exhausted
   targets. Assert no claim and no unintended mutation. In a separate
   connection hold a conflicting row lock, require a prompt zero result
   without fallback, roll back the holder and require success on the next
   pass. Bound the test with a statement timeout. Include an untargeted
   control that retains normal ordering and sweep behavior.
10. Settlement. run_guardian defaults retry_transient_errors to True and
    forwards the flag to finish_call. The flag controls a settlement that
    commits under a live lease. With otherwise identical first attempts
    and an injected timeout, assert one authorization and one outcome per
    call, the same safe reason `timeout`, and the actual public narrative
    read: default gives queued/retrying, False gives dead/unavailable.
    Under default an injected permanent `tool_attempt` gives
    dead/unavailable with that reason and one outcome. Force cancellation
    after provider return or lose the lease before commit with False.
    Assert no stale receipt or publication, then exercise expiry/recovery:
    one abandoned_unknown outcome and a queued job below the attempt
    limit. Recovery may authorize another call. Disabling transient
    retries gives no exactly-once guarantee.

#### Baseline-failure proof and verification

Against main, show the directory-lifetime exclusion assertion fails with
the original single lock. Against 05a47de show the wrong-kind exhausted
target changes and that missing-lock alias enrollment reaches insertion.
For targeted dispatch and policy forwarding, disable each filter/forwarding
change in an isolated test checkout and observe the wrong row or public
settlement. A signature error or a recording cursor alone is insufficient.

Use the local private lane for PG proof. Use migrated_workspace_db,
app_connection and admin_connection with disposable PostgreSQL 16 via
Docker or an approved disposable WS_TEST_ADMIN_DSN runtime loader. Keep
fixture connection details private. On every reviewed WS-A head, including
rebases, run all of the following:

```sh
uv run --locked python -m pytest -q --tb=no verification/python/test_model_profile.py verification/python/test_targeted_claim.py
uv run --locked python -m pytest -q --tb=no --disable-warnings tests/workspace/db/test_ws_a_contract.py tests/workspace/db/test_narrative_durability_independent.py
git rev-parse HEAD
sha256sum tests/workspace/db/test_ws_a_contract.py
make ci-check
```

Record HEAD, private test file digest, PG major version, named cases,
pass/skip/fail counts and commands in the PR. A missing fixture, skip,
empty selection, unavailable DB or previous-head result leaves this gate
open. PR CI covers only the public tests.

### WS-B. Keyboard focus in six dialogs (#77)

Branch `fix/dialog-focus-trap`. Owned files:
`web/src/app/{CustomRange.tsx,custom-range.css,CommandPalette.tsx,App.tsx}`,
`web/src/components/ui/sheet.tsx`, `web/src/features/queue/QueuePage.tsx`,
`web/src/features/alerts/AlertsPage.tsx`,
`web/src/features/investigate/EvidenceDrawer.tsx` and
`web/verification/browser/routes.check.ts`. Limit production edits to
failures demonstrated by the tests.

Contract and tests. Convert custom range to a modal focus scope using the
installed Radix dialog primitive. Preserve UTC editing, validation, Apply
and dismissal. For the controlled Queue sheet capture the actual row opener
and use SheetContent.restoreFocus. Preserve the command palette's native
showModal, combobox and arrow-key navigation. Suppress Ctrl+K and Meta+K
while another modal is open.

Give Queue, Alerts evidence, mobile navigation (390px), command palette,
custom range and Investigate evidence separate named Chromium tests. Enter
each with the keyboard. Record the real invoker, assert focus enters, use
real Tab and Shift+Tab and assert containment after every press. Visit at
least two distinct named controls in both directions and observe last to
first and first to last. Allow internal datetime-local stops with a bounded
loop. Examples include Search and Close, the two UTC inputs, and Investigate
Close and Copy. Escape hides the dialog and focuses the exact invoker.
Also open the palette by shortcut from a different control than its button.
With Investigate evidence open, try each shortcut, assert only the original
dialog remains visible and focused within, then Escape once and check the
evidence opener. Keep existing passing cases as controls.

Baseline proof. With these tests on main, record each repaired behavior's
failing focus or dismissal assertion, including custom range escape by Tab,
Queue opener restoration and the conflicting shortcut. Verify:

```sh
npm --prefix web run test:browser -- routes.check.ts
make ci-check
```

### WS-C. Severity fills (#71, existing PR #80)

Branch `cursor/semantic-tag-fills-fdc7`. Owned files:
`web/src/lib/semantic.ts`, `web/src/components/ui/tag.tsx`,
`web/src/styles/tokens.css`, `web/verification/unit/semantic.check.ts`
and `web/verification/browser/theme.check.ts`.

Contract and tests. Add an explicit severity variant to Tag, default quiet.
Have severityTag return it so the existing Alerts spread opts in without a
page edit. Use variant-scoped styling in tag.tsx and theme tokens for its
fill, border and text. Map numeric alert levels 0-6 green, 7-9 amber,
10-11 orange and 12-15 red. This preserves the existing red threshold
and gives low and upper-warning levels distinct fills. Unknown/null and
info stay neutral. Keep the visible level number. Queue's numeric risk
score remains a score. Apply no tone-wide fill or rail override. Status,
disposition, entity, health and rail tags keep their quiet surface and
existing dot/outline treatment, including when their tone matches severity.

Cover boundaries 0, 6, 7, 9, 10, 11, 12, 15 and info in the semantic unit
test. In separate browser tests for Light and Dark, use the theme control.
Render synthetic Alerts rows for all four tones (supply test-local response
overrides for missing levels), an unknown tag, and actual same-tone Queue
disposition and status examples. Check the variant, text, border and fill
against computed values of the active theme tokens, including transparent
neutral. Compare a red or green disposition with a severity of that exact
tone. For each severity check >=4.5:1 text contrast at rest and with its
row actually hovered. Composite the computed foreground, translucent fill
and underlying row/surfaces to opaque colors before calculating WCAG
relative luminance. Use severity-specific token adjustments where needed.

Baseline proof. Keep the synthetic rows present on main and assert, for
example, the visible level 12 has a neutral background where the red fill
is required. With the unscoped #80 styling show the same-tone quiet
control fails. Verify:

```sh
npm --prefix web run test:unit -- semantic.check.ts
npm --prefix web run test:browser -- theme.check.ts
make ci-check
```

### WS-D. Compact titles and shipped dashboard coverage (#73, existing PR #81)

Branch `cursor/compact-page-titles-fdc7`. Owned files:
`web/src/styles/global.css` (page-head rules only) and
`web/verification/browser/{overview-cards.check.ts,dashboard-empty.check.ts}`.

Contract and tests. Use 24px Source Serif 4, weight 500, for .page-head h1
at 1440x900 and 390x844. Commit c500134 deliberately chose the typeface
and weight. At both sizes check resolved family, font size, weight and
header bottom margin (0..16px) on loaded, fresh full-mode Overview after
document.fonts.ready. Measure the actual gap from the header's bottom to
the summary's top (0..16 CSS px). At desktop separately require the first
summary metric's viewport top <320px at scroll origin. Name each viewport
case. PageHeading has no description paragraph.

For each of #ai_quality and #soc_operations at both sizes, wait for its
visible index. Require the route-specific description, exactly one empty
state, zero widget cards, respectively seven and six list items, each with
a visible nonempty title and explanatory sentence. Check the available
metrics link has href="#metrics", activate it and assert the Metrics h1.
Measure document scrollWidth <= clientWidth on each mobile dashboard
before following the link.

Baseline proof. Main computes a 32px title. For the already shipped
dashboard, keep the passing main control and demonstrate that removing one
SOC Operations entry or breaking its link fails that route's test. Reuse
#81 for both changes. #72 and #82 require no action. Verify:

```sh
npm --prefix web run test:browser -- overview-cards.check.ts dashboard-empty.check.ts
make ci-check
```

### WS-E. Overflow with stressed workspace data (#76, existing PR #98)

Branch `cursor/workspace-stress-fixture-fdc7`. Owned files:
`web/verification/mocks/workspace-handlers.ts`,
`web/src/app/Navigation.tsx` (scenario entry only),
`web/src/features/{overview/overview-v2.css,alerts/alerts-v2.css,queue/queue-v2.css,metrics/metrics-v2.css}`,
`web/verification/browser/stress-layout.check.ts` and
`web/verification/browser.config.ts`. Retain main's row-targets.check.ts
unchanged, including the Metrics edit control's fresh lookup and retry.

Contract and tests. Port the workspace_stress fixture and selector. Apply
route-scoped layout fixes where the fixture demonstrates a failure. Use a
named test per route and width for Overview, Alerts, Queue and Metrics at
390x844 and 1280x900. Set the browser locale to en-US and the UI to English.
Wait for visible stressed data in the measured component and for
document.fonts.ready. Require documentElement.scrollWidth <= clientWidth
separately from content geometry. A table may scroll inside its wrapper.

- In Overview measure the ranked hostname inside its button and the rule
  inside its list row. Require the rendered text or ellipsis to fit and
  the hostname button and adjacent count to occupy disjoint space.
- In Alerts check the rendered rule description and hostname against their
  table cells. In Queue check the long group title and host against the
  identity button and cell, and the count against its own cell.
- In Metrics check the stressed hostname and complete tag list inside the
  asset row and the large backlog/volume counts inside their containers.
  For wrapped text check line rectangles. Accept intentional ellipsis only
  with constrained width, clipping and a way to read the full value.
- At each visible stressed count in these routes require exact grouped
  text for its fixture value (12,345,678 for the single large count), one
  rendered line and containment in its cell/card. Use a Range over the
  numeric text to exclude adjacent dates or explanatory text. Check any
  visible aggregate against the aggregate of its fixture buckets.

Baseline proof. Keep identical fixture, scenario, test registration and
checks on a baseline with main layout. Identify a route, viewport and
failing geometry measurement, then rerun the same case with the layout
fix. Fixture lookup, navigation or absent data cannot establish overflow.
Verify:

```sh
npm --prefix web run test:browser -- stress-layout.check.ts row-targets.check.ts
make ci-check
```

## 3. Conflict plan

File ownership is exclusive. Main already registers routes.check.ts,
theme.check.ts, overview-cards.check.ts and dashboard-empty.check.ts.
WS-B/C/D extend those files. WS-E alone adds stress-layout.check.ts
immediately after citation-label.check.ts in testMatch. Preserve the
remaining entries and separate CSP registration. On rebase, discard the
old config hunks in #80 and #81, keep only the new entry from #98, and
port assertions to their assigned files. WS-C styles Tag at its definition,
WS-D owns the global title rules, and WS-E owns the affected route styles.
Do not carry unrelated branch hunks through a rebase.

## 4. Dependency graph

```text
main -> WS-A -> backend PR
main -> WS-B -> #77 PR
main -> WS-C -> #80
main -> WS-D -> #81
main -> WS-E -> #98
```

All five may land in any order. There is no WS-F PR.

## 5. Verification and delivery

1. Use the reviewed baseline for red/green comparisons. Keep the new
   test code and all required synthetic inputs/registration in both runs.
   Revert only the behavior under test in a disposable development copy.
   Record the named failing assertion, baseline SHA, green head SHA and
   commands. Preserve passing compatibility cases. For a shipped feature,
   a scoped negative control proves its coverage.
2. Use the repository's pinned CI environment. Run the targeted commands
   above, then make ci-check, and require the PR's CI verify job to pass.
   Browser cases must have individual names and fit the existing 30-minute
   job. Keep the private PG proof as an additional WS-A merge gate.
3. Reuse each existing UI PR. Rebase from current main and update its own
   branch with lease protection under the implementation authorization.
   Link each UI fix to its listed open issue. No new PR for a closed item.

## 6. Privacy

Use synthetic providers, fixtures, temporary directories and disposable
databases. Never print credentials, tokens, DSNs, raw event bodies or label
bodies. Use runtime loaders for protected configuration. Keep reports to
identifiers of test cases, versions, safe reason codes, dimensions, counts
and hashes. Do not dump SQL parameters, fixture bodies, environments or
private pytest traces. No access to internal/, records/, private content or
protected config for this work. No live Wazuh or model account calls.
Before staging check ignore rules and the Git index. Stage only owned
public ai-soc paths. Keep private tests, local state, evidence, dist-demo
and the parent .gitignore out of the PRs.

## 7. Review disposition

| ID | Decision | Reason |
| --- | --- | --- |
| A1 | amend | Lock the already bound directory and drain mixed versions to preserve existing manifest bytes. |
| A2 | accept | The retry switch governs committed live-lease settlements and the loss case exercises recovery. |
| A3 | accept | Targeted expiry intersects both kind filters exactly as the claim does. |
| A4 | amend | Document the single-account, shared-authority deployment boundary. |
| A5 | accept | Only the explicit severity variant receives a filled surface. |
| A6 | accept | A zero count describes this pass and has separate contention, reclaim and exhaustion cases. |
| A7 | accept | Hold the stress scenario constant and compare measured geometry. |
| A8 | accept | Refresh fstat after flock and compare the resolved alias target across observations. |
| A9 | accept | Alias enrollment validates the existing lock before inserting a binding. |
| A10 | accept | Validate type and signed bigint bounds before issuing SQL. |
| B1 | amend | Make actual PG outcomes mandatory on every reviewed backend head using the private fixtures. |
| B2 | accept | Define all four numeric tones and resolve theme tokens through the real theme control. |
| B3 | accept | Restore Queue's actual opener and test custom range and native palette with real keys. |
| B4 | accept | Measure text, siblings and cells on settled data and retain the Metrics retry. |
| B5 | accept | Run the guardian for both policies and dispatch the target through the actual worker. |
| B6 | accept | Enrollment stores the canonical row after filesystem verification and rejects unsafe entries. |
| B7 | accept | WS-D exercises both shipped dashboard indexes and their navigation. |
| B8 | accept | Require distinct focused controls, both wraps, hidden dialogs and exact opener restoration. |
| B9 | accept | Pin the deliberate serif weight and measure margin, visible gap and metric position. |
| B10 | accept | Name each dialog and route/viewport case independently within the existing CI budget. |
| C1 | accept | Directory admission persists for the full lifetime of updated cost-bearing processes. |
| C2 | amend | Permit privileged enrollment in another DB sharing the verified physical authority. |
| C3 | accept | Severity opts in at the semantic helper and same-tone disposition stays quiet. |
| C4 | accept | Require composited text contrast of at least 4.5:1 at rest and on row hover. |
| C5 | accept | Pin the alias target and distinguish initial absence from observed manifest or target changes. |
| C6 | accept | Suppress the palette shortcut while a different modal is open and test one Escape. |
| C7 | accept | Check the real public status, safe reason and outcome count for both retry policies. |
| C8 | accept | Add signed bigint bounds, foreign-site claim/expiry cases and lexical versus resolved alias checks. |
