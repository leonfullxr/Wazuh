# Replay evaluation corpus v1

This corpus is synthetic. It exists to validate the replay runner and its
denominator logic. It makes no accuracy claim about the product or any model.

## What it contains

- 16 pack-stage cases: frozen EvidencePack files for one topic (`ssh_auth`).
  Each is judged by three comparators: deterministic only (D), one model only
  (M), and the product path (D+M).
- 5 source-stage cases: frozen indexer responses and a question. They run
  through the fixture composition and the planner, and are scored only by
  observation accuracy. They make no model calls. Their outcome label is
  `unresolved` and they appear in no binary metric.
- Labels, scripted model responses and hand-computed expected metrics.

Every scenario is described in `labels.json`. Expected values were written from
the scenario descriptions and the documented metric definitions, not from running any
evaluation code.

## Files

- `catalog/`: evaluation content records. `topics/`, `playbooks/`,
  `expectations/` and `finding-templates/` are hand-authored. `cues/` and
  `context/` are written by `generate_cases.py` because they carry hashes.
- `generate_cases.py`: stdlib-only, deterministic generator. Re-running it
  must produce byte-identical output.
- `cases/`: generated EvidencePack files (`pack_*.json`) and source-case inputs
  (`source_*.json`).
- `manifest.json`: generated. Case list, input hashes, partitions, dedup keys,
  deterministic rules, escalation template IDs, and identities.
- `holdout.lock`: generated. SHA-256 of each holdout case file.
- `labels.json`: hand-authored labels, one per case.
- `scripts.json`: scripted converse responses per pack case. Evidence is
  selected by fetch or check ID, kind and field, never by evidence ID.
- `expected_metrics.json`: hand-computed outcome class per case and comparator,
  counts, and every metric with its numerator, denominator and Wilson interval.

## Partitions

- dev: the attack family (`pack_attack_en`, `pack_attack_es`,
  `pack_attack_injection`), the two separate attack packs
  (`pack_attack_truncated`, `pack_attack_guardrail`), and the other
  insufficient, false-detection and unresolved packs, plus `source_reused_id`
  and `source_approximate_total`.
- holdout: the benign family (`pack_benign_en`, `pack_benign_es`), the filtered,
  unknown-visibility and denied packs, and `source_missing_index`,
  `source_filtered_role` and `source_mixed_language`.

Variants (Spanish twins and the injection variant) share their family's
`dedup_key` and `entity_keys` and stay in one partition. Each case has its own
`incident_id`.

## Identities

The manifest fixes `policy_hash` to the canonical policy hash that every pack
file carries. It is the canonical hash of `config_hash` = SHA-256 of
`soc-eval-v1 synthetic site configuration`, roles `["analyst"]`, visibility
`full`, and `effective_permission_scope` `dls-v1`. The runner must verify that
every pack carries this value and use it as the pack-stage context policy hash.

The runner must compute these identities and record them with each run. They
are set to `"runtime"` in the manifest:

- `code_sha`
- `mapping_sha256`
- `query_sha256`
- `model_capability_sha256`
- `prompt_sha256`

The generator fills `content_sha` (first 40 hex of the SHA-256 over the
non-context catalog files) and `content_pack_sha256` (SHA-256 over all catalog
files). `enrichment` is `{"state": "none"}`.

## Hashes the runner must match

- Pack `sha256` is the canonical SHA-256 of the pack without its `sha256` field.
  The generator computes it the same way the product does.
- Source request keys are `(method, path, sha256(canonical body))`. The path
  includes the query string as sent. A bodiless request hashes `null`. The
  PIT keep-alive is `5m`, which `WazuhIndexer` fixes.
- Source `as_of` is the fixture clock. Windows are rolling 24 hours ending at
  `as_of`.

## Scripted behaviours

Every scripted behaviour in `scripts.json` reaches the D+M validator or provider
on a pack where `engine.prepare` returns Ready: invalid JSON, max_tokens,
guardrail intervention, empty findings, unsupported claim, omission, false
escalation, miss, correct attack, correct benign, and a raised exception. Scripts
on skipped packs (denied, filtered, unknown visibility, missing index) do not
reach D+M and only drive M.

## Model-output conventions

For M, which has no validator, every parsed candidate counts as rendered. The
omitted-required and unsupported-claim metrics for M use that definition.

## Frozen questions

Each pack case carries a frozen `question` in its manifest entry: English for
`en` cases and Spanish for `es` cases. The runner must pass this text as the
judgment question and must not invent prompt text.

## Source cases

Each source case file holds the question, site, principal and frozen response
map. The manifest entry for the same case carries the same fields. An unmatched
request is a harness error, not a 404 or an empty result.

Source entity keys are the agent ID and a per-partition source IP (`192.0.2.21`
in dev, `192.0.2.22` in holdout). They are listed in the manifest.

The mixed-language source question replaces the `G031.en.mixed` golden case
reference. G031 is a mixed-topic question (LDAP and DNS), and it cannot plan
against this single-topic catalog. The replacement mixes Spanish and English
within one topic.

## Known limits of v1

- No holdout attack cases. The one attack family must stay in one partition, so
  holdout attack metrics are `empty_cohort`.
- No scripted budget or capacity failures. `budget_exceeded` and
  `capacity_limited` are not exercised.
- Injection case. `pack_attack_injection` carries instruction-like text and an
  example.test URL in an `agent.name` value. URL rejection applies to bound
  values only, and `agent.name` is not bound by any template, so URL rejection
  on `agent.name` is not exercised in v1.
- `pack_unresolved` uses `authorized_window` outcome `not_configured` with no
  expectation, so the label rests on a missing configuration, not a failed
  comparison. The frozen pack asserts `not_configured`; a source-stage run of the
  same rows against the shared catalog expectation would compute `failed`.
- Stale context is a product gap. The stale pack has no staleness check in the
  product, so D+M escalates it. It is a known source-freshness gap and is not a corpus
  failure. Its rows are dated 2026-10-09, outside the 24-hour window, on purpose.

## Regenerate

    python tests/fixtures/evaluation/v1/generate_cases.py
