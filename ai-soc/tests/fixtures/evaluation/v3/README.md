# Replay evaluation corpus v3

This corpus is synthetic. The labels and expected observations were authored
from the scenario descriptions, the accepted SOC-007 rules and the metric
definitions. They were not produced by running the replay evaluator.

v3 measures the authentication `record_age` check and the `auth_recency_gap`
disclosure. Recency is a disclosure only. The `auth_recency_gap` template is
not an escalation template, and freshness changes no escalation. The escalation
template IDs and deterministic rules are exactly those in v2: D escalates when
`auth_volume` passes for `auth_review` or `vuln_priority` passes for
`vuln_review`. No vulnerability recency check exists; detection time does not
measure inventory or ingestion freshness.

## Contents and conventions

The file set and record shapes follow v2. Source cases freeze indexer replies
and run through the planner and playbook executor without model calls. Pack
cases freeze EvidencePacks and are judged by D, M and D+M. Existing v2 cases
are retained as baselines; added cases isolate the recency boundaries, invalid
timestamp handling, denial, unavailable reads, approximate totals, first-page
reads, stale returned pages and vulnerability detection-time non-use.

`generate_cases.py` writes only cases, catalog records, the manifest and the
holdout lock. `labels.json`, `scripts.json` and `expected_metrics.json` are
hand-authored oracles and remain unchanged when the generator runs.

Labels follow scenario truth. Fresh and stale variants share the same
`dedup_key`, partition and attack or benign label. v3 is a locked synthetic
evaluation set: nearly every case is in holdout because cases share entities,
and the oracle was corrected after review in this round. It gives no untouched-
holdout estimate. Recency never changes the
attack or authorized-test truth. Only returned rows determine the authentication
recency outcome. Exactly 3600 seconds passes. A failed outcome describes the
newest valid returned row only; it does not establish source health.

The v2 `checks` observation map carries `auth_recency`. The additive shapes are
limited to:

- `expected_observations.check_explanations`: per-check expected explanation
  facts, including invalid timestamp row count, returned-rows-only wording,
  whether an approximate total was noted as not used and whether the read was
  first-page-only.
- `expected_observations.no_check_ids`: check IDs that must be absent from a
  topic response, used to show that `vuln_review` has no recency check.
- `expected_disclosures`: expected rendered disclosure template IDs per pack
  case and comparator (`D`, `M`, `D+M`). M has no validator and renders every
  parsed proposal, including denied-read and wrong-topic proposals. D+M renders
  only findings accepted by validation.
- `expected_eligible_disclosures`: policy-eligible template IDs per comparator,
  separate from what is actually rendered. For M this is empty because M does
  not validate proposals.

## Runner additions required

The source scorer must compare `check_explanations` facts and `no_check_ids` in
addition to the v2 check outcomes, cardinality, row values, counts and fetch
state. In source metrics, each declared explanation fact is one `checks`
comparison, and each `no_check_ids` assertion is one `checks` comparison. Each
expected table's `row_cardinality` is one `rows` comparison, in addition to
each per-field row value comparison. The pack scorer must report
`expected_disclosures` by comparator and count disclosures rendered when
expected, rendered when not expected, and missed when expected and scripted.
These additions do not change escalation classification.

The frozen source harness cannot currently represent a second follow-up turn
whose replayed rolling window ended more than 300 seconds before the executor
anchor. Add `source_case.follow_up_turns[].replayed_window` before measuring
that case. No such case is fabricated here.

## Regeneration

    python tests/fixtures/evaluation/v3/generate_cases.py
