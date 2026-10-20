# Replay evaluation corpus v2

This corpus is synthetic. Labels and expected observations describe the
scenario ground truth and the product rules. They were authored without
running the replay evaluator. v1 is unchanged.

## Contents and conventions

- `cases/pack_*.json` are frozen EvidencePacks judged by D, M and D+M.
- `cases/source_*.json` freeze indexer responses for the real planner and
  playbook executor. Source outcomes are `unresolved`; only observations are
  scored and no model calls are specified.
- `catalog/` contains strict JSON copies of both seed topics, their playbooks,
  expectations and finding templates. Cue and context records are generated.
- `generate_cases.py` uses only the standard library and generates the frozen
  inputs, manifest, cue/context records and holdout lock deterministically.
- `labels.json`, `scripts.json` and `expected_metrics.json` are hand-authored
  oracles. A rerun must leave them byte-identical.

The v1 conventions continue to apply: partitions are disjoint by `incident_id`,
`entity_keys` and `dedup_key`; variants share a family `dedup_key` and remain in
one partition; the manifest carries runtime-filled identity fields; Wilson
intervals use z = 1.959964; and a zero-denominator cohort has a null rate,
null interval and `empty_cohort` status. Source cases have the outcome label
`unresolved` and appear only in source observation metrics.

Escalation is a manual-review referral, not an attack verdict. The escalation
templates are `auth_volume_review` and `vuln_priority_review`. D refers iff
`auth_volume` passes for `auth_review` or `vuln_priority` passes for
`vuln_review`. The volume threshold does not establish password guessing; a
Critical inventory record does not establish exploitation or current affected
status.

## Scenario limits

`auth_guess_11` and `auth_authorized_11` carry identical record values. The
scenario truth differs, so they have separate labels but share a family key.
No comparator can separate them from these records. `vuln_critical_exploited`
and `vuln_critical_not_exploited` likewise carry identical inventory values;
the label follows the scenario's exploitation truth. Metric results expose
these irreducible false referral or miss limits.

`auth_guess_9` is independently known guessing below D's volume threshold.
`auth_level10` and `auth_level9` hold the count below that threshold so the
priority boundary is isolated. The approximate auth total makes count-based
checks unknown. The denied read is a denial, and an empty exact total is not an
all-clear. `vuln_page_miss` has 21 matching records, 20 displayed High rows and
one Critical record outside the displayed page. Its returned-row priority
check fails, so D misses the known exploited case by design.

## Source observation shape

Source expected observations include all playbook check IDs, count fields,
row cardinality and every projected row field. Auth rows cover `agent.id`,
`rule.id`, `rule.level`, `data.srcip` and `timestamp`. Vulnerability rows cover
`agent.id`, `vulnerability.id`, `vulnerability.severity`,
`vulnerability.detected_at`, `package.name` and `package.version`.

### Runner additions required

Use the v1 `checks` mapping keyed by playbook check ID. The source scorer must
read `TopicAnswer.checks` and compare outcomes by topic and check ID. Add only
the following source observation support:

- `expected_observations.row_cardinality`: mapping from `fetch_id` to expected
  returned row count.
- `expected_observations.rows`: ordered row objects keyed by projected field
  ID, with typed scalar or null values. The v1 string-only values need to accept
  integers and null for fields such as rule level and missing package version.

For pack output, the existing observation shape already carries check outcomes.
The source scorer must compare the complete row lists, projected values and
cardinality. No other additive oracle shape is used.

## Regeneration

Run `python tests/fixtures/evaluation/v2/generate_cases.py` from the repository
root. The generator writes cases, `manifest.json`, `holdout.lock`, and derived
cue/context records. It does not write labels, scripts or expected metrics.
