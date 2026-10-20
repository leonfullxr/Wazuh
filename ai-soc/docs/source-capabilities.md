# Source capabilities

This document is the reviewed capability record for the alert and vulnerability sources. It describes what the service reads, what each read reports, and what the service cannot know without operator input. It is documentation, not a signed content pack, and it does not qualify any deployed Wazuh release.

## 1. Supported source matrix

| Family | Mapping profile | Support | Status |
|---|---|---|---|
| Alerts (`alerts_rows_v1`, `alerts_count_v1`, `alerts_group_v1`) | `wazuh-v4-fixture` | fixture only | No Wazuh release is qualified. |
| Vulnerabilities (`vulnerabilities_rows_v1`, `vulnerabilities_count_v1`, `vulnerabilities_group_v1`) | `wazuh-v4-fixture` | fixture only | No Wazuh release is qualified. |

The profile name does not establish support for any deployed release. Support here means that the query compiler, the playbooks and the seed content were tested against the fixture paths below. Live sites must select and validate their own pinned mapping profile before use.

## 2. Field matrix

Paths come from the `wazuh-v4-fixture` profile in `src/ai_soc/query/compiler.py`. Declared types are the types the seed public documents state for the fixture profile. They are declarations, not runtime attestations: the service does not inspect backend field types, and it checks bound values only when it validates a finding.

| Logical field | Fixture path | Declared type | Family |
|---|---|---|---|
| `timestamp` | `@timestamp` | date | alerts |
| `agent.id` | `agent.id` | keyword identifier | alerts, vulnerabilities |
| `agent.name` | `agent.name` | keyword or text | alerts, vulnerabilities |
| `rule.id` | `rule.id` | keyword identifier | alerts |
| `rule.level` | `rule.level` | integer | alerts |
| `rule.groups` | `rule.groups` | keyword array | alerts |
| `data.srcip` | `data.srcip` | IP address or keyword | alerts |
| `data.dstip` | `data.dstip` | IP address or keyword | alerts |
| `vulnerability.id` | `vulnerability.id` | keyword identifier | vulnerabilities |
| `vulnerability.severity` | `vulnerability.severity` | keyword | vulnerabilities |
| `vulnerability.detected_at` | `vulnerability.detected_at` | date | vulnerabilities |
| `package.name` | `package.name` | keyword or text | vulnerabilities |
| `package.version` | `package.version` | keyword or text | vulnerabilities |

Fields outside a family are rejected at compile time with `MAPPING_UNSUPPORTED`. Paths that start with an underscore or contain wildcard characters are rejected the same way.

## 3. Timestamp meaning

- Alerts: `timestamp` maps to `@timestamp`, which is the alert record time. Whether that equals the underlying event time, or the time the manager generated the alert, is not qualified for any release. Treat alert time as record time only.
- Vulnerabilities: `vulnerability.detected_at` is the detection time. It is not the time of the last scan, the time the inventory was collected, or the time the record was ingested. A recent detection does not show that the asset was scanned recently.
- Neither family projects an ingestion timestamp or a scan timestamp. Ingestion lag and inventory scan age are therefore unknown (see section 8).
- Snapshot times in responses are retrieval metadata. They say when the service read the source, not when the source event happened or when the inventory was scanned.

## 4. How windows are applied

- Each read applies a `[start, end)` range to the family time field: `@timestamp` for alerts and `vulnerability.detected_at` for vulnerabilities. A record at exactly `end` is outside the window.
- Rows are returned latest first by default. `earliest` order is available only where the fetch requests it.
- Counts and group reads use the same range and filters as the row read.
- Playbook reads default to a rolling 24-hour window ending at the request time. Follow-up questions may replace the window, and the window is then recorded on the plan.

## 5. Visibility

Visibility comes from the authorized site policy for the verified principal: `full` or `filtered`. It is never inferred from the returned rows. A `filtered` read returns only the records the policy allows, so a filtered read with no visible rows is not evidence that no matching records exist.

## 6. What reads report

Each read reports its visibility, window, displayed rows, backend count and exactness, snapshot, diagnostics and an error when one applies.

- Denied: the backend returned 403 (error `INDEXER_DENIED`). The state is `denied`, and the read reports no rows or counts.
- Unavailable: the backend could not answer. The state is `unavailable` with a named error code.
- Unsupported mapping: the backend returned 400 or 404 for the read, or the mapping profile cannot express the requested field.
- Authentication rejected: the backend returned 401. The read is terminal.
- Approximate totals: a total with relation `gte` is a lower bound. Checks that need an exact count report `unknown`.
- First page: when a point-in-time snapshot is not used, the read covers only the first page. Checks describe the returned rows only.

HTTP error mapping, as implemented in `src/ai_soc/query/indexer.py`, is:

- 401 becomes an authentication rejection.
- 403 becomes a denial.
- 400 and 404 become an unsupported mapping.
- Any other failure becomes an unavailable read.

These are terminal read failures for the read that receives them. Two cases are tolerated on purpose. Opening a point-in-time snapshot that returns 400, 404 or 405 falls back to a first-page read (`indexer.py` around line 151). Validation that returns 404 or 405 is not treated as a failure (`indexer.py` around line 193). Diagnostic probes that fail for other reasons, such as index existence and empty-result counts, do not fail the read. They become unknown inputs, so the service reports the unknown rather than an answer (`indexer.py` around lines 678 and 703).

## 7. The record_age check

The `record_age` playbook step reports whether the newest returned record with a valid timestamp inside the read window of an earlier fetch is within `max_age_seconds` of the playbook run time. It uses the family time field: `@timestamp` for alerts and `vulnerability.detected_at` for vulnerabilities.

- It is evaluable only for a rolling window whose end is at most 300 seconds before the run time. Any other window reports `unknown`.
- `passed` means at least one returned record is within the limit. It is existential over the returned rows. It does not show source health, completeness, ingestion lag or scan freshness.
- `failed` means the newest returned record with a valid timestamp inside the read window is older than the limit. A failed check only supports a disclosure that the newest returned record with a valid timestamp inside the read window is older than the configured limit. It does not say the source is stale as a whole.
- `unknown` covers a source read that was unavailable or unsupported, no returned rows, and no returned row with a valid timestamp inside the window.
- `denied` is reported when the read was denied.
- The explanation always says that only returned rows were used. It also notes first-page reads and approximate totals.
- Only the authentication review uses a `record_age` check in the seed (3600 seconds, synthetic). Real limits are deployment inputs.
- The vulnerability review has no recency check because detections are not a continuous stream, so detection time cannot show whether the inventory or ingestion is current. Inventory scan age is unknown and must be confirmed in the authoritative inventory (section 8).

## 8. Unknown inputs and the operator input each needs

Each item below is unknown in this release. The service reports it as unknown rather than inferring it.

- Retained event classes: which alert and event classes the manager retains for the site. Needed from the site administrator to say what a read can and cannot contain.
- Coverage and roster: which endpoints should report and whether they do. Needed from the operator's authoritative asset list. Without it, an absent record is not evidence of an absent endpoint.
- Ingestion lag: the delay between event time and index time. Needed from the pipeline owner as an independent ingestion timestamp or watermark. Without it, undelivered or late events cannot be detected.
- Retention: how far back the index keeps records. Needed from the backend lifecycle configuration. The oldest visible record does not establish retention.
- Inventory scan time: when each asset's inventory was last collected. Needed from the scanner's own scan record. The vulnerability detection time does not provide it, and no vulnerability recency check is built on it.

## 9. Related documents

The contract for playbook steps and the freeze revision is in `docs/contracts.md`. The record_age step and its build rules are described there and in section 7 above.
