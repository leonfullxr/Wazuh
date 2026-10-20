# Service specification

This document contains the public behavioral requirements that define the service alongside the [wire contracts](contracts.md). The JSON schemas under `contracts/v1/` define exact serialized field layouts.

## Query fields and filters

The query compiler accepts only a finite set of service-owned templates:
`alerts_rows_v1`, `alerts_count_v1`, `alerts_group_v1`,
`vulnerabilities_rows_v1`, `vulnerabilities_count_v1` and
`vulnerabilities_group_v1`. A caller can select a template and provide approved
field values. A caller cannot provide an index name or query DSL.

| Field | Index family | Allowed operations | Type and constraints |
|---|---|---|---|
| `timestamp` | alerts | window range only | UTC timestamp |
| `agent.id`, `agent.name` | both | `eq`, `in`, `exists` | Strings; agent IDs are never converted to integers |
| `rule.id` | alerts | `eq`, `in`, `exists` | String |
| `rule.level` | alerts | `eq`, `gte`, `lte`, `exists` | Integer from 0 through 16 |
| `rule.groups` | alerts | `eq`, `in`, `exists` | Reviewed exact terms |
| `data.srcip`, `data.dstip` | alerts | `eq`, `in`, `exists` | Canonical IPv4 or IPv6 literal |
| `vulnerability.id` | vulnerabilities | `eq`, `in`, `exists` | Canonical CVE identifier |
| `vulnerability.severity` | vulnerabilities | `eq`, `in`, `exists` | Reviewed enum |
| `vulnerability.detected_at` | vulnerabilities | window range only | Timestamp with meaning established by the mapping profile |
| `package.name`, `package.version` | vulnerabilities | `eq`, `in`, `exists` | Strings |

String filter values are at most 128 UTF-8 bytes. An `in` list contains at most
16 distinct strings. Filter values are strings, integers, string lists or null;
booleans are not integers. Timestamp range predicates come only from the
resolved question window. User filters cannot use wildcards, scripts,
regular expressions, free query text, arbitrary JSON or URLs. Filter literals
are encoded through the indexer's JSON API.

Group fields are limited to `agent.id`, `rule.id` and `rule.level` for alerts,
and `agent.id` and `vulnerability.severity` for vulnerabilities. A response
contains at most 20 buckets and identifies incomplete or approximate bucket
results. A count-only query returns count evidence, never a fabricated record.

Projected columns are fixed by template and mapping profile. Raw `full_log`,
arbitrary `_source`, secrets, usernames and file payloads are excluded. Missing
fields are represented as null with a mapping or evidence check. Unsupported
mapping produces an explicit mapping error and never a zero-result response.

## Query authorization and result states

Policy, schema and mapping checks run before the final read. Validation queries,
index discovery and diagnostics run with the same analyst authority as the
requested read. A successful query validation does not prove authorization for
the final query. The site's policy determines whether visibility is full,
filtered or unknown; returned rows do not establish full visibility. Unknown
visibility prevents all-clear claims.

HTTP 403 maps to denied; 401 maps to unavailable or authentication rejected;
timeouts and server errors map to unavailable. A missing index or mapping stays
unknown or unavailable rather than empty. For a known filtered role, the result
state remains filtered even when rows are present or the count is zero.

For a visible zero result, the service may make at most one index-existence
probe, one unfiltered window-count probe and ten reviewed single-filter probes.
Each filter probe uses the same window, template and authorization. A qualified
empty result requires a confirmed index, a positive exact visible window count,
full visibility and an identified filter or verified combination that matches
nothing. It can support the statement that no records matched the stated scope
and window; it cannot support a claim that the system is healthy. Unknown
ingestion or visibility produces fixed wording and no generated all-clear.

## Evidence and pagination

Evidence is canonical sanitized JSON bound to one topic and validated against
the service schemas. Evidence IDs use the algorithm implemented by the service
and covered by the canonical vectors. IDs cannot collide across topics, even
when the same source record appears more than once. Model-visible values are a
typed allowlist. Logs and other source text are data and never executable
instructions. Count evidence has its own aggregate ID and is not inferred by
counting displayed rows.

The default page size is 20 and the maximum is 50. `top N` limits displayed
rows and disables further paging beyond N; the count still describes all
matching visible records and its exactness. Stable pagination uses a read-only
point-in-time snapshot and `search_after` with a mapping-profile-approved
order of timestamp, concrete index and record ID, all in the requested direction.
Record IDs reused across indices retain distinct evidence. Equivalent repeats
of the same index/ID deduplicate within a page and disclose one duplicate-source
check; backend counts remain independent of displayed rows. Every returned sort
tuple must match its source identity before a cursor can be issued. The boundary
comes from the last raw hit, including a removed repeat. If those capabilities
are unavailable, the service returns only the first page, no cursor and an
explicit limitation. A cursor is authenticated
and encrypted, bound to the owner, site, policy, content, query and snapshot,
and reauthorized on every page. Legacy cursors without index identity require
a fresh query and are rejected before credential or backend work. Sort support
requires site-specific qualification. Paging never changes a previous judgment.

## Compatibility

Wire schema version `1` remains stable across additive freeze revisions. Exact
field defaults and requiredness are defined by the generated model schema. New
optional serialized fields use compatibility defaults where existing stored
records or cursors need to remain readable. Internal accounting metadata does
not change API behavior.
