# Claude Opus 5.5 high implementation review

The initial independent review of the MCP implementation requested changes. Claude inspected a read-only snapshot. The implementation team reproduced the findings and verified the revisions against the normal server entry points.

| Finding | Revision and evidence |
|---|---|
| Write-action logs lost the principal and target | All 14 write paths now emit paired records with a readable verified principal, opaque owner ID, correlation ID, cluster and applicable validated target fields. Tests cover both successful and failed stub dispatch, escaped text and exclusion of private payloads. |
| Integer keys disappeared from rule counts | Rule counts retain JSON-compatible numeric keys. Date, time and UUID values survive sanitization. A regression checks the tool, resource and decoded GCF results. |
| API key entries without a scope list lost their historical default | An omitted list grants read. An explicitly empty list grants nothing. Tests exercise bearer tokens, OAuth and HTTP tool calls. |
| Dynamic OAuth registration lifetime was unclear | Dynamic client registration remains process-local and fails closed on restart or idle eviction. The operations guide explains re-registration, reauthorization and replica affinity. |
| Schema validation rejected established client inputs | Named legacy coercions cover decimal limits, case-insensitive severity, supported boolean spellings, optional null values and individual rule groups. Unknown arguments and unsafe confirmations stay rejected. |
| Redaction missed credential aliases and damaged ordinary prose | Tests cover password assignments, structured aliases, authorization headers, all-letter standalone credentials and ordinary authentication terminology. |
| Timeline status, catalog ownership and session throughput | The Manager refreshes a stale token once within the original byte and time budgets. Callers get independent JSON schemas. Atomic store operations permit independent session updates without holding a process-wide lock during Redis I/O. |
| Generic size-limit warning | Oversized legacy output produces a complete parseable warning. Investigation results have source-level matched and returned counts where available. Generic responses can lack a known total. |

The pre-staging local matrix exercised Python 3.11 and 3.13, with 771 tests passing on each against real Redis. Specialized browser verification uses the official SDK and Apps bridge with synthetic upstreams. See the [delivery report](delivery_report.md) for coverage and deployment-specific qualification.

## Follow-up verdict

The second read-only review accepted five of the six findings and all four lower-severity notes. It identified one remaining credential-redaction regression in command-line flags and prefixed environment or header names. The configuration guide now also states the default for an omitted API key scope list.

The third review returned **PASS** for the remaining blocker. Claude verified the prefixed assignment cases, bounded structured-key suffix matching, preservation of near matches, and the scope documentation. It suggested extending coverage to dotted and camel-case structured keys, strengthening one long-key assertion, and giving the suffix variable a distinct name.

**Final verdict — PASS.** On the delivered code, Claude confirmed all three refinements and accepted the added handling for common separate-value command-line flags. It found no blocking regression. Its final pass was a static review of the redaction code and tests. The orchestrator ran the executable checks separately.

The reviewer recorded residual limits in free-text and field-name matching. Some alternate flag spellings, unusual values, acronym-heavy keys and non-ASCII keys fall outside the supported patterns. Multiline flags and benign fields whose names end in a sensitive term can be over-redacted. Production operators should continue to restrict telemetry and log access at the source.

## Live staging correction

Wazuh 4.14.5 exposed the incorrect Manager route and a missing sort-key value in real Indexer results. Claude Opus 5.5 high reviewed the incremental implementation and returned **PASS**. The corrected adapter requests and verifies the agent ID and status. The compatibility snapshots check both query parameters. The regression suite covers missing, malformed, mismatched and ambiguous Manager rows. Removing the null-key guard in a temporary copy made its dedicated regression report false complete coverage, as expected. The [delivery report](delivery_report.md) records the real service and browser results.
