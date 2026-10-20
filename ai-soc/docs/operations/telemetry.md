# Telemetry and audit operations

## Trace and metric path

Application traces use the pinned OpenTelemetry API, SDK and OTLP/gRPC exporter. The
application sends to the task-local ADOT receiver at `127.0.0.1:4317`; the collector
uses the ECS default configuration to export spans to X-Ray through the private X-Ray
VPC endpoint. The fixture Compose stack uses the pinned ADOT image and a local-only
configuration with the debug exporter. It has no host port and no AWS exporter.

Trace parents come from the request's validated W3C `TraceContext`. Span names are the
frozen stage enum. Exported span attributes are limited to stage, outcome, latency,
error code, visibility and fetch classification. The service resource has only the
fixed service name and committed service SHA. Do not add question, owner, site, query,
row, prompt, token, model response or credential values as attributes.

Each question path opens one trace context for the ask (or unplanned clarify/refusal)
and records stage spans at real call sites: auth, plan, content, broker, fetch,
checks, count, reserve, converse, validate, render, feedback and audit. Completed
spans append to `AuditEvent.stage_outcomes` for durable audit. Telemetry export
failures are isolated: they never fail the user-visible answer after audit ack.

CloudWatch metrics use the fixed `AISOC/Service` namespace. Core per-stage metrics are
`StageLatency` and `StageOutcome` (dimensions: finite `Stage` and `Outcome` enums) and
`AuditDelivery` (stage `audit` plus outcome). Operational counters use only fixed names
and finite dimensions:

| Metric | Unit | Dimensions |
| --- | --- | --- |
| `FetchResult` | Count | `Classification` (`FetchState`) |
| `RemovedFinding` | Count | `Reason` (`RemovedReason`) |
| `CacheTokens` | Count | none |
| `BudgetReserved` / `BudgetCharged` | Count | none |
| `ContentProvenanceFailure` | Count | none |
| `FeedbackEnqueueFailure` | Count | none |
| `LeaseConflict` | Count | none |
| `TokenBrokerFailure` | Count | none |
| `RecoveryLagSeconds` | Seconds | none |
| `RecoveryBacklog` | Count | none |
| `AdmissionRejected` | Count | none |

A missing metric is never interpreted as a zero count. The private `monitoring` endpoint
policy permits metric publication only to this namespace.

## Durable audit lifecycle

The request path sends one strict `AuditEvent` to the KMS-encrypted audit SQS queue.
It may return an `AuditAck` only after SQS returns a nonempty message ID. Queue or
acknowledgment failure fails the request closed. Producers send no question text,
query text, filters, evidence rows, prompt, token or model output. Fetch entries carry
the frozen scope/query hashes, resolved window, template, result class, bounded count
and typed evidence checks.

The scheduled private ECS consumer receives at most ten messages per poll with a
30-second visibility timeout. It validates each event, writes the canonical event
under `events/<event-id-prefix>/<event-id>.json` with `If-None-Match: *`, and only
then deletes the SQS message. HTTP 412 `PreconditionFailed` confirms that the object
already exists and is treated as an archived retry. HTTP 409
`ConditionalRequestConflict` is transient and does not confirm an existing object, so
the consumer leaves that message on the queue for redelivery. Other invalid messages
or failed archive writes are also left for retry and eventual redrive. See
[AWS PutObject](https://docs.aws.amazon.com/AmazonS3/latest/API/API_PutObject.html).
The source queue retains messages for seven days; its DLQ retains
messages for fourteen days. The archive bucket is encrypted, versioned and retains
objects for at least ninety days.

The `AuditQueueAge` alarm fires when the oldest message exceeds 120 seconds for two
one-minute periods. `AuditDlqNotEmpty` fires as soon as a visible DLQ message appears.
Missing age data is treated as breaching; missing DLQ data is treated as empty. On
either alarm, verify the consumer task role, SQS receive/delete access, KMS decrypt,
S3 `PutObject` and KMS data-key permissions, then inspect aggregate consumer counts.
Never copy message bodies into tickets or ordinary logs. Restore service and archive
first; review a DLQ event only through the approved encrypted audit path.

The consumer's one-shot output contains only received, archived and failed counts.
It never prints message bodies, event IDs or cloud SDK exception text. SQS retries
are at least once; event ID and conditional object creation make archival idempotent.
